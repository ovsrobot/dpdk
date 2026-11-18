/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Isaac Boukris
 */

/*
 * Tests of the virtio PMD on a virtio-user port backed by vhost-net and a TAP
 * interface. They need no VM and no PCI device. The kernel's end is a packet
 * socket on the TAP interface.
 */

#include "test.h"

#include <stdio.h>

#ifndef RTE_EXEC_ENV_LINUX

static int
test_pmd_virtio_user(void)
{
	printf("virtio-user with vhost-net is only available on Linux, skipping test\n");
	return TEST_SKIPPED;
}

#else /* RTE_EXEC_ENV_LINUX */

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/virtio_net.h>

#include <rte_bus_vdev.h>
#include <rte_cycles.h>
#include <rte_epoll.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

#define VDEV_NAME "net_virtio_user_test"
#define TAP_NAME "dtap_vu_test"
#define RING_SIZE 256
#define NB_MBUF 1024
#define BURST 32
#define WAIT_MS 1000
/* The test frames' IP protocol (experimental, RFC 3692) */
#define TEST_IP_PROTO 253
#define NB_FLOWS 16

static struct rte_mempool *mp;
static uint16_t port_id = RTE_MAX_ETHPORTS;
static int ksock = -1; /* the kernel's end, each frame follows a virtio_net_hdr */
static bool started;

static int
port_stop(void)
{
	int ret;

	if (!started)
		return TEST_SUCCESS;
	started = false;
	ret = rte_eth_dev_stop(port_id);
	TEST_ASSERT_SUCCESS(ret, "stop failed: %s", rte_strerror(-ret));

	return TEST_SUCCESS;
}

/* Configure the port and start it. A failed case may have left it started. */
static int
port_start(const struct rte_eth_conf *conf)
{
	int ret;

	TEST_ASSERT_SUCCESS(port_stop(), "port stop failed");
	ret = rte_eth_dev_configure(port_id, 1, 1, conf);
	TEST_ASSERT_SUCCESS(ret, "configure failed: %s", rte_strerror(-ret));
	ret = rte_eth_rx_queue_setup(port_id, 0, RING_SIZE, SOCKET_ID_ANY, NULL, mp);
	TEST_ASSERT_SUCCESS(ret, "Rx queue setup failed: %s", rte_strerror(-ret));
	ret = rte_eth_tx_queue_setup(port_id, 0, RING_SIZE, SOCKET_ID_ANY, NULL);
	TEST_ASSERT_SUCCESS(ret, "Tx queue setup failed: %s", rte_strerror(-ret));
	ret = rte_eth_dev_start(port_id);
	TEST_ASSERT_SUCCESS(ret, "start failed: %s", rte_strerror(-ret));
	started = true;

	return TEST_SUCCESS;
}

/*
 * A frame from the kernel's end to the port. The kernel picks a queue of the
 * TAP interface by a hash of the frame's addresses, so the source address
 * makes the flow.
 */
static int
kernel_send(uint8_t flow)
{
	struct {
		struct virtio_net_hdr vnet; /* no offload */
		struct rte_ether_hdr eth;
		struct rte_ipv4_hdr ip;
		uint8_t payload[RTE_ETHER_MIN_LEN];
	} frame;
	ssize_t n;

	memset(&frame, 0, sizeof(frame));
	memset(&frame.eth.dst_addr, 0xff, RTE_ETHER_ADDR_LEN);
	frame.eth.src_addr.addr_bytes[0] = RTE_ETHER_LOCAL_ADMIN_ADDR;
	frame.eth.ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
	frame.ip.version_ihl = RTE_IPV4_VHL_DEF;
	frame.ip.total_length = rte_cpu_to_be_16(sizeof(frame.ip) + sizeof(frame.payload));
	frame.ip.time_to_live = 64;
	frame.ip.next_proto_id = TEST_IP_PROTO;
	frame.ip.src_addr = rte_cpu_to_be_32(RTE_IPV4(192, 0, 2, flow));
	frame.ip.dst_addr = rte_cpu_to_be_32(RTE_IPV4(198, 51, 100, 1));
	frame.ip.hdr_checksum = rte_ipv4_cksum(&frame.ip);
	n = send(ksock, &frame, sizeof(frame), 0);
	TEST_ASSERT(n == (ssize_t)sizeof(frame), "send on %s failed: %s", TAP_NAME,
		    strerror(errno));

	return TEST_SUCCESS;
}

/* Receive what the queue holds. Return the flows of the frames of kernel_send(), a bit each. */
static uint32_t
port_receive(void)
{
	struct rte_mbuf *pkts[BURST];
	uint32_t flows = 0;
	uint16_t i, n;

	while ((n = rte_eth_rx_burst(port_id, 0, pkts, BURST)) != 0) {
		for (i = 0; i < n; i++) {
			const struct rte_ether_hdr *eth =
				rte_pktmbuf_mtod(pkts[i], const struct rte_ether_hdr *);
			const struct rte_ipv4_hdr *ip = (const struct rte_ipv4_hdr *)(eth + 1);

			if (rte_pktmbuf_data_len(pkts[i]) >= sizeof(*eth) + sizeof(*ip) &&
			    eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4) &&
			    ip->next_proto_id == TEST_IP_PROTO)
				flows |= UINT32_C(1) << (rte_be_to_cpu_32(ip->src_addr) & 0xff);
		}
		rte_pktmbuf_free_bulk(pkts, n);
	}

	return flows;
}

/*
 * The port has two queue pairs and the test configures one Rx queue. The
 * kernel picks a queue for each flow, so send frames of several flows. All of
 * them must arrive on the one Rx queue.
 */
static int
test_virtio_user_rx_flows(void)
{
	const uint32_t all = RTE_LEN2MASK(NB_FLOWS, uint32_t);
	struct rte_eth_conf conf = { 0 };
	uint32_t flows = 0;
	uint64_t deadline;
	uint8_t flow;

	TEST_ASSERT_SUCCESS(port_start(&conf), "port start failed");
	for (flow = 0; flow < NB_FLOWS; flow++)
		TEST_ASSERT_SUCCESS(kernel_send(flow), "kernel send failed");
	deadline = rte_get_timer_cycles() + rte_get_timer_hz() * WAIT_MS / 1000;
	while (flows != all && rte_get_timer_cycles() < deadline)
		flows |= port_receive();
	TEST_ASSERT(flows == all, "received the flows 0x%x of 0x%x", flows, all);
	TEST_ASSERT_SUCCESS(port_stop(), "port stop failed");

	return TEST_SUCCESS;
}

/* Sleep on the Rx queue's interrupt. A frame from the kernel must end the sleep. */
static int
rx_intr_wakes(void)
{
	uint64_t deadline = rte_get_timer_cycles() + rte_get_timer_hz() * WAIT_MS / 1000;
	struct rte_epoll_event event;
	bool found;
	int ret;

	ret = rte_eth_dev_rx_intr_ctl_q(port_id, 0, RTE_EPOLL_PER_THREAD, RTE_INTR_EVENT_ADD,
					NULL);
	TEST_ASSERT_SUCCESS(ret, "no interrupt for the Rx queue: %s", rte_strerror(-ret));

	do {
		/*
		 * Enable the interrupt before the kernel sends. A frame that
		 * arrives from now on raises it, also before the sleep below.
		 */
		ret = rte_eth_dev_rx_intr_enable(port_id, 0);
		TEST_ASSERT_SUCCESS(ret, "Rx interrupt enable failed: %s", rte_strerror(-ret));
		/* Drop the frames that the kernel sent earlier, and their event. */
		port_receive();
		rte_epoll_wait(RTE_EPOLL_PER_THREAD, &event, 1, 0);

		TEST_ASSERT_SUCCESS(kernel_send(0), "kernel send failed");
		ret = rte_epoll_wait(RTE_EPOLL_PER_THREAD, &event, 1, WAIT_MS);
		TEST_ASSERT(ret == 1, "no Rx interrupt within %d ms", WAIT_MS);
		ret = rte_eth_dev_rx_intr_disable(port_id, 0);
		TEST_ASSERT_SUCCESS(ret, "Rx interrupt disable failed: %s", rte_strerror(-ret));
		/* If another frame of the kernel raised the interrupt, send again. */
		found = port_receive() != 0;
	} while (!found && rte_get_timer_cycles() < deadline);
	TEST_ASSERT(found, "frame from the kernel not received");

	ret = rte_eth_dev_rx_intr_ctl_q(port_id, 0, RTE_EPOLL_PER_THREAD, RTE_INTR_EVENT_DEL,
					NULL);
	TEST_ASSERT_SUCCESS(ret, "Rx interrupt removal failed: %s", rte_strerror(-ret));

	return TEST_SUCCESS;
}

/*
 * Rx interrupts with an offload, which makes configure initialize the device
 * twice. Then a second configure. The port has more interrupt eventfds than
 * Rx queues. They belong to the backend, so the driver must not release them
 * when it initializes the device again.
 */
static int
test_virtio_user_rx_intr(void)
{
	struct rte_eth_conf conf = {
		.intr_conf.rxq = 1,
		.rxmode.offloads = RTE_ETH_RX_OFFLOAD_UDP_CKSUM | RTE_ETH_RX_OFFLOAD_TCP_CKSUM,
	};
	struct rte_eth_dev_info info;
	int round, ret;

	ret = rte_eth_dev_info_get(port_id, &info);
	TEST_ASSERT_SUCCESS(ret, "dev_info failed: %s", rte_strerror(-ret));
	conf.rxmode.offloads &= info.rx_offload_capa;
	TEST_ASSERT(conf.rxmode.offloads != 0, "no Rx checksum offload to request");

	for (round = 0; round < 2; round++) {
		TEST_ASSERT_SUCCESS(port_start(&conf), "round %d: port start failed", round);
		TEST_ASSERT_SUCCESS(rx_intr_wakes(), "round %d: Rx interrupt failed", round);
		TEST_ASSERT_SUCCESS(port_stop(), "round %d: port stop failed", round);
	}

	return TEST_SUCCESS;
}

static void
test_virtio_user_cleanup(void)
{
	if (ksock >= 0)
		close(ksock);
	ksock = -1;
	if (port_id != RTE_MAX_ETHPORTS) {
		port_stop();
		rte_eth_dev_close(port_id);
		rte_vdev_uninit(VDEV_NAME);
	}
	port_id = RTE_MAX_ETHPORTS;
	rte_mempool_free(mp);
	mp = NULL;
}

/* Open the kernel's end. Set the TAP interface up and bind a packet socket to it. */
static int
kernel_open(void)
{
	struct sockaddr_ll addr = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_ALL),
	};
	struct ifreq ifr;
	int one = 1;

	ksock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (ksock < 0)
		return -1;
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, TAP_NAME, sizeof(ifr.ifr_name));
	if (ioctl(ksock, SIOCGIFFLAGS, &ifr) < 0)
		return -1;
	ifr.ifr_flags |= IFF_UP;
	if (ioctl(ksock, SIOCSIFFLAGS, &ifr) < 0)
		return -1;
	addr.sll_ifindex = if_nametoindex(TAP_NAME);
	if (addr.sll_ifindex == 0 ||
	    bind(ksock, (const struct sockaddr *)&addr, sizeof(addr)) < 0 ||
	    setsockopt(ksock, SOL_PACKET, PACKET_VNET_HDR, &one, sizeof(one)) < 0)
		return -1;

	return 0;
}

static int
test_virtio_user_setup(void)
{
	mp = rte_pktmbuf_pool_create("virtio_user_test", NB_MBUF, 32, 0,
				     RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	TEST_ASSERT_NOT_NULL(mp, "mempool creation failed: %s", rte_strerror(rte_errno));

	/*
	 * The port has two queue pairs and the tests configure one Rx queue.
	 * vhost-net creates the TAP interface, which takes root or CAP_NET_ADMIN.
	 */
	if (rte_vdev_init(VDEV_NAME, "path=/dev/vhost-net,iface=" TAP_NAME ",queues=2") < 0 ||
	    rte_eth_dev_get_port_by_name(VDEV_NAME, &port_id) != 0) {
		printf("No virtio-user port on /dev/vhost-net, skipping test\n");
		test_virtio_user_cleanup();
		return TEST_SKIPPED;
	}
	if (kernel_open() < 0) {
		printf("No packet socket on %s (%s), skipping test\n", TAP_NAME, strerror(errno));
		test_virtio_user_cleanup();
		return TEST_SKIPPED;
	}

	return TEST_SUCCESS;
}

static struct unit_test_suite test_pmd_virtio_user_suite = {
	.setup = test_virtio_user_setup,
	.teardown = test_virtio_user_cleanup,
	.suite_name = "virtio-user PMD Unit Test Suite",
	.unit_test_cases = {
		TEST_CASE(test_virtio_user_rx_flows),
		TEST_CASE(test_virtio_user_rx_intr),
		TEST_CASES_END()
	}
};

static int
test_pmd_virtio_user(void)
{
	return unit_test_suite_runner(&test_pmd_virtio_user_suite);
}

#endif /* RTE_EXEC_ENV_LINUX */

REGISTER_FAST_TEST(virtio_user_pmd_autotest, NOHUGE_OK, ASAN_OK, test_pmd_virtio_user);

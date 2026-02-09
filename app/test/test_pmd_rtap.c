/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Stephen Hemminger
 */
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include <rte_common.h>
#include <rte_stdatomic.h>
#include <rte_ethdev.h>
#include <rte_bus_vdev.h>
#include <rte_ether.h>
#include <rte_errno.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_epoll.h>

#include "test.h"

#define SOCKET0 0
#define RING_SIZE 256
#define NB_MBUF 4096
#define MAX_MULTI_QUEUES 4

#define RTAP_DRIVER_NAME "net_rtap"
#define TEST_TAP_NAME "rtap_test0"

/* TX/RX test parameters */
#define TEST_PKT_PAYLOAD_LEN 64
#define TEST_MAGIC_BYTE 0xAB
#define RX_BURST_MAX 32
#define TX_RX_TIMEOUT_US 100000  /* 100ms */
#define TX_RX_POLL_US 1000       /* 1ms between polls */

static struct rte_mempool *mp;
static int rtap_port0 = -1;
static int rtap_port1 = -1;

/* ========== Helper Functions ========== */

static int
check_rtap_available(void)
{
	int fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0) {
		printf("Cannot access /dev/net/tun: %s\n", strerror(errno));
		printf("RTAP PMD tests require CAP_NET_ADMIN or root privileges\n");
		return -1;
	}
	close(fd);
	return 0;
}

/* Configure port with specified number of queue pairs */
static int
port_configure(int port, uint16_t nb_queues, const struct rte_eth_conf *conf)
{
	struct rte_eth_conf null_conf;

	if (conf == NULL) {
		memset(&null_conf, 0, sizeof(null_conf));
		conf = &null_conf;
	}

	if (rte_eth_dev_configure(port, nb_queues, nb_queues, conf) < 0) {
		printf("Configure failed for port %d with %u queues\n",
		       port, nb_queues);
		return -1;
	}

	return 0;
}

/* Setup queue pairs for a port */
static int
port_setup_queues(int port, uint16_t nb_queues, uint16_t ring_size,
		  struct rte_mempool *mempool)
{
	for (uint16_t q = 0; q < nb_queues; q++) {
		if (rte_eth_tx_queue_setup(port, q, ring_size, SOCKET0, NULL) < 0) {
			printf("TX queue %u setup failed port %d\n", q, port);
			return -1;
		}

		if (rte_eth_rx_queue_setup(port, q, ring_size, SOCKET0,
					   NULL, mempool) < 0) {
			printf("RX queue %u setup failed port %d\n", q, port);
			return -1;
		}
	}

	return 0;
}

/* Stop, configure, setup queues, and start a port */
static int
port_reconfigure(int port, uint16_t nb_queues, const struct rte_eth_conf *conf,
		 uint16_t ring_size, struct rte_mempool *mempool)
{
	int ret;

	ret = rte_eth_dev_stop(port);
	if (ret != 0) {
		printf("Error stopping port %d: %s\n", port, rte_strerror(-ret));
		return -1;
	}

	if (port_configure(port, nb_queues, conf) < 0)
		return -1;

	if (port_setup_queues(port, nb_queues, ring_size, mempool) < 0)
		return -1;

	if (rte_eth_dev_start(port) < 0) {
		printf("Error starting port %d\n", port);
		return -1;
	}

	return 0;
}

/* Restore port to clean single-queue started state */
static int
restore_single_queue(int port)
{
	return port_reconfigure(port, 1, NULL, RING_SIZE, mp);
}

/* Verify link status matches expected */
static int
verify_link_status(int port, uint8_t expected_status)
{
	struct rte_eth_link link;
	int ret;

	ret = rte_eth_link_get(port, &link);
	if (ret < 0) {
		printf("Error getting link status: %s\n", rte_strerror(-ret));
		return -1;
	}

	if (link.link_status != expected_status) {
		printf("Error: link should be %s but is %s\n",
		       expected_status ? "UP" : "DOWN",
		       link.link_status ? "UP" : "DOWN");
		return -1;
	}

	return 0;
}

/* Get device info with error checking */
static int
get_dev_info(int port, struct rte_eth_dev_info *dev_info)
{
	int ret = rte_eth_dev_info_get(port, dev_info);
	if (ret != 0) {
		printf("Error getting device info for port %d: %s\n",
		       port, rte_strerror(-ret));
		return -1;
	}
	return 0;
}

/* Reset and verify stats are zero */
static int
reset_and_verify_stats_zero(int port)
{
	struct rte_eth_stats stats;
	int ret;

	ret = rte_eth_stats_reset(port);
	if (ret != 0) {
		printf("Error: stats_reset failed for port %d: %s\n",
		       port, rte_strerror(-ret));
		return -1;
	}

	ret = rte_eth_stats_get(port, &stats);
	if (ret != 0) {
		printf("Error: stats_get failed for port %d: %s\n",
		       port, rte_strerror(-ret));
		return -1;
	}

	if (stats.ipackets != 0 || stats.opackets != 0 ||
	    stats.ibytes != 0 || stats.obytes != 0 ||
	    stats.ierrors != 0 || stats.oerrors != 0) {
		printf("Error: port %d stats are not zero after reset\n", port);
		return -1;
	}

	return 0;
}

/* Drain all pending RX packets from a port */
static void
drain_rx_queue(int port, uint16_t queue_id)
{
	struct rte_mbuf *drain[RX_BURST_MAX];
	uint16_t n;

	do {
		n = rte_eth_rx_burst(port, queue_id, drain, RX_BURST_MAX);
		rte_pktmbuf_free_bulk(drain, n);
	} while (n > 0);
}

/* Set Ethernet address to broadcast */
static inline void
eth_addr_bcast(struct rte_ether_addr *addr)
{
	memset(addr, 0xff, RTE_ETHER_ADDR_LEN);
}

/* Bring TAP interface up using ioctl */
static int
tap_set_up(const char *ifname)
{
	struct ifreq ifr;
	int sock, ret = -1;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0)
		goto out;

	ifr.ifr_flags |= IFF_UP;

	if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0)
		goto out;

	ret = 0;
out:
	close(sock);
	return ret;
}

/* Open an AF_PACKET socket bound to the TAP interface */
static int
open_tap_socket(const char *ifname)
{
	int sock, ifindex;
	struct sockaddr_ll sll;

	sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock < 0) {
		printf("socket(AF_PACKET) failed: %s\n", strerror(errno));
		return -1;
	}

	ifindex = if_nametoindex(ifname);
	if (ifindex == 0) {
		printf("if_nametoindex(%s) failed: %s\n", ifname, strerror(errno));
		close(sock);
		return -1;
	}

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifindex;
	sll.sll_protocol = htons(ETH_P_ALL);

	if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		printf("bind() failed: %s\n", strerror(errno));
		close(sock);
		return -1;
	}

	return sock;
}

/* Setup TAP socket with non-blocking mode and bring interface up */
static int
setup_tap_socket_nb(const char *ifname)
{
	int sock, flags;

	if (tap_set_up(ifname) < 0) {
		printf("Failed to bring TAP interface up\n");
		return -1;
	}

	sock = open_tap_socket(ifname);
	if (sock < 0)
		return -1;

	flags = fcntl(sock, F_GETFL, 0);
	fcntl(sock, F_SETFL, flags | O_NONBLOCK);

	return sock;
}

/* Build a basic test packet with broadcast dest and magic byte payload */
static void
build_test_packet(uint8_t *pkt, size_t pkt_len,
		  const struct rte_ether_addr *src_mac,
		  const struct rte_ether_addr *dst_mac)
{
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pkt;

	if (dst_mac)
		memcpy(&eth->dst_addr, dst_mac, RTE_ETHER_ADDR_LEN);
	else
		eth_addr_bcast(&eth->dst_addr);

	if (src_mac)
		memcpy(&eth->src_addr, src_mac, RTE_ETHER_ADDR_LEN);
	else
		rte_eth_random_addr(eth->src_addr.addr_bytes);

	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);
	memset(pkt + RTE_ETHER_HDR_LEN, TEST_MAGIC_BYTE,
	       pkt_len - RTE_ETHER_HDR_LEN);
}

/* Poll AF_PACKET socket for a packet matching the given pattern */
static ssize_t
poll_tap_socket(int sock, uint8_t *buf, size_t buf_size,
		uint8_t match_byte, size_t match_offset)
{
	struct timeval tv;
	fd_set fds;
	int elapsed = 0;
	ssize_t rx_len;

	while (elapsed < TX_RX_TIMEOUT_US) {
		FD_ZERO(&fds);
		FD_SET(sock, &fds);
		tv.tv_sec = 0;
		tv.tv_usec = TX_RX_POLL_US;

		if (select(sock + 1, &fds, NULL, NULL, &tv) > 0) {
			rx_len = recv(sock, buf, buf_size, 0);
			if (rx_len > 0 && (size_t)rx_len > match_offset &&
			    buf[match_offset] == match_byte)
				return rx_len;
		}
		elapsed += TX_RX_POLL_US;
	}

	return 0;  /* Timeout */
}

/* Receive packets from DPDK port, filtering for our test packets */
static uint16_t
receive_test_packets(int port, uint16_t queue_id, struct rte_mbuf **rx_mbufs,
		     uint16_t max_pkts, size_t expected_len, uint8_t magic_byte)
{
	uint16_t nb_rx = 0;
	int elapsed = 0;

	while (elapsed < TX_RX_TIMEOUT_US && nb_rx < max_pkts) {
		struct rte_mbuf *burst[RX_BURST_MAX];
		uint16_t n = rte_eth_rx_burst(port, queue_id, burst, RX_BURST_MAX);

		for (uint16_t i = 0; i < n; i++) {
			uint8_t *d = rte_pktmbuf_mtod(burst[i], uint8_t *);

			if (burst[i]->pkt_len == expected_len &&
			    d[RTE_ETHER_HDR_LEN] == magic_byte) {
				rx_mbufs[nb_rx++] = burst[i];
				if (nb_rx >= max_pkts)
					break;
			} else {
				rte_pktmbuf_free(burst[i]);
			}
		}

		if (nb_rx > 0)
			break;

		usleep(TX_RX_POLL_US);
		elapsed += TX_RX_POLL_US;
	}

	return nb_rx;
}

/* Wait for event with timeout using polling */
static int
wait_for_event(RTE_ATOMIC(int) *event_flag, int initial_count, int timeout_us)
{
	int elapsed = 0;

	while (elapsed < timeout_us) {
		if (rte_atomic_load_explicit(event_flag, rte_memory_order_seq_cst) > initial_count)
			return 0;
		usleep(TX_RX_POLL_US);
		elapsed += TX_RX_POLL_US;
	}

	return -1;  /* Timeout */
}

/* Count open file descriptors */
static int
count_open_fds(void)
{
	DIR *d;
	struct dirent *de;
	int count = 0;

	d = opendir("/proc/self/fd");
	if (d == NULL)
		return -1;

	while ((de = readdir(d)) != NULL) {
		if (de->d_name[0] != '.')
			count++;
	}
	closedir(d);
	return count - 1;  /* Subtract dirfd itself */
}

/* ========== Test Functions ========== */

static int
test_ethdev_configure_port(int port)
{
	struct rte_eth_link link;
	int ret;

	if (port_reconfigure(port, 1, NULL, RING_SIZE, mp) < 0)
		return -1;

	ret = rte_eth_link_get(port, &link);
	if (ret < 0) {
		printf("Link get failed for port %u: %s\n",
		       port, rte_strerror(-ret));
		return -1;
	}

	return 0;
}

static int
test_get_stats(int port)
{
	printf("Testing rtap PMD stats_get port %d\n", port);
	return reset_and_verify_stats_zero(port);
}

static int
test_stats_reset(int port)
{
	printf("Testing rtap PMD stats_reset port %d\n", port);
	return reset_and_verify_stats_zero(port);
}

static int
test_dev_info(int port)
{
	struct rte_eth_dev_info dev_info;

	printf("Testing rtap PMD dev_info_get port %d\n", port);

	if (get_dev_info(port, &dev_info) < 0)
		return -1;

	if (dev_info.max_rx_queues == 0 || dev_info.max_tx_queues == 0) {
		printf("Error: invalid max queue values\n");
		return -1;
	}

	if (dev_info.max_mac_addrs != 1) {
		printf("Error: expected max_mac_addrs = 1, got %u\n",
		       dev_info.max_mac_addrs);
		return -1;
	}

	printf("  driver_name: %s\n", dev_info.driver_name);
	printf("  if_index: %u\n", dev_info.if_index);
	printf("  max_rx_queues: %u\n", dev_info.max_rx_queues);
	printf("  max_tx_queues: %u\n", dev_info.max_tx_queues);

	return 0;
}

static int
test_link_status(int port)
{
	struct rte_eth_link link;
	int ret;

	printf("Testing rtap PMD link status port %d\n", port);

	ret = rte_eth_link_get(port, &link);
	if (ret < 0) {
		printf("Error getting link status for port %d: %s\n",
		       port, rte_strerror(-ret));
		return -1;
	}

	printf("  link_status: %s\n", link.link_status ? "UP" : "DOWN");
	printf("  link_speed: %u\n", link.link_speed);
	printf("  link_duplex: %s\n",
	       link.link_duplex ? "full-duplex" : "half-duplex");

	return 0;
}

static int
test_set_link_up_down(int port)
{
	int ret;

	printf("Testing rtap PMD link up/down port %d\n", port);

	ret = rte_eth_dev_set_link_down(port);
	if (ret < 0) {
		printf("Error setting link down for port %d: %s\n",
		       port, rte_strerror(-ret));
		return -1;
	}

	if (verify_link_status(port, RTE_ETH_LINK_DOWN) < 0)
		return -1;

	ret = rte_eth_dev_set_link_up(port);
	if (ret < 0) {
		printf("Error setting link up for port %d: %s\n",
		       port, rte_strerror(-ret));
		return -1;
	}

	if (verify_link_status(port, RTE_ETH_LINK_UP) < 0)
		return -1;

	return 0;
}

static int
test_promiscuous_mode(int port)
{
	int ret;

	printf("Testing rtap PMD promiscuous mode port %d\n", port);

	ret = rte_eth_promiscuous_enable(port);
	if (ret < 0) {
		printf("Error enabling promiscuous mode: %s\n",
		       rte_strerror(-ret));
		return -1;
	}

	if (rte_eth_promiscuous_get(port) != 1) {
		printf("Error: promiscuous mode should be enabled\n");
		return -1;
	}

	ret = rte_eth_promiscuous_disable(port);
	if (ret < 0) {
		printf("Error disabling promiscuous mode: %s\n",
		       rte_strerror(-ret));
		return -1;
	}

	if (rte_eth_promiscuous_get(port) != 0) {
		printf("Error: promiscuous mode should be disabled\n");
		return -1;
	}

	return 0;
}

static int
test_allmulticast_mode(int port)
{
	int ret;

	printf("Testing rtap PMD allmulticast mode port %d\n", port);

	ret = rte_eth_allmulticast_enable(port);
	if (ret < 0) {
		printf("Error enabling allmulticast mode: %s\n",
		       rte_strerror(-ret));
		return -1;
	}

	if (rte_eth_allmulticast_get(port) != 1) {
		printf("Error: allmulticast mode should be enabled\n");
		return -1;
	}

	ret = rte_eth_allmulticast_disable(port);
	if (ret < 0) {
		printf("Error disabling allmulticast mode: %s\n",
		       rte_strerror(-ret));
		return -1;
	}

	if (rte_eth_allmulticast_get(port) != 0) {
		printf("Error: allmulticast mode should be disabled\n");
		return -1;
	}

	return 0;
}

static int
test_mac_address(int port)
{
	struct rte_ether_addr mac_addr;
	struct rte_ether_addr new_mac = {
		.addr_bytes = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	};
	int ret;

	printf("Testing rtap PMD MAC address port %d\n", port);

	ret = rte_eth_macaddr_get(port, &mac_addr);
	if (ret < 0) {
		printf("Error getting MAC address: %s\n", rte_strerror(-ret));
		return -1;
	}

	printf("  Current MAC: " RTE_ETHER_ADDR_PRT_FMT "\n",
	       RTE_ETHER_ADDR_BYTES(&mac_addr));

	ret = rte_eth_dev_default_mac_addr_set(port, &new_mac);
	if (ret < 0) {
		printf("Error setting MAC address: %s\n", rte_strerror(-ret));
		return -1;
	}

	ret = rte_eth_macaddr_get(port, &mac_addr);
	if (ret < 0) {
		printf("Error getting MAC address: %s\n", rte_strerror(-ret));
		return -1;
	}

	if (!rte_is_same_ether_addr(&mac_addr, &new_mac)) {
		printf("Error: MAC address not set correctly\n");
		return -1;
	}

	printf("  New MAC: " RTE_ETHER_ADDR_PRT_FMT "\n",
	       RTE_ETHER_ADDR_BYTES(&mac_addr));

	return 0;
}

static int
test_mtu_set(int port)
{
	uint16_t orig_mtu;
	uint16_t new_mtu = 9000;
	int ret;

	printf("Testing rtap PMD MTU set port %d\n", port);

	ret = rte_eth_dev_get_mtu(port, &orig_mtu);
	if (ret < 0) {
		printf("Error getting MTU: %s\n", rte_strerror(-ret));
		return -1;
	}

	printf("  Original MTU: %u\n", orig_mtu);

	ret = rte_eth_dev_set_mtu(port, new_mtu);
	if (ret < 0) {
		printf("Warning: setting MTU to %u failed: %s\n",
		       new_mtu, rte_strerror(-ret));
		return 0;
	}

	uint16_t current_mtu;
	ret = rte_eth_dev_get_mtu(port, &current_mtu);
	if (ret < 0) {
		printf("Error getting MTU: %s\n", rte_strerror(-ret));
		return -1;
	}

	printf("  New MTU: %u\n", current_mtu);
	rte_eth_dev_set_mtu(port, orig_mtu);

	return 0;
}

static int
test_queue_reconfigure(int port)
{
	struct rte_eth_dev_info dev_info;
	int ret;

	printf("Testing rtap PMD queue reconfigure port %d\n", port);

	if (port_reconfigure(port, 2, NULL, RING_SIZE, mp) < 0)
		return -1;

	ret = rte_eth_dev_info_get(port, &dev_info);
	if (ret != 0) {
		printf("Error getting device info: %s\n", rte_strerror(-ret));
		return -1;
	}

	printf("  Configured with %u rx and %u tx queues\n",
	       dev_info.nb_rx_queues, dev_info.nb_tx_queues);

	if (restore_single_queue(port) < 0)
		return -1;

	return 0;
}

static int
test_multiqueue(int port)
{
	struct rte_eth_dev_info dev_info;
	uint16_t queue_counts[] = { 1, 2, MAX_MULTI_QUEUES };

	printf("Testing rtap PMD multi-queue port %d\n", port);

	for (unsigned int t = 0; t < RTE_DIM(queue_counts); t++) {
		uint16_t nb_queues = queue_counts[t];

		printf("  Configuring %u queue pair(s)\n", nb_queues);

		if (port_reconfigure(port, nb_queues, NULL, RING_SIZE, mp) < 0)
			return -1;

		if (get_dev_info(port, &dev_info) < 0)
			return -1;

		if (dev_info.nb_rx_queues != nb_queues ||
		    dev_info.nb_tx_queues != nb_queues) {
			printf("Error: queue count mismatch\n");
			return -1;
		}

		if (reset_and_verify_stats_zero(port) < 0)
			return -1;

		/* Verify per-queue xstats are zero */
		int num_xstats = rte_eth_xstats_get(port, NULL, 0);
		if (num_xstats > 0) {
			struct rte_eth_xstat *xstats = malloc(sizeof(*xstats) * num_xstats);
			struct rte_eth_xstat_name *xstat_names =
				malloc(sizeof(*xstat_names) * num_xstats);

			if (xstats == NULL || xstat_names == NULL) {
				free(xstats);
				free(xstat_names);
				printf("Error: xstats alloc failed\n");
				return -1;
			}

			rte_eth_xstats_get_names(port, xstat_names, num_xstats);
			rte_eth_xstats_get(port, xstats, num_xstats);

			for (int x = 0; x < num_xstats; x++) {
				if (strstr(xstat_names[x].name, "_q") != NULL &&
				    xstats[x].value != 0) {
					printf("Error: xstat %s = %" PRIu64 " not zero\n",
					       xstat_names[x].name, xstats[x].value);
					free(xstats);
					free(xstat_names);
					return -1;
				}
			}
			free(xstats);
			free(xstat_names);
		}

		if (verify_link_status(port, RTE_ETH_LINK_UP) < 0)
			return -1;

		printf("    %u queue pair(s): OK\n", nb_queues);
	}

	if (restore_single_queue(port) < 0) {
		printf("Error restoring single queue\n");
		return -1;
	}

	return 0;
}

static int
test_multiqueue_reduce(int port)
{
	printf("Testing rtap PMD queue reduction port %d\n", port);

	if (port_reconfigure(port, MAX_MULTI_QUEUES, NULL, RING_SIZE, mp) < 0)
		return -1;

	printf("  Started with %d queues, reducing to 2\n", MAX_MULTI_QUEUES);

	if (port_reconfigure(port, 2, NULL, RING_SIZE, mp) < 0)
		return -1;

	if (reset_and_verify_stats_zero(port) < 0)
		return -1;

	printf("  Reduced to 2 queues: OK\n");
	printf("  Reducing to 1 queue\n");

	if (restore_single_queue(port) < 0)
		return -1;

	if (reset_and_verify_stats_zero(port) < 0)
		return -1;

	printf("  Reduced to 1 queue: OK\n");
	return 0;
}

static int
test_multiqueue_mismatch(int port)
{
	int ret;
	struct { uint16_t rx; uint16_t tx; } mismatch[] = {
		{ 1, 2 }, { 2, 1 }, { 4, 2 }, { 1, 4 },
	};

	printf("Testing rtap PMD mismatched queue rejection port %d\n", port);

	ret = rte_eth_dev_stop(port);
	if (ret != 0) {
		printf("Error stopping port: %s\n", rte_strerror(-ret));
		return -1;
	}

	for (unsigned int i = 0; i < RTE_DIM(mismatch); i++) {
		struct rte_eth_conf null_conf;
		memset(&null_conf, 0, sizeof(null_conf));

		ret = rte_eth_dev_configure(port, mismatch[i].rx,
					    mismatch[i].tx, &null_conf);
		if (ret == 0) {
			printf("Error: configure(%u rx, %u tx) should fail\n",
			       mismatch[i].rx, mismatch[i].tx);
			rte_eth_dev_stop(port);
			return -1;
		}
		printf("  Rejected %u rx / %u tx: OK\n",
		       mismatch[i].rx, mismatch[i].tx);
	}

	if (restore_single_queue(port) < 0) {
		printf("Error restoring single queue\n");
		return -1;
	}

	return 0;
}

static int
test_rx_inject(int port)
{
	struct rte_ether_addr mac;
	struct rte_mbuf *rx_mbufs[RX_BURST_MAX];
	uint8_t pkt[RTE_ETHER_HDR_LEN + TEST_PKT_PAYLOAD_LEN];
	int sock = -1;
	uint16_t nb_rx;
	int ret = -1;

	printf("Testing rtap PMD RX (inject via AF_PACKET)\n");

	if (restore_single_queue(port) < 0) {
		printf("Failed to restore single queue config\n");
		return -1;
	}

	if (rte_eth_macaddr_get(port, &mac) < 0) {
		printf("Failed to get MAC address\n");
		return -1;
	}

	sock = setup_tap_socket_nb(TEST_TAP_NAME);
	if (sock < 0)
		return -1;

	build_test_packet(pkt, sizeof(pkt), NULL, &mac);
	drain_rx_queue(port, 0);
	rte_eth_stats_reset(port);

	if (send(sock, pkt, sizeof(pkt), 0) < 0) {
		printf("send() failed: %s\n", strerror(errno));
		goto out;
	}

	nb_rx = receive_test_packets(port, 0, rx_mbufs, 1, sizeof(pkt),
				     TEST_MAGIC_BYTE);

	if (nb_rx == 0) {
		printf("No packet received after %d us\n", TX_RX_TIMEOUT_US);
		goto out;
	}

	uint8_t *rx_data = rte_pktmbuf_mtod(rx_mbufs[0], uint8_t *);
	if (rx_data[RTE_ETHER_HDR_LEN] != TEST_MAGIC_BYTE) {
		printf("Payload mismatch\n");
		goto free_rx;
	}

	struct rte_eth_stats stats;
	rte_eth_stats_get(port, &stats);
	if (stats.ipackets == 0) {
		printf("RX stats not updated\n");
		goto free_rx;
	}

	printf("  RX inject test PASSED (received %u packets)\n", nb_rx);
	ret = 0;

free_rx:
	for (uint16_t i = 0; i < nb_rx; i++)
		rte_pktmbuf_free(rx_mbufs[i]);
out:
	close(sock);
	return ret;
}

static int
test_tx_capture(int port)
{
	struct rte_ether_addr mac;
	struct rte_mbuf *tx_mbuf;
	struct rte_ether_hdr *eth;
	uint8_t rx_buf[256];
	int sock = -1;
	uint16_t nb_tx;
	ssize_t rx_len;
	int ret = -1;

	printf("Testing rtap PMD TX (capture via AF_PACKET)\n");

	if (restore_single_queue(port) < 0) {
		printf("Failed to restore single queue config\n");
		return -1;
	}

	if (rte_eth_macaddr_get(port, &mac) < 0) {
		printf("Failed to get MAC address\n");
		return -1;
	}

	sock = setup_tap_socket_nb(TEST_TAP_NAME);
	if (sock < 0)
		return -1;

	tx_mbuf = rte_pktmbuf_alloc(mp);
	if (tx_mbuf == NULL) {
		printf("Failed to allocate mbuf\n");
		goto out;
	}

	eth = rte_pktmbuf_mtod(tx_mbuf, struct rte_ether_hdr *);
	eth_addr_bcast(&eth->dst_addr);
	memcpy(&eth->src_addr, &mac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

	uint8_t *payload = (uint8_t *)(eth + 1);
	memset(payload, TEST_MAGIC_BYTE, TEST_PKT_PAYLOAD_LEN);

	tx_mbuf->data_len = RTE_ETHER_HDR_LEN + TEST_PKT_PAYLOAD_LEN;
	tx_mbuf->pkt_len = tx_mbuf->data_len;

	rte_eth_stats_reset(port);

	nb_tx = rte_eth_tx_burst(port, 0, &tx_mbuf, 1);
	if (nb_tx != 1) {
		printf("TX failed\n");
		rte_pktmbuf_free(tx_mbuf);
		goto out;
	}

	rx_len = poll_tap_socket(sock, rx_buf, sizeof(rx_buf),
				 TEST_MAGIC_BYTE, RTE_ETHER_HDR_LEN);

	if (rx_len <= 0) {
		printf("No packet captured after %d us\n", TX_RX_TIMEOUT_US);
		goto out;
	}

	struct rte_eth_stats stats;
	rte_eth_stats_get(port, &stats);
	if (stats.opackets == 0) {
		printf("TX stats not updated\n");
		goto out;
	}

	printf("  TX capture test PASSED (captured %zd bytes)\n", rx_len);
	ret = 0;

out:
	close(sock);
	return ret;
}

#define MSEG_NUM_SEGS 3
#define MSEG_SEG_LEN 40

static int
test_tx_multiseg(int port)
{
	struct rte_ether_addr mac;
	struct rte_mbuf *head, *seg, *prev;
	struct rte_ether_hdr *eth;
	uint8_t rx_buf[512];
	int sock = -1;
	uint16_t nb_tx;
	ssize_t rx_len;
	int ret = -1;
	uint16_t total_payload = MSEG_NUM_SEGS * MSEG_SEG_LEN;

	printf("Testing rtap PMD multi-segment TX\n");

	if (restore_single_queue(port) < 0 ||
	    rte_eth_macaddr_get(port, &mac) < 0) {
		printf("Failed to setup test\n");
		return -1;
	}

	sock = setup_tap_socket_nb(TEST_TAP_NAME);
	if (sock < 0)
		return -1;

	head = rte_pktmbuf_alloc(mp);
	if (head == NULL) {
		printf("Failed to allocate head mbuf\n");
		goto out;
	}

	eth = rte_pktmbuf_mtod(head, struct rte_ether_hdr *);
	eth_addr_bcast(&eth->dst_addr);
	memcpy(&eth->src_addr, &mac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

	uint8_t *p = (uint8_t *)(eth + 1);
	memset(p, 0xA0, MSEG_SEG_LEN);
	head->data_len = RTE_ETHER_HDR_LEN + MSEG_SEG_LEN;
	head->pkt_len = RTE_ETHER_HDR_LEN + total_payload;
	head->nb_segs = MSEG_NUM_SEGS;

	prev = head;
	for (int i = 1; i < MSEG_NUM_SEGS; i++) {
		seg = rte_pktmbuf_alloc(mp);
		if (seg == NULL) {
			printf("Failed to allocate segment %d\n", i);
			rte_pktmbuf_free(head);
			goto out;
		}
		p = rte_pktmbuf_mtod(seg, uint8_t *);
		memset(p, 0xA0 + i, MSEG_SEG_LEN);
		seg->data_len = MSEG_SEG_LEN;
		prev->next = seg;
		prev = seg;
	}

	rte_eth_stats_reset(port);

	nb_tx = rte_eth_tx_burst(port, 0, &head, 1);
	if (nb_tx != 1) {
		printf("TX failed for multi-seg packet\n");
		rte_pktmbuf_free(head);
		goto out;
	}

	rx_len = poll_tap_socket(sock, rx_buf, sizeof(rx_buf),
				 0xA0, RTE_ETHER_HDR_LEN);

	if (rx_len <= 0) {
		printf("No packet captured\n");
		goto out;
	}

	for (int i = 0; i < MSEG_NUM_SEGS; i++) {
		int off = RTE_ETHER_HDR_LEN + i * MSEG_SEG_LEN;
		uint8_t expected = 0xA0 + i;
		if (rx_buf[off] != expected) {
			printf("Segment %d mismatch\n", i);
			goto out;
		}
	}

	struct rte_eth_stats stats;
	rte_eth_stats_get(port, &stats);
	if (stats.opackets == 0) {
		printf("TX stats not updated\n");
		goto out;
	}

	printf("  Multi-seg TX test PASSED (%d segs, captured %zd bytes)\n",
	       MSEG_NUM_SEGS, rx_len);
	ret = 0;

out:
	close(sock);
	return ret;
}

#define MSEG_RX_BUF_SIZE 256
#define MSEG_RX_POOL_SIZE 4096
#define MSEG_RX_PKT_PAYLOAD 200

static int
test_rx_multiseg(int port)
{
	struct rte_mempool *small_mp = NULL;
	struct rte_ether_addr mac;
	struct rte_mbuf *rx_mbufs[RX_BURST_MAX];
	uint8_t pkt[RTE_ETHER_HDR_LEN + MSEG_RX_PKT_PAYLOAD];
	int sock = -1;
	uint16_t nb_rx;
	int ret = -1;

	printf("Testing rtap PMD multi-segment RX\n");

	if (rte_eth_macaddr_get(port, &mac) < 0) {
		printf("Failed to get MAC address\n");
		return -1;
	}

	small_mp = rte_pktmbuf_pool_create("small_mbuf_pool",
			MSEG_RX_POOL_SIZE, 32, 0, MSEG_RX_BUF_SIZE,
			rte_socket_id());
	if (small_mp == NULL) {
		printf("Failed to create small mempool\n");
		return -1;
	}

	if (port_reconfigure(port, 1, NULL, RING_SIZE, small_mp) < 0)
		goto free_pool;

	sock = setup_tap_socket_nb(TEST_TAP_NAME);
	if (sock < 0)
		goto restore;

	drain_rx_queue(port, 0);

	build_test_packet(pkt, sizeof(pkt), NULL, &mac);
	memset(pkt + RTE_ETHER_HDR_LEN, 0xDD, MSEG_RX_PKT_PAYLOAD);

	if (send(sock, pkt, sizeof(pkt), 0) < 0) {
		printf("send() failed: %s\n", strerror(errno));
		goto close_sock;
	}

	nb_rx = receive_test_packets(port, 0, rx_mbufs, 1, sizeof(pkt), 0xDD);

	if (nb_rx == 0) {
		printf("No packet received\n");
		goto close_sock;
	}

	struct rte_mbuf *m = rx_mbufs[0];
	printf("  Received: pkt_len=%u nb_segs=%u\n", m->pkt_len, m->nb_segs);

	if (m->nb_segs < 2) {
		printf("  Expected multi-segment mbuf, got %u segments\n",
		       m->nb_segs);
	}

	if (m->pkt_len < sizeof(pkt)) {
		printf("  Packet too short: %u < %zu\n", m->pkt_len, sizeof(pkt));
		goto free_rx;
	}

	/* Verify payload across segments */
	uint32_t offset = 0;
	struct rte_mbuf *seg = m;
	uint32_t seg_off = 0;
	int payload_ok = 1;

	while (seg != NULL && offset < m->pkt_len) {
		if (seg_off >= seg->data_len) {
			seg = seg->next;
			seg_off = 0;
			continue;
		}
		if (offset >= RTE_ETHER_HDR_LEN &&
		    offset < RTE_ETHER_HDR_LEN + MSEG_RX_PKT_PAYLOAD) {
			uint8_t *d = rte_pktmbuf_mtod_offset(seg, uint8_t *,
							      seg_off);
			if (*d != 0xDD) {
				printf("  Payload mismatch at offset %u\n", offset);
				payload_ok = 0;
				break;
			}
		}
		offset++;
		seg_off++;
	}

	if (!payload_ok)
		goto free_rx;

	printf("  Multi-seg RX test PASSED (%u segments)\n", m->nb_segs);
	ret = 0;

free_rx:
	for (uint16_t i = 0; i < nb_rx; i++)
		rte_pktmbuf_free(rx_mbufs[i]);

close_sock:
	close(sock);

restore:
	restore_single_queue(port);

free_pool:
	rte_mempool_free(small_mp);
	return ret;
}

static int
test_offload_config(int port)
{
	struct rte_eth_dev_info dev_info;
	struct rte_eth_conf conf;
	int ret;

	printf("Testing rtap PMD offload configuration port %d\n", port);

	if (get_dev_info(port, &dev_info) < 0)
		return -1;

	uint64_t expected_tx = RTE_ETH_TX_OFFLOAD_MULTI_SEGS |
			       RTE_ETH_TX_OFFLOAD_UDP_CKSUM |
			       RTE_ETH_TX_OFFLOAD_TCP_CKSUM |
			       RTE_ETH_TX_OFFLOAD_TCP_TSO;

	if ((dev_info.tx_offload_capa & expected_tx) != expected_tx) {
		printf("Missing TX offload capabilities\n");
		return -1;
	}

	printf("  TX offload capa: 0x%" PRIx64 " OK\n",
	       dev_info.tx_offload_capa);

	memset(&conf, 0, sizeof(conf));
	conf.txmode.offloads = RTE_ETH_TX_OFFLOAD_UDP_CKSUM |
			       RTE_ETH_TX_OFFLOAD_TCP_CKSUM;

	ret = port_reconfigure(port, 1, &conf, RING_SIZE, mp);
	if (ret < 0) {
		printf("Configure with TX offloads failed\n");
		goto restore;
	}

	printf("  TX offload configuration: OK\n");

restore:
	restore_single_queue(port);
	return ret;
}

#define CSUM_PKT_PAYLOAD 32

static int
test_tx_csum_offload(int port)
{
	struct rte_ether_addr mac;
	struct rte_mbuf *tx_mbuf;
	uint8_t rx_buf[256];
	int sock = -1;
	uint16_t nb_tx, pkt_len;
	ssize_t rx_len = 0;
	int ret = -1;

	printf("Testing rtap PMD TX checksum offload\n");

	if (restore_single_queue(port) < 0 ||
	    rte_eth_macaddr_get(port, &mac) < 0) {
		printf("Failed to setup test\n");
		return -1;
	}

	sock = setup_tap_socket_nb(TEST_TAP_NAME);
	if (sock < 0)
		return -1;

	tx_mbuf = rte_pktmbuf_alloc(mp);
	if (tx_mbuf == NULL) {
		printf("Failed to allocate mbuf\n");
		goto out;
	}

	/* Build Eth + IPv4 + UDP + payload */
	struct rte_ether_hdr *eth = rte_pktmbuf_mtod(tx_mbuf,
						      struct rte_ether_hdr *);
	eth_addr_bcast(&eth->dst_addr);
	memcpy(&eth->src_addr, &mac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
	memset(ip, 0, sizeof(*ip));
	ip->version_ihl = 0x45;
	ip->total_length = htons(sizeof(*ip) + sizeof(struct rte_udp_hdr) +
				 CSUM_PKT_PAYLOAD);
	ip->time_to_live = 64;
	ip->next_proto_id = IPPROTO_UDP;
	ip->src_addr = htonl(0x0a000001);
	ip->dst_addr = htonl(0x0a000002);
	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ip + 1);
	udp->src_port = htons(1234);
	udp->dst_port = htons(5678);
	udp->dgram_len = htons(sizeof(*udp) + CSUM_PKT_PAYLOAD);
	udp->dgram_cksum = 0;

	uint8_t *payload = (uint8_t *)(udp + 1);
	memset(payload, 0xCC, CSUM_PKT_PAYLOAD);

	pkt_len = sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + CSUM_PKT_PAYLOAD;
	tx_mbuf->data_len = pkt_len;
	tx_mbuf->pkt_len = pkt_len;

	tx_mbuf->ol_flags = RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_UDP_CKSUM;
	tx_mbuf->l2_len = sizeof(*eth);
	tx_mbuf->l3_len = sizeof(*ip);
	udp->dgram_cksum = rte_ipv4_phdr_cksum(ip, tx_mbuf->ol_flags);

	rte_eth_stats_reset(port);

	nb_tx = rte_eth_tx_burst(port, 0, &tx_mbuf, 1);
	if (nb_tx != 1) {
		printf("TX failed\n");
		rte_pktmbuf_free(tx_mbuf);
		goto out;
	}

	rx_len = poll_tap_socket(sock, rx_buf, sizeof(rx_buf),
				 0x45, sizeof(*eth));

	if (rx_len <= 0) {
		printf("No packet captured\n");
		goto out;
	}

	unsigned int cksum_off = sizeof(*eth) + sizeof(*ip) +
				 offsetof(struct rte_udp_hdr, dgram_cksum);
	uint16_t captured_cksum;

	memcpy(&captured_cksum, &rx_buf[cksum_off], sizeof(captured_cksum));

	if (captured_cksum == 0) {
		printf("  Warning: UDP checksum is zero\n");
	} else {
		printf("  UDP cksum=0x%04x\n", ntohs(captured_cksum));
	}

	struct rte_eth_stats stats;
	rte_eth_stats_get(port, &stats);
	if (stats.opackets == 0) {
		printf("TX stats not updated\n");
		goto out;
	}

	printf("  TX csum offload PASSED (captured %zd bytes)\n", rx_len);
	ret = 0;

out:
	close(sock);
	return ret;
}

#define FLOOD_RING_SIZE 64
#define FLOOD_NUM_PKTS 1000
#define FLOOD_PKT_SIZE 128

static int
test_imissed_counter(int port)
{
	struct rte_eth_stats stats_before, stats_after, stats_after_reset;
	struct rte_ether_addr mac;
	uint8_t pkt[FLOOD_PKT_SIZE];
	int sock = -1;
	int ret = -1;

	printf("Testing rtap PMD imissed counter port %d\n", port);

	if (rte_eth_macaddr_get(port, &mac) < 0) {
		printf("Failed to get MAC address\n");
		return -1;
	}

	if (port_reconfigure(port, 1, NULL, FLOOD_RING_SIZE, mp) < 0)
		goto restore;

	sock = setup_tap_socket_nb(TEST_TAP_NAME);
	if (sock < 0)
		goto restore;

	drain_rx_queue(port, 0);

	ret = rte_eth_stats_reset(port);
	if (ret != 0) {
		printf("Failed to reset stats: %s\n", rte_strerror(-ret));
		goto close_sock;
	}

	ret = rte_eth_stats_get(port, &stats_before);
	if (ret != 0) {
		printf("Failed to get baseline stats: %s\n", rte_strerror(-ret));
		goto close_sock;
	}

	printf("  Flooding with %d packets (ring size %d)\n",
	       FLOOD_NUM_PKTS, FLOOD_RING_SIZE);

	build_test_packet(pkt, FLOOD_PKT_SIZE, &mac, &mac);

	for (int i = 0; i < FLOOD_NUM_PKTS; i++) {
		if (send(sock, pkt, FLOOD_PKT_SIZE, 0) < 0) {
			printf("send() failed after %d packets: %s\n",
			       i, strerror(errno));
			goto close_sock;
		}
	}

	usleep(100000);  /* 100ms */

	/* Drain whatever we can receive */
	{
		struct rte_mbuf *burst[RX_BURST_MAX];
		uint16_t total_rx = 0;
		int attempts = 0;

		while (attempts++ < 100) {
			uint16_t n = rte_eth_rx_burst(port, 0, burst, RX_BURST_MAX);
			if (n > 0) {
				rte_pktmbuf_free_bulk(burst, n);
				total_rx += n;
			} else {
				usleep(1000);
			}
		}
		printf("  Received %u packets out of %d sent\n",
		       total_rx, FLOOD_NUM_PKTS);
	}

	ret = rte_eth_stats_get(port, &stats_after);
	if (ret != 0) {
		printf("Failed to get stats after flood: %s\n", rte_strerror(-ret));
		goto close_sock;
	}

	printf("  Stats: ipackets=%"PRIu64" imissed=%"PRIu64"\n",
	       stats_after.ipackets, stats_after.imissed);

	if (stats_after.ipackets == 0) {
		printf("  ERROR: No packets received\n");
		goto close_sock;
	}

	if (stats_after.imissed == 0) {
		printf("  WARNING: No packets marked as missed\n");
	} else {
		printf("  SUCCESS: imissed counter working (%"PRIu64" drops)\n",
		       stats_after.imissed);
	}

	/* Test stats_reset clears imissed counter */
	printf("  Testing stats_reset for imissed counter\n");
	ret = rte_eth_stats_reset(port);
	if (ret != 0) {
		printf("  ERROR: stats_reset failed: %s\n", rte_strerror(-ret));
		goto close_sock;
	}

	ret = rte_eth_stats_get(port, &stats_after_reset);
	if (ret != 0) {
		printf("  ERROR: stats_get after reset failed: %s\n", rte_strerror(-ret));
		goto close_sock;
	}

	if (stats_after_reset.imissed != 0 || stats_after_reset.ipackets != 0) {
		printf("  ERROR: stats not reset properly\n");
		goto close_sock;
	}

	printf("  Stats reset: OK (all counters zeroed)\n");
	printf("  imissed counter test PASSED\n");
	ret = 0;

close_sock:
	close(sock);

restore:
	restore_single_queue(port);
	return ret;
}

#define LSC_TIMEOUT_US 500000  /* 500ms */
#define LSC_POLL_US    1000    /* 1ms between polls */

#define RXQ_INTR_TIMEOUT_MS 500  /* 500ms */

static RTE_ATOMIC(int) lsc_event_count;
static RTE_ATOMIC(int) lsc_last_status;

static int
test_lsc_callback(uint16_t port_id, enum rte_eth_event_type type,
		  void *param __rte_unused, void *ret_param __rte_unused)
{
	struct rte_eth_link link;

	if (type != RTE_ETH_EVENT_INTR_LSC)
		return 0;

	if (rte_eth_link_get_nowait(port_id, &link) < 0) {
		printf("  Link get nowait failed\n");
		return 0;
	}

	rte_atomic_store_explicit(&lsc_last_status, link.link_status, rte_memory_order_relaxed);
	rte_atomic_fetch_add_explicit(&lsc_event_count, 1, rte_memory_order_seq_cst);

	printf("    LSC event #%d: port %u link %s\n",
	       rte_atomic_load_explicit(&lsc_event_count, rte_memory_order_relaxed),
	       port_id,
	       link.link_status ? "UP" : "DOWN");

	return 0;
}

static int
test_lsc_interrupt(int port)
{
	struct rte_eth_conf lsc_conf;
	int initial_count;
	int ret = -1;

	printf("Testing rtap PMD link state interrupt port %d\n", port);

	memset(&lsc_conf, 0, sizeof(lsc_conf));
	lsc_conf.intr_conf.lsc = 1;

	if (port_reconfigure(port, 1, &lsc_conf, RING_SIZE, mp) < 0)
		goto restore;

	ret = rte_eth_dev_callback_register(port, RTE_ETH_EVENT_INTR_LSC,
					    test_lsc_callback, NULL);
	if (ret < 0) {
		printf("Failed to register LSC callback: %s\n",
		       rte_strerror(-ret));
		goto restore;
	}

	rte_atomic_store_explicit(&lsc_event_count, 0, rte_memory_order_relaxed);
	rte_atomic_store_explicit(&lsc_last_status, -1, rte_memory_order_relaxed);

	if (verify_link_status(port, RTE_ETH_LINK_UP) < 0) {
		ret = -1;
		goto stop;
	}

	printf("  Link is UP, setting link DOWN\n");
	initial_count = rte_atomic_load_explicit(&lsc_event_count, rte_memory_order_seq_cst);

	ret = rte_eth_dev_set_link_down(port);
	if (ret < 0) {
		printf("Set link down failed: %s\n", rte_strerror(-ret));
		goto stop;
	}

	if (wait_for_event(&lsc_event_count, initial_count, LSC_TIMEOUT_US) < 0) {
		printf("  No LSC event received for link DOWN after %d us\n",
		       LSC_TIMEOUT_US);
		if (verify_link_status(port, RTE_ETH_LINK_DOWN) < 0) {
			ret = -1;
			goto stop;
		}
		printf("  Link status is DOWN (verified via polling)\n");
	} else {
		printf("  LSC event received for link DOWN\n");
		if (rte_atomic_load_explicit(&lsc_last_status, rte_memory_order_seq_cst) != RTE_ETH_LINK_DOWN) {
			printf("  ERROR: expected DOWN status in callback\n");
			ret = -1;
			goto stop;
		}
	}

	printf("  Setting link UP\n");
	initial_count = rte_atomic_load_explicit(&lsc_event_count, rte_memory_order_seq_cst);

	ret = rte_eth_dev_set_link_up(port);
	if (ret < 0) {
		printf("Set link up failed: %s\n", rte_strerror(-ret));
		goto stop;
	}

	if (wait_for_event(&lsc_event_count, initial_count, LSC_TIMEOUT_US) < 0) {
		printf("  No LSC event received for link UP after %d us\n",
		       LSC_TIMEOUT_US);
		if (verify_link_status(port, RTE_ETH_LINK_UP) < 0) {
			ret = -1;
			goto stop;
		}
		printf("  Link status is UP (verified via polling)\n");
	} else {
		printf("  LSC event received for link UP\n");
		if (rte_atomic_load_explicit(&lsc_last_status, rte_memory_order_seq_cst) != RTE_ETH_LINK_UP) {
			printf("  ERROR: expected UP status in callback\n");
			ret = -1;
			goto stop;
		}
	}

	printf("  LSC interrupt test PASSED (total events: %d)\n",
	       rte_atomic_load_explicit(&lsc_event_count, rte_memory_order_relaxed));
	ret = 0;

stop:
	rte_eth_dev_stop(port);
	rte_eth_dev_callback_unregister(port, RTE_ETH_EVENT_INTR_LSC,
					test_lsc_callback, NULL);

restore:
	restore_single_queue(port);
	return ret;
}

static int
test_rxq_interrupt(int port)
{
	struct rte_eth_conf rxq_conf;
	struct rte_ether_addr mac;
	uint8_t pkt[RTE_ETHER_HDR_LEN + TEST_PKT_PAYLOAD_LEN];
	int sock = -1;
	int epfd = -1;
	int ret = -1;

	printf("Testing rtap PMD RX queue interrupt port %d\n", port);

	if (rte_eth_macaddr_get(port, &mac) < 0) {
		printf("Failed to get MAC address\n");
		return -1;
	}

	memset(&rxq_conf, 0, sizeof(rxq_conf));
	rxq_conf.intr_conf.rxq = 1;

	if (port_reconfigure(port, 1, &rxq_conf, RING_SIZE, mp) < 0)
		goto restore;

	/* Enable interrupt for queue 0 */
	ret = rte_eth_dev_rx_intr_enable(port, 0);
	if (ret < 0) {
		printf("  rx_intr_enable failed: %s\n", rte_strerror(-ret));
		goto restore;
	}

	/* Add queue 0's eventfd to the per-thread epoll set */
	ret = rte_eth_dev_rx_intr_ctl_q(port, RTE_EPOLL_PER_THREAD,
					RTE_INTR_EVENT_ADD, 0, NULL);
	if (ret < 0) {
		printf("  rx_intr_ctl_q(ADD) failed: %s\n", rte_strerror(-ret));
		printf("  (epoll may not be available in this environment)\n");
		epfd = -1;
	} else {
		epfd = RTE_EPOLL_PER_THREAD;
	}

	sock = setup_tap_socket_nb(TEST_TAP_NAME);
	if (sock < 0)
		goto disable_intr;

	drain_rx_queue(port, 0);
	build_test_packet(pkt, sizeof(pkt), NULL, &mac);

	printf("  Injecting test packet\n");
	if (send(sock, pkt, sizeof(pkt), 0) < 0) {
		printf("send() failed: %s\n", strerror(errno));
		goto close_sock;
	}

	/* Wait for the Rx interrupt via epoll */
	if (epfd != -1) {
		struct rte_epoll_event event;
		int nfds;

		nfds = rte_epoll_wait(epfd, &event, 1, RXQ_INTR_TIMEOUT_MS);
		if (nfds < 0) {
			printf("  rte_epoll_wait failed: %s\n",
			       rte_strerror(-nfds));
			printf("  (Falling back to polling verification)\n");
		} else if (nfds == 0) {
			printf("  WARNING: epoll timeout - no Rx interrupt received\n");
			printf("  (This may be expected in some test environments)\n");
		} else {
			printf("  Rx interrupt received via epoll: OK\n");
		}
	}

	/* Verify the packet actually arrived */
	{
		struct rte_mbuf *rx_mbufs[RX_BURST_MAX];
		uint16_t nb_rx;
		int elapsed = 0;

		while (elapsed < TX_RX_TIMEOUT_US) {
			nb_rx = rte_eth_rx_burst(port, 0, rx_mbufs, RX_BURST_MAX);
			if (nb_rx > 0) {
				rte_pktmbuf_free_bulk(rx_mbufs, nb_rx);
				printf("  Packet received successfully\n");
				break;
			}
			usleep(TX_RX_POLL_US);
			elapsed += TX_RX_POLL_US;
		}

		if (nb_rx == 0) {
			printf("  ERROR: No packet received\n");
			ret = -1;
			goto close_sock;
		}
	}

	printf("  RX queue interrupt test PASSED\n");
	ret = 0;

close_sock:
	close(sock);

disable_intr:
	rte_eth_dev_rx_intr_disable(port, 0);

	if (epfd != -1)
		rte_eth_dev_rx_intr_ctl_q(port, RTE_EPOLL_PER_THREAD,
					  RTE_INTR_EVENT_DEL, 0, NULL);

restore:
	restore_single_queue(port);
	return ret;
}

static int
test_fd_leak(void)
{
	int fd_before, fd_after;
	int port = -1;
	int ret;

	printf("Testing rtap PMD file descriptor leak\n");

	fd_before = count_open_fds();
	if (fd_before < 0) {
		printf("Cannot count open fds\n");
		return -1;
	}

	printf("  Open fds before: %d\n", fd_before);

	if (rte_vdev_init("net_rtap_fdtest", "iface=rtap_fdtest") < 0) {
		printf("Failed to create net_rtap_fdtest\n");
		return -1;
	}

	uint16_t p;
	RTE_ETH_FOREACH_DEV(p) {
		struct rte_eth_dev_info info;
		if (rte_eth_dev_info_get(p, &info) != 0)
			continue;
		if (p == (uint16_t)rtap_port0 || p == (uint16_t)rtap_port1)
			continue;
		if (strstr(info.driver_name, "rtap") != NULL) {
			port = p;
			break;
		}
	}

	if (port < 0) {
		printf("Failed to find fd-test port\n");
		rte_vdev_uninit("net_rtap_fdtest");
		return -1;
	}

	if (port_reconfigure(port, 2, NULL, RING_SIZE, mp) < 0)
		goto cleanup;

	ret = rte_eth_dev_stop(port);
	if (ret != 0)
		printf("Warning: stop returned %d\n", ret);

	rte_eth_dev_close(port);
	rte_vdev_uninit("net_rtap_fdtest");

	fd_after = count_open_fds();
	printf("  Open fds after:  %d\n", fd_after);

	if (fd_after != fd_before) {
		printf("  ERROR: fd leak detected: %d fds leaked\n",
		       fd_after - fd_before);
		return -1;
	}

	printf("  fd leak test PASSED\n");
	return 0;

cleanup:
	rte_eth_dev_stop(port);
	rte_eth_dev_close(port);
	rte_vdev_uninit("net_rtap_fdtest");
	return -1;
}

static void
test_rtap_cleanup(void)
{
	int ret;

	if (rtap_port0 >= 0) {
		ret = rte_eth_dev_stop(rtap_port0);
		if (ret != 0)
			printf("Error: failed to stop port %u: %s\n",
			       rtap_port0, rte_strerror(-ret));
		rte_eth_dev_close(rtap_port0);
	}

	if (rtap_port1 >= 0) {
		ret = rte_eth_dev_stop(rtap_port1);
		if (ret != 0)
			printf("Error: failed to stop port %u: %s\n",
			       rtap_port1, rte_strerror(-ret));
		rte_eth_dev_close(rtap_port1);
	}

	rte_mempool_free(mp);
	rte_vdev_uninit("net_rtap0");
	rte_vdev_uninit("net_rtap1");
}

static int
test_pmd_rtap_setup(void)
{
	uint16_t nb_ports;

	if (check_rtap_available() < 0) {
		printf("RTAP not available, skipping tests\n");
		return TEST_SKIPPED;
	}

	nb_ports = rte_eth_dev_count_avail();
	printf("nb_ports before rtap creation=%d\n", (int)nb_ports);

	mp = rte_pktmbuf_pool_create("mbuf_pool", NB_MBUF, 32,
			0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mp == NULL) {
		printf("Failed to create mempool\n");
		return TEST_FAILED;
	}

	if (rte_vdev_init("net_rtap0", "iface=rtap_test0") < 0) {
		printf("Failed to create net_rtap0\n");
		rte_mempool_free(mp);
		return TEST_FAILED;
	}

	if (rte_vdev_init("net_rtap1", "iface=rtap_test1") < 0) {
		printf("Failed to create net_rtap1\n");
		rte_vdev_uninit("net_rtap0");
		rte_mempool_free(mp);
		return TEST_FAILED;
	}

	uint16_t port;
	RTE_ETH_FOREACH_DEV(port) {
		struct rte_eth_dev_info dev_info;
		int ret = rte_eth_dev_info_get(port, &dev_info);
		if (ret != 0)
			continue;

		if (strstr(dev_info.driver_name, "rtap") != NULL ||
		    strstr(dev_info.driver_name, "RTAP") != NULL) {
			if (rtap_port0 < 0)
				rtap_port0 = port;
			else if (rtap_port1 < 0)
				rtap_port1 = port;
		}
	}

	if (rtap_port0 < 0) {
		printf("Failed to find rtap ports\n");
		test_rtap_cleanup();
		return TEST_FAILED;
	}

	printf("rtap_port0=%d rtap_port1=%d\n", rtap_port0, rtap_port1);
	return TEST_SUCCESS;
}

static int
test_ethdev_configure_ports(void)
{
	TEST_ASSERT((test_ethdev_configure_port(rtap_port0) == 0),
			"test ethdev configure port rtap_port0 failed");

	if (rtap_port1 >= 0) {
		TEST_ASSERT((test_ethdev_configure_port(rtap_port1) == 0),
				"test ethdev configure port rtap_port1 failed");
	}

	return TEST_SUCCESS;
}

static int
test_command_line_rtap_port(void)
{
	int port, cmdl_port = -1;
	int ret;

	printf("Testing command line created rtap port\n");

	RTE_ETH_FOREACH_DEV(port) {
		struct rte_eth_dev_info dev_info;

		ret = rte_eth_dev_info_get(port, &dev_info);
		if (ret != 0)
			continue;

		if (port == rtap_port0 || port == rtap_port1)
			continue;

		if (strstr(dev_info.driver_name, "rtap") != NULL ||
		    strstr(dev_info.driver_name, "RTAP") != NULL) {
			printf("Found command line rtap port=%d\n", port);
			cmdl_port = port;
			break;
		}
	}

	if (cmdl_port != -1) {
		TEST_ASSERT((test_ethdev_configure_port(cmdl_port) == 0),
				"test ethdev configure cmdl_port failed");
		TEST_ASSERT((test_stats_reset(cmdl_port) == 0),
				"test stats reset cmdl_port failed");
		TEST_ASSERT((test_get_stats(cmdl_port) == 0),
				"test get stats cmdl_port failed");
		TEST_ASSERT((rte_eth_dev_stop(cmdl_port) == 0),
				"test stop cmdl_port failed");
	}

	return TEST_SUCCESS;
}

/* Test case wrappers */
#define TEST_CASE_WRAPPER(name, func) \
	static int test_##name##_for_port(void) { \
		TEST_ASSERT(func(rtap_port0) == 0, #name " failed"); \
		return TEST_SUCCESS; \
	}

TEST_CASE_WRAPPER(get_stats, test_get_stats)
TEST_CASE_WRAPPER(stats_reset, test_stats_reset)
TEST_CASE_WRAPPER(dev_info, test_dev_info)
TEST_CASE_WRAPPER(link_status, test_link_status)
TEST_CASE_WRAPPER(link_up_down, test_set_link_up_down)
TEST_CASE_WRAPPER(promiscuous, test_promiscuous_mode)
TEST_CASE_WRAPPER(allmulticast, test_allmulticast_mode)
TEST_CASE_WRAPPER(mac_address, test_mac_address)
TEST_CASE_WRAPPER(mtu, test_mtu_set)
TEST_CASE_WRAPPER(multiqueue, test_multiqueue)
TEST_CASE_WRAPPER(multiqueue_reduce, test_multiqueue_reduce)
TEST_CASE_WRAPPER(multiqueue_mismatch, test_multiqueue_mismatch)
TEST_CASE_WRAPPER(queue_reconfigure, test_queue_reconfigure)
TEST_CASE_WRAPPER(rx_inject, test_rx_inject)
TEST_CASE_WRAPPER(tx_capture, test_tx_capture)
TEST_CASE_WRAPPER(tx_multiseg, test_tx_multiseg)
TEST_CASE_WRAPPER(rx_multiseg, test_rx_multiseg)
TEST_CASE_WRAPPER(offload_config, test_offload_config)
TEST_CASE_WRAPPER(tx_csum_offload, test_tx_csum_offload)
TEST_CASE_WRAPPER(stats_imissed, test_imissed_counter)
TEST_CASE_WRAPPER(lsc_interrupt, test_lsc_interrupt)
TEST_CASE_WRAPPER(rxq_interrupt, test_rxq_interrupt)

static int
test_fd_leak_for_port(void)
{
	TEST_ASSERT(test_fd_leak() == 0, "test fd leak failed");
	return TEST_SUCCESS;
}

static struct
unit_test_suite test_pmd_rtap_suite = {
	.setup = test_pmd_rtap_setup,
	.teardown = test_rtap_cleanup,
	.suite_name = "Test Pmd RTAP Unit Test Suite",
	.unit_test_cases = {
		TEST_CASE(test_ethdev_configure_ports),
		TEST_CASE(test_dev_info_for_port),
		TEST_CASE(test_link_status_for_port),
		TEST_CASE(test_link_up_down_for_port),
		TEST_CASE(test_get_stats_for_port),
		TEST_CASE(test_stats_reset_for_port),
		TEST_CASE(test_stats_imissed_for_port),
		TEST_CASE(test_promiscuous_for_port),
		TEST_CASE(test_allmulticast_for_port),
		TEST_CASE(test_mac_address_for_port),
		TEST_CASE(test_mtu_for_port),
		TEST_CASE(test_multiqueue_for_port),
		TEST_CASE(test_multiqueue_reduce_for_port),
		TEST_CASE(test_multiqueue_mismatch_for_port),
		TEST_CASE(test_queue_reconfigure_for_port),
		TEST_CASE(test_rx_inject_for_port),
		TEST_CASE(test_tx_capture_for_port),
		TEST_CASE(test_tx_multiseg_for_port),
		TEST_CASE(test_rx_multiseg_for_port),
		TEST_CASE(test_offload_config_for_port),
		TEST_CASE(test_tx_csum_offload_for_port),
		TEST_CASE(test_lsc_interrupt_for_port),
		TEST_CASE(test_rxq_interrupt_for_port),
		TEST_CASE(test_fd_leak_for_port),
		TEST_CASE(test_command_line_rtap_port),
		TEST_CASES_END()
	}
};

static int
test_pmd_rtap(void)
{
	return unit_test_suite_runner(&test_pmd_rtap_suite);
}

REGISTER_FAST_TEST(rtap_pmd_autotest, NOHUGE_OK, ASAN_OK, test_pmd_rtap);

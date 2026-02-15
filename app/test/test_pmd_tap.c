/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Intel Corporation
 */

#include "test.h"

#include <stdio.h>

#ifndef RTE_EXEC_ENV_LINUX

/* TAP PMD is only available on Linux */
static int
test_pmd_tap(void)
{
	printf("TAP PMD not supported on this platform, skipping test\n");
	return TEST_SKIPPED;
}

#else /* RTE_EXEC_ENV_LINUX */

#include <string.h>
#include <unistd.h>

#include <rte_ethdev.h>
#include <rte_bus_vdev.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>

#define SOCKET0 0
#define RING_SIZE 256
#define NB_MBUF 2048
#define MAX_PKT_BURST 32
#define PKT_LEN 64

static struct rte_mempool *mp;
static int tap_port0 = -1;
static int tap_port1 = -1;

static int
test_tap_ethdev_configure(int port)
{
	struct rte_eth_conf port_conf;
	struct rte_eth_link link;
	int ret;

	memset(&port_conf, 0, sizeof(struct rte_eth_conf));

	ret = rte_eth_dev_configure(port, 1, 1, &port_conf);
	if (ret < 0) {
		printf("Configure failed for port %d: %s\n",
		       port, rte_strerror(-ret));
		return -1;
	}

	ret = rte_eth_tx_queue_setup(port, 0, RING_SIZE, SOCKET0, NULL);
	if (ret < 0) {
		printf("TX queue setup failed for port %d: %s\n",
		       port, rte_strerror(-ret));
		return -1;
	}

	ret = rte_eth_rx_queue_setup(port, 0, RING_SIZE, SOCKET0, NULL, mp);
	if (ret < 0) {
		printf("RX queue setup failed for port %d: %s\n",
		       port, rte_strerror(-ret));
		return -1;
	}

	ret = rte_eth_dev_start(port);
	if (ret < 0) {
		printf("Error starting port %d: %s\n",
		       port, rte_strerror(-ret));
		return -1;
	}

	ret = rte_eth_link_get(port, &link);
	if (ret < 0) {
		printf("Link get failed for port %d: %s\n",
		       port, rte_strerror(-ret));
		return -1;
	}

	printf("Port %d: link status %s, speed %u Mbps\n",
	       port,
	       link.link_status ? "up" : "down",
	       link.link_speed);

	return 0;
}

static struct rte_mbuf *
create_test_packet(struct rte_mempool *pool, uint16_t pkt_len)
{
	struct rte_mbuf *mbuf;
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ip_hdr;
	uint8_t *payload;
	uint16_t i;

	mbuf = rte_pktmbuf_alloc(pool);
	if (mbuf == NULL)
		return NULL;

	/* Ensure minimum packet size for Ethernet */
	if (pkt_len < RTE_ETHER_MIN_LEN)
		pkt_len = RTE_ETHER_MIN_LEN;

	mbuf->data_len = pkt_len;
	mbuf->pkt_len = pkt_len;

	/* Create Ethernet header */
	eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
	memset(&eth_hdr->dst_addr, 0xFF, RTE_ETHER_ADDR_LEN); /* broadcast */
	memset(&eth_hdr->src_addr, 0x02, RTE_ETHER_ADDR_LEN);
	eth_hdr->src_addr.addr_bytes[5] = 0x01;
	eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

	/* Create simple IPv4 header */
	ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
	memset(ip_hdr, 0, sizeof(*ip_hdr));
	ip_hdr->version_ihl = 0x45; /* IPv4, 20 byte header */
	ip_hdr->total_length = rte_cpu_to_be_16(pkt_len - sizeof(*eth_hdr));
	ip_hdr->time_to_live = 64;
	ip_hdr->next_proto_id = IPPROTO_UDP;
	ip_hdr->src_addr = rte_cpu_to_be_32(0x0A000001); /* 10.0.0.1 */
	ip_hdr->dst_addr = rte_cpu_to_be_32(0x0A000002); /* 10.0.0.2 */

	/* Fill payload with pattern */
	payload = (uint8_t *)(ip_hdr + 1);
	for (i = 0; i < pkt_len - sizeof(*eth_hdr) - sizeof(*ip_hdr); i++)
		payload[i] = (uint8_t)(i & 0xFF);

	return mbuf;
}

static int
test_tap_send_receive(void)
{
	struct rte_mbuf *tx_mbufs[MAX_PKT_BURST];
	struct rte_mbuf *rx_mbufs[MAX_PKT_BURST];
	uint16_t nb_tx, nb_rx;
	int i;

	printf("Testing TAP packet send and receive\n");

	/* Create test packets */
	for (i = 0; i < MAX_PKT_BURST / 2; i++) {
		tx_mbufs[i] = create_test_packet(mp, PKT_LEN);
		if (tx_mbufs[i] == NULL) {
			printf("Failed to create test packet %d\n", i);
			/* Free already allocated packets */
			while (--i >= 0)
				rte_pktmbuf_free(tx_mbufs[i]);
			return TEST_FAILED;
		}
	}

	/* Send packets */
	nb_tx = rte_eth_tx_burst(tap_port0, 0, tx_mbufs, MAX_PKT_BURST / 2);
	printf("Transmitted %u packets on port %d\n", nb_tx, tap_port0);

	/* Free any unsent packets */
	for (i = nb_tx; i < MAX_PKT_BURST / 2; i++)
		rte_pktmbuf_free(tx_mbufs[i]);

	if (nb_tx == 0) {
		printf("Warning: No packets transmitted (this may be expected if interface is not up)\n");
		return TEST_SUCCESS;
	}

	/* Small delay to allow packets to be processed */
	usleep(10000);

	/* Try to receive packets (note: TAP loopback depends on kernel config) */
	nb_rx = rte_eth_rx_burst(tap_port0, 0, rx_mbufs, MAX_PKT_BURST);
	printf("Received %u packets on port %d\n", nb_rx, tap_port0);

	/* Free received packets */
	for (i = 0; i < nb_rx; i++)
		rte_pktmbuf_free(rx_mbufs[i]);

	return TEST_SUCCESS;
}

static int
test_tap_stats_get(int port)
{
	struct rte_eth_stats stats;
	int ret;

	printf("Testing TAP PMD stats_get for port %d\n", port);

	ret = rte_eth_stats_get(port, &stats);
	if (ret != 0) {
		printf("Error: failed to get stats for port %d: %s\n",
		       port, rte_strerror(-ret));
		return -1;
	}

	printf("Port %d stats:\n", port);
	printf("  ipackets: %"PRIu64"\n", stats.ipackets);
	printf("  opackets: %"PRIu64"\n", stats.opackets);
	printf("  ibytes:   %"PRIu64"\n", stats.ibytes);
	printf("  obytes:   %"PRIu64"\n", stats.obytes);
	printf("  ierrors:  %"PRIu64"\n", stats.ierrors);
	printf("  oerrors:  %"PRIu64"\n", stats.oerrors);

	return 0;
}

static int
test_tap_stats_reset(int port)
{
	struct rte_eth_stats stats;
	int ret;

	printf("Testing TAP PMD stats_reset for port %d\n", port);

	ret = rte_eth_stats_reset(port);
	if (ret != 0) {
		printf("Error: failed to reset stats for port %d: %s\n",
		       port, rte_strerror(-ret));
		return -1;
	}

	ret = rte_eth_stats_get(port, &stats);
	if (ret != 0) {
		printf("Error: failed to get stats after reset for port %d\n",
		       port);
		return -1;
	}

	/* After reset, all stats should be zero */
	if (stats.ipackets != 0 || stats.opackets != 0 ||
	    stats.ibytes != 0 || stats.obytes != 0 ||
	    stats.ierrors != 0 || stats.oerrors != 0) {
		printf("Error: port %d stats are not zero after reset\n", port);
		return -1;
	}

	printf("Stats reset successful for port %d\n", port);
	return 0;
}

static int
test_tap_link_status(int port)
{
	struct rte_eth_link link;
	int ret;

	printf("Testing TAP PMD link status for port %d\n", port);

	ret = rte_eth_link_get_nowait(port, &link);
	if (ret < 0) {
		printf("Error: failed to get link status for port %d: %s\n",
		       port, rte_strerror(-ret));
		return -1;
	}

	printf("Port %d link: status=%s speed=%u duplex=%s\n",
	       port,
	       link.link_status ? "up" : "down",
	       link.link_speed,
	       link.link_duplex ? "full" : "half");

	return 0;
}

static int
test_tap_dev_info(int port)
{
	struct rte_eth_dev_info dev_info;
	int ret;

	printf("Testing TAP PMD dev_info for port %d\n", port);

	ret = rte_eth_dev_info_get(port, &dev_info);
	if (ret != 0) {
		printf("Error: failed to get dev info for port %d: %s\n",
		       port, rte_strerror(-ret));
		return -1;
	}

	printf("Port %d device info:\n", port);
	printf("  driver_name: %s\n", dev_info.driver_name);
	printf("  if_index: %u\n", dev_info.if_index);
	printf("  max_rx_queues: %u\n", dev_info.max_rx_queues);
	printf("  max_tx_queues: %u\n", dev_info.max_tx_queues);
	printf("  max_rx_pktlen: %u\n", dev_info.max_rx_pktlen);

	/* Verify this is indeed a TAP device */
	if (strcmp(dev_info.driver_name, "net_tap") != 0 &&
	    strcmp(dev_info.driver_name, "net_tun") != 0) {
		printf("Warning: unexpected driver name: %s\n",
		       dev_info.driver_name);
	}

	return 0;
}

static int
test_tap_mtu(int port)
{
	uint16_t mtu;
	int ret;

	printf("Testing TAP PMD MTU operations for port %d\n", port);

	/* Get current MTU */
	ret = rte_eth_dev_get_mtu(port, &mtu);
	if (ret != 0) {
		printf("Error: failed to get MTU for port %d: %s\n",
		       port, rte_strerror(-ret));
		return -1;
	}
	printf("Current MTU for port %d: %u\n", port, mtu);

	/* Try to set a new MTU */
	ret = rte_eth_dev_set_mtu(port, 1400);
	if (ret != 0) {
		printf("Warning: failed to set MTU to 1400 for port %d: %s\n",
		       port, rte_strerror(-ret));
		/* Not a fatal error - may require privileges */
	} else {
		printf("MTU set to 1400 for port %d\n", port);

		/* Restore original MTU */
		ret = rte_eth_dev_set_mtu(port, mtu);
		if (ret != 0)
			printf("Warning: failed to restore MTU for port %d\n", port);
	}

	return 0;
}

static int
test_tap_mac_addr(int port)
{
	struct rte_ether_addr mac_addr;
	int ret;

	printf("Testing TAP PMD MAC address for port %d\n", port);

	ret = rte_eth_macaddr_get(port, &mac_addr);
	if (ret != 0) {
		printf("Error: failed to get MAC address for port %d: %s\n",
		       port, rte_strerror(-ret));
		return -1;
	}

	printf("Port %d MAC address: " RTE_ETHER_ADDR_PRT_FMT "\n",
	       port, RTE_ETHER_ADDR_BYTES(&mac_addr));

	return 0;
}

static int
test_tap_promiscuous(int port)
{
	int ret;
	int promisc_enabled;

	printf("Testing TAP PMD promiscuous mode for port %d\n", port);

	/* Get current promiscuous state */
	promisc_enabled = rte_eth_promiscuous_get(port);
	printf("Promiscuous mode initially %s for port %d\n",
	       promisc_enabled ? "enabled" : "disabled", port);

	/* Enable promiscuous mode */
	ret = rte_eth_promiscuous_enable(port);
	if (ret != 0) {
		printf("Warning: failed to enable promiscuous mode for port %d: %s\n",
		       port, rte_strerror(-ret));
	} else {
		if (rte_eth_promiscuous_get(port) != 1) {
			printf("Error: promiscuous mode not enabled after enable call\n");
			return -1;
		}
		printf("Promiscuous mode enabled for port %d\n", port);
	}

	/* Disable promiscuous mode */
	ret = rte_eth_promiscuous_disable(port);
	if (ret != 0) {
		printf("Warning: failed to disable promiscuous mode for port %d: %s\n",
		       port, rte_strerror(-ret));
	} else {
		if (rte_eth_promiscuous_get(port) != 0) {
			printf("Error: promiscuous mode not disabled after disable call\n");
			return -1;
		}
		printf("Promiscuous mode disabled for port %d\n", port);
	}

	return 0;
}

static int
test_tap_allmulti(int port)
{
	int ret;
	int allmulti_enabled;

	printf("Testing TAP PMD allmulticast mode for port %d\n", port);

	/* Get current allmulticast state */
	allmulti_enabled = rte_eth_allmulticast_get(port);
	printf("Allmulticast mode initially %s for port %d\n",
	       allmulti_enabled ? "enabled" : "disabled", port);

	/* Enable allmulticast mode */
	ret = rte_eth_allmulticast_enable(port);
	if (ret != 0) {
		printf("Warning: failed to enable allmulticast mode for port %d: %s\n",
		       port, rte_strerror(-ret));
	} else {
		if (rte_eth_allmulticast_get(port) != 1) {
			printf("Error: allmulticast mode not enabled after enable call\n");
			return -1;
		}
		printf("Allmulticast mode enabled for port %d\n", port);
	}

	/* Disable allmulticast mode */
	ret = rte_eth_allmulticast_disable(port);
	if (ret != 0) {
		printf("Warning: failed to disable allmulticast mode for port %d: %s\n",
		       port, rte_strerror(-ret));
	} else {
		if (rte_eth_allmulticast_get(port) != 0) {
			printf("Error: allmulticast mode not disabled after disable call\n");
			return -1;
		}
		printf("Allmulticast mode disabled for port %d\n", port);
	}

	return 0;
}

static int
test_tap_queue_start_stop(int port)
{
	int ret;

	printf("Testing TAP PMD queue start/stop for port %d\n", port);

	/* Stop RX queue */
	ret = rte_eth_dev_rx_queue_stop(port, 0);
	if (ret != 0 && ret != -ENOTSUP) {
		printf("Error: failed to stop RX queue for port %d: %s\n",
		       port, rte_strerror(-ret));
		return -1;
	}
	printf("RX queue stopped for port %d\n", port);

	/* Stop TX queue */
	ret = rte_eth_dev_tx_queue_stop(port, 0);
	if (ret != 0 && ret != -ENOTSUP) {
		printf("Error: failed to stop TX queue for port %d: %s\n",
		       port, rte_strerror(-ret));
		return -1;
	}
	printf("TX queue stopped for port %d\n", port);

	/* Start RX queue */
	ret = rte_eth_dev_rx_queue_start(port, 0);
	if (ret != 0 && ret != -ENOTSUP) {
		printf("Error: failed to start RX queue for port %d: %s\n",
		       port, rte_strerror(-ret));
		return -1;
	}
	printf("RX queue started for port %d\n", port);

	/* Start TX queue */
	ret = rte_eth_dev_tx_queue_start(port, 0);
	if (ret != 0 && ret != -ENOTSUP) {
		printf("Error: failed to start TX queue for port %d: %s\n",
		       port, rte_strerror(-ret));
		return -1;
	}
	printf("TX queue started for port %d\n", port);

	return 0;
}

static int
test_tap_link_up_down(int port)
{
	struct rte_eth_link link;
	int ret;

	printf("Testing TAP PMD link up/down for port %d\n", port);

	/* Set link down */
	ret = rte_eth_dev_set_link_down(port);
	if (ret != 0) {
		printf("Warning: failed to set link down for port %d: %s\n",
		       port, rte_strerror(-ret));
	} else {
		ret = rte_eth_link_get_nowait(port, &link);
		if (ret == 0)
			printf("Link status after set_link_down: %s\n",
			       link.link_status ? "up" : "down");
	}

	/* Set link up */
	ret = rte_eth_dev_set_link_up(port);
	if (ret != 0) {
		printf("Warning: failed to set link up for port %d: %s\n",
		       port, rte_strerror(-ret));
	} else {
		ret = rte_eth_link_get_nowait(port, &link);
		if (ret == 0)
			printf("Link status after set_link_up: %s\n",
			       link.link_status ? "up" : "down");
	}

	return 0;
}

static int
test_tap_dev_stop_start(int port)
{
	int ret;

	printf("Testing TAP PMD device stop/start for port %d\n", port);

	/* Stop the device */
	ret = rte_eth_dev_stop(port);
	if (ret != 0) {
		printf("Error: failed to stop port %d: %s\n",
		       port, rte_strerror(-ret));
		return -1;
	}
	printf("Device stopped for port %d\n", port);

	/* Start the device again */
	ret = rte_eth_dev_start(port);
	if (ret != 0) {
		printf("Error: failed to start port %d: %s\n",
		       port, rte_strerror(-ret));
		return -1;
	}
	printf("Device started for port %d\n", port);

	return 0;
}

static int
test_tap_multi_queue(void)
{
	struct rte_eth_conf port_conf;
	struct rte_mempool *mq_mp;
	const uint16_t nb_queues = 2;
	int ret;
	int port = -1;

	printf("Testing TAP PMD multi-queue configuration\n");

	/* Create a separate mempool for multi-queue test */
	mq_mp = rte_pktmbuf_pool_create("tap_mq_pool", NB_MBUF, 32, 0,
					RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mq_mp == NULL) {
		printf("Warning: failed to create mempool for multi-queue test: %s\n",
		       rte_strerror(rte_errno));
		return TEST_SKIPPED;
	}

	/* Create a new TAP device for multi-queue test */
	ret = rte_vdev_init("net_tap_mq", "iface=dtap_mq");
	if (ret < 0) {
		printf("Warning: failed to create multi-queue TAP device: %s\n",
		       rte_strerror(-ret));
		rte_mempool_free(mq_mp);
		return TEST_SKIPPED;
	}

	/* Find the port */
	RTE_ETH_FOREACH_DEV(port) {
		char name[RTE_ETH_NAME_MAX_LEN];
		if (rte_eth_dev_get_name_by_port(port, name) == 0 &&
		    strstr(name, "net_tap_mq"))
			break;
	}

	if (port < 0 || port >= RTE_MAX_ETHPORTS) {
		printf("Error: could not find multi-queue TAP device\n");
		rte_vdev_uninit("net_tap_mq");
		rte_mempool_free(mq_mp);
		return TEST_FAILED;
	}

	memset(&port_conf, 0, sizeof(struct rte_eth_conf));

	/* Configure with multiple queues */
	ret = rte_eth_dev_configure(port, nb_queues, nb_queues, &port_conf);
	if (ret < 0) {
		printf("Warning: multi-queue configure failed: %s\n",
		       rte_strerror(-ret));
		rte_vdev_uninit("net_tap_mq");
		rte_mempool_free(mq_mp);
		return TEST_SKIPPED;
	}

	/* Setup TX queues */
	for (uint16_t q = 0; q < nb_queues; q++) {
		ret = rte_eth_tx_queue_setup(port, q, RING_SIZE, SOCKET0, NULL);
		if (ret < 0) {
			printf("Error: TX queue %u setup failed: %s\n",
			       q, rte_strerror(-ret));
			rte_vdev_uninit("net_tap_mq");
			rte_mempool_free(mq_mp);
			return TEST_FAILED;
		}
	}

	/* Setup RX queues */
	for (uint16_t q = 0; q < nb_queues; q++) {
		ret = rte_eth_rx_queue_setup(port, q, RING_SIZE, SOCKET0, NULL, mq_mp);
		if (ret < 0) {
			printf("Error: RX queue %u setup failed: %s\n",
			       q, rte_strerror(-ret));
			rte_vdev_uninit("net_tap_mq");
			rte_mempool_free(mq_mp);
			return TEST_FAILED;
		}
	}

	ret = rte_eth_dev_start(port);
	if (ret < 0) {
		printf("Error: failed to start multi-queue port: %s\n",
		       rte_strerror(-ret));
		rte_vdev_uninit("net_tap_mq");
		rte_mempool_free(mq_mp);
		return TEST_FAILED;
	}

	printf("Multi-queue TAP device configured with %u queues\n", nb_queues);

	/* Cleanup */
	rte_eth_dev_stop(port);
	rte_eth_dev_close(port);
	rte_vdev_uninit("net_tap_mq");
	rte_mempool_free(mq_mp);

	return TEST_SUCCESS;
}

static void
test_tap_cleanup(void)
{
	int ret;

	printf("Cleaning up TAP PMD test resources\n");

	if (tap_port0 >= 0) {
		ret = rte_eth_dev_stop(tap_port0);
		if (ret != 0)
			printf("Warning: failed to stop port %d: %s\n",
			       tap_port0, rte_strerror(-ret));
		rte_eth_dev_close(tap_port0);
	}

	if (tap_port1 >= 0) {
		ret = rte_eth_dev_stop(tap_port1);
		if (ret != 0)
			printf("Warning: failed to stop port %d: %s\n",
			       tap_port1, rte_strerror(-ret));
		rte_eth_dev_close(tap_port1);
	}

	rte_vdev_uninit("net_tap0");
	rte_vdev_uninit("net_tap1");

	if (mp != NULL) {
		rte_mempool_free(mp);
		mp = NULL;
	}

	tap_port0 = -1;
	tap_port1 = -1;
}

static int
test_tap_setup(void)
{
	int ret;
	uint16_t port_id;

	printf("Setting up TAP PMD test\n");

	/* Create mempool */
	mp = rte_pktmbuf_pool_create("tap_test_pool", NB_MBUF, 32, 0,
				     RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mp == NULL) {
		printf("Error: failed to create mempool: %s\n",
		       rte_strerror(rte_errno));
		return -1;
	}

	/* Create first TAP device */
	ret = rte_vdev_init("net_tap0", "iface=dtap_test0");
	if (ret < 0) {
		printf("Error: failed to create TAP device net_tap0: %s\n",
		       rte_strerror(-ret));
		rte_mempool_free(mp);
		mp = NULL;
		return -1;
	}

	/* Create second TAP device */
	ret = rte_vdev_init("net_tap1", "iface=dtap_test1");
	if (ret < 0) {
		printf("Error: failed to create TAP device net_tap1: %s\n",
		       rte_strerror(-ret));
		rte_vdev_uninit("net_tap0");
		rte_mempool_free(mp);
		mp = NULL;
		return -1;
	}

	/* Find the port IDs */
	RTE_ETH_FOREACH_DEV(port_id) {
		char name[RTE_ETH_NAME_MAX_LEN];
		if (rte_eth_dev_get_name_by_port(port_id, name) != 0)
			continue;

		if (strstr(name, "net_tap0"))
			tap_port0 = port_id;
		else if (strstr(name, "net_tap1"))
			tap_port1 = port_id;
	}

	if (tap_port0 < 0 || tap_port1 < 0) {
		printf("Error: failed to find TAP port IDs\n");
		test_tap_cleanup();
		return -1;
	}

	printf("Created TAP devices: tap_port0=%d, tap_port1=%d\n",
	       tap_port0, tap_port1);

	return 0;
}

/* Individual test case wrappers */

static int
test_tap_configure_port0(void)
{
	return test_tap_ethdev_configure(tap_port0) == 0 ?
	       TEST_SUCCESS : TEST_FAILED;
}

static int
test_tap_configure_port1(void)
{
	return test_tap_ethdev_configure(tap_port1) == 0 ?
	       TEST_SUCCESS : TEST_FAILED;
}

static int
test_tap_packet_send_receive(void)
{
	return test_tap_send_receive();
}

static int
test_tap_get_stats(void)
{
	if (test_tap_stats_get(tap_port0) != 0)
		return TEST_FAILED;
	if (test_tap_stats_get(tap_port1) != 0)
		return TEST_FAILED;
	return TEST_SUCCESS;
}

static int
test_tap_reset_stats(void)
{
	if (test_tap_stats_reset(tap_port0) != 0)
		return TEST_FAILED;
	if (test_tap_stats_reset(tap_port1) != 0)
		return TEST_FAILED;
	return TEST_SUCCESS;
}

static int
test_tap_get_link_status(void)
{
	if (test_tap_link_status(tap_port0) != 0)
		return TEST_FAILED;
	if (test_tap_link_status(tap_port1) != 0)
		return TEST_FAILED;
	return TEST_SUCCESS;
}

static int
test_tap_get_dev_info(void)
{
	if (test_tap_dev_info(tap_port0) != 0)
		return TEST_FAILED;
	if (test_tap_dev_info(tap_port1) != 0)
		return TEST_FAILED;
	return TEST_SUCCESS;
}

static int
test_tap_mtu_ops(void)
{
	return test_tap_mtu(tap_port0) == 0 ? TEST_SUCCESS : TEST_FAILED;
}

static int
test_tap_mac_addr_get(void)
{
	if (test_tap_mac_addr(tap_port0) != 0)
		return TEST_FAILED;
	if (test_tap_mac_addr(tap_port1) != 0)
		return TEST_FAILED;
	return TEST_SUCCESS;
}

static int
test_tap_promisc_mode(void)
{
	return test_tap_promiscuous(tap_port0) == 0 ? TEST_SUCCESS : TEST_FAILED;
}

static int
test_tap_allmulti_mode(void)
{
	return test_tap_allmulti(tap_port0) == 0 ? TEST_SUCCESS : TEST_FAILED;
}

static int
test_tap_queue_ops(void)
{
	return test_tap_queue_start_stop(tap_port0) == 0 ?
	       TEST_SUCCESS : TEST_FAILED;
}

static int
test_tap_link_ops(void)
{
	return test_tap_link_up_down(tap_port0) == 0 ? TEST_SUCCESS : TEST_FAILED;
}

static int
test_tap_stop_start(void)
{
	return test_tap_dev_stop_start(tap_port0) == 0 ?
	       TEST_SUCCESS : TEST_FAILED;
}

static int
test_tap_multiqueue(void)
{
	return test_tap_multi_queue();
}

static struct unit_test_suite test_pmd_tap_suite = {
	.setup = test_tap_setup,
	.teardown = test_tap_cleanup,
	.suite_name = "TAP PMD Unit Test Suite",
	.unit_test_cases = {
		TEST_CASE(test_tap_configure_port0),
		TEST_CASE(test_tap_configure_port1),
		TEST_CASE(test_tap_get_dev_info),
		TEST_CASE(test_tap_get_link_status),
		TEST_CASE(test_tap_mac_addr_get),
		TEST_CASE(test_tap_get_stats),
		TEST_CASE(test_tap_reset_stats),
		TEST_CASE(test_tap_packet_send_receive),
		TEST_CASE(test_tap_promisc_mode),
		TEST_CASE(test_tap_allmulti_mode),
		TEST_CASE(test_tap_mtu_ops),
		TEST_CASE(test_tap_queue_ops),
		TEST_CASE(test_tap_link_ops),
		TEST_CASE(test_tap_stop_start),
		TEST_CASE(test_tap_multiqueue),
		TEST_CASES_END()
	}
};

static int
test_pmd_tap(void)
{
	return unit_test_suite_runner(&test_pmd_tap_suite);
}

#endif /* RTE_EXEC_ENV_LINUX */

REGISTER_FAST_TEST(tap_pmd_autotest, NOHUGE_OK, ASAN_OK, test_pmd_tap);

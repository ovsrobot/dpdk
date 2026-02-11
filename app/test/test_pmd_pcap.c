/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Stephen Hemminger
 */

#include "test.h"
#include "packet_burst_generator.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <pcap/pcap.h>

#include <rte_ethdev.h>
#include <rte_bus_vdev.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>
#include <rte_mempool.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>

#define SOCKET0 0
#define RING_SIZE 256
#define NB_MBUF 1024
#define NUM_PACKETS 64
#define MAX_PKT_BURST 32
#define PCAP_SNAPLEN 65535

/* Packet sizes to test */
#define PKT_SIZE_MIN 60
#define PKT_SIZE_SMALL 128
#define PKT_SIZE_MEDIUM 512
#define PKT_SIZE_LARGE 1024
#define PKT_SIZE_MTU 1500
#define PKT_SIZE_JUMBO 9000

static struct rte_mempool *mp;

/* Timestamp dynamic field access */
static int timestamp_dynfield_offset = -1;
static uint64_t timestamp_rx_dynflag;

/* Temporary file paths */
static char tx_pcap_path[PATH_MAX];
static char rx_pcap_path[PATH_MAX];
static char infinite_pcap_path[PATH_MAX];
static char timestamp_pcap_path[PATH_MAX];
static char varied_pcap_path[PATH_MAX];
static char jumbo_pcap_path[PATH_MAX];

/* Constants for multi-queue tests */
#define MULTI_QUEUE_NUM_QUEUES   4U
#define MULTI_QUEUE_NUM_PACKETS  100U
#define MULTI_QUEUE_BURST_SIZE   32U

static char multi_tx_pcap_paths[MULTI_QUEUE_NUM_QUEUES][PATH_MAX];
static char multi_rx_pcap_path[PATH_MAX];

/* MAC addresses for packet generation */
static struct rte_ether_addr src_mac;
static struct rte_ether_addr dst_mac = {
	.addr_bytes = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }
};

/* Sample Ethernet/IPv4/UDP packet for testing */
static const uint8_t test_packet[] = {
	/* Ethernet header */
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  /* dst MAC (broadcast) */
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  /* src MAC */
	0x08, 0x00,                          /* EtherType: IPv4 */
	/* IPv4 header */
	0x45, 0x00, 0x00, 0x2e,              /* ver, ihl, tos, len */
	0x00, 0x01, 0x00, 0x00,              /* id, flags, frag */
	0x40, 0x11, 0x00, 0x00,              /* ttl, proto(UDP), csum */
	0x0a, 0x00, 0x00, 0x01,              /* src: 10.0.0.1 */
	0x0a, 0x00, 0x00, 0x02,              /* dst: 10.0.0.2 */
	/* UDP header */
	0x04, 0xd2, 0x04, 0xd2,              /* sport, dport (1234) */
	0x00, 0x1a, 0x00, 0x00,              /* len, csum */
	/* Payload: "Test packet!" */
	0x54, 0x65, 0x73, 0x74, 0x20, 0x70,
	0x61, 0x63, 0x6b, 0x65, 0x74, 0x21
};

/* Helper: Get timestamp from mbuf using dynamic field */
static inline rte_mbuf_timestamp_t
mbuf_timestamp_get(const struct rte_mbuf *mbuf)
{
	return *RTE_MBUF_DYNFIELD(mbuf, timestamp_dynfield_offset, rte_mbuf_timestamp_t *);
}

/* Helper: Check if mbuf has valid timestamp */
static inline int
mbuf_has_timestamp(const struct rte_mbuf *mbuf)
{
	return (mbuf->ol_flags & timestamp_rx_dynflag) != 0;
}

/* Helper: Initialize timestamp dynamic field access */
static int
timestamp_init(void)
{
	int offset;

	offset = rte_mbuf_dynfield_lookup(RTE_MBUF_DYNFIELD_TIMESTAMP_NAME, NULL);
	if (offset < 0) {
		printf("Timestamp dynfield not registered\n");
		return -1;
	}
	timestamp_dynfield_offset = offset;

	offset = rte_mbuf_dynflag_lookup(RTE_MBUF_DYNFLAG_RX_TIMESTAMP_NAME, NULL);
	if (offset < 0) {
		printf("Timestamp dynflag not registered\n");
		return -1;
	}
	timestamp_rx_dynflag = RTE_BIT64(offset);
	return 0;
}

/*
 * Helper: Create a unique temporary file path
 */
static int
create_temp_path(char *buf, size_t buflen, const char *prefix)
{
	int fd;

	snprintf(buf, buflen, "/tmp/%s_XXXXXX.pcap", prefix);
	fd = mkstemps(buf, 5);  /* 5 = strlen(".pcap") */
	if (fd < 0)
		return -1;
	close(fd);
	return 0;
}

/*
 * Helper: Create a pcap file with test packets using libpcap
 */
static int
create_test_pcap(const char *path, unsigned int num_pkts)
{
	pcap_t *pd;
	pcap_dumper_t *dumper;
	struct pcap_pkthdr hdr;
	unsigned int i;

	pd = pcap_open_dead(DLT_EN10MB, PCAP_SNAPLEN);
	if (pd == NULL) {
		printf("pcap_open_dead failed\n");
		return -1;
	}

	dumper = pcap_dump_open(pd, path);
	if (dumper == NULL) {
		printf("pcap_dump_open failed: %s\n", pcap_geterr(pd));
		pcap_close(pd);
		return -1;
	}

	memset(&hdr, 0, sizeof(hdr));
	hdr.caplen = sizeof(test_packet);
	hdr.len = sizeof(test_packet);

	for (i = 0; i < num_pkts; i++) {
		hdr.ts.tv_sec = i;
		hdr.ts.tv_usec = 0;
		pcap_dump((u_char *)dumper, &hdr, test_packet);
	}

	pcap_dump_close(dumper);
	pcap_close(pd);
	return 0;
}

/*
 * Helper: Create pcap file with packets of specified size
 */
static int
create_sized_pcap(const char *path, unsigned int num_pkts, uint16_t pkt_size)
{
	pcap_t *pd;
	pcap_dumper_t *dumper;
	struct pcap_pkthdr hdr;
	uint8_t *pkt_data;
	unsigned int i;

	/* Minimum valid ethernet frame */
	if (pkt_size < 60)
		pkt_size = 60;

	pkt_data = calloc(1, pkt_size);
	if (pkt_data == NULL)
		return -1;

	/* Build ethernet header */
	struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)pkt_data;
	rte_ether_addr_copy(&src_mac, &eth_hdr->src_addr);
	rte_ether_addr_copy(&dst_mac, &eth_hdr->dst_addr);
	eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

	/* Build IP header */
	struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
	uint16_t ip_len = pkt_size - sizeof(struct rte_ether_hdr);
	ip_hdr->version_ihl = RTE_IPV4_VHL_DEF;
	ip_hdr->total_length = rte_cpu_to_be_16(ip_len);
	ip_hdr->time_to_live = 64;
	ip_hdr->next_proto_id = IPPROTO_UDP;
	ip_hdr->src_addr = rte_cpu_to_be_32(IPV4_ADDR(10, 0, 0, 1));
	ip_hdr->dst_addr = rte_cpu_to_be_32(IPV4_ADDR(10, 0, 0, 2));
	ip_hdr->hdr_checksum = 0;
	ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);

	/* Build UDP header */
	struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(ip_hdr + 1);
	uint16_t udp_len = ip_len - sizeof(struct rte_ipv4_hdr);
	udp_hdr->src_port = rte_cpu_to_be_16(1234);
	udp_hdr->dst_port = rte_cpu_to_be_16(1234);
	udp_hdr->dgram_len = rte_cpu_to_be_16(udp_len);
	udp_hdr->dgram_cksum = 0;

	/* Fill payload with pattern */
	uint8_t *payload = (uint8_t *)(udp_hdr + 1);
	uint16_t payload_len = udp_len - sizeof(struct rte_udp_hdr);
	for (uint16_t j = 0; j < payload_len; j++)
		payload[j] = (uint8_t)(j & 0xFF);

	pd = pcap_open_dead(DLT_EN10MB, PCAP_SNAPLEN);
	if (pd == NULL) {
		free(pkt_data);
		return -1;
	}

	dumper = pcap_dump_open(pd, path);
	if (dumper == NULL) {
		pcap_close(pd);
		free(pkt_data);
		return -1;
	}

	memset(&hdr, 0, sizeof(hdr));
	hdr.caplen = pkt_size;
	hdr.len = pkt_size;

	for (i = 0; i < num_pkts; i++) {
		hdr.ts.tv_sec = i;
		hdr.ts.tv_usec = 0;
		/* Vary sequence byte in payload */
		payload[0] = (uint8_t)(i & 0xFF);
		pcap_dump((u_char *)dumper, &hdr, pkt_data);
	}

	pcap_dump_close(dumper);
	pcap_close(pd);
	free(pkt_data);
	return 0;
}

/*
 * Helper: Create pcap file with varied packet sizes
 */
static int
create_varied_pcap(const char *path, unsigned int num_pkts)
{
	static const uint16_t sizes[] = {
		PKT_SIZE_MIN, PKT_SIZE_SMALL, PKT_SIZE_MEDIUM,
		PKT_SIZE_LARGE, PKT_SIZE_MTU
	};
	pcap_t *pd;
	pcap_dumper_t *dumper;
	struct pcap_pkthdr hdr;
	uint8_t *pkt_data;
	unsigned int i;

	pkt_data = calloc(1, PKT_SIZE_MTU);
	if (pkt_data == NULL)
		return -1;

	pd = pcap_open_dead(DLT_EN10MB, PCAP_SNAPLEN);
	if (pd == NULL) {
		free(pkt_data);
		return -1;
	}

	dumper = pcap_dump_open(pd, path);
	if (dumper == NULL) {
		pcap_close(pd);
		free(pkt_data);
		return -1;
	}

	for (i = 0; i < num_pkts; i++) {
		uint16_t pkt_size = sizes[i % RTE_DIM(sizes)];

		memset(pkt_data, 0, pkt_size);

		/* Build ethernet header */
		struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)pkt_data;
		rte_ether_addr_copy(&src_mac, &eth_hdr->src_addr);
		rte_ether_addr_copy(&dst_mac, &eth_hdr->dst_addr);
		eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

		/* Build IP header */
		struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
		uint16_t ip_len = pkt_size - sizeof(struct rte_ether_hdr);
		ip_hdr->version_ihl = RTE_IPV4_VHL_DEF;
		ip_hdr->total_length = rte_cpu_to_be_16(ip_len);
		ip_hdr->time_to_live = 64;
		ip_hdr->next_proto_id = IPPROTO_UDP;
		ip_hdr->src_addr = rte_cpu_to_be_32(IPV4_ADDR(10, 0, 0, 1));
		ip_hdr->dst_addr = rte_cpu_to_be_32(IPV4_ADDR(10, 0, 0, 2));
		ip_hdr->hdr_checksum = 0;
		ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);

		/* Build UDP header */
		struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(ip_hdr + 1);
		uint16_t udp_len = ip_len - sizeof(struct rte_ipv4_hdr);
		udp_hdr->src_port = rte_cpu_to_be_16(1234);
		udp_hdr->dst_port = rte_cpu_to_be_16(1234);
		udp_hdr->dgram_len = rte_cpu_to_be_16(udp_len);

		memset(&hdr, 0, sizeof(hdr));
		hdr.ts.tv_sec = i;
		hdr.caplen = pkt_size;
		hdr.len = pkt_size;

		pcap_dump((u_char *)dumper, &hdr, pkt_data);
	}

	pcap_dump_close(dumper);
	pcap_close(pd);
	free(pkt_data);
	return 0;
}

/*
 * Helper: Create pcap file with specific timestamps for testing
 */
static int
create_timestamped_pcap(const char *path, unsigned int num_pkts,
			uint32_t base_sec, uint32_t usec_increment)
{
	pcap_t *pd;
	pcap_dumper_t *dumper;
	struct pcap_pkthdr hdr;
	unsigned int i;

	pd = pcap_open_dead_with_tstamp_precision(DLT_EN10MB, PCAP_SNAPLEN,
						  PCAP_TSTAMP_PRECISION_MICRO);
	if (pd == NULL)
		return -1;

	dumper = pcap_dump_open(pd, path);
	if (dumper == NULL) {
		pcap_close(pd);
		return -1;
	}

	memset(&hdr, 0, sizeof(hdr));
	hdr.caplen = sizeof(test_packet);
	hdr.len = sizeof(test_packet);

	for (i = 0; i < num_pkts; i++) {
		uint64_t total_usec = (uint64_t)i * usec_increment;
		hdr.ts.tv_sec = base_sec + total_usec / 1000000;
		hdr.ts.tv_usec = total_usec % 1000000;
		pcap_dump((u_char *)dumper, &hdr, test_packet);
	}

	pcap_dump_close(dumper);
	pcap_close(pd);
	return 0;
}

/*
 * Helper: Count packets in a pcap file using libpcap
 */
static int
count_pcap_packets(const char *path)
{
	pcap_t *pd;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *hdr;
	const u_char *data;
	int count = 0;

	pd = pcap_open_offline(path, errbuf);
	if (pd == NULL)
		return -1;

	while (pcap_next_ex(pd, &hdr, &data) == 1)
		count++;

	pcap_close(pd);
	return count;
}

/*
 * Helper: Get packet sizes from pcap file
 */
static int
get_pcap_packet_sizes(const char *path, uint16_t *sizes, unsigned int max_pkts)
{
	pcap_t *pd;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *hdr;
	const u_char *data;
	unsigned int count = 0;

	pd = pcap_open_offline(path, errbuf);
	if (pd == NULL)
		return -1;

	while (pcap_next_ex(pd, &hdr, &data) == 1 && count < max_pkts) {
		sizes[count] = hdr->caplen;
		count++;
	}

	pcap_close(pd);
	return count;
}

/*
 * Helper: Configure and start a pcap ethdev port
 */
static int
setup_pcap_port(uint16_t port)
{
	struct rte_eth_conf port_conf = {
		.rxmode.offloads = RTE_ETH_RX_OFFLOAD_TIMESTAMP,
	};
	int ret;

	ret = rte_eth_dev_configure(port, 1, 1, &port_conf);
	TEST_ASSERT(ret == 0, "Failed to configure port %u: %s",
		    port, rte_strerror(-ret));

	ret = rte_eth_rx_queue_setup(port, 0, RING_SIZE, SOCKET0, NULL, mp);
	TEST_ASSERT(ret == 0, "Failed to setup RX queue on port %u: %s",
		    port, rte_strerror(-ret));

	ret = rte_eth_tx_queue_setup(port, 0, RING_SIZE, SOCKET0, NULL);
	TEST_ASSERT(ret == 0, "Failed to setup TX queue on port %u: %s",
		    port, rte_strerror(-ret));

	ret = rte_eth_dev_start(port);
	TEST_ASSERT(ret == 0, "Failed to start port %u: %s",
		    port, rte_strerror(-ret));

	return 0;
}

/*
 * Helper: Create a pcap vdev and return its port ID
 */
static int
create_pcap_vdev(const char *name, const char *devargs, uint16_t *port_id)
{
	int ret;

	ret = rte_vdev_init(name, devargs);
	TEST_ASSERT(ret == 0, "Failed to create vdev %s: %s",
		    name, rte_strerror(-ret));

	ret = rte_eth_dev_get_port_by_name(name, port_id);
	TEST_ASSERT(ret == 0, "Failed to get port ID for %s", name);

	return 0;
}

/*
 * Helper: Cleanup a pcap vdev
 */
static void
cleanup_pcap_vdev(const char *name, uint16_t port_id)
{
	rte_eth_dev_stop(port_id);
	rte_vdev_uninit(name);
}

/*
 * Helper: Generate test packets using packet_burst_generator
 */
static int
generate_test_packets(struct rte_mempool *pool, struct rte_mbuf **mbufs,
		      unsigned int count, uint8_t pkt_len)
{
	struct rte_ether_hdr eth_hdr;
	struct rte_ipv4_hdr ip_hdr;
	struct rte_udp_hdr udp_hdr;
	uint16_t ip_pkt_data_len;
	int nb_pkt;

	/* Initialize ethernet header */
	initialize_eth_header(&eth_hdr, &src_mac, &dst_mac,
			      RTE_ETHER_TYPE_IPV4, 0, 0);

	/* Calculate IP payload length (total - eth - ip headers) */
	ip_pkt_data_len = pkt_len - sizeof(struct rte_ether_hdr) -
			  sizeof(struct rte_ipv4_hdr);

	/* Initialize UDP header */
	initialize_udp_header(&udp_hdr, 1234, 1234,
			      ip_pkt_data_len - sizeof(struct rte_udp_hdr));

	/* Initialize IPv4 header */
	initialize_ipv4_header(&ip_hdr, IPV4_ADDR(10, 0, 0, 1),
			       IPV4_ADDR(10, 0, 0, 2), ip_pkt_data_len);

	/* Generate packet burst */
	nb_pkt = generate_packet_burst(pool, mbufs, &eth_hdr, 0,
				       &ip_hdr, 1, &udp_hdr,
				       count, pkt_len, 1);

	return nb_pkt;
}

/*
 * Helper: Allocate mbufs and fill with test packet data (legacy method)
 */
static int
alloc_test_mbufs(struct rte_mbuf **mbufs, unsigned int count)
{
	unsigned int i;
	int ret;

	ret = rte_pktmbuf_alloc_bulk(mp, mbufs, count);
	if (ret != 0)
		return -1;

	for (i = 0; i < count; i++) {
		rte_memcpy(rte_pktmbuf_mtod(mbufs[i], void *),
			   test_packet, sizeof(test_packet));
		mbufs[i]->data_len = sizeof(test_packet);
		mbufs[i]->pkt_len = sizeof(test_packet);
	}
	return 0;
}

/*
 * Helper: Allocate a multi-segment mbuf for jumbo frames
 * Returns the head mbuf with chained segments, or NULL on failure
 */
static struct rte_mbuf *
alloc_jumbo_mbuf(uint32_t pkt_len, uint8_t fill_byte)
{
	struct rte_mbuf *head = NULL;
	struct rte_mbuf **prev = &head;
	uint32_t remaining = pkt_len;
	uint16_t nb_segs = 0;

	while (remaining > 0) {
		struct rte_mbuf *seg = rte_pktmbuf_alloc(mp);
		uint16_t seg_size;

		if (seg == NULL) {
			rte_pktmbuf_free(head);
			return NULL;
		}

		seg_size = RTE_MIN(remaining, rte_pktmbuf_tailroom(seg));
		seg->data_len = seg_size;

		/* Fill segment with pattern */
		memset(rte_pktmbuf_mtod(seg, void *), fill_byte, seg_size);

		*prev = seg;
		prev = &seg->next;
		remaining -= seg_size;
		nb_segs++;
	}

	if (head != NULL) {
		head->pkt_len = pkt_len;
		head->nb_segs = nb_segs;
	}

	return head;
}

/*
 * Helper: Receive packets from port (no retry needed for file-based RX)
 */
static int
receive_packets(uint16_t port, struct rte_mbuf **mbufs,
		unsigned int max_pkts, unsigned int *received)
{
	unsigned int total = 0;

	while (total < max_pkts) {
		uint16_t nb_rx = rte_eth_rx_burst(port, 0, &mbufs[total], max_pkts - total);
		if (nb_rx == 0)
			break;
		total += nb_rx;
	}
	*received = total;
	return 0;
}

/*
 * Helper: Verify mbuf contains expected test packet
 */
static int
verify_packet(struct rte_mbuf *mbuf)
{
	TEST_ASSERT_EQUAL(rte_pktmbuf_data_len(mbuf), sizeof(test_packet),
			  "Packet length mismatch");
	TEST_ASSERT_BUFFERS_ARE_EQUAL(rte_pktmbuf_mtod(mbuf, void *),
				      test_packet, sizeof(test_packet),
				      "Packet data mismatch");
	return 0;
}

/*
 * Helper: Check if network interface exists
 */
static int
iface_exists(const char *name)
{
	struct ifreq ifr;
	int sock, ret;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		return 0;

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, name, IFNAMSIZ);
	ret = ioctl(sock, SIOCGIFINDEX, &ifr);
	close(sock);
	return ret == 0;
}

/*
 * Helper: Find a usable test interface
 */
static const char *
find_test_iface(void)
{
	if (iface_exists("dummy0"))
		return "dummy0";
	if (iface_exists("lo"))
		return "lo";
	return NULL;
}

/*
 * Test: Transmit packets to pcap file
 */
static int
test_tx_to_file(void)
{
	struct rte_mbuf *mbufs[NUM_PACKETS];
	char devargs[256];
	uint16_t port_id;
	int nb_tx, pkt_count;

	printf("Testing TX to pcap file\n");

	TEST_ASSERT(create_temp_path(tx_pcap_path, sizeof(tx_pcap_path),
				     "pcap_tx") == 0,
		    "Failed to create temp file path");

	snprintf(devargs, sizeof(devargs), "tx_pcap=%s", tx_pcap_path);
	TEST_ASSERT(create_pcap_vdev("net_pcap_tx", devargs, &port_id) == 0,
		    "Failed to create TX vdev");
	TEST_ASSERT(setup_pcap_port(port_id) == 0,
		    "Failed to setup TX port");
	TEST_ASSERT(alloc_test_mbufs(mbufs, NUM_PACKETS) == 0,
		    "Failed to allocate mbufs");

	nb_tx = rte_eth_tx_burst(port_id, 0, mbufs, NUM_PACKETS);
	TEST_ASSERT_EQUAL(nb_tx, NUM_PACKETS,
			  "TX burst failed: sent %d/%d", nb_tx, NUM_PACKETS);

	cleanup_pcap_vdev("net_pcap_tx", port_id);

	pkt_count = count_pcap_packets(tx_pcap_path);
	TEST_ASSERT_EQUAL(pkt_count, NUM_PACKETS,
			  "Pcap file has %d packets, expected %d",
			  pkt_count, NUM_PACKETS);

	printf("TX to file PASSED: %d packets written\n", NUM_PACKETS);
	return TEST_SUCCESS;
}

/*
 * Test: Receive packets from pcap file
 * Uses output from TX test as input
 */
static int
test_rx_from_file(void)
{
	struct rte_mbuf *mbufs[NUM_PACKETS];
	char devargs[256];
	uint16_t port_id;
	unsigned int received, i;

	printf("Testing RX from pcap file\n");

	/* Create input file if TX test didn't run */
	if (access(tx_pcap_path, F_OK) != 0) {
		TEST_ASSERT(create_temp_path(tx_pcap_path, sizeof(tx_pcap_path),
					     "pcap_rx_input") == 0,
			    "Failed to create temp path");
		TEST_ASSERT(create_test_pcap(tx_pcap_path, NUM_PACKETS) == 0,
			    "Failed to create input pcap");
	}

	snprintf(devargs, sizeof(devargs), "rx_pcap=%s", tx_pcap_path);
	TEST_ASSERT(create_pcap_vdev("net_pcap_rx", devargs, &port_id) == 0,
		    "Failed to create RX vdev");
	TEST_ASSERT(setup_pcap_port(port_id) == 0,
		    "Failed to setup RX port");

	receive_packets(port_id, mbufs, NUM_PACKETS, &received);
	TEST_ASSERT_EQUAL(received, NUM_PACKETS,
			  "Received %u packets, expected %d", received, NUM_PACKETS);

	for (i = 0; i < received; i++) {
		TEST_ASSERT(verify_packet(mbufs[i]) == 0,
			    "Packet %u verification failed", i);
	}
	rte_pktmbuf_free_bulk(mbufs, received);

	cleanup_pcap_vdev("net_pcap_rx", port_id);

	printf("RX from file PASSED: %u packets verified\n", received);
	return TEST_SUCCESS;
}

/*
 * Test: TX with varied packet sizes using packet_burst_generator
 */
static int
test_tx_varied_sizes(void)
{
	static const uint8_t test_sizes[] = {
		PKT_SIZE_MIN, PKT_SIZE_SMALL, PACKET_BURST_GEN_PKT_LEN_128
	};
	char tx_path[PATH_MAX];
	char devargs[256];
	uint16_t port_id;
	unsigned int i;

	printf("Testing TX with varied packet sizes\n");

	TEST_ASSERT(create_temp_path(tx_path, sizeof(tx_path),
				     "pcap_tx_varied") == 0,
		    "Failed to create temp file path");

	snprintf(devargs, sizeof(devargs), "tx_pcap=%s", tx_path);
	TEST_ASSERT(create_pcap_vdev("net_pcap_tx_var", devargs, &port_id) == 0,
		    "Failed to create TX vdev");
	TEST_ASSERT(setup_pcap_port(port_id) == 0,
		    "Failed to setup TX port");

	for (i = 0; i < RTE_DIM(test_sizes); i++) {
		struct rte_mbuf *mbufs[MAX_PKT_BURST];
		int nb_pkt, nb_tx;

		nb_pkt = generate_test_packets(mp, mbufs, MAX_PKT_BURST,
					       test_sizes[i]);
		TEST_ASSERT(nb_pkt > 0,
			    "Failed to generate packets of size %u",
			    test_sizes[i]);

		nb_tx = rte_eth_tx_burst(port_id, 0, mbufs, nb_pkt);
		if (nb_tx < nb_pkt)
			rte_pktmbuf_free_bulk(&mbufs[nb_tx], nb_pkt - nb_tx);

		printf("  Size %u: generated %d, transmitted %d\n",
		       test_sizes[i], nb_pkt, nb_tx);
		TEST_ASSERT(nb_tx > 0, "Failed to TX packets of size %u",
			    test_sizes[i]);
	}

	cleanup_pcap_vdev("net_pcap_tx_var", port_id);
	unlink(tx_path);

	printf("TX varied sizes PASSED\n");
	return TEST_SUCCESS;
}

/*
 * Test: RX with varied packet sizes
 */
static int
test_rx_varied_sizes(void)
{
	static const uint16_t expected_sizes[] = {
		PKT_SIZE_MIN, PKT_SIZE_SMALL, PKT_SIZE_MEDIUM,
		PKT_SIZE_LARGE, PKT_SIZE_MTU
	};
	struct rte_mbuf *mbufs[NUM_PACKETS];
	uint16_t rx_sizes[NUM_PACKETS];
	char devargs[256];
	uint16_t port_id;
	unsigned int received, i;

	printf("Testing RX with varied packet sizes\n");

	TEST_ASSERT(create_temp_path(varied_pcap_path, sizeof(varied_pcap_path),
				     "pcap_varied") == 0,
		    "Failed to create temp path");
	TEST_ASSERT(create_varied_pcap(varied_pcap_path, NUM_PACKETS) == 0,
		    "Failed to create varied pcap");

	snprintf(devargs, sizeof(devargs), "rx_pcap=%s", varied_pcap_path);
	TEST_ASSERT(create_pcap_vdev("net_pcap_var", devargs, &port_id) == 0,
		    "Failed to create varied RX vdev");
	TEST_ASSERT(setup_pcap_port(port_id) == 0,
		    "Failed to setup varied RX port");

	receive_packets(port_id, mbufs, NUM_PACKETS, &received);
	TEST_ASSERT_EQUAL(received, NUM_PACKETS,
			  "Received %u packets, expected %d", received, NUM_PACKETS);

	/* Verify packet sizes match expected pattern */
	for (i = 0; i < received; i++) {
		uint16_t expected = expected_sizes[i % RTE_DIM(expected_sizes)];
		rx_sizes[i] = rte_pktmbuf_pkt_len(mbufs[i]);
		TEST_ASSERT_EQUAL(rx_sizes[i], expected,
				  "Packet %u: size %u, expected %u",
				  i, rx_sizes[i], expected);
	}

	rte_pktmbuf_free_bulk(mbufs, received);
	cleanup_pcap_vdev("net_pcap_var", port_id);

	printf("RX varied sizes PASSED: %u packets with correct sizes\n", received);
	return TEST_SUCCESS;
}

/*
 * Test: Infinite RX mode - loops through pcap file continuously
 */
static int
test_infinite_rx(void)
{
	struct rte_mbuf *mbufs[MAX_PKT_BURST];
	char devargs[256];
	uint16_t port_id;
	unsigned int total_rx = 0;
	int iter, attempts;

	printf("Testing infinite RX mode\n");

	TEST_ASSERT(create_temp_path(infinite_pcap_path, sizeof(infinite_pcap_path),
				     "pcap_inf") == 0,
		    "Failed to create temp path");
	TEST_ASSERT(create_test_pcap(infinite_pcap_path, NUM_PACKETS) == 0,
		    "Failed to create input pcap");

	snprintf(devargs, sizeof(devargs),
		 "rx_pcap=%s,infinite_rx=1", infinite_pcap_path);
	TEST_ASSERT(create_pcap_vdev("net_pcap_inf", devargs, &port_id) == 0,
		    "Failed to create infinite RX vdev");
	TEST_ASSERT(setup_pcap_port(port_id) == 0,
		    "Failed to setup infinite RX port");

	/* Read more packets than file contains to verify looping */
	for (iter = 0; iter < 3 && total_rx < NUM_PACKETS * 2; iter++) {
		for (attempts = 0; attempts < 100 && total_rx < NUM_PACKETS * 2;
		     attempts++) {
			uint16_t nb_rx = rte_eth_rx_burst(port_id, 0, mbufs,
							  MAX_PKT_BURST);
			if (nb_rx > 0)
				rte_pktmbuf_free_bulk(mbufs, nb_rx);
			total_rx += nb_rx;
			if (nb_rx == 0)
				usleep(100);
		}
	}

	cleanup_pcap_vdev("net_pcap_inf", port_id);

	TEST_ASSERT(total_rx >= NUM_PACKETS * 2,
		    "Infinite RX: got %u packets, need >= %d",
		    total_rx, NUM_PACKETS * 2);

	printf("Infinite RX PASSED: %u packets (file has %d)\n",
	       total_rx, NUM_PACKETS);
	return TEST_SUCCESS;
}

/*
 * Test: TX drop mode - packets dropped when no tx_pcap specified
 */
static int
test_tx_drop(void)
{
	struct rte_mbuf *mbufs[NUM_PACKETS];
	struct rte_eth_stats stats;
	char devargs[256];
	uint16_t port_id;
	int nb_tx;

	printf("Testing TX drop mode\n");

	TEST_ASSERT(create_temp_path(rx_pcap_path, sizeof(rx_pcap_path),
				     "pcap_drop") == 0,
		    "Failed to create temp path");
	TEST_ASSERT(create_test_pcap(rx_pcap_path, NUM_PACKETS) == 0,
		    "Failed to create input pcap");

	/* Only rx_pcap - TX should silently drop */
	snprintf(devargs, sizeof(devargs), "rx_pcap=%s", rx_pcap_path);
	TEST_ASSERT(create_pcap_vdev("net_pcap_drop", devargs, &port_id) == 0,
		    "Failed to create drop vdev");
	TEST_ASSERT(setup_pcap_port(port_id) == 0,
		    "Failed to setup drop port");
	TEST_ASSERT(alloc_test_mbufs(mbufs, NUM_PACKETS) == 0,
		    "Failed to allocate mbufs");

	TEST_ASSERT(rte_eth_stats_reset(port_id) == 0,
		    "Failed to reset stats");
	nb_tx = rte_eth_tx_burst(port_id, 0, mbufs, NUM_PACKETS);

	/* Packets should be accepted even in drop mode */
	TEST_ASSERT_EQUAL(nb_tx, NUM_PACKETS,
			  "Drop mode TX: %d/%d accepted", nb_tx, NUM_PACKETS);

	TEST_ASSERT(rte_eth_stats_get(port_id, &stats) == 0,
		    "Failed to get stats");
	cleanup_pcap_vdev("net_pcap_drop", port_id);

	printf("TX drop PASSED: %d packets dropped, opackets=%" PRIu64"\n",
	       nb_tx, stats.opackets);
	return TEST_SUCCESS;
}

/*
 * Test: Statistics accuracy and reset
 */
static int
test_stats(void)
{
	struct rte_mbuf *mbufs[NUM_PACKETS];
	struct rte_eth_stats stats;
	char devargs[256];
	char stats_tx_path[PATH_MAX];
	uint16_t port_id;
	unsigned int received;
	int nb_tx;

	printf("Testing statistics accuracy\n");

	TEST_ASSERT(create_temp_path(rx_pcap_path, sizeof(rx_pcap_path),
				     "pcap_stats_rx") == 0,
		    "Failed to create RX temp path");
	TEST_ASSERT(create_temp_path(stats_tx_path, sizeof(stats_tx_path),
				     "pcap_stats_tx") == 0,
		    "Failed to create TX temp path");
	TEST_ASSERT(create_test_pcap(rx_pcap_path, NUM_PACKETS) == 0,
		    "Failed to create input pcap");

	snprintf(devargs, sizeof(devargs),
		 "rx_pcap=%s,tx_pcap=%s", rx_pcap_path, stats_tx_path);
	TEST_ASSERT(create_pcap_vdev("net_pcap_stats", devargs, &port_id) == 0,
		    "Failed to create stats vdev");
	TEST_ASSERT(setup_pcap_port(port_id) == 0,
		    "Failed to setup stats port");

	/* Verify stats start at zero */
	TEST_ASSERT(rte_eth_stats_reset(port_id) == 0,
		    "Failed to reset stats");
	TEST_ASSERT(rte_eth_stats_get(port_id, &stats) == 0,
		    "Failed to get stats");
	TEST_ASSERT(stats.ipackets == 0 && stats.opackets == 0 &&
		    stats.ibytes == 0 && stats.obytes == 0,
		    "Initial stats not zero");

	/* RX and verify stats */
	receive_packets(port_id, mbufs, NUM_PACKETS, &received);
	TEST_ASSERT(rte_eth_stats_get(port_id, &stats) == 0,
		    "Failed to get stats after RX");
	TEST_ASSERT_EQUAL(stats.ipackets, received,
			  "RX stats: ipackets=%"PRIu64", received=%u",
			  stats.ipackets, received);

	/* TX and verify stats */
	nb_tx = rte_eth_tx_burst(port_id, 0, mbufs, received);
	TEST_ASSERT(rte_eth_stats_get(port_id, &stats) == 0,
		    "Failed to get stats after TX");
	TEST_ASSERT_EQUAL(stats.opackets, (uint64_t)nb_tx,
			  "TX stats: opackets=%"PRIu64", sent=%u",
			  stats.opackets, nb_tx);

	/* Verify stats reset */
	TEST_ASSERT(rte_eth_stats_reset(port_id) == 0,
		    "Failed to reset stats");
	TEST_ASSERT(rte_eth_stats_get(port_id, &stats) == 0,
		    "Failed to get stats after reset");
	TEST_ASSERT(stats.ipackets == 0 && stats.opackets == 0,
		    "Stats not reset to zero");

	cleanup_pcap_vdev("net_pcap_stats", port_id);
	unlink(stats_tx_path);

	printf("Statistics PASSED: RX=%u, TX=%d\n", received, nb_tx);
	return TEST_SUCCESS;
}

/*
 * Test: MTU configuration
 */
static int
test_set_mtu(void)
{
	char devargs[256];
	char mtu_tx_path[PATH_MAX];
	uint16_t port_id;
	static const uint16_t mtu_values[] = {1500, 9000, 1280};
	int ret = 0;
	size_t i;

	printf("Testing MTU configuration\n");

	TEST_ASSERT(create_temp_path(rx_pcap_path, sizeof(rx_pcap_path),
				     "pcap_mtu_rx") == 0,
		    "Failed to create RX temp path");
	TEST_ASSERT(create_temp_path(mtu_tx_path, sizeof(mtu_tx_path),
				     "pcap_mtu_tx") == 0,
		    "Failed to create TX temp path");
	TEST_ASSERT(create_test_pcap(rx_pcap_path, 1) == 0,
		    "Failed to create input pcap");

	snprintf(devargs, sizeof(devargs),
		 "rx_pcap=%s,tx_pcap=%s", rx_pcap_path, mtu_tx_path);
	TEST_ASSERT(create_pcap_vdev("net_pcap_mtu", devargs, &port_id) == 0,
		    "Failed to create MTU vdev");
	TEST_ASSERT(setup_pcap_port(port_id) == 0,
		    "Failed to setup MTU port");

	for (i = 0; i < RTE_DIM(mtu_values); i++) {
		uint16_t mtu;

		ret = rte_eth_dev_set_mtu(port_id, mtu_values[i]);
		if (ret != 0)
			break;

		TEST_ASSERT(rte_eth_dev_get_mtu(port_id, &mtu) == 0, "Failed to get MTU");
		TEST_ASSERT_EQUAL(mtu, mtu_values[i], "MTU set mismatch for %u", mtu_values[i]);
	}

	cleanup_pcap_vdev("net_pcap_mtu", port_id);
	unlink(mtu_tx_path);

	if (ret == 0) {
		printf("MTU test completed\n");
		return TEST_SUCCESS;
	}

	if (ret == -ENOTSUP) {
		printf("MTU set not supported\n");
		return TEST_SKIPPED;
	}

	printf("Failed to set MTU: %s", strerror(-ret));
	return TEST_FAILED;
}

/*
 * Test: Jumbo frame RX (multi-segment mbufs)
 */
static int
test_jumbo_rx(void)
{
	struct rte_mbuf *mbufs[NUM_PACKETS];
	char devargs[256];
	uint16_t port_id;
	unsigned int received, i;
	const unsigned int num_jumbo = 16;

	printf("Testing jumbo frame RX (%u byte packets, multi-segment)\n",
	       PKT_SIZE_JUMBO);

	TEST_ASSERT(create_temp_path(jumbo_pcap_path, sizeof(jumbo_pcap_path),
				     "pcap_jumbo") == 0,
		    "Failed to create temp path");
	TEST_ASSERT(create_sized_pcap(jumbo_pcap_path, num_jumbo,
				      PKT_SIZE_JUMBO) == 0,
		    "Failed to create jumbo pcap");

	snprintf(devargs, sizeof(devargs), "rx_pcap=%s", jumbo_pcap_path);
	TEST_ASSERT(create_pcap_vdev("net_pcap_jumbo", devargs, &port_id) == 0,
		    "Failed to create jumbo RX vdev");
	TEST_ASSERT(setup_pcap_port(port_id) == 0,
		    "Failed to setup jumbo RX port");

	receive_packets(port_id, mbufs, num_jumbo, &received);
	TEST_ASSERT_EQUAL(received, num_jumbo,
			  "Received %u packets, expected %u", received, num_jumbo);

	/* Verify all packets are jumbo size (may be multi-segment) */
	for (i = 0; i < received; i++) {
		uint32_t pkt_len = rte_pktmbuf_pkt_len(mbufs[i]);
		uint16_t nb_segs = mbufs[i]->nb_segs;

		TEST_ASSERT_EQUAL(pkt_len, PKT_SIZE_JUMBO,
				  "Packet %u: size %u, expected %u",
				  i, pkt_len, PKT_SIZE_JUMBO);

		/* Jumbo frames should use multiple segments */
		if (nb_segs > 1)
			printf("  Packet %u: %u segments\n", i, nb_segs);
	}

	rte_pktmbuf_free_bulk(mbufs, received);
	cleanup_pcap_vdev("net_pcap_jumbo", port_id);

	printf("Jumbo RX PASSED: %u jumbo packets received\n", received);
	return TEST_SUCCESS;
}

/*
 * Test: Jumbo frame TX (multi-segment mbufs)
 */
static int
test_jumbo_tx(void)
{
	struct rte_mbuf *mbufs[MAX_PKT_BURST];
	char tx_path[PATH_MAX];
	char devargs[256];
	uint16_t port_id;
	uint16_t sizes[MAX_PKT_BURST];
	int nb_tx, pkt_count, ret;
	unsigned int i;
	const unsigned int num_jumbo = 8;

	printf("Testing jumbo frame TX (multi-segment mbufs)\n");

	TEST_ASSERT(create_temp_path(tx_path, sizeof(tx_path),
				     "pcap_jumbo_tx") == 0,
		    "Failed to create temp file path");

	snprintf(devargs, sizeof(devargs), "tx_pcap=%s", tx_path);
	TEST_ASSERT(create_pcap_vdev("net_pcap_jumbo_tx", devargs, &port_id) == 0,
		    "Failed to create TX vdev");
	TEST_ASSERT(setup_pcap_port(port_id) == 0,
		    "Failed to setup TX port");

	/* Set MTU to allow jumbo frames - PMD drops packets exceeding MTU */
	ret = rte_eth_dev_set_mtu(port_id, PKT_SIZE_JUMBO);
	if (ret != 0) {
		printf("Failed to set MTU to %u: %s\n",
		       PKT_SIZE_JUMBO, rte_strerror(-ret));
		cleanup_pcap_vdev("net_pcap_jumbo_tx", port_id);
		unlink(tx_path);
		return TEST_SKIPPED;
	}

	/* Allocate multi-segment mbufs for jumbo frames */
	for (i = 0; i < num_jumbo; i++) {
		mbufs[i] = alloc_jumbo_mbuf(PKT_SIZE_JUMBO, (uint8_t)(i & 0xFF));
		if (mbufs[i] == NULL) {
			/* Free already allocated mbufs */
			while (i > 0)
				rte_pktmbuf_free(mbufs[--i]);
			cleanup_pcap_vdev("net_pcap_jumbo_tx", port_id);
			unlink(tx_path);
			return TEST_FAILED;
		}
		printf("  Packet %u: %u segments for %u bytes\n",
		       i, mbufs[i]->nb_segs, PKT_SIZE_JUMBO);
	}

	nb_tx = rte_eth_tx_burst(port_id, 0, mbufs, num_jumbo);
	/* Free any unsent mbufs */
	for (i = nb_tx; i < num_jumbo; i++)
		rte_pktmbuf_free(mbufs[i]);

	TEST_ASSERT_EQUAL(nb_tx, (int)num_jumbo,
			  "TX burst failed: sent %d/%u", nb_tx, num_jumbo);

	cleanup_pcap_vdev("net_pcap_jumbo_tx", port_id);

	/* Verify pcap file has correct packet count and sizes */
	pkt_count = get_pcap_packet_sizes(tx_path, sizes, MAX_PKT_BURST);
	TEST_ASSERT_EQUAL(pkt_count, (int)num_jumbo,
			  "Pcap file has %d packets, expected %u",
			  pkt_count, num_jumbo);

	for (i = 0; i < (unsigned int)pkt_count; i++) {
		TEST_ASSERT_EQUAL(sizes[i], PKT_SIZE_JUMBO,
				  "Packet %u: size %u, expected %u",
				  i, sizes[i], PKT_SIZE_JUMBO);
	}

	unlink(tx_path);

	printf("Jumbo TX PASSED: %d jumbo packets written\n", nb_tx);
	return TEST_SUCCESS;
}

/*
 * Test: Layering on Linux network interface
 */
static int
test_iface(void)
{
	struct rte_mbuf *mbufs[MAX_PKT_BURST];
	struct rte_eth_dev_info dev_info;
	char devargs[256];
	uint16_t port_id;
	const char *iface;
	int ret, nb_tx, nb_pkt;

	printf("Testing pcap on network interface\n");

	iface = find_test_iface();
	if (iface == NULL) {
		printf("No suitable interface, skipping\n");
		return TEST_SKIPPED;
	}
	printf("Using interface: %s\n", iface);

	snprintf(devargs, sizeof(devargs), "iface=%s", iface);
	if (rte_vdev_init("net_pcap_iface", devargs) < 0) {
		printf("Cannot create iface vdev (needs root?), skipping\n");
		return TEST_SKIPPED;
	}

	TEST_ASSERT(rte_eth_dev_get_port_by_name("net_pcap_iface",
						 &port_id) == 0,
		    "Failed to get iface port ID");
	TEST_ASSERT(setup_pcap_port(port_id) == 0,
		    "Failed to setup iface port");

	ret = rte_eth_dev_info_get(port_id, &dev_info);
	TEST_ASSERT(ret == 0, "Failed to get dev info: %s", rte_strerror(-ret));

	printf("Driver: %s, max_rx_queues=%u, max_tx_queues=%u\n",
	       dev_info.driver_name, dev_info.max_rx_queues,
	       dev_info.max_tx_queues);

	/* Use packet_burst_generator for interface test */
	nb_pkt = generate_test_packets(mp, mbufs, MAX_PKT_BURST,
				       PACKET_BURST_GEN_PKT_LEN);
	TEST_ASSERT(nb_pkt > 0, "Failed to generate packets");

	nb_tx = rte_eth_tx_burst(port_id, 0, mbufs, nb_pkt);
	if (nb_tx < nb_pkt)
		rte_pktmbuf_free_bulk(&mbufs[nb_tx], nb_pkt - nb_tx);

	cleanup_pcap_vdev("net_pcap_iface", port_id);

	printf("Interface test PASSED: sent %d packets\n", nb_tx);
	return TEST_SUCCESS;
}

/*
 * Test: MAC address with phy_mac option
 */
static int
test_mac_address(void)
{
	struct rte_ether_addr orig_mac, new_mac, read_mac;
	char devargs[256];
	uint16_t port_id;
	const char *iface;
	int ret;

	printf("Testing MAC address configuration\n");

	iface = find_test_iface();
	if (iface == NULL) {
		printf("No suitable interface, skipping\n");
		return TEST_SKIPPED;
	}

	if (strcmp(iface, "lo") == 0) {
		printf("Need dummy interface to test setting mac address\n");
		return TEST_SKIPPED;
	}

	snprintf(devargs, sizeof(devargs), "iface=%s,phy_mac=1", iface);
	if (rte_vdev_init("net_pcap_mac", devargs) < 0) {
		printf("Cannot create mac vdev (needs root?), skipping\n");
		return TEST_SKIPPED;
	}

	TEST_ASSERT(rte_eth_dev_get_port_by_name("net_pcap_mac", &port_id) == 0,
		    "Failed to get mac port ID");
	TEST_ASSERT(setup_pcap_port(port_id) == 0,
		    "Failed to setup mac port");

	ret = rte_eth_macaddr_get(port_id, &orig_mac);
	TEST_ASSERT(ret == 0, "Failed to get original MAC");
	printf("Original MAC: " RTE_ETHER_ADDR_PRT_FMT "\n",
	       RTE_ETHER_ADDR_BYTES(&orig_mac));

	/* Try to set a new MAC */
	rte_eth_random_addr(new_mac.addr_bytes);

	ret = rte_eth_dev_default_mac_addr_set(port_id, &new_mac);
	if (ret == 0) {
		rte_eth_macaddr_get(port_id, &read_mac);
		printf("New MAC: " RTE_ETHER_ADDR_PRT_FMT "\n",
		       RTE_ETHER_ADDR_BYTES(&read_mac));
		/* Restore original */
		rte_eth_dev_default_mac_addr_set(port_id, &orig_mac);
		ret = TEST_SUCCESS;
	} else if (ret == -ENOTSUP) {
		printf("MAC change not supported\n");
		ret = TEST_SKIPPED;
	} else {
		printf("MAC change failed: %s\n", rte_strerror(-ret));
		ret = TEST_FAILED;
	}

	cleanup_pcap_vdev("net_pcap_mac", port_id);

	printf("MAC address test completed\n");
	return ret;
}

/*
 * Test: Verify receive timestamps from pcap file
 */
static int
test_rx_timestamp(void)
{
	struct rte_mbuf *mbufs[NUM_PACKETS];
	char devargs[256];
	uint16_t port_id;
	unsigned int received, i;
	const uint32_t base_sec = 1000;
	const uint32_t usec_increment = 10000; /* 10ms between packets */
	rte_mbuf_timestamp_t prev_ts = 0;

	printf("Testing RX timestamp accuracy\n");

	TEST_ASSERT(create_temp_path(timestamp_pcap_path, sizeof(timestamp_pcap_path),
				     "pcap_ts") == 0,
		    "Failed to create temp path");
	TEST_ASSERT(create_timestamped_pcap(timestamp_pcap_path, NUM_PACKETS,
					    base_sec, usec_increment) == 0,
		    "Failed to create timestamped pcap");

	snprintf(devargs, sizeof(devargs), "rx_pcap=%s", timestamp_pcap_path);
	TEST_ASSERT(create_pcap_vdev("net_pcap_ts", devargs, &port_id) == 0,
		    "Failed to create timestamp vdev");
	TEST_ASSERT(setup_pcap_port(port_id) == 0,
		    "Failed to setup timestamp port");

	/* Try to initialize timestamp dynamic field access */
	TEST_ASSERT(timestamp_init() == 0, "Timestamp dynfield not available");

	receive_packets(port_id, mbufs, NUM_PACKETS, &received);
	TEST_ASSERT_EQUAL(received, NUM_PACKETS,
			  "Received %u packets, expected %d", received, NUM_PACKETS);

	/* Check if first packet has timestamp flag set */
	if (!mbuf_has_timestamp(mbufs[0])) {
		printf("Timestamps not enabled in mbufs, skipping validation\n");
		rte_pktmbuf_free_bulk(mbufs, received);
		cleanup_pcap_vdev("net_pcap_ts", port_id);
		return TEST_SUCCESS;
	}

	for (i = 0; i < received; i++) {
		struct rte_mbuf *m = mbufs[i];

		TEST_ASSERT(mbuf_has_timestamp(m),
			    "Packet %u missing timestamp flag", i);

		/* PCAP PMD stores timestamp in nanoseconds */
		rte_mbuf_timestamp_t ts = mbuf_timestamp_get(mbufs[i]);
		uint64_t expected = (uint64_t)base_sec * NS_PER_S
			+ (uint64_t)i * usec_increment * 1000;

		if (ts != expected)
			printf("Packet %u: timestamp mismatch, expected=%"PRIu64" actual=%"PRIu64"\n",
			       i, expected, ts);

		/* Verify monotonically increasing timestamps */
		if (i > 0) {
			TEST_ASSERT(ts >= prev_ts,
				    "Packet %u: timestamp not monotonic %"PRIu64" > %"PRIu64,
				    i, prev_ts, ts);
		}
		prev_ts = ts;
	}

	rte_pktmbuf_free_bulk(mbufs, received);
	cleanup_pcap_vdev("net_pcap_ts", port_id);

	printf("RX timestamp PASSED: %u packets with valid timestamps\n", received);
	return TEST_SUCCESS;
}

/* Helper: Generate packets for multi-queue tests */
static int
generate_mq_test_packets(struct rte_mbuf **pkts, unsigned int nb_pkts, uint16_t queue_id)
{
	struct rte_ether_hdr eth_hdr;
	struct rte_ipv4_hdr ip_hdr;
	struct rte_udp_hdr udp_hdr;
	uint16_t pkt_data_len;
	unsigned int i;

	initialize_eth_header(&eth_hdr, &src_mac, &dst_mac, RTE_ETHER_TYPE_IPV4, 0, 0);
	pkt_data_len = sizeof(struct rte_udp_hdr);
	initialize_udp_header(&udp_hdr, 1234, 1234, pkt_data_len);
	initialize_ipv4_header(&ip_hdr, IPV4_ADDR(192, 168, 1, 1), IPV4_ADDR(192, 168, 1, 2),
			       pkt_data_len + sizeof(struct rte_udp_hdr));

	for (i = 0; i < nb_pkts; i++) {
		pkts[i] = rte_pktmbuf_alloc(mp);
		if (pkts[i] == NULL) {
			printf("Failed to allocate mbuf\n");
			while (i > 0)
				rte_pktmbuf_free(pkts[--i]);
			return -1;
		}

		char *pkt_data = rte_pktmbuf_append(pkts[i], PACKET_BURST_GEN_PKT_LEN);
		if (pkt_data == NULL) {
			printf("Failed to append data to mbuf\n");
			rte_pktmbuf_free(pkts[i]);
			while (i > 0)
				rte_pktmbuf_free(pkts[--i]);
			return -1;
		}

		size_t offset = 0;
		memcpy(pkt_data + offset, &eth_hdr, sizeof(eth_hdr));
		offset += sizeof(eth_hdr);

		/* Mark packet with queue ID in IP packet_id field for tracing */
		ip_hdr.packet_id = rte_cpu_to_be_16((queue_id << 8) | (i & 0xFF));
		ip_hdr.hdr_checksum = 0;
		ip_hdr.hdr_checksum = rte_ipv4_cksum(&ip_hdr);

		memcpy(pkt_data + offset, &ip_hdr, sizeof(ip_hdr));
		offset += sizeof(ip_hdr);
		memcpy(pkt_data + offset, &udp_hdr, sizeof(udp_hdr));
	}
	return (int)nb_pkts;
}

/* Helper: Validate pcap file structure using libpcap */
static int
validate_pcap_file(const char *filename)
{
	pcap_t *pcap;
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap = pcap_open_offline(filename, errbuf);
	if (pcap == NULL) {
		printf("Failed to validate pcap file %s: %s\n", filename, errbuf);
		return -1;
	}
	if (pcap_datalink(pcap) != DLT_EN10MB) {
		printf("Unexpected datalink type: %d\n", pcap_datalink(pcap));
		pcap_close(pcap);
		return -1;
	}
	pcap_close(pcap);
	return 0;
}

/*
 * Test: Multiple TX queues writing to separate pcap files
 *
 * This test creates a pcap PMD with multiple TX queues, each configured
 * to write to its own output file. We verify that:
 * 1. All packets from all queues are written
 * 2. Each resulting pcap file is valid
 * 3. Each file has the expected packet count
 */
static int
test_multi_tx_queue(void)
{
	char devargs[512];
	uint16_t port_id;
	struct rte_eth_conf port_conf;
	struct rte_eth_txconf tx_conf;
	struct rte_mbuf *pkts[MULTI_QUEUE_BURST_SIZE];
	uint16_t q;
	int ret;
	unsigned int total_tx = 0;
	unsigned int tx_per_queue[MULTI_QUEUE_NUM_QUEUES] = {0};

	printf("Testing multiple TX queues to separate files\n");

	/* Create temp paths for each TX queue */
	for (q = 0; q < MULTI_QUEUE_NUM_QUEUES; q++) {
		char prefix[32];
		snprintf(prefix, sizeof(prefix), "pcap_multi_tx%u", q);
		TEST_ASSERT(create_temp_path(multi_tx_pcap_paths[q],
					     sizeof(multi_tx_pcap_paths[q]), prefix) == 0,
			    "Failed to create temp path for queue %u", q);
	}

	/* Create the pcap PMD with multiple TX queues to separate files */
	snprintf(devargs, sizeof(devargs), "tx_pcap=%s,tx_pcap=%s,tx_pcap=%s,tx_pcap=%s",
		 multi_tx_pcap_paths[0], multi_tx_pcap_paths[1],
		 multi_tx_pcap_paths[2], multi_tx_pcap_paths[3]);

	ret = rte_vdev_init("net_pcap_multi_tx", devargs);
	TEST_ASSERT_SUCCESS(ret, "Failed to create pcap PMD: %s", rte_strerror(-ret));

	ret = rte_eth_dev_get_port_by_name("net_pcap_multi_tx", &port_id);
	TEST_ASSERT_SUCCESS(ret, "Cannot find added pcap device");

	memset(&port_conf, 0, sizeof(port_conf));
	ret = rte_eth_dev_configure(port_id, 0, MULTI_QUEUE_NUM_QUEUES, &port_conf);
	TEST_ASSERT_SUCCESS(ret, "Failed to configure device: %s", rte_strerror(-ret));

	memset(&tx_conf, 0, sizeof(tx_conf));
	for (q = 0; q < MULTI_QUEUE_NUM_QUEUES; q++) {
		ret = rte_eth_tx_queue_setup(port_id, q, RING_SIZE,
					     rte_eth_dev_socket_id(port_id), &tx_conf);
		TEST_ASSERT_SUCCESS(ret, "Failed to setup TX queue %u: %s", q, rte_strerror(-ret));
	}

	ret = rte_eth_dev_start(port_id);
	TEST_ASSERT_SUCCESS(ret, "Failed to start device: %s", rte_strerror(-ret));

	/* Transmit packets from each queue */
	for (q = 0; q < MULTI_QUEUE_NUM_QUEUES; q++) {
		unsigned int pkts_to_send = MULTI_QUEUE_NUM_PACKETS / MULTI_QUEUE_NUM_QUEUES;

		while (tx_per_queue[q] < pkts_to_send) {
			unsigned int burst = RTE_MIN(MULTI_QUEUE_BURST_SIZE,
						     pkts_to_send - tx_per_queue[q]);

			ret = generate_mq_test_packets(pkts, burst, q);
			TEST_ASSERT(ret >= 0, "Failed to generate packets for queue %u", q);

			uint16_t nb_tx = rte_eth_tx_burst(port_id, q, pkts, burst);
			for (unsigned int i = nb_tx; i < burst; i++)
				rte_pktmbuf_free(pkts[i]);

			tx_per_queue[q] += nb_tx;
			total_tx += nb_tx;

			if (nb_tx == 0) {
				printf("TX stall on queue %u\n", q);
				break;
			}
		}
		printf("  Queue %u: transmitted %u packets\n", q, tx_per_queue[q]);
	}

	rte_eth_dev_stop(port_id);
	rte_vdev_uninit("net_pcap_multi_tx");
	rte_delay_ms(100);

	/* Validate each pcap file */
	unsigned int total_in_files = 0;
	for (q = 0; q < MULTI_QUEUE_NUM_QUEUES; q++) {
		ret = validate_pcap_file(multi_tx_pcap_paths[q]);
		TEST_ASSERT_SUCCESS(ret, "pcap file for queue %u is invalid", q);

		int pkt_count = count_pcap_packets(multi_tx_pcap_paths[q]);
		TEST_ASSERT(pkt_count >= 0, "Could not count packets in pcap file for queue %u", q);

		printf("  Queue %u file: %d packets\n", q, pkt_count);
		TEST_ASSERT_EQUAL((unsigned int)pkt_count, tx_per_queue[q],
				  "Queue %u: file has %d packets, expected %u",
				  q, pkt_count, tx_per_queue[q]);
		total_in_files += pkt_count;
	}

	printf("  Total packets transmitted: %u\n", total_tx);
	printf("  Total packets in all files: %u\n", total_in_files);

	TEST_ASSERT_EQUAL(total_in_files, total_tx,
			  "Total packet count mismatch: expected %u, got %u", total_tx, total_in_files);

	printf("Multi-TX queue PASSED\n");
	return TEST_SUCCESS;
}

/*
 * Test: Multiple RX queues reading from the same pcap file
 *
 * This test creates a pcap PMD with multiple RX queues all configured
 * to read from the same input file. We verify that:
 * 1. Each queue can read packets
 * 2. The total packets read equals the file content (or expected behavior)
 */
static int
test_multi_rx_queue_same_file(void)
{
	char devargs[512];
	uint16_t port_id;
	struct rte_eth_conf port_conf;
	struct rte_eth_rxconf rx_conf;
	struct rte_mbuf *pkts[MULTI_QUEUE_BURST_SIZE];
	uint16_t q;
	int ret;
	unsigned int total_rx = 0;
	unsigned int rx_per_queue[MULTI_QUEUE_NUM_QUEUES] = {0};
	unsigned int seed_packets = MULTI_QUEUE_NUM_PACKETS;
	unsigned int expected_total;

	printf("Testing multiple RX queues from same file\n");

	TEST_ASSERT(create_temp_path(multi_rx_pcap_path, sizeof(multi_rx_pcap_path),
				     "pcap_multi_rx") == 0, "Failed to create temp path");

	ret = create_test_pcap(multi_rx_pcap_path, seed_packets);
	TEST_ASSERT_SUCCESS(ret, "Failed to create seed pcap file");
	printf("  Created seed pcap file with %u packets\n", seed_packets);

	snprintf(devargs, sizeof(devargs), "rx_pcap=%s,rx_pcap=%s,rx_pcap=%s,rx_pcap=%s",
		 multi_rx_pcap_path, multi_rx_pcap_path, multi_rx_pcap_path, multi_rx_pcap_path);

	ret = rte_vdev_init("net_pcap_multi_rx", devargs);
	TEST_ASSERT_SUCCESS(ret, "Failed to create pcap PMD: %s", rte_strerror(-ret));

	ret = rte_eth_dev_get_port_by_name("net_pcap_multi_rx", &port_id);
	TEST_ASSERT_SUCCESS(ret, "Cannot find added pcap device");

	memset(&port_conf, 0, sizeof(port_conf));
	ret = rte_eth_dev_configure(port_id, MULTI_QUEUE_NUM_QUEUES, 0, &port_conf);
	TEST_ASSERT_SUCCESS(ret, "Failed to configure device: %s", rte_strerror(-ret));

	memset(&rx_conf, 0, sizeof(rx_conf));
	for (q = 0; q < MULTI_QUEUE_NUM_QUEUES; q++) {
		ret = rte_eth_rx_queue_setup(port_id, q, RING_SIZE,
					     rte_eth_dev_socket_id(port_id), &rx_conf, mp);
		TEST_ASSERT_SUCCESS(ret, "Failed to setup RX queue %u: %s", q, rte_strerror(-ret));
	}

	ret = rte_eth_dev_start(port_id);
	TEST_ASSERT_SUCCESS(ret, "Failed to start device: %s", rte_strerror(-ret));

	/* Receive packets from all queues. Each queue has its own file handle. */
	int empty_rounds = 0;
	while (empty_rounds < 10) {
		int received_this_round = 0;
		for (q = 0; q < MULTI_QUEUE_NUM_QUEUES; q++) {
			uint16_t nb_rx = rte_eth_rx_burst(port_id, q, pkts, MULTI_QUEUE_BURST_SIZE);
			if (nb_rx > 0) {
				rx_per_queue[q] += nb_rx;
				total_rx += nb_rx;
				received_this_round += nb_rx;
				rte_pktmbuf_free_bulk(pkts, nb_rx);
			}
		}
		if (received_this_round == 0)
			empty_rounds++;
		else
			empty_rounds = 0;
	}

	printf("  RX Results:\n");
	for (q = 0; q < MULTI_QUEUE_NUM_QUEUES; q++)
		printf("    Queue %u: received %u packets\n", q, rx_per_queue[q]);
	printf("    Total received: %u packets\n", total_rx);

	/* Each RX queue opens its own file handle, so each reads all packets */
	expected_total = seed_packets * MULTI_QUEUE_NUM_QUEUES;
	printf("    Expected total (each queue reads all): %u packets\n", expected_total);

	rte_eth_dev_stop(port_id);
	rte_vdev_uninit("net_pcap_multi_rx");

	TEST_ASSERT(total_rx > 0, "No packets received at all");
	for (q = 0; q < MULTI_QUEUE_NUM_QUEUES; q++) {
		TEST_ASSERT(rx_per_queue[q] > 0, "Queue %u received no packets", q);
		TEST_ASSERT_EQUAL(rx_per_queue[q], seed_packets,
				  "Queue %u received %u packets, expected %u",
				  q, rx_per_queue[q], seed_packets);
	}
	TEST_ASSERT_EQUAL(total_rx, expected_total,
			  "Total RX mismatch: expected %u, got %u", expected_total, total_rx);

	printf("Multi-RX queue PASSED\n");
	return TEST_SUCCESS;
}

/*
 * Test: Device info reports correct queue counts and MTU limits
 *
 * This test verifies that rte_eth_dev_info_get() returns correct values:
 * 1. max_rx_queues matches the number of rx_pcap files passed
 * 2. max_tx_queues matches the number of tx_pcap files passed
 * 3. min_mtu and max_mtu are set to reasonable values
 */
static int
test_dev_info(void)
{
	struct rte_eth_dev_info dev_info;
	char devargs[512];
	char rx_paths[3][PATH_MAX];
	char tx_paths[2][PATH_MAX];
	uint16_t port_id;
	int ret;
	unsigned int i;

	printf("Testing device info reporting\n");

	/* Create temp RX pcap files (3 queues) */
	for (i = 0; i < 3; i++) {
		char prefix[32];
		snprintf(prefix, sizeof(prefix), "pcap_devinfo_rx%u", i);
		TEST_ASSERT(create_temp_path(rx_paths[i], sizeof(rx_paths[i]), prefix) == 0,
			    "Failed to create RX temp path %u", i);
		TEST_ASSERT(create_test_pcap(rx_paths[i], 1) == 0, "Failed to create RX pcap %u", i);
	}

	/* Create temp TX pcap files (2 queues) */
	for (i = 0; i < 2; i++) {
		char prefix[32];
		snprintf(prefix, sizeof(prefix), "pcap_devinfo_tx%u", i);
		TEST_ASSERT(create_temp_path(tx_paths[i], sizeof(tx_paths[i]), prefix) == 0,
			    "Failed to create TX temp path %u", i);
	}

	/* Create device with 3 RX queues and 2 TX queues */
	snprintf(devargs, sizeof(devargs), "rx_pcap=%s,rx_pcap=%s,rx_pcap=%s,tx_pcap=%s,tx_pcap=%s",
		 rx_paths[0], rx_paths[1], rx_paths[2], tx_paths[0], tx_paths[1]);

	ret = rte_vdev_init("net_pcap_devinfo", devargs);
	TEST_ASSERT_SUCCESS(ret, "Failed to create pcap PMD: %s", rte_strerror(-ret));

	ret = rte_eth_dev_get_port_by_name("net_pcap_devinfo", &port_id);
	TEST_ASSERT_SUCCESS(ret, "Cannot find added pcap device");

	ret = rte_eth_dev_info_get(port_id, &dev_info);
	TEST_ASSERT_SUCCESS(ret, "Failed to get device info: %s", rte_strerror(-ret));

	printf("  Device info:\n");
	printf("    driver_name: %s\n", dev_info.driver_name);
	printf("    max_rx_queues: %u (expected: 3)\n", dev_info.max_rx_queues);
	printf("    max_tx_queues: %u (expected: 2)\n", dev_info.max_tx_queues);
	printf("    min_mtu: %u\n", dev_info.min_mtu);
	printf("    max_mtu: %u\n", dev_info.max_mtu);

	/* Verify queue counts match number of pcap files */
	TEST_ASSERT_EQUAL(dev_info.max_rx_queues, 3U,
			  "max_rx_queues mismatch: expected 3, got %u", dev_info.max_rx_queues);
	TEST_ASSERT_EQUAL(dev_info.max_tx_queues, 2U,
			  "max_tx_queues mismatch: expected 2, got %u", dev_info.max_tx_queues);

	/* Verify MTU limits are reasonable */
	TEST_ASSERT(dev_info.min_mtu > 0, "min_mtu should be > 0, got %u", dev_info.min_mtu);
	TEST_ASSERT(dev_info.min_mtu <= RTE_ETHER_MIN_MTU,
		    "min_mtu should be <= %u, got %u", RTE_ETHER_MIN_MTU, dev_info.min_mtu);
	TEST_ASSERT(dev_info.max_mtu <= RTE_ETHER_MAX_JUMBO_FRAME_LEN,
		    "max_mtu should be <= %u, got %u", RTE_ETHER_MAX_JUMBO_FRAME_LEN, dev_info.max_mtu);

	rte_vdev_uninit("net_pcap_devinfo");

	/* Cleanup temp files */
	for (i = 0; i < 3; i++)
		unlink(rx_paths[i]);
	for (i = 0; i < 2; i++)
		unlink(tx_paths[i]);

	printf("Device info PASSED\n");
	return TEST_SUCCESS;
}

/*
 * Test suite setup
 */
static int
test_setup(void)
{
	/* Generate random source MAC address */
	rte_eth_random_addr(src_mac.addr_bytes);

	mp = rte_pktmbuf_pool_create("pcap_test_pool", NB_MBUF, 32, 0,
				     RTE_MBUF_DEFAULT_BUF_SIZE,
				     rte_socket_id());
	TEST_ASSERT_NOT_NULL(mp, "Failed to create mempool");

	return 0;
}

/*
 * Test suite teardown
 */
static void
test_teardown(void)
{
	unsigned int i;

	/* Cleanup temp files */
	if (tx_pcap_path[0] != '\0')
		unlink(tx_pcap_path);
	if (rx_pcap_path[0] != '\0')
		unlink(rx_pcap_path);
	if (infinite_pcap_path[0] != '\0')
		unlink(infinite_pcap_path);
	if (timestamp_pcap_path[0] != '\0')
		unlink(timestamp_pcap_path);
	if (varied_pcap_path[0] != '\0')
		unlink(varied_pcap_path);
	if (jumbo_pcap_path[0] != '\0')
		unlink(jumbo_pcap_path);
	for (i = 0; i < RTE_DIM(multi_tx_pcap_paths); i++) {
		if (multi_tx_pcap_paths[i][0] != '\0')
			unlink(multi_tx_pcap_paths[i]);
	}
	if (multi_rx_pcap_path[0] != '\0')
		unlink(multi_rx_pcap_path);

	rte_mempool_free(mp);
	mp = NULL;
}

static struct unit_test_suite test_pmd_pcap_suite = {
	.setup = test_setup,
	.teardown = test_teardown,
	.suite_name = "PCAP PMD Unit Test Suite",
	.unit_test_cases = {
		TEST_CASE(test_dev_info),
		TEST_CASE(test_tx_to_file),
		TEST_CASE(test_rx_from_file),
		TEST_CASE(test_tx_varied_sizes),
		TEST_CASE(test_rx_varied_sizes),
		TEST_CASE(test_jumbo_rx),
		TEST_CASE(test_jumbo_tx),
		TEST_CASE(test_infinite_rx),
		TEST_CASE(test_tx_drop),
		TEST_CASE(test_stats),
		TEST_CASE(test_set_mtu),
		TEST_CASE(test_iface),
		TEST_CASE(test_mac_address),
		TEST_CASE(test_rx_timestamp),
		TEST_CASE(test_multi_tx_queue),
		TEST_CASE(test_multi_rx_queue_same_file),
		TEST_CASES_END()
	}
};

static int
test_pmd_pcap(void)
{
	return unit_test_suite_runner(&test_pmd_pcap_suite);
}

REGISTER_FAST_TEST(pcap_pmd_autotest, true, true, test_pmd_pcap);

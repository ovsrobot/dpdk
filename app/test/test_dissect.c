/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024 Stephen Hemminger <stephen@networkplumber.org>
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include <rte_bus_vdev.h>
#include <rte_dissect.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_net.h>
#include <rte_random.h>
#include <rte_udp.h>
#include <rte_vxlan.h>

#include "test.h"

#ifndef LINE_MAX
#define LINE_MAX	2048
#endif

#define TOTAL_PACKETS	100
#define PACKET_LEN	1000
#define ETH_IP_UDP_VXLAN_SIZE (sizeof(struct rte_ether_hdr) + \
			       sizeof(struct rte_ipv4_hdr) + \
			       sizeof(struct rte_udp_hdr) + \
			       sizeof(struct rte_vxlan_hdr))


static uint16_t port_id;
static const char null_dev[] = "net_null0";

static void
add_header(struct rte_mbuf *mb, uint32_t plen,
	   rte_be16_t src_port, rte_be16_t dst_port)
{
	struct {
		struct rte_ether_hdr eth;
		struct rte_ipv4_hdr ip;
		struct rte_udp_hdr udp;
	} pkt = {
		.eth = {
			.dst_addr.addr_bytes = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
			.ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4),
		},
		.ip = {
			.version_ihl = RTE_IPV4_VHL_DEF,
			.time_to_live = 1,
			.next_proto_id = IPPROTO_UDP,
			.src_addr = rte_cpu_to_be_32(RTE_IPV4_LOOPBACK),
			.dst_addr = rte_cpu_to_be_32(RTE_IPV4_BROADCAST),
		},
		.udp = {
			.dst_port = dst_port,
			.src_port = src_port,
		},
	};

	rte_eth_random_addr(pkt.eth.src_addr.addr_bytes);

	plen -= sizeof(struct rte_ether_hdr);
	pkt.ip.total_length = rte_cpu_to_be_16(plen);
	pkt.ip.hdr_checksum = rte_ipv4_cksum(&pkt.ip);

	plen -= sizeof(struct rte_ipv4_hdr);
	pkt.udp.dgram_len = rte_cpu_to_be_16(plen);

	/* Copy header into mbuf */
	memcpy(rte_pktmbuf_append(mb, sizeof(pkt)), &pkt, sizeof(pkt));
}

static void
add_vxlan(struct rte_mbuf *mb, rte_be32_t vni)
{
	struct rte_vxlan_hdr *vxlan;

	vxlan = (struct rte_vxlan_hdr *)rte_pktmbuf_append(mb, sizeof(*vxlan));
	memset(vxlan, 0, sizeof(*vxlan));
	vxlan->flag_i = 1;
	vxlan->vx_vni = vni;
}


static void
fill_data(struct rte_mbuf *mb, uint32_t len)
{
	uint32_t i;
	char *ptr = rte_pktmbuf_append(mb, len);
	char c = '!';

	/* traditional barber pole pattern */
	for (i = 0; i < len; i++) {
		ptr[i] = c++;
		if (c == 0x7f)
			c = '!';
	}
}

static void
mbuf_prep(struct rte_mbuf *mb, uint8_t buf[], uint32_t buf_len)
{
	mb->buf_addr = buf;
	rte_mbuf_iova_set(mb, (uintptr_t)buf);
	mb->buf_len = buf_len;
	rte_mbuf_refcnt_set(mb, 1);

	/* set pool pointer to dummy value, test doesn't use it */
	mb->pool = (void *)buf;

	rte_pktmbuf_reset(mb);
}

static int
test_setup(void)
{
	port_id = rte_eth_dev_count_avail();

	/* Make a dummy null device to snoop on */
	if (rte_vdev_init(null_dev, NULL) != 0) {
		fprintf(stderr, "Failed to create vdev '%s'\n", null_dev);
		goto fail;
	}
	return 0;

fail:
	rte_vdev_uninit(null_dev);
	return -1;
}

static void
test_cleanup(void)
{
	rte_vdev_uninit(null_dev);
}


static int
test_simple(void)
{
	struct rte_mbuf mb;
	uint8_t buf[RTE_MBUF_DEFAULT_BUF_SIZE];
	uint32_t data_len = PACKET_LEN;
	rte_be16_t src_port = rte_rand_max(UINT16_MAX);
	const rte_be16_t dst_port = rte_cpu_to_be_16(9); /* Discard port */
	char obuf[LINE_MAX] = { };
	char result[LINE_MAX] = { };

	/* make a dummy packet */
	mbuf_prep(&mb, buf, sizeof(buf));
	add_header(&mb, data_len, src_port, dst_port);
	fill_data(&mb, data_len - mb.data_off);

	/* construct the expected result */
	int len = snprintf(result, sizeof(result),
			   "127.0.0.1 → 224.0.0.0 UDP 966 %u → 9",
			   rte_be_to_cpu_16(src_port));

	rte_dissect_mbuf(obuf, sizeof(obuf), &mb, 0);
	TEST_ASSERT_BUFFERS_ARE_EQUAL(obuf, result, len,
				      "Dissect string differs:\nexpect \"%s\"\n   got \"%s\"",
				      result, obuf);

	return TEST_SUCCESS;
}

static int
test_truncated(void)
{
	struct rte_mbuf mb;
	uint8_t buf[RTE_MBUF_DEFAULT_BUF_SIZE];
	uint32_t pkt_len, data_len = PACKET_LEN;
	rte_be16_t dst_port = rte_cpu_to_be_16(RTE_VXLAN_DEFAULT_PORT);
	char obuf[LINE_MAX];

	/* make a really nested vxlan packet */
	mbuf_prep(&mb, buf, sizeof(buf));
	pkt_len = data_len;
	do {
		rte_be16_t src_port = rte_rand_max(UINT16_MAX);
		uint32_t vni = rte_rand_max(1ul << 24);

		add_header(&mb, data_len, src_port, dst_port);
		add_vxlan(&mb, vni);
		pkt_len -= ETH_IP_UDP_VXLAN_SIZE;
	} while (pkt_len > ETH_IP_UDP_VXLAN_SIZE);

	fill_data(&mb, pkt_len);

	/* dissect it but snip off some amount of data */
	for (unsigned int i = 0; i < TOTAL_PACKETS; i++) {
		uint32_t snaplen = rte_rand_max(pkt_len);

		rte_dissect_mbuf(obuf, sizeof(obuf), &mb, snaplen);
	}

	return TEST_SUCCESS;
}

static int
test_fuzz(void)
{
	struct rte_mbuf mb;
	uint8_t buf[RTE_MBUF_DEFAULT_BUF_SIZE];
	uint32_t data_len = PACKET_LEN;
	const rte_be16_t dst_port = rte_cpu_to_be_16(rte_rand_max(1024));
	const rte_be16_t src_port = rte_rand_max(UINT16_MAX);
	char obuf[LINE_MAX];

	/* make a dummy packet */
	mbuf_prep(&mb, buf, sizeof(buf));
	add_header(&mb, data_len, src_port, dst_port);
	fill_data(&mb, data_len - mb.data_off);

	/* randomly flip bits in it */
	for (unsigned int i = 0; i < TOTAL_PACKETS; i++) {
		uint32_t bit = rte_rand_max(data_len) * 8;
		uint8_t *bp = buf + bit / 8;
		uint8_t mask = 1u << (bit % 8);

		/* twiddle one bit */
		*bp ^= mask;
		rte_dissect_mbuf(obuf, sizeof(obuf), &mb, 0);
		*bp ^= mask;
	}

	return TEST_SUCCESS;
}

static struct
unit_test_suite test_dissect_suite  = {
	.setup = test_setup,
	.teardown = test_cleanup,
	.suite_name = "Test Dissect Unit Test Suite",
	.unit_test_cases = {
		TEST_CASE(test_simple),
		TEST_CASE(test_truncated),
		TEST_CASE(test_fuzz),
		TEST_CASES_END()
	}
};

static int
test_dissect(void)
{
	return unit_test_suite_runner(&test_dissect_suite);
}

REGISTER_FAST_TEST(dissect_autotest, true, true, test_dissect);

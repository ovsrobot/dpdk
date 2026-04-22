/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2026 Red Hat, Inc.
 */

#include <string.h>

#include <rte_mbuf.h>
#include <rte_net.h>

#include <rte_test.h>
#include "test.h"

#define MEMPOOL_CACHE_SIZE 0
#define MBUF_DATA_SIZE 256
#define NB_MBUF 128

/* Ether()/IP()/UDP()/Raw('x') */
static const char pkt_ether_ipv4_udp[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x1d, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11,
	0x7c, 0xcd, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00,
	0x00, 0x01, 0x00, 0x35, 0x00, 0x35, 0x00, 0x09,
	0x89, 0x6f, 0x78,
};

/* Ether()/Dot1Q(vlan=42)/IP()/UDP()/Raw('x') */
static const char pkt_vlan_ipv4_udp[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x81, 0x00, 0x00, 0x2a,
	0x08, 0x00, 0x45, 0x00, 0x00, 0x1d, 0x00, 0x01,
	0x00, 0x00, 0x40, 0x11, 0x7c, 0xcd, 0x7f, 0x00,
	0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x35,
	0x00, 0x35, 0x00, 0x09, 0x89, 0x6f, 0x78,
};

/* Ether()/Dot1AD(vlan=42)/Dot1Q(vlan=43)/IP()/UDP()/Raw('x') */
static const char pkt_qinq_ipv4_udp[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x88, 0xa8, 0x00, 0x2a,
	0x81, 0x00, 0x00, 0x2b, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x1d, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11,
	0x7c, 0xcd, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00,
	0x00, 0x01, 0x00, 0x35, 0x00, 0x35, 0x00, 0x09,
	0x89, 0x6f, 0x78,
};

static int
test_get_ptype(struct rte_mempool *pool, const char *pktdata, size_t len,
	       uint32_t expected_l2, uint8_t expected_l2_len)
{
	struct rte_net_hdr_lens hdr_lens;
	struct rte_mbuf *m;
	uint32_t ptype;
	uint32_t l2;
	char *data;

	m = rte_pktmbuf_alloc(pool);
	RTE_TEST_ASSERT_NOT_NULL(m, "cannot allocate mbuf");

	data = rte_pktmbuf_append(m, len);
	if (data == NULL) {
		rte_pktmbuf_free(m);
		RTE_TEST_ASSERT_NOT_NULL(data, "cannot append data");
	}

	memcpy(data, pktdata, len);

	ptype = rte_net_get_ptype(m, &hdr_lens, RTE_PTYPE_ALL_MASK);
	l2 = ptype & RTE_PTYPE_L2_MASK;

	rte_pktmbuf_free(m);

	RTE_TEST_ASSERT_EQUAL(l2, expected_l2,
		"unexpected L2 ptype: got 0x%x, expected 0x%x",
		l2, expected_l2);
	RTE_TEST_ASSERT_EQUAL(hdr_lens.l2_len, expected_l2_len,
		"unexpected l2_len: got %u, expected %u",
		hdr_lens.l2_len, expected_l2_len);

	return 0;
}

static int
test_net_ptype(void)
{
	struct rte_mempool *pool;

	pool = rte_pktmbuf_pool_create("test_ptype_mbuf_pool",
			NB_MBUF, MEMPOOL_CACHE_SIZE, 0, MBUF_DATA_SIZE,
			SOCKET_ID_ANY);
	RTE_TEST_ASSERT_NOT_NULL(pool, "cannot allocate mbuf pool");

	if (test_get_ptype(pool, pkt_ether_ipv4_udp,
			   sizeof(pkt_ether_ipv4_udp),
			   RTE_PTYPE_L2_ETHER, 14))
		goto fail;

	if (test_get_ptype(pool, pkt_vlan_ipv4_udp,
			   sizeof(pkt_vlan_ipv4_udp),
			   RTE_PTYPE_L2_ETHER_VLAN, 18))
		goto fail;

	if (test_get_ptype(pool, pkt_qinq_ipv4_udp,
			   sizeof(pkt_qinq_ipv4_udp),
			   RTE_PTYPE_L2_ETHER_QINQ, 22))
		goto fail;

	rte_mempool_free(pool);
	return 0;

fail:
	rte_mempool_free(pool);
	return -1;
}

REGISTER_FAST_TEST(net_ptype_autotest, NOHUGE_OK, ASAN_OK, test_net_ptype);

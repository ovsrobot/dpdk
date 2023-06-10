/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include "test.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <rte_common.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_ether.h>
#include <rte_mpls.h>

#define MEMPOOL_CACHE_SIZE      32
#define MBUF_DATA_SIZE          2048
#define NB_MBUF                 128

static int
test_mpls_fail_push(struct rte_mbuf *m)
{
	struct rte_mpls_hdr mpls;

	/* create dummy MPLS header */
	mpls.tag_msb = 1;
	mpls.tag_lsb = 2;
	mpls.bs = 1;
	mpls.tc = 1;
	mpls.ttl = 255;

	/* push first MPLS header */
	if (rte_mpls_push_over_l2(m, &mpls) != 0)
		return 0;
	return -1;
}

static int
test_mpls_push(struct rte_mbuf *m)
{
	struct rte_mpls_hdr mpls;

	/* create dummy MPLS header */
	mpls.tag_msb = 1;
	mpls.tag_lsb = 2;
	mpls.bs = 1;
	mpls.tc = 1;
	mpls.ttl = 255;

	/* push first MPLS header */
	if (rte_mpls_push_over_l2(m, &mpls) != 0) {
		printf("Failed to insert mpls 1\n");
		return -1;
	}
	if (rte_pktmbuf_pkt_len(m) != RTE_ETHER_HDR_LEN + RTE_MPLS_HLEN) {
		printf("Bad pkt length after inserting first mpls header\n");
		return -1;
	}

	/* push second MPLS header*/
	if (rte_mpls_push_over_l2(m, &mpls) != 0) {
		printf("failed to insert mpls 1\n");
		return -1;
	}
	if (rte_pktmbuf_pkt_len(m) != RTE_ETHER_HDR_LEN + RTE_MPLS_HLEN * 2) {
		printf("bad pkt length after inserting second mpls header\n");
		return -1;
	}
	return 0;
}

static int
test_mpls_fail_strip(struct rte_mbuf *m)
{
	/* strip MPLS headers */
	if (rte_mpls_strip_over_l2(m) != 0)
		return 0;
	return -1;
}

static int
test_mpls_strip(struct rte_mbuf *m)
{
	/* strip MPLS headers */
	return rte_mpls_strip_over_l2(m);
}

static int
test_mpls(void)
{
	int ret = -1;
	struct rte_mempool *pktmbuf_pool = NULL;
	struct rte_mbuf *m = NULL;
	char *data;
	struct rte_ether_hdr eh;

	/* create pktmbuf pool */
	pktmbuf_pool = rte_pktmbuf_pool_create("test_mpls_pool",
			NB_MBUF, MEMPOOL_CACHE_SIZE, 0, MBUF_DATA_SIZE,
			SOCKET_ID_ANY);

	if (pktmbuf_pool == NULL) {
		printf("cannot allocate mbuf pool\n");
		goto err;
	}

    /* allocate mbuf from pool */
	m = rte_pktmbuf_alloc(pktmbuf_pool);
	if (m == NULL) {
		printf("mbuf alloc failed\n");
		goto err;
	}
	if (rte_pktmbuf_data_len(m) != 0) {
		printf("mbuf alloc bad length\n");
		goto err;
	}

	if (test_mpls_fail_push(m) < 0) {
		printf("test_mpls_fail_push() failed\n");
		goto err;
	}

	if (test_mpls_fail_strip(m) < 0) {
		printf("test_mpls_fail_strip() failed\n");
		goto err;
	}

	/* create a dummy ethernet header */
	memset(&eh.src_addr, 0, RTE_ETHER_ADDR_LEN);
	memset(&eh.dst_addr, 0, RTE_ETHER_ADDR_LEN);
	eh.ether_type = rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4);

	/* append ethernet header into mbuf */
	data = rte_pktmbuf_append(m, RTE_ETHER_HDR_LEN);
	if (data == NULL) {
		printf("cannot append data\n");
		goto err;
	}
	if (rte_pktmbuf_data_len(m) != RTE_ETHER_HDR_LEN) {
		printf("bad pkt data length\n");
		goto err;
	}
	memcpy(data, &eh, RTE_ETHER_HDR_LEN);

	if (test_mpls_push(m) < 0) {
		printf("test_mpls_push() failed\n");
		goto err;
	}

	if (test_mpls_strip(m) < 0) {
		printf("test_mpls_push() failed\n");
		goto err;
	}
	if (rte_pktmbuf_data_len(m) != RTE_ETHER_HDR_LEN + RTE_MPLS_HLEN) {
		printf("bad pkt data length after stripping first MPLS header\n");
		goto err;
	}

	if (test_mpls_strip(m) < 0) {
		printf("test_mpls_push() failed\n");
		goto err;
	}
	if (rte_pktmbuf_data_len(m) != RTE_ETHER_HDR_LEN) {
		printf("bad pkt data length after stripping second MPLS header\n");
		goto err;
	}
	ret = 0;
err:
	if (m)
		rte_pktmbuf_free(m);
	if (pktmbuf_pool)
		rte_mempool_free(pktmbuf_pool);
	return ret;
}

REGISTER_TEST_COMMAND(mpls_autotest, test_mpls);

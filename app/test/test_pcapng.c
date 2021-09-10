/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 Microsoft Corporation
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_net.h>
#include <rte_pcapng.h>

#include "test.h"

#define DUMMY_MBUF_NUM 3

static rte_pcapng_t *pcapng;
static struct rte_mempool *mp;
static const uint32_t pkt_len = 200;
static uint64_t ifrecv, ifdrop;
static uint16_t port_id;

/* first mbuf in the packet, should always be at offset 0 */
struct dummy_mbuf {
	struct rte_mbuf mb[DUMMY_MBUF_NUM];
	uint8_t buf[DUMMY_MBUF_NUM][RTE_MBUF_DEFAULT_BUF_SIZE];
};

static void
dummy_mbuf_prep(struct rte_mbuf *mb, uint8_t buf[], uint32_t buf_len,
	uint32_t data_len)
{
	uint32_t i;
	uint8_t *db;

	mb->buf_addr = buf;
	mb->buf_iova = (uintptr_t)buf;
	mb->buf_len = buf_len;
	rte_mbuf_refcnt_set(mb, 1);

	/* set pool pointer to dummy value, test doesn't use it */
	mb->pool = (void *)buf;

	rte_pktmbuf_reset(mb);
	db = (uint8_t *)rte_pktmbuf_append(mb, data_len);

	for (i = 0; i != data_len; i++)
		db[i] = i;
}

/* Make an IP packet consisting of chain of two packets */
static void
mbuf1_prepare(struct dummy_mbuf *dm, uint32_t plen)
{
	struct rte_ipv4_hdr *ph;
	const struct rte_ipv4_hdr iph = {
		.version_ihl = RTE_IPV4_VHL_DEF,
		.total_length = rte_cpu_to_be_16(plen),
		.time_to_live = IPDEFTTL,
		.next_proto_id = IPPROTO_RAW,
		.src_addr = rte_cpu_to_be_32(RTE_IPV4_LOOPBACK),
		.dst_addr = rte_cpu_to_be_32(RTE_IPV4_BROADCAST),
	};

	memset(dm, 0, sizeof(*dm));
	dummy_mbuf_prep(&dm->mb[0], dm->buf[0], sizeof(dm->buf[0]), plen);

	ph = rte_pktmbuf_mtod(dm->mb, typeof(ph));
	memcpy(ph, &iph, sizeof(iph));
}

static int
test_setup(void)
{
	char file_template[] = "/tmp/pcapng_test_XXXXXX.pcapng";
	int tmp_fd;

	port_id = rte_eth_find_next(0);
	if (port_id >= RTE_MAX_ETHPORTS) {
		fprintf(stderr, "No valid Ether port\n");
		return -1;
	}

	tmp_fd = mkstemps(file_template, strlen(".pcapng"));
	if (tmp_fd == -1) {
		perror("mkstemps() failure");
		return -1;
	}

	/* open a test capture file */
	pcapng = rte_pcapng_fdopen(tmp_fd, NULL, NULL, "pcapng_test", NULL);
	if (pcapng == NULL) {
		fprintf(stderr, "rte_pcapng_fdopen failed\n");
		close(tmp_fd);
		return -1;
	}

	/* Make a pool for cloned packeets */
	mp = rte_pktmbuf_pool_create_by_ops("pcapng_test_pool", DUMMY_MBUF_NUM,
					    0, 0,
					    rte_pcapng_mbuf_size(pkt_len),
					    SOCKET_ID_ANY, "ring_mp_sc");
	if (mp == NULL) {
		fprintf(stderr, "Cannot create mempool\n");
		return -1;
	}
	return 0;

}

static int
test_basic_packets(void)
{
	struct rte_mbuf *orig, *clone = NULL;
	struct dummy_mbuf mbfs;
	ssize_t len;

	/* make a dummy packet */
	mbuf1_prepare(&mbfs, pkt_len);

	/* clone them */
	orig  = &mbfs.mb[0];
	clone = rte_pcapng_copy(port_id, 0, orig, mp, pkt_len,
				rte_get_tsc_cycles(), 0);
	if (clone == NULL) {
		fprintf(stderr, "Cannot copy packet\n");
		return -1;
	}

	/* write it to capture file */
	len = rte_pcapng_write_packets(pcapng, &clone, 1);
	rte_pktmbuf_free(clone);

	if (len <= 0) {
		fprintf(stderr, "Write of packets failed\n");
		return -1;
	}

	++ifrecv;
	return 0;
}

static int
test_write_stats(void)
{
	ssize_t len;

	/* write a statistics block */
	len = rte_pcapng_write_stats(pcapng, port_id,
				     NULL, 0, 0,
				     ifrecv, ifdrop);
	if (len <= 0) {
		fprintf(stderr, "Write of statistics failed\n");
		return -1;
	}
	return 0;
}

static void
test_cleanup(void)
{
	if (mp)
		rte_mempool_free(mp);

	if (pcapng)
		rte_pcapng_close(pcapng);

}

static struct
unit_test_suite test_pcapng_suite  = {
	.setup = test_setup,
	.teardown = test_cleanup,
	.suite_name = "Test Pcapng Unit Test Suite",
	.unit_test_cases = {
		TEST_CASE(test_basic_packets),
		TEST_CASE(test_write_stats),
		TEST_CASES_END()
	}
};

static int
test_pcapng(void)
{
	return unit_test_suite_runner(&test_pcapng_suite);
}

REGISTER_TEST_COMMAND(pcapng_autotest, test_pcapng);

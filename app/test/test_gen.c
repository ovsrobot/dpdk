/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Intel Corporation
 */

#include <rte_common.h>
#include <rte_gen.h>
#include <rte_mbuf.h>
#include <rte_random.h>

#include "test.h"

#define BURST_MAX 32

static struct rte_mempool *mp;

static int
testsuite_setup(void)
{
	if (!mp) {
		mp = rte_pktmbuf_pool_create("test_gen_mp", 8192, 256, 0, 2048,
						SOCKET_ID_ANY);
	}
	return mp ? TEST_SUCCESS : TEST_FAILED;
}

static void
testsuite_teardown(void)
{
	rte_mempool_free(mp);
}

static int
test_gen_create(void)
{
	struct rte_gen *gen = rte_gen_create(mp);
	TEST_ASSERT_FAIL(gen, "Expected valid pointer after create()");

	rte_gen_destroy(gen);
	return 0;
}

static int
test_gen_basic_rxtx(void)
{
	struct rte_gen *gen = rte_gen_create(mp);
	TEST_ASSERT_FAIL(gen, "Expected valid pointer after create()");

	struct rte_mbuf *bufs[BURST_MAX];
	uint16_t nb_rx = rte_gen_rx_burst(gen, bufs, BURST_MAX);
	TEST_ASSERT_EQUAL(nb_rx, BURST_MAX, "Expected rx packet burst.");

	uint64_t latency[BURST_MAX];
	uint16_t nb_tx = rte_gen_tx_burst(gen, bufs, latency, BURST_MAX);
	TEST_ASSERT_EQUAL(nb_tx, BURST_MAX, "Expected tx packet burst.");

	rte_gen_destroy(gen);
	return 0;
}

static int
test_gen_loop_rxtx(void)
{
	struct rte_gen *gen = rte_gen_create(mp);
	TEST_ASSERT_FAIL(gen, "Expected valid pointer after create()");

	uint32_t total_sent = 0;

	while (total_sent < 1000000) {
		struct rte_mbuf *bufs[BURST_MAX];
		uint16_t nb_rx = rte_gen_rx_burst(gen, bufs, BURST_MAX);
		TEST_ASSERT_EQUAL(nb_rx, BURST_MAX, "Expected rx packet burst.");

		uint64_t latency[BURST_MAX];
		uint16_t nb_tx = rte_gen_tx_burst(gen, bufs, latency, nb_rx);
		TEST_ASSERT_EQUAL(nb_tx, BURST_MAX, "Expected tx packet burst.");

		total_sent += nb_tx;
	}
	rte_gen_destroy(gen);
	return 0;
}

static int
test_gen_packet_set_raw(void)
{
	struct rte_gen *gen = rte_gen_create(mp);
	TEST_ASSERT_FAIL(gen, "Expected valid pointer after create()");

	/* Set a raw packet payload, and ensure the next received packet has
	 * that packet data as contents and size.
	 */
	uint64_t pkt_data[8];
	uint32_t i;
	for (i = 0; i < 8; i++)
		pkt_data[i] = rte_rand();

	int32_t err = rte_gen_packet_set_raw(gen, (void *)pkt_data, 64);
	TEST_ASSERT_EQUAL(err, 0, "Expected set raw() to return success.");

	struct rte_mbuf *bufs[BURST_MAX];
	uint16_t nb_rx = rte_gen_rx_burst(gen, bufs, 1);
	TEST_ASSERT_EQUAL(nb_rx, 1, "Expected rx packet burst.");

	void *mbuf_data = rte_pktmbuf_mtod(bufs[0], void *);
	int32_t data_equal = memcmp(pkt_data, mbuf_data, 64) == 0;
	TEST_ASSERT_EQUAL(data_equal, 1,
		"Expected packet data equal to input data.");

	rte_pktmbuf_free(bufs[0]);

	rte_gen_destroy(gen);
	return 0;
}

static int
test_gen_packet_parse_string(void)
{
	struct rte_gen *gen = rte_gen_create(mp);
	TEST_ASSERT_FAIL(gen, "Expected valid pointer after create()");
	struct str_parse_t {
		const char *str;
		uint32_t expected_to_fail;
	} pkt_strings[] = {
		{ .str = "Ether()"},
		{ .str = "Ether()/"},
		{ .str = "/Ether()"},
		{ .str = "/Ether()/"},
		{ .str = "Ether()/IP()"},
		{ .str = "Ether()/IP(src=1.2.3.4,dst=5.6.7.8)"},
		{ .str = "Ether()/IP(src=1.2.3.4,dst=192.168.255.255)"},
		{ .str = "Ether()/IP(dst=172.16.0.9,src=1.2.3.4)"},
		{ .str = "Ether()/IP(src=1.2.3.4)"},
		{ .str = "Ether()/IP(srdst=5.6.7.8)", .expected_to_fail = 1},
		{ .str = "Ether()/IP(src=1.2.3.4,ds=)", .expected_to_fail = 1},
		{ .str = "Ether()/IP(src=1.2.3.4,dst=)", .expected_to_fail = 1},
		{ .str = "Ether()/IP(src=,dst=5.6.7.8)", .expected_to_fail = 1},
		{ .str = "Ether()/IP(sr=,dst=5.6.7.8)", .expected_to_fail = 1},
		{ .str = "Ether()/IP(src=1.2.3.fail,dst=5.6.7.8)",
					.expected_to_fail = 1},
	};

	uint32_t i;
	for (i = 0; i < RTE_DIM(pkt_strings); i++) {
		const char *pkt_str = pkt_strings[i].str;
		int32_t err = rte_gen_packet_parse_string(gen, pkt_str, NULL);

		if (err && pkt_strings[i].expected_to_fail != 1) {
			printf("Expected string %s to parse.", pkt_str);
			return -1;
		}
		/* False pass if reached with no err when e_t_f = 1 */
		if (!err && pkt_strings[i].expected_to_fail) {
			printf("False Pass on string: %s\n", pkt_str);
			return -1;
		}
	}

	rte_gen_destroy(gen);
	return 0;

}


static struct unit_test_suite gen_suite  = {
	.suite_name = "gen: packet generator unit test suite",
	.setup = testsuite_setup,
	.teardown = testsuite_teardown,
	.unit_test_cases = {
		TEST_CASE_ST(NULL, NULL, test_gen_create),
		TEST_CASE_ST(NULL, NULL, test_gen_basic_rxtx),
		TEST_CASE_ST(NULL, NULL, test_gen_loop_rxtx),
		TEST_CASE_ST(NULL, NULL, test_gen_packet_set_raw),
		TEST_CASE_ST(NULL, NULL, test_gen_packet_parse_string),
		TEST_CASES_END() /**< NULL terminate unit test array */
	}
};

static int
test_gen_suite(void)
{
	return unit_test_suite_runner(&gen_suite);
}

REGISTER_TEST_COMMAND(gen_autotest, test_gen_suite);

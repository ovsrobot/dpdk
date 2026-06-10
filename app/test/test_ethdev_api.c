/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2023, Advanced Micro Devices, Inc.
 */

#include <rte_log.h>
#include <rte_ethdev.h>
#include <rte_flow.h>

#include <rte_test.h>
#include "test.h"

#define NUM_RXQ	2
#define NUM_TXQ	2
#define NUM_RXD 512
#define NUM_TXD 512
#define NUM_MBUF 1024
#define MBUF_CACHE_SIZE 256

static int32_t
ethdev_api_flow_conv_pattern_masked(void)
{
	const struct rte_flow_item_eth spec = {
		.hdr.dst_addr.addr_bytes = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 },
		.hdr.src_addr.addr_bytes = { 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
		.hdr.ether_type = RTE_BE16(0x1234),
	};
	const struct rte_flow_item_eth last = {
		.hdr.dst_addr.addr_bytes = { 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 },
		.hdr.src_addr.addr_bytes = { 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f },
		.hdr.ether_type = RTE_BE16(0x5678),
	};
	const struct rte_flow_item_eth mask = {
		.hdr.dst_addr.addr_bytes = { 0xff, 0xff, 0x00, 0x00, 0xff, 0xff },
		.hdr.src_addr.addr_bytes = { 0xff, 0x00, 0xff, 0x00, 0xff, 0x00 },
		.hdr.ether_type = RTE_BE16(0xffff),
	};
	const struct rte_flow_item pattern[] = {
		{
			.type = RTE_FLOW_ITEM_TYPE_ETH,
			.spec = &spec,
			.last = &last,
			.mask = &mask,
		},
		{ .type = RTE_FLOW_ITEM_TYPE_END },
	};
	union {
		struct rte_flow_item item;
		struct rte_flow_item_eth eth;
		double align;
		uint8_t raw[256];
	} dst;
	const struct rte_flow_item *item;
	const struct rte_flow_item_eth *conv_spec;
	const struct rte_flow_item_eth *conv_last;
	int ret;

	ret = rte_flow_conv(RTE_FLOW_CONV_OP_PATTERN_MASKED, NULL, 0, pattern, NULL);
	TEST_ASSERT(ret > 0, "Masked pattern conversion size query failed");
	TEST_ASSERT((size_t)ret <= sizeof(dst.raw),
		    "Masked pattern conversion needs too much storage");

	memset(&dst, 0, sizeof(dst));
	ret = rte_flow_conv(RTE_FLOW_CONV_OP_PATTERN_MASKED, dst.raw,
			    sizeof(dst.raw), pattern, NULL);
	TEST_ASSERT(ret > 0, "Masked pattern conversion failed");

	item = (const struct rte_flow_item *)dst.raw;
	conv_spec = item[0].spec;
	conv_last = item[0].last;
	TEST_ASSERT_NOT_NULL(conv_spec, "Converted spec must be set");
	TEST_ASSERT_NOT_NULL(conv_last, "Converted last must be set");

	TEST_ASSERT_EQUAL(conv_spec->hdr.dst_addr.addr_bytes[0], 0x01,
			  "Masked spec dst byte 0 mismatch");
	TEST_ASSERT_EQUAL(conv_spec->hdr.dst_addr.addr_bytes[2], 0x00,
			  "Masked spec dst byte 2 mismatch");
	TEST_ASSERT_EQUAL(conv_spec->hdr.src_addr.addr_bytes[1], 0x00,
			  "Masked spec src byte 1 mismatch");
	TEST_ASSERT_EQUAL(conv_spec->hdr.ether_type, RTE_BE16(0x1234),
			  "Masked spec ether type mismatch");
	TEST_ASSERT_EQUAL(conv_last->hdr.dst_addr.addr_bytes[0], 0x11,
			  "Masked last dst byte 0 mismatch");
	TEST_ASSERT_EQUAL(conv_last->hdr.dst_addr.addr_bytes[2], 0x00,
			  "Masked last dst byte 2 mismatch");
	TEST_ASSERT_EQUAL(conv_last->hdr.src_addr.addr_bytes[1], 0x00,
			  "Masked last src byte 1 mismatch");
	TEST_ASSERT_EQUAL(conv_last->hdr.ether_type, RTE_BE16(0x5678),
			  "Masked last ether type mismatch");

	return TEST_SUCCESS;
}

static int32_t
ethdev_api_queue_status(void)
{
	struct rte_eth_dev_info dev_info;
	struct rte_eth_rxq_info rx_qinfo;
	struct rte_eth_txq_info tx_qinfo;
	struct rte_mempool *mbuf_pool;
	struct rte_eth_conf eth_conf;
	uint16_t port_id;
	int ret;

	if (rte_eth_dev_count_avail() == 0)
		return TEST_SKIPPED;

	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUF, MBUF_CACHE_SIZE, 0,
			RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	RTE_ETH_FOREACH_DEV(port_id) {
		memset(&eth_conf, 0, sizeof(eth_conf));
		ret = rte_eth_dev_configure(port_id, NUM_RXQ, NUM_TXQ, &eth_conf);
		TEST_ASSERT(ret == 0,
			"Port(%u) failed to configure.\n", port_id);

		/* RxQ setup */
		for (uint16_t queue_id = 0; queue_id < NUM_RXQ; queue_id++) {
			ret = rte_eth_rx_queue_setup(port_id, queue_id, NUM_RXD,
				rte_socket_id(), NULL,  mbuf_pool);
			TEST_ASSERT(ret == 0,
				"Port(%u), queue(%u) failed to setup RxQ.\n",
				port_id, queue_id);
		}

		/* TxQ setup */
		for (uint16_t queue_id = 0; queue_id < NUM_TXQ; queue_id++) {
			ret = rte_eth_tx_queue_setup(port_id, queue_id, NUM_TXD,
				rte_socket_id(), NULL);
			TEST_ASSERT(ret == 0,
				"Port(%u), queue(%u) failed to setup TxQ.\n",
				port_id, queue_id);
		}

		ret = rte_eth_dev_info_get(port_id, &dev_info);
		TEST_ASSERT(ret == 0,
			"Port(%u) failed to get dev info.\n", port_id);

		/* Initial RxQ */
		for (uint16_t queue_id = 0; queue_id < dev_info.nb_rx_queues; queue_id++) {
			ret = rte_eth_rx_queue_info_get(port_id, queue_id, &rx_qinfo);
			if (ret == -ENOTSUP)
				continue;

			TEST_ASSERT(ret == 0,
				"Port(%u), queue(%u) failed to get RxQ info.\n",
				port_id, queue_id);

			TEST_ASSERT(rx_qinfo.queue_state == RTE_ETH_QUEUE_STATE_STOPPED,
				"Wrong initial Rx queue(%u) state(%d)\n",
				queue_id, rx_qinfo.queue_state);
		}

		/* Initial TxQ */
		for (uint16_t queue_id = 0; queue_id < dev_info.nb_tx_queues; queue_id++) {
			ret = rte_eth_tx_queue_info_get(port_id, queue_id, &tx_qinfo);
			if (ret == -ENOTSUP)
				continue;

			TEST_ASSERT(ret == 0,
				"Port(%u), queue(%u) failed to get TxQ info.\n",
				port_id, queue_id);

			TEST_ASSERT(tx_qinfo.queue_state == RTE_ETH_QUEUE_STATE_STOPPED,
				"Wrong initial Tx queue(%u) state(%d)\n",
				queue_id, tx_qinfo.queue_state);
		}

		ret = rte_eth_dev_start(port_id);
		TEST_ASSERT(ret == 0,
			"Port(%u) failed to start.\n", port_id);

		/* Started RxQ */
		for (uint16_t queue_id = 0; queue_id < dev_info.nb_rx_queues; queue_id++) {
			ret = rte_eth_rx_queue_info_get(port_id, queue_id, &rx_qinfo);
			if (ret == -ENOTSUP)
				continue;

			TEST_ASSERT(ret == 0,
				"Port(%u), queue(%u) failed to get RxQ info.\n",
				port_id, queue_id);

			TEST_ASSERT(rx_qinfo.queue_state == RTE_ETH_QUEUE_STATE_STARTED,
				"Wrong started Rx queue(%u) state(%d)\n",
				queue_id, rx_qinfo.queue_state);
		}

		/* Started TxQ */
		for (uint16_t queue_id = 0; queue_id < dev_info.nb_tx_queues; queue_id++) {
			ret = rte_eth_tx_queue_info_get(port_id, queue_id, &tx_qinfo);
			if (ret == -ENOTSUP)
				continue;

			TEST_ASSERT(ret == 0,
				"Port(%u), queue(%u) failed to get TxQ info.\n",
				port_id, queue_id);

			TEST_ASSERT(tx_qinfo.queue_state == RTE_ETH_QUEUE_STATE_STARTED,
				"Wrong started Tx queue(%u) state(%d)\n",
				queue_id, tx_qinfo.queue_state);
		}

		ret = rte_eth_dev_stop(port_id);
		TEST_ASSERT(ret == 0,
			"Port(%u) failed to stop.\n", port_id);

		/* Stopped RxQ */
		for (uint16_t queue_id = 0; queue_id < dev_info.nb_rx_queues; queue_id++) {
			ret = rte_eth_rx_queue_info_get(port_id, queue_id, &rx_qinfo);
			if (ret == -ENOTSUP)
				continue;

			TEST_ASSERT(ret == 0,
				"Port(%u), queue(%u) failed to get RxQ info.\n",
				port_id, queue_id);

			TEST_ASSERT(rx_qinfo.queue_state == RTE_ETH_QUEUE_STATE_STOPPED,
				"Wrong stopped Rx queue(%u) state(%d)\n",
				queue_id, rx_qinfo.queue_state);
		}

		/* Stopped TxQ */
		for (uint16_t queue_id = 0; queue_id < dev_info.nb_tx_queues; queue_id++) {
			ret = rte_eth_tx_queue_info_get(port_id, queue_id, &tx_qinfo);
			if (ret == -ENOTSUP)
				continue;

			TEST_ASSERT(ret == 0,
				"Port(%u), queue(%u) failed to get TxQ info.\n",
				port_id, queue_id);

			TEST_ASSERT(tx_qinfo.queue_state == RTE_ETH_QUEUE_STATE_STOPPED,
				"Wrong stopped Tx queue(%u) state(%d)\n",
				queue_id, tx_qinfo.queue_state);
		}
	}

	return TEST_SUCCESS;
}

static struct unit_test_suite ethdev_api_testsuite = {
	.suite_name = "ethdev API tests",
	.setup = NULL,
	.teardown = NULL,
	.unit_test_cases = {
		TEST_CASE(ethdev_api_flow_conv_pattern_masked),
		TEST_CASE(ethdev_api_queue_status),
		/* TODO: Add deferred_start queue status test */
		TEST_CASES_END() /**< NULL terminate unit test array */
	}
};

static int
test_ethdev_api(void)
{
	rte_log_set_global_level(RTE_LOG_DEBUG);
	rte_log_set_level(RTE_LOGTYPE_EAL, RTE_LOG_DEBUG);

	return unit_test_suite_runner(&ethdev_api_testsuite);
}

/* TODO: Make part of the fast test suite, `REGISTER_FAST_TEST()`,
 *       when all drivers complies to the queue state requirement
 */
REGISTER_DRIVER_TEST(ethdev_api, test_ethdev_api);

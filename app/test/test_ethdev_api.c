/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2023, Advanced Micro Devices, Inc.
 */

#include <string.h>

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
	const uint8_t raw_pattern[] = { 0xaa, 0xbb, 0xcc, 0xdd };
	const uint8_t raw_pattern_mask[] = { 0x0f, 0xf0, 0x00, 0xff };
	const struct rte_flow_item_raw raw_spec = {
		.relative = 1,
		.search = 1,
		.offset = 8,
		.limit = 4,
		.length = sizeof(raw_pattern),
		.pattern = raw_pattern,
	};
	const struct rte_flow_item_raw raw_mask = {
		.relative = 1,
		.search = 0,
		.reserved = 0x3fffffff,
		.offset = 0xffffffff,
		.limit = 0xffff,
		.length = 0xffff,
		.pattern = raw_pattern_mask,
	};
	const struct rte_flow_item pattern[] = {
		{
			.type = RTE_FLOW_ITEM_TYPE_ETH,
			.spec = &spec,
			.last = &last,
			.mask = &mask,
		},
		{
			.type = RTE_FLOW_ITEM_TYPE_RAW,
			.spec = &raw_spec,
			.mask = &raw_mask,
		},
		{ .type = RTE_FLOW_ITEM_TYPE_END },
	};
	union {
		struct rte_flow_item item;
		struct rte_flow_item_eth eth;
		struct rte_flow_item_raw raw;
		double align;
		uint8_t buf[256];
	} dst;
	const struct rte_flow_item *item;
	const struct rte_flow_item_eth *conv_spec;
	const struct rte_flow_item_eth *conv_last;
	const struct rte_flow_item_raw *conv_raw_spec;
	int ret;

	ret = rte_flow_conv(RTE_FLOW_CONV_OP_PATTERN_MASKED, NULL, 0, pattern, NULL);
	TEST_ASSERT(ret > 0, "Masked pattern conversion size query failed");
	TEST_ASSERT((size_t)ret <= sizeof(dst.buf),
		    "Masked pattern conversion needs too much storage");

	memset(&dst, 0, sizeof(dst));
	ret = rte_flow_conv(RTE_FLOW_CONV_OP_PATTERN_MASKED, dst.buf,
			    sizeof(dst.buf), pattern, NULL);
	TEST_ASSERT(ret > 0, "Masked pattern conversion failed");

	item = (const struct rte_flow_item *)dst.buf;
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

	conv_raw_spec = item[1].spec;
	TEST_ASSERT_NOT_NULL(conv_raw_spec, "Converted RAW spec must be set");
	TEST_ASSERT_NOT_NULL(conv_raw_spec->pattern,
			     "Converted RAW pattern pointer must be set");
	TEST_ASSERT(conv_raw_spec->pattern != raw_pattern,
		    "Converted RAW pattern must be deep-copied");
	TEST_ASSERT_EQUAL(conv_raw_spec->relative, 1,
			  "Masked RAW relative mismatch");
	TEST_ASSERT_EQUAL(conv_raw_spec->search, 0,
			  "Masked RAW search mismatch");
	TEST_ASSERT_EQUAL(conv_raw_spec->offset, raw_spec.offset,
			  "Masked RAW offset mismatch");
	TEST_ASSERT_EQUAL(conv_raw_spec->limit, raw_spec.limit,
			  "Masked RAW limit mismatch");
	TEST_ASSERT_EQUAL(conv_raw_spec->length, raw_spec.length,
			  "Masked RAW length mismatch");
	TEST_ASSERT_BUFFERS_ARE_EQUAL(conv_raw_spec->pattern, raw_pattern,
				      sizeof(raw_pattern),
				      "RAW pattern bytes must not be masked");

	/*
	 * NULL mask keeps spec and last unchanged: the IPv4 default mask
	 * (addresses only) is not substituted. An explicit mask is applied
	 * to both spec and last. Private items, GENEVE_OPT length and data,
	 * TAG index and COMPARE items are not masked.
	 */
	{
		const struct rte_flow_item_ipv4 ipv4_open = {
			.hdr = {
				.type_of_service = 0xab,
				.time_to_live = 0x40,
				.src_addr = RTE_BE32(0x0a010203),
				.dst_addr = RTE_BE32(0xc0a80001),
			},
		};
		const struct rte_flow_item_ipv4 ipv4_spec = {
			.hdr = {
				.type_of_service = 0xab,
				.time_to_live = 0x40,
				.src_addr = RTE_BE32(0x0a000001),
				.dst_addr = RTE_BE32(0x0a000002),
			},
		};
		const struct rte_flow_item_ipv4 ipv4_last = {
			.hdr = {
				.type_of_service = 0xcd,
				.time_to_live = 0x20,
				.src_addr = RTE_BE32(0x0a0000ff),
				.dst_addr = RTE_BE32(0x0a00ffff),
			},
		};
		const struct rte_flow_item_ipv4 ipv4_mask = {
			.hdr = {
				.type_of_service = 0x0f,
				.src_addr = RTE_BE32(0xffffffff),
				.dst_addr = RTE_BE32(0x0000ffff),
			},
		};
		const struct {
			uint64_t value;
			uint32_t tail;
		} priv_spec = {
			.value = 0x1122334455667788ULL,
			.tail = 0xaabbccdd,
		};
		const struct {
			uint64_t value;
			uint32_t tail;
		} priv_mask = {
			.value = 0,
			.tail = 0,
		};
		uint32_t opt_data[2] = { 0xffffffff, 0x11111111 };
		uint32_t opt_data_mask[2] = { 0, 0 };
		const struct rte_flow_item_geneve_opt opt_spec = {
			.option_class = RTE_BE16(0x1234),
			.option_type = 0xaa,
			.option_len = 2,
			.data = opt_data,
		};
		const struct rte_flow_item_geneve_opt opt_mask = {
			.option_type = 0xff,
			.data = opt_data_mask,
		};
		uint32_t cmp_value = 0x12345678;
		const struct rte_flow_item_compare cmp_spec = {
			.operation = RTE_FLOW_ITEM_COMPARE_GT,
			.a = {
				.field = RTE_FLOW_FIELD_TAG,
				.tag_index = 1,
			},
			.b = {
				.field = RTE_FLOW_FIELD_POINTER,
				.pvalue = &cmp_value,
			},
			.width = 32,
		};
		const struct rte_flow_item_compare cmp_mask = {
			.width = UINT32_MAX,
		};
		const struct rte_flow_item_tag tag_spec = {
			.data = 0x12345678,
			.index = 3,
		};
		const struct rte_flow_item_tag tag_last = {
			.data = 0xabcdef01,
			.index = 3,
		};
		const struct rte_flow_item_tag tag_mask = {
			.data = 0x00ff00ff,
			.index = 0,
		};
		const struct rte_flow_item limits[] = {
			{
				.type = RTE_FLOW_ITEM_TYPE_IPV4,
				.spec = &ipv4_open,
				.last = &ipv4_open,
			},
			{
				.type = RTE_FLOW_ITEM_TYPE_IPV4,
				.spec = &ipv4_spec,
				.last = &ipv4_last,
				.mask = &ipv4_mask,
			},
			{
				.type = (enum rte_flow_item_type)-1,
				.spec = &priv_spec,
				.mask = &priv_mask,
			},
			{
				.type = RTE_FLOW_ITEM_TYPE_GENEVE_OPT,
				.spec = &opt_spec,
				.last = &opt_spec,
				.mask = &opt_mask,
			},
			{
				.type = RTE_FLOW_ITEM_TYPE_COMPARE,
				.spec = &cmp_spec,
				.mask = &cmp_mask,
			},
			{
				.type = RTE_FLOW_ITEM_TYPE_TAG,
				.spec = &tag_spec,
				.last = &tag_last,
				.mask = &tag_mask,
			},
			{ .type = RTE_FLOW_ITEM_TYPE_END },
		};
		union {
			struct rte_flow_item item;
			uint8_t buf[1024];
		} conv;
		const struct rte_flow_item *out;
		const struct rte_flow_item_ipv4 *ipv4;
		const struct rte_flow_item_geneve_opt *opt;
		const struct rte_flow_item_compare *cmp;
		const struct rte_flow_item_tag *tag;

		memset(&conv, 0, sizeof(conv));
		ret = rte_flow_conv(RTE_FLOW_CONV_OP_PATTERN_MASKED, conv.buf,
				    sizeof(conv.buf), limits, NULL);
		TEST_ASSERT(ret > 0, "Limit pattern conversion failed");
		TEST_ASSERT((size_t)ret <= sizeof(conv.buf),
			    "Limit pattern conversion needs too much storage");

		out = (const struct rte_flow_item *)conv.buf;
		TEST_ASSERT_NULL(out[0].mask, "NULL mask must stay NULL");
		ipv4 = out[0].spec;
		TEST_ASSERT_NOT_NULL(ipv4, "Unmasked IPv4 spec must be set");
		TEST_ASSERT_EQUAL(ipv4->hdr.type_of_service, 0xab,
				  "NULL mask must not clear IPv4 TOS");
		TEST_ASSERT_EQUAL(ipv4->hdr.time_to_live, 0x40,
				  "NULL mask must not clear IPv4 TTL");
		TEST_ASSERT_EQUAL(ipv4->hdr.src_addr, ipv4_open.hdr.src_addr,
				  "NULL mask must keep IPv4 source address");
		TEST_ASSERT_EQUAL(ipv4->hdr.dst_addr, ipv4_open.hdr.dst_addr,
				  "NULL mask must keep IPv4 destination address");
		ipv4 = out[0].last;
		TEST_ASSERT_NOT_NULL(ipv4, "Unmasked IPv4 last must be set");
		TEST_ASSERT_EQUAL(ipv4->hdr.type_of_service, 0xab,
				  "NULL mask must not clear IPv4 last TOS");
		TEST_ASSERT_EQUAL(ipv4->hdr.time_to_live, 0x40,
				  "NULL mask must not clear IPv4 last TTL");

		ipv4 = out[1].spec;
		TEST_ASSERT_NOT_NULL(ipv4, "Masked IPv4 spec must be set");
		TEST_ASSERT_EQUAL(ipv4->hdr.type_of_service, 0x0b,
				  "IPv4 spec TOS mask mismatch");
		TEST_ASSERT_EQUAL(ipv4->hdr.time_to_live, 0,
				  "IPv4 spec TTL must be cleared by the mask");
		TEST_ASSERT_EQUAL(ipv4->hdr.src_addr, ipv4_spec.hdr.src_addr,
				  "IPv4 spec source address mismatch");
		TEST_ASSERT_EQUAL(ipv4->hdr.dst_addr, RTE_BE32(0x00000002),
				  "IPv4 spec destination address mismatch");
		ipv4 = out[1].last;
		TEST_ASSERT_NOT_NULL(ipv4, "Masked IPv4 last must be set");
		TEST_ASSERT_EQUAL(ipv4->hdr.type_of_service, 0x0d,
				  "IPv4 last TOS mask mismatch");
		TEST_ASSERT_EQUAL(ipv4->hdr.time_to_live, 0,
				  "IPv4 last TTL must be cleared by the mask");
		TEST_ASSERT_EQUAL(ipv4->hdr.src_addr, ipv4_last.hdr.src_addr,
				  "IPv4 last source address mismatch");
		TEST_ASSERT_EQUAL(ipv4->hdr.dst_addr, RTE_BE32(0x0000ffff),
				  "IPv4 last destination address mismatch");

		TEST_ASSERT_NOT_NULL(out[2].spec, "Private spec must be set");
		TEST_ASSERT_BUFFERS_ARE_EQUAL(out[2].spec, &priv_spec,
					      sizeof(void *),
					      "PMD private spec must not be masked");

		opt = out[3].spec;
		TEST_ASSERT_NOT_NULL(opt, "GENEVE_OPT spec must be set");
		TEST_ASSERT_EQUAL(opt->option_class, 0,
				  "GENEVE_OPT class must be masked");
		TEST_ASSERT_EQUAL(opt->option_type, 0xaa,
				  "GENEVE_OPT type mask mismatch");
		TEST_ASSERT_EQUAL(opt->option_len, opt_spec.option_len,
				  "GENEVE_OPT length must not be masked");
		TEST_ASSERT(opt->data != opt_data,
			    "GENEVE_OPT data must be deep-copied");
		TEST_ASSERT_BUFFERS_ARE_EQUAL(opt->data, opt_data, sizeof(opt_data),
					      "GENEVE_OPT data must not be masked");
		opt = out[3].last;
		TEST_ASSERT_NOT_NULL(opt, "GENEVE_OPT last must be set");
		TEST_ASSERT_EQUAL(opt->option_class, 0,
				  "GENEVE_OPT last class must be masked");
		TEST_ASSERT_EQUAL(opt->option_type, 0xaa,
				  "GENEVE_OPT last type mask mismatch");
		TEST_ASSERT_EQUAL(opt->option_len, opt_spec.option_len,
				  "GENEVE_OPT last length must not be masked");
		TEST_ASSERT(opt->data != opt_data,
			    "GENEVE_OPT last data must be deep-copied");
		TEST_ASSERT_BUFFERS_ARE_EQUAL(opt->data, opt_data, sizeof(opt_data),
					      "GENEVE_OPT last data must not be masked");

		cmp = out[4].spec;
		TEST_ASSERT_NOT_NULL(cmp, "COMPARE spec must be set");
		TEST_ASSERT_EQUAL(cmp->operation, RTE_FLOW_ITEM_COMPARE_GT,
				  "COMPARE operation must not be masked");
		TEST_ASSERT_EQUAL(cmp->a.field, RTE_FLOW_FIELD_TAG,
				  "COMPARE field a must not be masked");
		TEST_ASSERT_EQUAL(cmp->a.tag_index, 1,
				  "COMPARE field a tag index must not be masked");
		TEST_ASSERT_EQUAL(cmp->b.field, RTE_FLOW_FIELD_POINTER,
				  "COMPARE field b must not be masked");
		TEST_ASSERT(cmp->b.pvalue == &cmp_value,
			    "COMPARE pointer must not be masked");

		tag = out[5].spec;
		TEST_ASSERT_NOT_NULL(tag, "TAG spec must be set");
		TEST_ASSERT_EQUAL(tag->data, 0x00340078,
				  "TAG spec data mask mismatch");
		TEST_ASSERT_EQUAL(tag->index, tag_spec.index,
				  "TAG spec index must not be masked");
		tag = out[5].last;
		TEST_ASSERT_NOT_NULL(tag, "TAG last must be set");
		TEST_ASSERT_EQUAL(tag->data, 0x00cd0001,
				  "TAG last data mask mismatch");
		TEST_ASSERT_EQUAL(tag->index, tag_last.index,
				  "TAG last index must not be masked");
		tag = out[5].mask;
		TEST_ASSERT_NOT_NULL(tag, "TAG mask must be set");
		TEST_ASSERT_EQUAL(tag->data, tag_mask.data,
				  "TAG data mask must not change");
		TEST_ASSERT_EQUAL(tag->index, tag_mask.index,
				  "TAG index mask must not change");
	}

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

static struct unit_test_suite ethdev_flow_conv_testsuite = {
	.suite_name = "ethdev flow conversion tests",
	.setup = NULL,
	.teardown = NULL,
	.unit_test_cases = {
		TEST_CASE(ethdev_api_flow_conv_pattern_masked),
		TEST_CASES_END()
	}
};

static int
test_ethdev_flow_conv(void)
{
	return unit_test_suite_runner(&ethdev_flow_conv_testsuite);
}

REGISTER_FAST_TEST(ethdev_flow_conv, NOHUGE_OK, ASAN_OK, test_ethdev_flow_conv);

static struct unit_test_suite ethdev_api_testsuite = {
	.suite_name = "ethdev API tests",
	.setup = NULL,
	.teardown = NULL,
	.unit_test_cases = {
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

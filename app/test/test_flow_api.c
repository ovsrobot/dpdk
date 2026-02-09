/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Stephen Hemminger
 */

/*
 * Unit tests for the rte_flow generic flow API (rte_flow.h).
 *
 * These tests exercise the full rte_flow code path through the null PMD,
 * which implements flow_ops that validate input and reject all rules with
 * properly typed rte_flow_error responses.  This lets us verify:
 *
 *   1. Specific error types (TYPE_ITEM, TYPE_ACTION, TYPE_ATTR_*, etc.)
 *      are reported for each class of rejection.
 *   2. The `cause` pointer in rte_flow_error points at the offending
 *      pattern item, action, or attribute structure.
 *   3. Descriptive error messages are propagated to the caller.
 *   4. Utility functions (rte_flow_error_set, rte_flow_conv) work.
 *   5. Edge cases (NULL pointers, invalid ports, VOID items) are
 *      handled without crashes.
 *
 * The test requires that net_null is built with null_flow.c (the stub
 * flow ops).  It is registered as a fast-test and can run with --no-huge.
 */

#include <string.h>
#include <errno.h>

#include <rte_common.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_malloc.h>
#include <rte_bus_vdev.h>

#include "test.h"

/* --------------------------------------------------------------------------
 * Constants
 * -------------------------------------------------------------------------- */

#define TEST_NULL_VDEV_NAME "net_null_flow_test"

static uint16_t test_port_id;
static int port_created;
static struct rte_mempool *mp;

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode = RTE_ETH_MQ_RX_NONE,
	},
	.txmode = {
		.mq_mode = RTE_ETH_MQ_TX_NONE,
	},
};

/* --------------------------------------------------------------------------
 * Suite setup / teardown
 * -------------------------------------------------------------------------- */

static int
testsuite_setup(void)
{
	int ret;

	ret = rte_vdev_init(TEST_NULL_VDEV_NAME, "copy=0");
	if (ret < 0) {
		printf("TEST-FLOW: failed to create net_null vdev: %s\n",
		       rte_strerror(-ret));
		return TEST_SKIPPED;
	}
	port_created = 1;

	if (rte_eth_dev_count_avail() == 0) {
		printf("TEST-FLOW: no available ports after vdev init\n");
		return TEST_SKIPPED;
	}

	RTE_ETH_FOREACH_DEV(test_port_id)
		break;

	mp = rte_pktmbuf_pool_create("flow_test_pool", 256, 32, 0,
				     RTE_MBUF_DEFAULT_BUF_SIZE,
				     rte_socket_id());
	if (mp == NULL) {
		printf("TEST-FLOW: mempool creation failed\n");
		return TEST_FAILED;
	}

	ret = rte_eth_dev_configure(test_port_id, 1, 1, &port_conf);
	if (ret < 0) {
		printf("TEST-FLOW: port configure failed: %s\n",
		       rte_strerror(-ret));
		return TEST_FAILED;
	}

	ret = rte_eth_rx_queue_setup(test_port_id, 0, 64,
				     rte_eth_dev_socket_id(test_port_id),
				     NULL, mp);
	if (ret < 0)
		return TEST_FAILED;

	ret = rte_eth_tx_queue_setup(test_port_id, 0, 64,
				     rte_eth_dev_socket_id(test_port_id),
				     NULL);
	if (ret < 0)
		return TEST_FAILED;

	ret = rte_eth_dev_start(test_port_id);
	if (ret < 0)
		return TEST_FAILED;

	/*
	 * Verify the PMD actually has flow ops.  If it returns -ENOSYS
	 * that means null_flow.c was not linked — skip the suite.
	 */
	{
		struct rte_flow_attr attr = { .ingress = 1 };
		struct rte_flow_item pattern[] = {
			{ .type = RTE_FLOW_ITEM_TYPE_END },
		};
		struct rte_flow_action actions[] = {
			{ .type = RTE_FLOW_ACTION_TYPE_END },
		};
		struct rte_flow_error error;

		ret = rte_flow_validate(test_port_id, &attr,
					pattern, actions, &error);
		if (ret == -ENOSYS) {
			printf("TEST-FLOW: null PMD has no flow_ops "
			       "(null_flow.c not linked) — skipping\n");
			return TEST_SKIPPED;
		}
	}

	return TEST_SUCCESS;
}

static void
testsuite_teardown(void)
{
	if (rte_eth_dev_is_valid_port(test_port_id)) {
		rte_eth_dev_stop(test_port_id);
		rte_eth_dev_close(test_port_id);
	}
	if (port_created)
		rte_vdev_uninit(TEST_NULL_VDEV_NAME);
	if (mp != NULL)
		rte_mempool_free(mp);
}

/* --------------------------------------------------------------------------
 * Helper builders
 * -------------------------------------------------------------------------- */

static void
build_eth_ipv4_pattern(struct rte_flow_item pattern[3])
{
	memset(pattern, 0, 3 * sizeof(struct rte_flow_item));
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[2].type = RTE_FLOW_ITEM_TYPE_END;
}

static void
build_drop_actions(struct rte_flow_action actions[2])
{
	memset(actions, 0, 2 * sizeof(struct rte_flow_action));
	actions[0].type = RTE_FLOW_ACTION_TYPE_DROP;
	actions[1].type = RTE_FLOW_ACTION_TYPE_END;
}

static void
build_queue_actions(struct rte_flow_action actions[2],
		    struct rte_flow_action_queue *q)
{
	memset(actions, 0, 2 * sizeof(struct rte_flow_action));
	memset(q, 0, sizeof(*q));
	q->index = 0;
	actions[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	actions[0].conf = q;
	actions[1].type = RTE_FLOW_ACTION_TYPE_END;
}

/* ==========================================================================
 *  Group 1: rte_flow_error_set() utility
 * ========================================================================== */

static int
test_error_set_basic(void)
{
	struct rte_flow_error error;
	int dummy = 42;
	int ret;

	memset(&error, 0x55, sizeof(error));

	ret = rte_flow_error_set(&error, EINVAL,
				 RTE_FLOW_ERROR_TYPE_ATTR,
				 &dummy,
				 "test error message");

	RTE_TEST_ASSERT(ret < 0,
			"error_set should return negative");
	RTE_TEST_ASSERT_EQUAL(error.type, RTE_FLOW_ERROR_TYPE_ATTR,
			      "error type mismatch");
	RTE_TEST_ASSERT(error.cause == &dummy,
			"cause pointer mismatch");
	RTE_TEST_ASSERT(error.message != NULL &&
			strcmp(error.message, "test error message") == 0,
			"message mismatch");
	RTE_TEST_ASSERT_EQUAL(rte_errno, EINVAL,
			      "rte_errno mismatch");

	/* NULL error pointer — must not crash. */
	ret = rte_flow_error_set(NULL, ENOTSUP,
				 RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				 NULL, NULL);
	RTE_TEST_ASSERT(ret < 0,
			"error_set(NULL) should return negative");

	return TEST_SUCCESS;
}

static int
test_error_set_type_none(void)
{
	struct rte_flow_error error;

	memset(&error, 0xFF, sizeof(error));
	rte_flow_error_set(&error, 0,
			   RTE_FLOW_ERROR_TYPE_NONE,
			   NULL, NULL);

	RTE_TEST_ASSERT_EQUAL(error.type, RTE_FLOW_ERROR_TYPE_NONE,
			      "type should be NONE");
	RTE_TEST_ASSERT(error.cause == NULL, "cause should be NULL");
	RTE_TEST_ASSERT(error.message == NULL, "message should be NULL");

	return TEST_SUCCESS;
}

static int
test_error_set_all_types(void)
{
	struct rte_flow_error error;
	static const enum rte_flow_error_type types[] = {
		RTE_FLOW_ERROR_TYPE_NONE,
		RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
		RTE_FLOW_ERROR_TYPE_HANDLE,
		RTE_FLOW_ERROR_TYPE_ATTR_GROUP,
		RTE_FLOW_ERROR_TYPE_ATTR_PRIORITY,
		RTE_FLOW_ERROR_TYPE_ATTR_INGRESS,
		RTE_FLOW_ERROR_TYPE_ATTR_EGRESS,
		RTE_FLOW_ERROR_TYPE_ATTR,
		RTE_FLOW_ERROR_TYPE_ITEM_NUM,
		RTE_FLOW_ERROR_TYPE_ITEM_SPEC,
		RTE_FLOW_ERROR_TYPE_ITEM_LAST,
		RTE_FLOW_ERROR_TYPE_ITEM_MASK,
		RTE_FLOW_ERROR_TYPE_ITEM,
		RTE_FLOW_ERROR_TYPE_ACTION_NUM,
		RTE_FLOW_ERROR_TYPE_ACTION_CONF,
		RTE_FLOW_ERROR_TYPE_ACTION,
	};
	unsigned int i;

	for (i = 0; i < RTE_DIM(types); i++) {
		memset(&error, 0xFF, sizeof(error));
		rte_flow_error_set(&error, EINVAL, types[i], NULL, NULL);
		RTE_TEST_ASSERT_EQUAL((int)error.type, (int)types[i],
				      "type mismatch at index %u", i);
	}
	return TEST_SUCCESS;
}

/* ==========================================================================
 *  Group 2: validate — attribute rejection
 * ========================================================================== */

static int
test_validate_no_direction(void)
{
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[3];
	struct rte_flow_action actions[2];
	struct rte_flow_error error;
	int ret;

	memset(&attr, 0, sizeof(attr));
	build_eth_ipv4_pattern(pattern);
	build_drop_actions(actions);
	memset(&error, 0, sizeof(error));

	ret = rte_flow_validate(test_port_id, &attr, pattern, actions, &error);

	RTE_TEST_ASSERT(ret != 0, "should reject no-direction rule");
	RTE_TEST_ASSERT_EQUAL(error.type, RTE_FLOW_ERROR_TYPE_ATTR,
			      "error type should be ATTR");
	RTE_TEST_ASSERT(error.message != NULL,
			"error message should be set");

	return TEST_SUCCESS;
}

static int
test_validate_transfer_rejected(void)
{
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[3];
	struct rte_flow_action actions[2];
	struct rte_flow_error error;
	int ret;

	memset(&attr, 0, sizeof(attr));
	attr.transfer = 1;
	build_eth_ipv4_pattern(pattern);
	build_drop_actions(actions);
	memset(&error, 0, sizeof(error));

	ret = rte_flow_validate(test_port_id, &attr, pattern, actions, &error);

	RTE_TEST_ASSERT(ret != 0, "transfer should be rejected");
	RTE_TEST_ASSERT_EQUAL(error.type, RTE_FLOW_ERROR_TYPE_ATTR_TRANSFER,
			      "should be ATTR_TRANSFER");

	return TEST_SUCCESS;
}

static int
test_validate_group_rejected(void)
{
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[3];
	struct rte_flow_action actions[2];
	struct rte_flow_error error;
	int ret;

	memset(&attr, 0, sizeof(attr));
	attr.ingress = 1;
	attr.group = 5;
	build_eth_ipv4_pattern(pattern);
	build_drop_actions(actions);
	memset(&error, 0, sizeof(error));

	ret = rte_flow_validate(test_port_id, &attr, pattern, actions, &error);

	RTE_TEST_ASSERT(ret != 0, "group > 0 should be rejected");
	RTE_TEST_ASSERT_EQUAL(error.type, RTE_FLOW_ERROR_TYPE_ATTR_GROUP,
			      "should be ATTR_GROUP");
	RTE_TEST_ASSERT_EQUAL(rte_errno, ENOTSUP, "errno should be ENOTSUP");

	return TEST_SUCCESS;
}

static int
test_validate_priority_rejected(void)
{
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[3];
	struct rte_flow_action actions[2];
	struct rte_flow_error error;
	int ret;

	memset(&attr, 0, sizeof(attr));
	attr.ingress = 1;
	attr.priority = 7;
	build_eth_ipv4_pattern(pattern);
	build_drop_actions(actions);
	memset(&error, 0, sizeof(error));

	ret = rte_flow_validate(test_port_id, &attr, pattern, actions, &error);

	RTE_TEST_ASSERT(ret != 0, "priority > 0 should be rejected");
	RTE_TEST_ASSERT_EQUAL(error.type, RTE_FLOW_ERROR_TYPE_ATTR_PRIORITY,
			      "should be ATTR_PRIORITY");

	return TEST_SUCCESS;
}

/* ==========================================================================
 *  Group 3: validate — pattern item rejection with cause pointer
 * ========================================================================== */

static int
test_validate_item_rejected(void)
{
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[3];
	struct rte_flow_action actions[2];
	struct rte_flow_error error;
	int ret;

	memset(&attr, 0, sizeof(attr));
	attr.ingress = 1;
	build_eth_ipv4_pattern(pattern);
	build_drop_actions(actions);
	memset(&error, 0, sizeof(error));

	ret = rte_flow_validate(test_port_id, &attr, pattern, actions, &error);

	RTE_TEST_ASSERT(ret != 0, "ETH item should be rejected");
	RTE_TEST_ASSERT_EQUAL(error.type, RTE_FLOW_ERROR_TYPE_ITEM,
			      "should be TYPE_ITEM");
	RTE_TEST_ASSERT(error.cause == &pattern[0],
			"cause should point at pattern[0] (ETH)");
	RTE_TEST_ASSERT_EQUAL(rte_errno, ENOTSUP, "errno should be ENOTSUP");
	RTE_TEST_ASSERT(error.message != NULL, "should have a message");

	return TEST_SUCCESS;
}

static int
test_validate_void_then_real_item(void)
{
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[5];
	struct rte_flow_action actions[2];
	struct rte_flow_error error;
	int ret;

	memset(&attr, 0, sizeof(attr));
	attr.ingress = 1;

	memset(pattern, 0, sizeof(pattern));
	pattern[0].type = RTE_FLOW_ITEM_TYPE_VOID;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[2].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[3].type = RTE_FLOW_ITEM_TYPE_END;

	build_drop_actions(actions);
	memset(&error, 0, sizeof(error));

	ret = rte_flow_validate(test_port_id, &attr, pattern, actions, &error);

	RTE_TEST_ASSERT(ret != 0, "should be rejected");
	RTE_TEST_ASSERT_EQUAL(error.type, RTE_FLOW_ERROR_TYPE_ITEM,
			      "should be TYPE_ITEM");
	RTE_TEST_ASSERT(error.cause == &pattern[1],
			"cause should skip VOID, point at ETH (pattern[1])");

	return TEST_SUCCESS;
}

static int
test_validate_ipv4_with_spec_mask(void)
{
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[4];
	struct rte_flow_action actions[2];
	struct rte_flow_error error;
	struct rte_flow_item_eth eth_spec, eth_mask;
	struct rte_flow_item_ipv4 ipv4_spec, ipv4_mask;
	int ret;

	memset(&attr, 0, sizeof(attr));
	attr.ingress = 1;

	memset(&eth_spec, 0, sizeof(eth_spec));
	memset(&eth_mask, 0, sizeof(eth_mask));
	eth_spec.hdr.ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
	eth_mask.hdr.ether_type = 0xFFFF;

	memset(&ipv4_spec, 0, sizeof(ipv4_spec));
	memset(&ipv4_mask, 0, sizeof(ipv4_mask));
	ipv4_spec.hdr.dst_addr = rte_cpu_to_be_32(0xC0A80001);
	ipv4_mask.hdr.dst_addr = 0xFFFFFFFF;

	memset(pattern, 0, sizeof(pattern));
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[0].spec = &eth_spec;
	pattern[0].mask = &eth_mask;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[1].spec = &ipv4_spec;
	pattern[1].mask = &ipv4_mask;
	pattern[2].type = RTE_FLOW_ITEM_TYPE_END;

	build_drop_actions(actions);
	memset(&error, 0, sizeof(error));

	ret = rte_flow_validate(test_port_id, &attr, pattern, actions, &error);

	RTE_TEST_ASSERT(ret != 0, "should be rejected");
	RTE_TEST_ASSERT_EQUAL(error.type, RTE_FLOW_ERROR_TYPE_ITEM,
			      "should be TYPE_ITEM");
	RTE_TEST_ASSERT(error.cause == &pattern[0],
			"cause should point at first real item");

	return TEST_SUCCESS;
}

/* ==========================================================================
 *  Group 4: validate — action rejection with cause pointer
 * ========================================================================== */

static int
test_validate_action_drop_rejected(void)
{
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[2];
	struct rte_flow_action actions[2];
	struct rte_flow_error error;
	int ret;

	memset(&attr, 0, sizeof(attr));
	attr.ingress = 1;

	memset(pattern, 0, sizeof(pattern));
	pattern[0].type = RTE_FLOW_ITEM_TYPE_END;

	build_drop_actions(actions);
	memset(&error, 0, sizeof(error));

	ret = rte_flow_validate(test_port_id, &attr, pattern, actions, &error);

	RTE_TEST_ASSERT(ret != 0, "DROP should be rejected");
	RTE_TEST_ASSERT_EQUAL(error.type, RTE_FLOW_ERROR_TYPE_ACTION,
			      "should be TYPE_ACTION");
	RTE_TEST_ASSERT(error.cause == &actions[0],
			"cause should point at the DROP action");

	return TEST_SUCCESS;
}

static int
test_validate_action_queue_rejected(void)
{
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[2];
	struct rte_flow_action actions[2];
	struct rte_flow_action_queue queue_conf;
	struct rte_flow_error error;
	int ret;

	memset(&attr, 0, sizeof(attr));
	attr.ingress = 1;

	memset(pattern, 0, sizeof(pattern));
	pattern[0].type = RTE_FLOW_ITEM_TYPE_END;

	build_queue_actions(actions, &queue_conf);
	memset(&error, 0, sizeof(error));

	ret = rte_flow_validate(test_port_id, &attr, pattern, actions, &error);

	RTE_TEST_ASSERT(ret != 0, "QUEUE should be rejected");
	RTE_TEST_ASSERT_EQUAL(error.type, RTE_FLOW_ERROR_TYPE_ACTION,
			      "should be TYPE_ACTION");
	RTE_TEST_ASSERT(error.cause == &actions[0],
			"cause should point at the QUEUE action");

	return TEST_SUCCESS;
}

static int
test_validate_void_only_rejected(void)
{
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[2];
	struct rte_flow_action actions[3];
	struct rte_flow_error error;
	int ret;

	memset(&attr, 0, sizeof(attr));
	attr.ingress = 1;

	memset(pattern, 0, sizeof(pattern));
	pattern[0].type = RTE_FLOW_ITEM_TYPE_END;

	memset(actions, 0, sizeof(actions));
	actions[0].type = RTE_FLOW_ACTION_TYPE_VOID;
	actions[1].type = RTE_FLOW_ACTION_TYPE_END;

	memset(&error, 0, sizeof(error));
	ret = rte_flow_validate(test_port_id, &attr, pattern, actions, &error);

	RTE_TEST_ASSERT(ret != 0, "VOID-only should still be rejected");
	RTE_TEST_ASSERT_EQUAL(error.type, RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
			      "should be UNSPECIFIED (generic reject)");
	RTE_TEST_ASSERT_EQUAL(rte_errno, ENOTSUP, "errno should be ENOTSUP");

	return TEST_SUCCESS;
}

static int
test_validate_action_mark_first(void)
{
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[2];
	struct rte_flow_action actions[4];
	struct rte_flow_action_mark mark_conf;
	struct rte_flow_action_queue queue_conf;
	struct rte_flow_error error;
	int ret;

	memset(&attr, 0, sizeof(attr));
	attr.ingress = 1;

	memset(pattern, 0, sizeof(pattern));
	pattern[0].type = RTE_FLOW_ITEM_TYPE_END;

	memset(actions, 0, sizeof(actions));
	memset(&mark_conf, 0, sizeof(mark_conf));
	memset(&queue_conf, 0, sizeof(queue_conf));
	mark_conf.id = 0xBEEF;
	queue_conf.index = 0;
	actions[0].type = RTE_FLOW_ACTION_TYPE_MARK;
	actions[0].conf = &mark_conf;
	actions[1].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	actions[1].conf = &queue_conf;
	actions[2].type = RTE_FLOW_ACTION_TYPE_END;

	memset(&error, 0, sizeof(error));
	ret = rte_flow_validate(test_port_id, &attr, pattern, actions, &error);

	RTE_TEST_ASSERT(ret != 0, "MARK+QUEUE should be rejected");
	RTE_TEST_ASSERT_EQUAL(error.type, RTE_FLOW_ERROR_TYPE_ACTION,
			      "should be TYPE_ACTION");
	RTE_TEST_ASSERT(error.cause == &actions[0],
			"cause should point at MARK (first non-VOID)");

	return TEST_SUCCESS;
}

/* ==========================================================================
 *  Group 5: rte_flow_create()
 * ========================================================================== */

static int
test_create_returns_null(void)
{
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[3];
	struct rte_flow_action actions[2];
	struct rte_flow_error error;
	struct rte_flow *flow;

	memset(&attr, 0, sizeof(attr));
	attr.ingress = 1;
	build_eth_ipv4_pattern(pattern);
	build_drop_actions(actions);
	memset(&error, 0, sizeof(error));

	flow = rte_flow_create(test_port_id, &attr, pattern, actions, &error);

	RTE_TEST_ASSERT(flow == NULL, "create should return NULL");
	RTE_TEST_ASSERT(error.type != RTE_FLOW_ERROR_TYPE_NONE,
			"error type should be set");
	RTE_TEST_ASSERT(error.message != NULL, "should have a message");

	return TEST_SUCCESS;
}

static int
test_create_invalid_port(void)
{
	struct rte_flow_attr attr = { .ingress = 1 };
	struct rte_flow_item pattern[3];
	struct rte_flow_action actions[2];
	struct rte_flow_error error;

	build_eth_ipv4_pattern(pattern);
	build_drop_actions(actions);
	memset(&error, 0, sizeof(error));

	RTE_TEST_ASSERT(rte_flow_create(RTE_MAX_ETHPORTS, &attr,
					pattern, actions, &error) == NULL,
			"create must fail on invalid port");

	return TEST_SUCCESS;
}

static int
test_create_null_error(void)
{
	struct rte_flow_attr attr = { .ingress = 1 };
	struct rte_flow_item pattern[3];
	struct rte_flow_action actions[2];

	build_eth_ipv4_pattern(pattern);
	build_drop_actions(actions);

	RTE_TEST_ASSERT(rte_flow_create(test_port_id, &attr,
					pattern, actions, NULL) == NULL,
			"create(null error) should return NULL");

	return TEST_SUCCESS;
}

/* ==========================================================================
 *  Group 6: rte_flow_destroy()
 * ========================================================================== */

static int
test_destroy_null_handle(void)
{
	struct rte_flow_error error;

	memset(&error, 0, sizeof(error));
	int ret = rte_flow_destroy(test_port_id, NULL, &error);

	RTE_TEST_ASSERT(ret != 0, "destroy(NULL) should fail");
	RTE_TEST_ASSERT_EQUAL(error.type, RTE_FLOW_ERROR_TYPE_HANDLE,
			      "should be TYPE_HANDLE");
	RTE_TEST_ASSERT_EQUAL(rte_errno, ENOENT, "errno should be ENOENT");
	RTE_TEST_ASSERT(error.message != NULL, "should have a message");

	return TEST_SUCCESS;
}

static int
test_destroy_invalid_port(void)
{
	struct rte_flow_error error;

	memset(&error, 0, sizeof(error));
	RTE_TEST_ASSERT(rte_flow_destroy(RTE_MAX_ETHPORTS, NULL, &error) != 0,
			"destroy should fail on bad port");

	return TEST_SUCCESS;
}

/* ==========================================================================
 *  Group 7: rte_flow_flush()
 * ========================================================================== */

static int
test_flush_succeeds(void)
{
	struct rte_flow_error error;

	memset(&error, 0, sizeof(error));
	RTE_TEST_ASSERT_EQUAL(rte_flow_flush(test_port_id, &error), 0,
			      "flush should succeed (nothing to flush)");

	return TEST_SUCCESS;
}

static int
test_flush_invalid_port(void)
{
	struct rte_flow_error error;

	memset(&error, 0, sizeof(error));
	RTE_TEST_ASSERT(rte_flow_flush(RTE_MAX_ETHPORTS, &error) != 0,
			"flush bad port should fail");

	return TEST_SUCCESS;
}

static int
test_flush_null_error(void)
{
	RTE_TEST_ASSERT_EQUAL(rte_flow_flush(test_port_id, NULL), 0,
			      "flush(null error) should succeed");

	return TEST_SUCCESS;
}

/* ==========================================================================
 *  Group 8: rte_flow_query()
 * ========================================================================== */

static int
test_query_rejected(void)
{
	struct rte_flow_action action = {
		.type = RTE_FLOW_ACTION_TYPE_COUNT,
	};
	struct rte_flow_query_count count;
	struct rte_flow_error error;

	memset(&count, 0, sizeof(count));
	memset(&error, 0, sizeof(error));

	int ret = rte_flow_query(test_port_id, NULL, &action, &count, &error);

	RTE_TEST_ASSERT(ret != 0, "query should fail");
	RTE_TEST_ASSERT_EQUAL(error.type, RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
			      "should be UNSPECIFIED");
	RTE_TEST_ASSERT_EQUAL(rte_errno, ENOTSUP, "errno should be ENOTSUP");

	return TEST_SUCCESS;
}

static int
test_query_invalid_port(void)
{
	struct rte_flow_action action = {
		.type = RTE_FLOW_ACTION_TYPE_COUNT,
	};
	struct rte_flow_query_count count;
	struct rte_flow_error error;

	memset(&count, 0, sizeof(count));
	memset(&error, 0, sizeof(error));

	RTE_TEST_ASSERT(rte_flow_query(RTE_MAX_ETHPORTS, NULL,
				       &action, &count, &error) != 0,
			"query bad port should fail");

	return TEST_SUCCESS;
}

/* ==========================================================================
 *  Group 9: rte_flow_isolate()
 * ========================================================================== */

static int
test_isolate_rejected(void)
{
	struct rte_flow_error error;

	memset(&error, 0, sizeof(error));
	int ret = rte_flow_isolate(test_port_id, 1, &error);

	RTE_TEST_ASSERT(ret != 0, "isolate should fail");
	RTE_TEST_ASSERT_EQUAL(error.type, RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
			      "should be UNSPECIFIED");
	RTE_TEST_ASSERT_EQUAL(rte_errno, ENOTSUP, "errno should be ENOTSUP");

	memset(&error, 0, sizeof(error));
	RTE_TEST_ASSERT(rte_flow_isolate(test_port_id, 0, &error) != 0,
			"isolate(0) should also fail");

	return TEST_SUCCESS;
}

static int
test_isolate_invalid_port(void)
{
	struct rte_flow_error error;

	memset(&error, 0, sizeof(error));
	RTE_TEST_ASSERT(rte_flow_isolate(RTE_MAX_ETHPORTS, 1, &error) != 0,
			"isolate bad port should fail");

	return TEST_SUCCESS;
}

/* ==========================================================================
 *  Group 10: rte_flow_conv() utilities
 * ========================================================================== */

static int
test_conv_item_name(void)
{
	const char *name = NULL;

	int ret = rte_flow_conv(RTE_FLOW_CONV_OP_ITEM_NAME_PTR,
				&name, sizeof(name),
				(void *)(uintptr_t)RTE_FLOW_ITEM_TYPE_ETH,
				NULL);
	RTE_TEST_ASSERT(ret > 0, "conv ETH should succeed");
	RTE_TEST_ASSERT(name != NULL, "name should be non-NULL");

	name = NULL;
	rte_flow_conv(RTE_FLOW_CONV_OP_ITEM_NAME_PTR, &name, sizeof(name),
		      (void *)(uintptr_t)RTE_FLOW_ITEM_TYPE_IPV4, NULL);
	RTE_TEST_ASSERT(name != NULL, "IPV4 name should be non-NULL");

	name = NULL;
	rte_flow_conv(RTE_FLOW_CONV_OP_ITEM_NAME_PTR, &name, sizeof(name),
		      (void *)(uintptr_t)RTE_FLOW_ITEM_TYPE_END, NULL);
	RTE_TEST_ASSERT(name != NULL, "END name should be non-NULL");

	return TEST_SUCCESS;
}

static int
test_conv_action_name(void)
{
	const char *name = NULL;

	int ret = rte_flow_conv(RTE_FLOW_CONV_OP_ACTION_NAME_PTR,
				&name, sizeof(name),
				(void *)(uintptr_t)RTE_FLOW_ACTION_TYPE_DROP,
				NULL);
	RTE_TEST_ASSERT(ret > 0, "conv DROP should succeed");
	RTE_TEST_ASSERT(name != NULL, "DROP name should be non-NULL");

	name = NULL;
	rte_flow_conv(RTE_FLOW_CONV_OP_ACTION_NAME_PTR, &name, sizeof(name),
		      (void *)(uintptr_t)RTE_FLOW_ACTION_TYPE_QUEUE, NULL);
	RTE_TEST_ASSERT(name != NULL, "QUEUE name should be non-NULL");

	return TEST_SUCCESS;
}

static int
test_conv_zero_len(void)
{
	int ret = rte_flow_conv(RTE_FLOW_CONV_OP_ITEM_NAME_PTR,
				NULL, 0,
				(void *)(uintptr_t)RTE_FLOW_ITEM_TYPE_ETH,
				NULL);
	RTE_TEST_ASSERT(ret != 0, "should return non-zero");

	return TEST_SUCCESS;
}

/* ==========================================================================
 *  Group 11: Egress direction and NULL error pointer
 * ========================================================================== */

static int
test_validate_egress(void)
{
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[3];
	struct rte_flow_action actions[2];
	struct rte_flow_error error;

	memset(&attr, 0, sizeof(attr));
	attr.egress = 1;
	build_eth_ipv4_pattern(pattern);
	build_drop_actions(actions);
	memset(&error, 0, sizeof(error));

	int ret = rte_flow_validate(test_port_id, &attr,
				    pattern, actions, &error);

	RTE_TEST_ASSERT(ret != 0, "egress rule should be rejected");
	RTE_TEST_ASSERT_EQUAL(error.type, RTE_FLOW_ERROR_TYPE_ITEM,
			      "should be TYPE_ITEM for egress too");

	return TEST_SUCCESS;
}

static int
test_validate_null_error(void)
{
	struct rte_flow_attr attr = { .ingress = 1 };
	struct rte_flow_item pattern[3];
	struct rte_flow_action actions[2];

	build_eth_ipv4_pattern(pattern);
	build_drop_actions(actions);

	RTE_TEST_ASSERT(rte_flow_validate(test_port_id, &attr,
					  pattern, actions, NULL) != 0,
			"validate(null error) should still fail");

	return TEST_SUCCESS;
}

/* ==========================================================================
 *  Suite definition
 * ========================================================================== */

static struct unit_test_suite flow_api_testsuite = {
	.suite_name = "rte_flow API unit tests",
	.setup = testsuite_setup,
	.teardown = testsuite_teardown,
	.unit_test_cases = {
		/* Error utility */
		TEST_CASE(test_error_set_basic),
		TEST_CASE(test_error_set_type_none),
		TEST_CASE(test_error_set_all_types),

		/* Validate — attributes */
		TEST_CASE(test_validate_no_direction),
		TEST_CASE(test_validate_transfer_rejected),
		TEST_CASE(test_validate_group_rejected),
		TEST_CASE(test_validate_priority_rejected),
		TEST_CASE(test_validate_egress),
		TEST_CASE(test_validate_null_error),

		/* Validate — pattern items */
		TEST_CASE(test_validate_item_rejected),
		TEST_CASE(test_validate_void_then_real_item),
		TEST_CASE(test_validate_ipv4_with_spec_mask),

		/* Validate — actions */
		TEST_CASE(test_validate_action_drop_rejected),
		TEST_CASE(test_validate_action_queue_rejected),
		TEST_CASE(test_validate_void_only_rejected),
		TEST_CASE(test_validate_action_mark_first),

		/* Create */
		TEST_CASE(test_create_returns_null),
		TEST_CASE(test_create_invalid_port),
		TEST_CASE(test_create_null_error),

		/* Destroy */
		TEST_CASE(test_destroy_null_handle),
		TEST_CASE(test_destroy_invalid_port),

		/* Flush */
		TEST_CASE(test_flush_succeeds),
		TEST_CASE(test_flush_invalid_port),
		TEST_CASE(test_flush_null_error),

		/* Query */
		TEST_CASE(test_query_rejected),
		TEST_CASE(test_query_invalid_port),

		/* Isolate */
		TEST_CASE(test_isolate_rejected),
		TEST_CASE(test_isolate_invalid_port),

		/* Conv utilities */
		TEST_CASE(test_conv_item_name),
		TEST_CASE(test_conv_action_name),
		TEST_CASE(test_conv_zero_len),

		TEST_CASES_END(),
	},
};

static int
test_flow_api(void)
{
	return unit_test_suite_runner(&flow_api_testsuite);
}

REGISTER_FAST_TEST(flow_api_autotest, NOHUGE_OK, ASAN_OK, test_flow_api);

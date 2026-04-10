/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 DynaNIC Semiconductors, Ltd.
 */

/*
 * Tests for the simple flow parser API (rte_flow_parser.h).
 * These tests do NOT require config registration — the simple API
 * is self-contained and works without rte_flow_parser_cmdline.h.
 */

#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <rte_byteorder.h>
#include <rte_flow.h>
#include <rte_flow_parser.h>

#include "test.h"

static int
test_flow_parser_public_attr_parsing(void)
{
	struct rte_flow_attr attr;
	int ret;

	/* Test basic ingress attribute */
	memset(&attr, 0, sizeof(attr));
	ret = rte_flow_parser_parse_attr_str("ingress", &attr);
	TEST_ASSERT_SUCCESS(ret, "ingress attr parse failed: %s",
		strerror(-ret));
	TEST_ASSERT(attr.ingress == 1 && attr.egress == 0,
		"attr flags mismatch ingress=%u egress=%u",
		attr.ingress, attr.egress);

	/* Test egress attribute */
	memset(&attr, 0, sizeof(attr));
	ret = rte_flow_parser_parse_attr_str("egress", &attr);
	TEST_ASSERT_SUCCESS(ret, "egress attr parse failed: %s",
		strerror(-ret));
	TEST_ASSERT(attr.ingress == 0 && attr.egress == 1,
		"attr flags mismatch ingress=%u egress=%u",
		attr.ingress, attr.egress);

	/* Test transfer attribute */
	memset(&attr, 0, sizeof(attr));
	ret = rte_flow_parser_parse_attr_str("transfer", &attr);
	TEST_ASSERT_SUCCESS(ret, "transfer attr parse failed: %s",
		strerror(-ret));
	TEST_ASSERT(attr.transfer == 1, "transfer flag not set");

	/* Test combined attributes with group and priority */
	memset(&attr, 0, sizeof(attr));
	ret = rte_flow_parser_parse_attr_str("ingress group 1 priority 5", &attr);
	TEST_ASSERT_SUCCESS(ret, "combined attr parse failed: %s",
		strerror(-ret));
	TEST_ASSERT_EQUAL(attr.group, 1, "attr group mismatch: %u", attr.group);
	TEST_ASSERT_EQUAL(attr.priority, 5,
		"attr priority mismatch: %u", attr.priority);
	TEST_ASSERT(attr.ingress == 1 && attr.egress == 0,
		"attr flags mismatch ingress=%u egress=%u",
		attr.ingress, attr.egress);

	/* Test multiple direction attributes (last one wins) */
	memset(&attr, 0, sizeof(attr));
	ret = rte_flow_parser_parse_attr_str("ingress egress", &attr);
	TEST_ASSERT_SUCCESS(ret, "multi-direction attr parse failed: %s",
		strerror(-ret));
	TEST_ASSERT(attr.ingress == 1 && attr.egress == 1,
		"both ingress and egress should be set");

	return TEST_SUCCESS;
}

static int
test_flow_parser_public_pattern_parsing(void)
{
	const struct rte_flow_item *pattern = NULL;
	uint32_t pattern_n = 0;
	int ret;

	ret = rte_flow_parser_parse_pattern_str("eth / end",
						&pattern, &pattern_n);
	TEST_ASSERT_SUCCESS(ret, "simple pattern parse failed: %s",
		strerror(-ret));
	TEST_ASSERT_EQUAL(pattern_n, 2, "expected 2 pattern items, got %u",
		pattern_n);
	TEST_ASSERT_EQUAL(pattern[0].type, RTE_FLOW_ITEM_TYPE_ETH,
		"pattern[0] expected ETH, got %d", pattern[0].type);
	TEST_ASSERT_EQUAL(pattern[1].type, RTE_FLOW_ITEM_TYPE_END,
		"pattern[1] expected END, got %d", pattern[1].type);

	ret = rte_flow_parser_parse_pattern_str("eth / ipv4 / end",
						&pattern, &pattern_n);
	TEST_ASSERT_SUCCESS(ret, "eth/ipv4 pattern parse failed: %s",
		strerror(-ret));
	TEST_ASSERT_EQUAL(pattern_n, 3, "expected 3 pattern items, got %u",
		pattern_n);
	TEST_ASSERT_EQUAL(pattern[0].type, RTE_FLOW_ITEM_TYPE_ETH,
		"pattern[0] expected ETH, got %d", pattern[0].type);
	TEST_ASSERT_EQUAL(pattern[1].type, RTE_FLOW_ITEM_TYPE_IPV4,
		"pattern[1] expected IPV4, got %d", pattern[1].type);
	TEST_ASSERT_EQUAL(pattern[2].type, RTE_FLOW_ITEM_TYPE_END,
		"pattern[2] expected END, got %d", pattern[2].type);

	ret = rte_flow_parser_parse_pattern_str("eth / ipv4 / tcp / end",
						&pattern, &pattern_n);
	TEST_ASSERT_SUCCESS(ret, "complex pattern parse failed: %s",
		strerror(-ret));
	TEST_ASSERT_EQUAL(pattern_n, 4, "expected 4 pattern items, got %u",
		pattern_n);
	TEST_ASSERT(pattern[0].type == RTE_FLOW_ITEM_TYPE_ETH &&
		pattern[1].type == RTE_FLOW_ITEM_TYPE_IPV4 &&
		pattern[2].type == RTE_FLOW_ITEM_TYPE_TCP &&
		pattern[3].type == RTE_FLOW_ITEM_TYPE_END,
		"complex pattern type mismatch");

	ret = rte_flow_parser_parse_pattern_str("eth / ipv6 / udp / end",
						&pattern, &pattern_n);
	TEST_ASSERT_SUCCESS(ret, "ipv6/udp pattern parse failed: %s",
		strerror(-ret));
	TEST_ASSERT_EQUAL(pattern_n, 4, "expected 4 pattern items, got %u",
		pattern_n);
	TEST_ASSERT_EQUAL(pattern[1].type, RTE_FLOW_ITEM_TYPE_IPV6,
		"pattern[1] expected IPV6, got %d", pattern[1].type);
	TEST_ASSERT_EQUAL(pattern[2].type, RTE_FLOW_ITEM_TYPE_UDP,
		"pattern[2] expected UDP, got %d", pattern[2].type);

	ret = rte_flow_parser_parse_pattern_str("eth / vlan / ipv4 / end",
						&pattern, &pattern_n);
	TEST_ASSERT_SUCCESS(ret, "vlan pattern parse failed: %s",
		strerror(-ret));
	TEST_ASSERT_EQUAL(pattern_n, 4, "expected 4 pattern items, got %u",
		pattern_n);
	TEST_ASSERT_EQUAL(pattern[1].type, RTE_FLOW_ITEM_TYPE_VLAN,
		"pattern[1] expected VLAN, got %d", pattern[1].type);

	/* Pattern without trailing "/ end" should succeed (auto-appended). */
	ret = rte_flow_parser_parse_pattern_str("eth / ipv4", &pattern, &pattern_n);
	TEST_ASSERT_SUCCESS(ret, "pattern without end should auto-complete: %s",
		strerror(-ret));

	return TEST_SUCCESS;
}

static int
test_flow_parser_public_actions_parsing(void)
{
	const struct rte_flow_action *actions = NULL;
	const struct rte_flow_action_queue *queue_conf;
	const struct rte_flow_action_mark *mark_conf;
	uint32_t actions_n = 0;
	int ret;

	ret = rte_flow_parser_parse_actions_str("drop / end",
						&actions, &actions_n);
	TEST_ASSERT_SUCCESS(ret, "drop action parse failed: %s",
		strerror(-ret));
	TEST_ASSERT_EQUAL(actions_n, 2, "expected 2 action items, got %u",
		actions_n);
	TEST_ASSERT_EQUAL(actions[0].type, RTE_FLOW_ACTION_TYPE_DROP,
		"actions[0] expected DROP, got %d", actions[0].type);
	TEST_ASSERT_EQUAL(actions[1].type, RTE_FLOW_ACTION_TYPE_END,
		"actions[1] expected END, got %d", actions[1].type);

	ret = rte_flow_parser_parse_actions_str("queue index 3 / end",
						&actions, &actions_n);
	TEST_ASSERT_SUCCESS(ret, "queue action parse failed: %s",
		strerror(-ret));
	TEST_ASSERT_EQUAL(actions_n, 2, "expected 2 action items, got %u",
		actions_n);
	TEST_ASSERT_EQUAL(actions[0].type, RTE_FLOW_ACTION_TYPE_QUEUE,
		"actions[0] expected QUEUE, got %d", actions[0].type);
	queue_conf = actions[0].conf;
	TEST_ASSERT_NOT_NULL(queue_conf, "queue action configuration missing");
	TEST_ASSERT_EQUAL(queue_conf->index, 3,
		"queue index expected 3, got %u", queue_conf->index);

	ret = rte_flow_parser_parse_actions_str("mark id 42 / drop / end",
						&actions, &actions_n);
	TEST_ASSERT_SUCCESS(ret, "multi-action parse failed: %s",
		strerror(-ret));
	TEST_ASSERT_EQUAL(actions_n, 3, "expected 3 action items, got %u",
		actions_n);
	TEST_ASSERT_EQUAL(actions[0].type, RTE_FLOW_ACTION_TYPE_MARK,
		"actions[0] expected MARK, got %d", actions[0].type);
	mark_conf = actions[0].conf;
	TEST_ASSERT_NOT_NULL(mark_conf, "mark action configuration missing");
	TEST_ASSERT_EQUAL(mark_conf->id, 42,
		"mark id expected 42, got %u", mark_conf->id);
	TEST_ASSERT_EQUAL(actions[1].type, RTE_FLOW_ACTION_TYPE_DROP,
		"actions[1] expected DROP, got %d", actions[1].type);
	TEST_ASSERT_EQUAL(actions[2].type, RTE_FLOW_ACTION_TYPE_END,
		"actions[2] expected END, got %d", actions[2].type);

	ret = rte_flow_parser_parse_actions_str("rss / end",
						&actions, &actions_n);
	TEST_ASSERT_SUCCESS(ret, "rss action parse failed: %s",
		strerror(-ret));
	TEST_ASSERT_EQUAL(actions[0].type, RTE_FLOW_ACTION_TYPE_RSS,
		"actions[0] expected RSS, got %d", actions[0].type);

	ret = rte_flow_parser_parse_actions_str("count / end",
						&actions, &actions_n);
	TEST_ASSERT_SUCCESS(ret, "count action parse failed: %s",
		strerror(-ret));
	TEST_ASSERT_EQUAL(actions[0].type, RTE_FLOW_ACTION_TYPE_COUNT,
		"actions[0] expected COUNT, got %d", actions[0].type);

	return TEST_SUCCESS;
}

static int
test_flow_parser_public_invalid_args(void)
{
	const struct rte_flow_item *pattern = NULL;
	const struct rte_flow_action *actions = NULL;
	struct rte_flow_attr attr;
	uint32_t count = 0;
	int ret;

	/* Test NULL attribute string */
	ret = rte_flow_parser_parse_attr_str(NULL, &attr);
	TEST_ASSERT_EQUAL(ret, -EINVAL, "NULL attr string should fail");

	/* Test NULL attribute output */
	ret = rte_flow_parser_parse_attr_str("ingress", NULL);
	TEST_ASSERT_EQUAL(ret, -EINVAL, "NULL attr output should fail");

	/* Test NULL pattern string */
	ret = rte_flow_parser_parse_pattern_str(NULL, &pattern, &count);
	TEST_ASSERT_EQUAL(ret, -EINVAL, "NULL pattern string should fail");

	/* Test NULL pattern output */
	ret = rte_flow_parser_parse_pattern_str("eth / end", NULL, &count);
	TEST_ASSERT_EQUAL(ret, -EINVAL, "NULL pattern out should fail");

	/* Test NULL pattern count */
	ret = rte_flow_parser_parse_pattern_str("eth / end", &pattern, NULL);
	TEST_ASSERT_EQUAL(ret, -EINVAL, "NULL pattern count should fail");

	/* Test NULL actions string */
	ret = rte_flow_parser_parse_actions_str(NULL, &actions, &count);
	TEST_ASSERT_EQUAL(ret, -EINVAL, "NULL actions string should fail");

	/* Test NULL actions output */
	ret = rte_flow_parser_parse_actions_str("drop / end", NULL, &count);
	TEST_ASSERT_EQUAL(ret, -EINVAL, "NULL actions out should fail");

	/* Test NULL actions count */
	ret = rte_flow_parser_parse_actions_str("drop / end", &actions, NULL);
	TEST_ASSERT_EQUAL(ret, -EINVAL, "NULL actions count should fail");

	return TEST_SUCCESS;
}

static int
test_flow_parser_public_invalid_syntax(void)
{
	const struct rte_flow_item *pattern = NULL;
	const struct rte_flow_action *actions = NULL;
	struct rte_flow_attr attr;
	uint32_t count = 0;
	int ret;

	/* Invalid attribute syntax */
	ret = rte_flow_parser_parse_attr_str("ingress group", &attr);
	TEST_ASSERT(ret < 0, "expected attr failure for missing group id: %d",
		ret);

	ret = rte_flow_parser_parse_attr_str("priority foo", &attr);
	TEST_ASSERT(ret < 0, "expected attr failure for invalid priority: %d",
		ret);

	ret = rte_flow_parser_parse_attr_str("ingress bogus 1", &attr);
	TEST_ASSERT(ret < 0, "expected attr failure for unknown token: %d",
		ret);

	ret = rte_flow_parser_parse_pattern_str("eth / unknown / end",
		&pattern, &count);
	TEST_ASSERT(ret < 0, "expected pattern failure for unknown item: %d",
		ret);

	ret = rte_flow_parser_parse_pattern_str("", &pattern, &count);
	TEST_ASSERT(ret < 0, "expected pattern failure for empty string: %d",
		ret);

	/* Invalid actions syntax */
	ret = rte_flow_parser_parse_actions_str("queue index / end",
		&actions, &count);
	TEST_ASSERT(ret < 0, "expected actions failure for missing index: %d",
		ret);

	ret = rte_flow_parser_parse_actions_str("mark id / end",
		&actions, &count);
	TEST_ASSERT(ret < 0, "expected actions failure for missing id: %d",
		ret);

	ret = rte_flow_parser_parse_actions_str("bogus / end",
		&actions, &count);
	TEST_ASSERT(ret < 0, "expected actions failure for unknown action: %d",
		ret);

	return TEST_SUCCESS;
}

static int
test_flow_parser_public_parse_flow_rule(void)
{
	struct rte_flow_attr attr;
	const struct rte_flow_item *pattern = NULL;
	uint32_t pattern_n = 0;
	const struct rte_flow_action *actions = NULL;
	uint32_t actions_n = 0;
	int ret;

	/* Basic ingress drop rule */
	ret = rte_flow_parser_parse_flow_rule(
		"ingress pattern eth / ipv4 / end actions drop / end",
		&attr, &pattern, &pattern_n, &actions, &actions_n);
	TEST_ASSERT_SUCCESS(ret, "parse_flow_rule failed: %d", ret);
	TEST_ASSERT(attr.ingress == 1, "expected ingress");
	TEST_ASSERT(attr.egress == 0, "expected no egress");
	TEST_ASSERT(pattern_n >= 3, "expected >= 3 pattern items, got %u",
		pattern_n);
	TEST_ASSERT_EQUAL(pattern[0].type, RTE_FLOW_ITEM_TYPE_ETH,
		"pattern[0] expected ETH");
	TEST_ASSERT_EQUAL(pattern[1].type, RTE_FLOW_ITEM_TYPE_IPV4,
		"pattern[1] expected IPV4");
	TEST_ASSERT_EQUAL(pattern[pattern_n - 1].type, RTE_FLOW_ITEM_TYPE_END,
		"last pattern item expected END");
	TEST_ASSERT(actions_n >= 2, "expected >= 2 actions, got %u", actions_n);
	TEST_ASSERT_EQUAL(actions[0].type, RTE_FLOW_ACTION_TYPE_DROP,
		"actions[0] expected DROP");
	TEST_ASSERT_EQUAL(actions[actions_n - 1].type,
		RTE_FLOW_ACTION_TYPE_END, "last action expected END");

	/* NULL argument checks */
	ret = rte_flow_parser_parse_flow_rule(NULL,
		&attr, &pattern, &pattern_n, &actions, &actions_n);
	TEST_ASSERT(ret < 0, "NULL src should fail");
	ret = rte_flow_parser_parse_flow_rule(
		"ingress pattern eth / end actions drop / end",
		NULL, &pattern, &pattern_n, &actions, &actions_n);
	TEST_ASSERT(ret < 0, "NULL attr should fail");

	/* NULL pattern output */
	ret = rte_flow_parser_parse_flow_rule(
		"ingress pattern eth / end actions drop / end",
		&attr, NULL, &pattern_n, &actions, &actions_n);
	TEST_ASSERT(ret < 0, "NULL pattern should fail");

	/* NULL pattern count */
	ret = rte_flow_parser_parse_flow_rule(
		"ingress pattern eth / end actions drop / end",
		&attr, &pattern, NULL, &actions, &actions_n);
	TEST_ASSERT(ret < 0, "NULL pattern_n should fail");

	/* NULL actions output */
	ret = rte_flow_parser_parse_flow_rule(
		"ingress pattern eth / end actions drop / end",
		&attr, &pattern, &pattern_n, NULL, &actions_n);
	TEST_ASSERT(ret < 0, "NULL actions should fail");

	/* NULL actions count */
	ret = rte_flow_parser_parse_flow_rule(
		"ingress pattern eth / end actions drop / end",
		&attr, &pattern, &pattern_n, &actions, NULL);
	TEST_ASSERT(ret < 0, "NULL actions_n should fail");

	return TEST_SUCCESS;
}

static int
test_flow_parser_no_registration(void)
{
	const struct rte_flow_action *actions = NULL;
	uint32_t actions_n = 0;
	int ret;

	/*
	 * Actions that depend on registered config (vxlan_encap, nvgre_encap,
	 * l2_encap, etc.) must not crash when no config is registered.
	 * The simple API never calls config_register, so the registry is
	 * empty. The parser should either parse successfully with NULL conf
	 * or fail gracefully.
	 */
	ret = rte_flow_parser_parse_actions_str("vxlan_encap / end",
						&actions, &actions_n);
	TEST_ASSERT(ret < 0,
		"vxlan_encap without registration should fail, got %d", ret);

	ret = rte_flow_parser_parse_actions_str("nvgre_encap / end",
						&actions, &actions_n);
	TEST_ASSERT(ret < 0,
		"nvgre_encap without registration should fail, got %d", ret);

	ret = rte_flow_parser_parse_actions_str("l2_encap / end",
						&actions, &actions_n);
	TEST_ASSERT(ret < 0,
		"l2_encap without registration should fail, got %d", ret);

	ret = rte_flow_parser_parse_actions_str("l2_decap / end",
						&actions, &actions_n);
	TEST_ASSERT(ret < 0,
		"l2_decap without registration should fail, got %d", ret);

	/* Non-config-dependent actions should still work */
	ret = rte_flow_parser_parse_actions_str("drop / end",
						&actions, &actions_n);
	TEST_ASSERT_SUCCESS(ret,
		"drop should work without registration: %s", strerror(-ret));
	TEST_ASSERT_EQUAL(actions[0].type, RTE_FLOW_ACTION_TYPE_DROP,
		"expected DROP action");

	ret = rte_flow_parser_parse_actions_str("queue index 0 / end",
						&actions, &actions_n);
	TEST_ASSERT_SUCCESS(ret,
		"queue should work without registration: %s", strerror(-ret));

	return TEST_SUCCESS;
}

static struct unit_test_suite flow_parser_simple_tests = {
	.suite_name = "flow parser simple API autotest",
	.unit_test_cases = {
		TEST_CASE(test_flow_parser_public_attr_parsing),
		TEST_CASE(test_flow_parser_public_pattern_parsing),
		TEST_CASE(test_flow_parser_public_actions_parsing),
		TEST_CASE(test_flow_parser_public_invalid_args),
		TEST_CASE(test_flow_parser_public_invalid_syntax),
		TEST_CASE(test_flow_parser_public_parse_flow_rule),
		TEST_CASE(test_flow_parser_no_registration),
		TEST_CASES_END()
	}
};

static int
test_flow_parser_simple(void)
{
	return unit_test_suite_runner(&flow_parser_simple_tests);
}

REGISTER_FAST_TEST(flow_parser_simple_autotest, NOHUGE_OK, ASAN_OK,
		   test_flow_parser_simple);

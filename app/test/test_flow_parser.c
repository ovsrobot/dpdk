/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdint.h>
#include <string.h>

#include <rte_flow.h>
#include <rte_flow_parser.h>

#include "test.h"

static int
test_flow_parser_command_mapping(void)
{
	static const char *create_cmd =
		"flow create 0 ingress pattern eth / end "
		"actions drop / end";
	static const char *list_cmd = "flow list 0";
	uint8_t outbuf[4096];
	struct rte_flow_parser_output *out = (void *)outbuf;
	int ret;

	ret = rte_flow_parser_init(NULL);
	if (ret != 0)
		return TEST_FAILED;

	/* Test flow create command parsing */
	memset(outbuf, 0, sizeof(outbuf));
	ret = rte_flow_parser_parse(create_cmd, out, sizeof(outbuf));
	if (ret != 0) {
		printf("flow create parse failed: %d\n", ret);
		return TEST_FAILED;
	}
	if (out->command != RTE_FLOW_PARSER_CMD_CREATE) {
		printf("expected CREATE command, got %d\n", out->command);
		return TEST_FAILED;
	}
	if (out->port != 0) {
		printf("expected port 0, got %u\n", out->port);
		return TEST_FAILED;
	}
	/* pattern: eth / end = 2 items */
	if (out->args.vc.pattern_n != 2) {
		printf("expected 2 pattern items, got %u\n",
		       out->args.vc.pattern_n);
		return TEST_FAILED;
	}
	if (out->args.vc.pattern[0].type != RTE_FLOW_ITEM_TYPE_ETH) {
		printf("expected ETH pattern, got %d\n",
		       out->args.vc.pattern[0].type);
		return TEST_FAILED;
	}
	if (out->args.vc.pattern[1].type != RTE_FLOW_ITEM_TYPE_END) {
		printf("expected END pattern, got %d\n",
		       out->args.vc.pattern[1].type);
		return TEST_FAILED;
	}
	/* actions: drop / end = 2 items */
	if (out->args.vc.actions_n != 2) {
		printf("expected 2 action items, got %u\n",
		       out->args.vc.actions_n);
		return TEST_FAILED;
	}
	if (out->args.vc.actions[0].type != RTE_FLOW_ACTION_TYPE_DROP) {
		printf("expected DROP action, got %d\n",
		       out->args.vc.actions[0].type);
		return TEST_FAILED;
	}
	if (out->args.vc.actions[1].type != RTE_FLOW_ACTION_TYPE_END) {
		printf("expected END action, got %d\n",
		       out->args.vc.actions[1].type);
		return TEST_FAILED;
	}
	/* ingress attribute */
	if (out->args.vc.attr.ingress != 1 || out->args.vc.attr.egress != 0) {
		printf("expected ingress=1 egress=0\n");
		return TEST_FAILED;
	}

	/* Test flow list command parsing */
	memset(outbuf, 0, sizeof(outbuf));
	ret = rte_flow_parser_parse(list_cmd, out, sizeof(outbuf));
	if (ret != 0 ||
	    out->command != RTE_FLOW_PARSER_CMD_LIST ||
	    out->port != 0)
		return TEST_FAILED;

	return TEST_SUCCESS;
}

static int
test_flow_parser_lightweight_helpers(void)
{
	const struct rte_flow_item *pattern = NULL;
	const struct rte_flow_action *actions = NULL;
	const struct rte_flow_action_queue *queue_conf;
	const struct rte_flow_action_mark *mark_conf;
	struct rte_flow_attr attr;
	uint32_t pattern_n = 0;
	uint32_t actions_n = 0;
	int ret;

	ret = rte_flow_parser_init(NULL);
	if (ret != 0)
		return TEST_FAILED;

	/* Test attribute parsing */
	memset(&attr, 0, sizeof(attr));
	ret = rte_flow_parser_parse_attr_str("ingress group 1 priority 5", &attr);
	if (ret != 0) {
		printf("attr parse failed: %d\n", ret);
		return TEST_FAILED;
	}
	if (attr.group != 1 || attr.priority != 5 ||
	    attr.ingress != 1 || attr.egress != 0) {
		printf("attr mismatch: group=%u priority=%u ingress=%u egress=%u\n",
		       attr.group, attr.priority, attr.ingress, attr.egress);
		return TEST_FAILED;
	}

	/* Test pattern parsing: eth / ipv4 / end = 3 items */
	ret = rte_flow_parser_parse_pattern_str("eth / ipv4 / end",
						&pattern, &pattern_n);
	if (ret != 0) {
		printf("pattern parse failed: %d\n", ret);
		return TEST_FAILED;
	}
	if (pattern_n != 3) {
		printf("expected 3 pattern items, got %u\n", pattern_n);
		return TEST_FAILED;
	}
	if (pattern[0].type != RTE_FLOW_ITEM_TYPE_ETH) {
		printf("pattern[0] expected ETH, got %d\n", pattern[0].type);
		return TEST_FAILED;
	}
	if (pattern[1].type != RTE_FLOW_ITEM_TYPE_IPV4) {
		printf("pattern[1] expected IPV4, got %d\n", pattern[1].type);
		return TEST_FAILED;
	}
	if (pattern[2].type != RTE_FLOW_ITEM_TYPE_END) {
		printf("pattern[2] expected END, got %d\n", pattern[2].type);
		return TEST_FAILED;
	}

	/* Test actions parsing with config values: queue index 3 / end = 2 items */
	ret = rte_flow_parser_parse_actions_str("queue index 3 / end",
						&actions, &actions_n);
	if (ret != 0) {
		printf("actions parse failed: %d\n", ret);
		return TEST_FAILED;
	}
	if (actions_n != 2) {
		printf("expected 2 action items, got %u\n", actions_n);
		return TEST_FAILED;
	}
	if (actions[0].type != RTE_FLOW_ACTION_TYPE_QUEUE) {
		printf("actions[0] expected QUEUE, got %d\n", actions[0].type);
		return TEST_FAILED;
	}
	queue_conf = actions[0].conf;
	if (queue_conf == NULL || queue_conf->index != 3) {
		printf("queue index expected 3, got %u\n",
		       queue_conf ? queue_conf->index : 0);
		return TEST_FAILED;
	}
	if (actions[1].type != RTE_FLOW_ACTION_TYPE_END) {
		printf("actions[1] expected END, got %d\n", actions[1].type);
		return TEST_FAILED;
	}

	/* Test multiple actions: mark id 42 / drop / end = 3 items */
	ret = rte_flow_parser_parse_actions_str("mark id 42 / drop / end",
						&actions, &actions_n);
	if (ret != 0) {
		printf("multi-action parse failed: %d\n", ret);
		return TEST_FAILED;
	}
	if (actions_n != 3) {
		printf("expected 3 action items, got %u\n", actions_n);
		return TEST_FAILED;
	}
	if (actions[0].type != RTE_FLOW_ACTION_TYPE_MARK) {
		printf("actions[0] expected MARK, got %d\n", actions[0].type);
		return TEST_FAILED;
	}
	mark_conf = actions[0].conf;
	if (mark_conf == NULL || mark_conf->id != 42) {
		printf("mark id expected 42, got %u\n",
		       mark_conf ? mark_conf->id : 0);
		return TEST_FAILED;
	}
	if (actions[1].type != RTE_FLOW_ACTION_TYPE_DROP) {
		printf("actions[1] expected DROP, got %d\n", actions[1].type);
		return TEST_FAILED;
	}
	if (actions[2].type != RTE_FLOW_ACTION_TYPE_END) {
		printf("actions[2] expected END, got %d\n", actions[2].type);
		return TEST_FAILED;
	}

	/* Test complex pattern: eth / ipv4 / tcp / end = 4 items */
	ret = rte_flow_parser_parse_pattern_str("eth / ipv4 / tcp / end",
						&pattern, &pattern_n);
	if (ret != 0) {
		printf("complex pattern parse failed: %d\n", ret);
		return TEST_FAILED;
	}
	if (pattern_n != 4) {
		printf("expected 4 pattern items, got %u\n", pattern_n);
		return TEST_FAILED;
	}
	if (pattern[0].type != RTE_FLOW_ITEM_TYPE_ETH ||
	    pattern[1].type != RTE_FLOW_ITEM_TYPE_IPV4 ||
	    pattern[2].type != RTE_FLOW_ITEM_TYPE_TCP ||
	    pattern[3].type != RTE_FLOW_ITEM_TYPE_END) {
		printf("complex pattern type mismatch\n");
		return TEST_FAILED;
	}

	return TEST_SUCCESS;
}

REGISTER_FAST_TEST(flow_parser_autotest, true, true,
		   test_flow_parser_command_mapping);

REGISTER_FAST_TEST(flow_parser_helpers_autotest, true, true,
		   test_flow_parser_lightweight_helpers);

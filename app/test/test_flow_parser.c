/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 DynaNIC Semiconductors, Ltd.
 */

#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>

#include <rte_byteorder.h>
#include <rte_flow.h>
#include <rte_flow_parser_cmdline.h>

#include "test.h"

static struct rte_flow_parser_vxlan_encap_conf test_vxlan_conf;
static struct rte_flow_parser_nvgre_encap_conf test_nvgre_conf;
static struct rte_flow_parser_l2_encap_conf test_l2_encap_conf;
static struct rte_flow_parser_l2_decap_conf test_l2_decap_conf;
static struct rte_flow_parser_mplsogre_encap_conf test_mplsogre_encap_conf;
static struct rte_flow_parser_mplsogre_decap_conf test_mplsogre_decap_conf;
static struct rte_flow_parser_mplsoudp_encap_conf test_mplsoudp_encap_conf;
static struct rte_flow_parser_mplsoudp_decap_conf test_mplsoudp_decap_conf;
static struct rte_flow_action_conntrack test_conntrack;

static struct rte_flow_parser_raw_encap_data test_raw_encap[RAW_ENCAP_CONFS_MAX_NUM];
static struct rte_flow_parser_raw_decap_data test_raw_decap[RAW_ENCAP_CONFS_MAX_NUM];
static struct rte_flow_parser_ipv6_ext_push_data test_ipv6_push[IPV6_EXT_PUSH_CONFS_MAX_NUM];
static struct rte_flow_parser_ipv6_ext_remove_data test_ipv6_remove[IPV6_EXT_PUSH_CONFS_MAX_NUM];
static struct rte_flow_parser_sample_slot test_sample[RAW_SAMPLE_CONFS_MAX_NUM];

static void test_dispatch_cb(const struct rte_flow_parser_output *in __rte_unused);
static cmdline_parse_inst_t test_flow_inst;

static void
test_register_config(void)
{
	memset(&test_raw_encap, 0, sizeof(test_raw_encap));
	memset(&test_raw_decap, 0, sizeof(test_raw_decap));
	memset(&test_ipv6_push, 0, sizeof(test_ipv6_push));
	memset(&test_ipv6_remove, 0, sizeof(test_ipv6_remove));
	memset(&test_sample, 0, sizeof(test_sample));
	memset(&test_conntrack, 0, sizeof(test_conntrack));
	memset(&test_l2_encap_conf, 0, sizeof(test_l2_encap_conf));
	memset(&test_l2_decap_conf, 0, sizeof(test_l2_decap_conf));
	memset(&test_mplsogre_encap_conf, 0, sizeof(test_mplsogre_encap_conf));
	memset(&test_mplsogre_decap_conf, 0, sizeof(test_mplsogre_decap_conf));
	memset(&test_mplsoudp_encap_conf, 0, sizeof(test_mplsoudp_encap_conf));
	memset(&test_mplsoudp_decap_conf, 0, sizeof(test_mplsoudp_decap_conf));

	test_vxlan_conf = (struct rte_flow_parser_vxlan_encap_conf){
		.select_ipv4 = 1,
		.udp_dst = RTE_BE16(RTE_VXLAN_DEFAULT_PORT),
		.ipv4_src = RTE_IPV4(127, 0, 0, 1),
		.ipv4_dst = RTE_IPV4(255, 255, 255, 255),
		.ip_ttl = 255,
		.eth_dst = { .addr_bytes = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } },
	};
	test_nvgre_conf = (struct rte_flow_parser_nvgre_encap_conf){
		.select_ipv4 = 1,
		.ipv4_src = RTE_IPV4(127, 0, 0, 1),
		.ipv4_dst = RTE_IPV4(255, 255, 255, 255),
		.eth_dst = { .addr_bytes = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } },
	};

	struct rte_flow_parser_config cfg = {
		.vxlan_encap = &test_vxlan_conf,
		.nvgre_encap = &test_nvgre_conf,
		.l2_encap = &test_l2_encap_conf,
		.l2_decap = &test_l2_decap_conf,
		.mplsogre_encap = &test_mplsogre_encap_conf,
		.mplsogre_decap = &test_mplsogre_decap_conf,
		.mplsoudp_encap = &test_mplsoudp_encap_conf,
		.mplsoudp_decap = &test_mplsoudp_decap_conf,
		.conntrack = &test_conntrack,
		.raw_encap = { test_raw_encap, RAW_ENCAP_CONFS_MAX_NUM },
		.raw_decap = { test_raw_decap, RAW_ENCAP_CONFS_MAX_NUM },
		.ipv6_ext_push = { test_ipv6_push, IPV6_EXT_PUSH_CONFS_MAX_NUM },
		.ipv6_ext_remove = { test_ipv6_remove, IPV6_EXT_PUSH_CONFS_MAX_NUM },
		.sample = { test_sample, RAW_SAMPLE_CONFS_MAX_NUM },
		.cmd_flow = &test_flow_inst,
		.dispatch = test_dispatch_cb,
	};
	rte_flow_parser_config_register(&cfg);
}

static int
flow_parser_setup(void)
{
	return 0;
}

static int
flow_parser_case_setup(void)
{
	test_register_config();
	return 0;
}

static void
flow_parser_teardown(void)
{
	test_register_config();
}

/* Cmdline API tests */

static int
test_flow_parser_cmdline_command_mapping(void)
{
	static const char *create_cmd =
		"flow create 0 ingress pattern eth / end "
		"actions drop / end";
	static const char *list_cmd = "flow list 0";
	static const char *destroy_cmd = "flow destroy 0 rule 1";
	static const char *flush_cmd = "flow flush 0";
	static const char *validate_cmd =
		"flow validate 0 ingress pattern eth / end actions drop / end";
	uint8_t outbuf[4096];
	struct rte_flow_parser_output *out = (void *)outbuf;
	int ret;

	ret = rte_flow_parser_parse(create_cmd, out, sizeof(outbuf));
	TEST_ASSERT_SUCCESS(ret, "flow create parse failed: %s",
		strerror(-ret));
	TEST_ASSERT_EQUAL(out->command, RTE_FLOW_PARSER_CMD_CREATE,
		"expected CREATE command, got %d", out->command);
	TEST_ASSERT_EQUAL(out->port, 0, "expected port 0, got %u", out->port);
	TEST_ASSERT_EQUAL(out->args.vc.pattern_n, 2,
		"expected 2 pattern items, got %u", out->args.vc.pattern_n);
	TEST_ASSERT_EQUAL(out->args.vc.pattern[0].type, RTE_FLOW_ITEM_TYPE_ETH,
		"expected ETH pattern, got %d", out->args.vc.pattern[0].type);
	TEST_ASSERT_EQUAL(out->args.vc.pattern[1].type, RTE_FLOW_ITEM_TYPE_END,
		"expected END pattern, got %d", out->args.vc.pattern[1].type);
	TEST_ASSERT_EQUAL(out->args.vc.actions_n, 2,
		"expected 2 action items, got %u", out->args.vc.actions_n);
	TEST_ASSERT_EQUAL(out->args.vc.actions[0].type,
		RTE_FLOW_ACTION_TYPE_DROP,
		"expected DROP action, got %d", out->args.vc.actions[0].type);
	TEST_ASSERT_EQUAL(out->args.vc.actions[1].type,
		RTE_FLOW_ACTION_TYPE_END,
		"expected END action, got %d", out->args.vc.actions[1].type);
	TEST_ASSERT(out->args.vc.attr.ingress == 1 &&
		out->args.vc.attr.egress == 0,
		"expected ingress=1 egress=0");

	ret = rte_flow_parser_parse(list_cmd, out, sizeof(outbuf));
	TEST_ASSERT_SUCCESS(ret, "flow list parse failed: %s", strerror(-ret));
	TEST_ASSERT_EQUAL(out->command, RTE_FLOW_PARSER_CMD_LIST,
		"expected LIST command, got %d", out->command);
	TEST_ASSERT_EQUAL(out->port, 0, "expected port 0, got %u", out->port);

	ret = rte_flow_parser_parse(destroy_cmd, out, sizeof(outbuf));
	TEST_ASSERT_SUCCESS(ret, "flow destroy parse failed: %s",
		strerror(-ret));
	TEST_ASSERT_EQUAL(out->command, RTE_FLOW_PARSER_CMD_DESTROY,
		"expected DESTROY command, got %d", out->command);

	ret = rte_flow_parser_parse(flush_cmd, out, sizeof(outbuf));
	TEST_ASSERT_SUCCESS(ret, "flow flush parse failed: %s", strerror(-ret));
	TEST_ASSERT_EQUAL(out->command, RTE_FLOW_PARSER_CMD_FLUSH,
		"expected FLUSH command, got %d", out->command);

	ret = rte_flow_parser_parse(validate_cmd, out, sizeof(outbuf));
	TEST_ASSERT_SUCCESS(ret, "flow validate parse failed: %s",
		strerror(-ret));
	TEST_ASSERT_EQUAL(out->command, RTE_FLOW_PARSER_CMD_VALIDATE,
		"expected VALIDATE command, got %d", out->command);

	return TEST_SUCCESS;
}

static int
test_flow_parser_cmdline_indirect_action(void)
{
	static const char *flow_indirect_sample =
		"flow indirect_action 0 create transfer list "
		"actions sample ratio 1 index 1 / jump group 2 / end";
	uint8_t outbuf[8192];
	struct rte_flow_parser_output *out = (void *)outbuf;
	const struct rte_flow_action *actions;
	const struct rte_flow_action_sample *sample_conf;
	const struct rte_flow_action_ethdev *repr;
	uint32_t actions_n;
	int ret;

	/* Pre-configure sample actions via the setter API. */
	ret = rte_flow_parser_parse_actions_str(
		"port_representor port_id 0xffff / end",
		&actions, &actions_n);
	TEST_ASSERT_SUCCESS(ret, "parse sample actions failed: %s",
		strerror(-ret));

	ret = rte_flow_parser_sample_actions_set(1, actions, actions_n);
	TEST_ASSERT_SUCCESS(ret, "sample_actions_set failed: %s",
		strerror(-ret));

	/* Parse an indirect_action that references sample index 1. */
	ret = rte_flow_parser_parse(flow_indirect_sample, out, sizeof(outbuf));
	TEST_ASSERT_SUCCESS(ret, "indirect sample parse failed: %s",
		strerror(-ret));
	TEST_ASSERT(out->command == RTE_FLOW_PARSER_CMD_INDIRECT_ACTION_LIST_CREATE ||
		out->command == RTE_FLOW_PARSER_CMD_INDIRECT_ACTION_CREATE ||
		out->command == RTE_FLOW_PARSER_CMD_QUEUE_INDIRECT_ACTION_LIST_CREATE ||
		out->command == RTE_FLOW_PARSER_CMD_QUEUE_INDIRECT_ACTION_CREATE,
		"expected indirect action create command, got %d", out->command);
	TEST_ASSERT(out->args.vc.actions_n >= 3,
		"expected sample + jump + end actions for indirect action");
	TEST_ASSERT_EQUAL(out->args.vc.actions[0].type,
		RTE_FLOW_ACTION_TYPE_SAMPLE, "indirect actions[0] not SAMPLE");
	sample_conf = out->args.vc.actions[0].conf;
	TEST_ASSERT_NOT_NULL(sample_conf, "indirect sample conf missing");
	TEST_ASSERT_NOT_NULL(sample_conf->actions,
		"indirect sample actions missing");
	TEST_ASSERT_EQUAL(sample_conf->actions[0].type,
		RTE_FLOW_ACTION_TYPE_PORT_REPRESENTOR,
		"indirect sample action[0] type mismatch: %d",
		sample_conf->actions[0].type);
	repr = sample_conf->actions[0].conf;
	TEST_ASSERT_NOT_NULL(repr, "indirect sample port conf missing");
	TEST_ASSERT_EQUAL(repr->port_id, 0xffff,
		"indirect sample port representor id mismatch");
	TEST_ASSERT_EQUAL(sample_conf->actions[1].type,
		RTE_FLOW_ACTION_TYPE_END,
		"indirect sample actions should end");

	return TEST_SUCCESS;
}

static int
test_flow_parser_cmdline_meter(void)
{
	/* meter itself needs to be created beforehand; here we just test parsing */
	static const char *flow_meter =
		"flow create 0 ingress group 1 pattern eth / end "
		"actions meter mtr_id 101 / end";
	uint8_t outbuf[8192];
	struct rte_flow_parser_output *out = (void *)outbuf;
	const struct rte_flow_action_meter *meter_conf;
	int ret;

	ret = rte_flow_parser_parse(flow_meter, out, sizeof(outbuf));
	TEST_ASSERT_SUCCESS(ret, "flow meter parse failed: %s", strerror(-ret));
	TEST_ASSERT_EQUAL(out->command, RTE_FLOW_PARSER_CMD_CREATE,
		"expected CREATE command, got %d", out->command);
	TEST_ASSERT_EQUAL(out->port, 0, "expected port 0, got %u", out->port);
	TEST_ASSERT(out->args.vc.attr.ingress == 1 &&
		out->args.vc.attr.egress == 0,
		"expected ingress=1 egress=0");
	TEST_ASSERT_EQUAL(out->args.vc.attr.group, 1,
		"expected group 1, got %u", out->args.vc.attr.group);
	TEST_ASSERT_EQUAL(out->args.vc.pattern_n, 2,
		"expected 2 pattern items, got %u", out->args.vc.pattern_n);
	TEST_ASSERT_EQUAL(out->args.vc.pattern[0].type, RTE_FLOW_ITEM_TYPE_ETH,
		"expected ETH pattern, got %d", out->args.vc.pattern[0].type);
	TEST_ASSERT_EQUAL(out->args.vc.pattern[1].type, RTE_FLOW_ITEM_TYPE_END,
		"expected END pattern, got %d", out->args.vc.pattern[1].type);
	TEST_ASSERT_EQUAL(out->args.vc.actions_n, 2,
		"expected 2 action items, got %u", out->args.vc.actions_n);
	TEST_ASSERT_EQUAL(out->args.vc.actions[0].type,
		RTE_FLOW_ACTION_TYPE_METER, "actions[0] not METER");
	meter_conf = out->args.vc.actions[0].conf;
	TEST_ASSERT_NOT_NULL(meter_conf, "meter action configuration missing");
	TEST_ASSERT_EQUAL(meter_conf->mtr_id, 101,
		"expected mtr_id 101, got %u", meter_conf->mtr_id);
	TEST_ASSERT_EQUAL(out->args.vc.actions[1].type,
		RTE_FLOW_ACTION_TYPE_END, "actions[1] not END");

	return TEST_SUCCESS;
}

static int
test_flow_parser_cmdline_queue_set_meta(void)
{
	static const char *flow_queue_meta =
		"flow create 0 ingress pattern eth / ipv4 / tcp dst is 80 / end "
		"actions queue index 0 / set_meta data 0x1234 / end";
	uint8_t outbuf[8192];
	struct rte_flow_parser_output *out = (void *)outbuf;
	const struct rte_flow_item_tcp *tcp_spec;
	const struct rte_flow_action_queue *queue_conf;
	const struct rte_flow_action_set_meta *set_meta_conf;
	int ret;

	ret = rte_flow_parser_parse(flow_queue_meta, out, sizeof(outbuf));
	TEST_ASSERT_SUCCESS(ret, "flow queue set_meta parse failed: %s",
		strerror(-ret));
	TEST_ASSERT_EQUAL(out->command, RTE_FLOW_PARSER_CMD_CREATE,
		"expected CREATE command, got %d", out->command);
	TEST_ASSERT_EQUAL(out->port, 0, "expected port 0, got %u", out->port);
	TEST_ASSERT(out->args.vc.attr.ingress == 1 &&
		out->args.vc.attr.egress == 0,
		"expected ingress=1 egress=0");
	TEST_ASSERT_EQUAL(out->args.vc.pattern_n, 4,
		"expected 4 pattern items, got %u", out->args.vc.pattern_n);
	TEST_ASSERT_EQUAL(out->args.vc.pattern[0].type, RTE_FLOW_ITEM_TYPE_ETH,
		"pattern[0] expected ETH, got %d", out->args.vc.pattern[0].type);
	TEST_ASSERT_EQUAL(out->args.vc.pattern[1].type, RTE_FLOW_ITEM_TYPE_IPV4,
		"pattern[1] expected IPV4, got %d", out->args.vc.pattern[1].type);
	TEST_ASSERT_EQUAL(out->args.vc.pattern[2].type, RTE_FLOW_ITEM_TYPE_TCP,
		"pattern[2] expected TCP, got %d", out->args.vc.pattern[2].type);
	tcp_spec = out->args.vc.pattern[2].spec;
	TEST_ASSERT_NOT_NULL(tcp_spec, "tcp spec missing");
	TEST_ASSERT_EQUAL(tcp_spec->hdr.dst_port, rte_cpu_to_be_16(80),
		"tcp dst port mismatch");
	TEST_ASSERT_EQUAL(out->args.vc.pattern[3].type, RTE_FLOW_ITEM_TYPE_END,
		"pattern[3] expected END, got %d", out->args.vc.pattern[3].type);

	TEST_ASSERT_EQUAL(out->args.vc.actions_n, 3,
		"expected 3 action items, got %u", out->args.vc.actions_n);
	TEST_ASSERT_EQUAL(out->args.vc.actions[0].type,
		RTE_FLOW_ACTION_TYPE_QUEUE, "actions[0] not QUEUE");
	queue_conf = out->args.vc.actions[0].conf;
	TEST_ASSERT_NOT_NULL(queue_conf, "queue action configuration missing");
	TEST_ASSERT_EQUAL(queue_conf->index, 0,
		"queue index expected 0, got %u", queue_conf->index);
	TEST_ASSERT_EQUAL(out->args.vc.actions[1].type,
		RTE_FLOW_ACTION_TYPE_SET_META, "actions[1] not SET_META");
	set_meta_conf = out->args.vc.actions[1].conf;
	TEST_ASSERT_NOT_NULL(set_meta_conf,
		"set_meta action configuration missing");
	TEST_ASSERT_EQUAL(set_meta_conf->data, 0x1234,
		"set_meta data expected 0x1234, got %#x",
		set_meta_conf->data);
	TEST_ASSERT_EQUAL(out->args.vc.actions[2].type,
		RTE_FLOW_ACTION_TYPE_END, "actions[2] not END");

	return TEST_SUCCESS;
}

static int
test_flow_parser_cmdline_modify_field_count(void)
{
	static const char *flow_modify_field =
		"flow validate 1 egress pattern "
		"tx_queue tx_queue_value is 0 / meta data is 0x1234 / end "
		"actions modify_field op set dst_type ipv4_src src_type value "
		"src_value 0x0a000001 width 32 / count / end";
	uint8_t outbuf[8192];
	struct rte_flow_parser_output *out = (void *)outbuf;
	const struct rte_flow_item_tx_queue *tx_queue_spec;
	const struct rte_flow_item_meta *meta_spec;
	const struct rte_flow_action_modify_field *modify_conf;
	const struct rte_flow_action_count *count_conf;
	const uint8_t expected_src_value[16] = { 0x0a, 0x00, 0x00, 0x01 };
	int ret;

	ret = rte_flow_parser_parse(flow_modify_field, out, sizeof(outbuf));
	TEST_ASSERT_SUCCESS(ret, "flow modify_field parse failed: %s",
		strerror(-ret));
	TEST_ASSERT_EQUAL(out->command, RTE_FLOW_PARSER_CMD_VALIDATE,
		"expected VALIDATE command, got %d", out->command);
	TEST_ASSERT_EQUAL(out->port, 1, "expected port 1, got %u", out->port);
	TEST_ASSERT(out->args.vc.attr.ingress == 0 &&
		out->args.vc.attr.egress == 1,
		"expected ingress=0 egress=1");
	TEST_ASSERT_EQUAL(out->args.vc.pattern_n, 3,
		"expected 3 pattern items, got %u", out->args.vc.pattern_n);
	TEST_ASSERT_EQUAL(out->args.vc.pattern[0].type,
		RTE_FLOW_ITEM_TYPE_TX_QUEUE,
		"pattern[0] expected TX_QUEUE, got %d",
		out->args.vc.pattern[0].type);
	tx_queue_spec = out->args.vc.pattern[0].spec;
	TEST_ASSERT_NOT_NULL(tx_queue_spec, "tx_queue spec missing");
	TEST_ASSERT_EQUAL(tx_queue_spec->tx_queue, 0,
		"tx_queue value expected 0, got %u",
		tx_queue_spec->tx_queue);
	TEST_ASSERT_EQUAL(out->args.vc.pattern[1].type,
		RTE_FLOW_ITEM_TYPE_META,
		"pattern[1] expected META, got %d",
		out->args.vc.pattern[1].type);
	meta_spec = out->args.vc.pattern[1].spec;
	TEST_ASSERT_NOT_NULL(meta_spec, "meta spec missing");
	TEST_ASSERT_EQUAL(meta_spec->data, 0x1234,
		"meta data expected 0x1234, got %#x",
		meta_spec->data);
	TEST_ASSERT_EQUAL(out->args.vc.pattern[2].type, RTE_FLOW_ITEM_TYPE_END,
		"pattern[2] expected END, got %d", out->args.vc.pattern[2].type);

	TEST_ASSERT_EQUAL(out->args.vc.actions_n, 3,
		"expected 3 action items, got %u", out->args.vc.actions_n);
	TEST_ASSERT_EQUAL(out->args.vc.actions[0].type,
		RTE_FLOW_ACTION_TYPE_MODIFY_FIELD, "actions[0] not MODIFY_FIELD");
	modify_conf = out->args.vc.actions[0].conf;
	TEST_ASSERT_NOT_NULL(modify_conf,
		"modify_field action configuration missing");
	TEST_ASSERT_EQUAL(modify_conf->operation, RTE_FLOW_MODIFY_SET,
		"modify_field operation expected SET, got %d",
		modify_conf->operation);
	TEST_ASSERT_EQUAL(modify_conf->dst.field, RTE_FLOW_FIELD_IPV4_SRC,
		"modify_field dst field expected IPV4_SRC, got %d",
		modify_conf->dst.field);
	TEST_ASSERT_EQUAL(modify_conf->src.field, RTE_FLOW_FIELD_VALUE,
		"modify_field src field expected VALUE, got %d",
		modify_conf->src.field);
	TEST_ASSERT_EQUAL(modify_conf->width, 32,
		"modify_field width expected 32, got %u",
		modify_conf->width);
	TEST_ASSERT_BUFFERS_ARE_EQUAL(modify_conf->src.value,
		expected_src_value, sizeof(expected_src_value),
		"modify_field src value mismatch");
	TEST_ASSERT_EQUAL(out->args.vc.actions[1].type,
		RTE_FLOW_ACTION_TYPE_COUNT, "actions[1] not COUNT");
	count_conf = out->args.vc.actions[1].conf;
	TEST_ASSERT_NOT_NULL(count_conf, "count action configuration missing");
	TEST_ASSERT_EQUAL(count_conf->id, 0,
		"count id expected 0, got %u", count_conf->id);
	TEST_ASSERT_EQUAL(out->args.vc.actions[2].type,
		RTE_FLOW_ACTION_TYPE_END, "actions[2] not END");

	return TEST_SUCCESS;
}

static int
test_flow_parser_cmdline_raw_decap_rss(void)
{
	char flow_raw_decap_rss[160];
	const uint16_t raw_decap_index = 0;
	uint8_t outbuf[8192];
	struct rte_flow_parser_output *out = (void *)outbuf;
	const struct rte_flow_item *items;
	uint32_t items_n;
	const struct rte_flow_action_raw_decap *raw_decap_action;
	const struct rte_flow_action_rss *rss_conf;
	const struct rte_flow_action_raw_decap *decap_conf;
	const struct rte_vxlan_hdr *vxlan_hdr;
	uint32_t vni;
	int len;
	int ret;

	/* Use the setter API: parse pattern, then set raw decap config. */
	ret = rte_flow_parser_parse_pattern_str(
		"vxlan vni is 33 / end", &items, &items_n);
	TEST_ASSERT_SUCCESS(ret, "pattern parse failed: %s", strerror(-ret));

	ret = rte_flow_parser_raw_decap_conf_set(raw_decap_index,
		items, items_n);
	TEST_ASSERT_SUCCESS(ret, "raw_decap_conf_set failed: %s",
		strerror(-ret));

	/* Verify the stored config via getter. */
	decap_conf = rte_flow_parser_raw_decap_conf(raw_decap_index);
	TEST_ASSERT_NOT_NULL(decap_conf, "raw_decap config missing");
	TEST_ASSERT(decap_conf->size >= sizeof(struct rte_vxlan_hdr),
		"raw_decap config size too small: %zu", decap_conf->size);
	vxlan_hdr = (const struct rte_vxlan_hdr *)decap_conf->data;
	vni = ((uint32_t)vxlan_hdr->vni[0] << 16) |
	      ((uint32_t)vxlan_hdr->vni[1] << 8) |
	      (uint32_t)vxlan_hdr->vni[2];
	TEST_ASSERT_EQUAL(vni, 33,
		"raw_decap vxlan vni expected 33, got %u", vni);

	/* Parse a flow rule that uses the stored raw_decap config. */
	len = snprintf(flow_raw_decap_rss, sizeof(flow_raw_decap_rss),
		"flow create 0 ingress pattern eth / ipv4 / end "
		"actions raw_decap index %u / rss / end",
		raw_decap_index);
	TEST_ASSERT(len > 0 && len < (int)sizeof(flow_raw_decap_rss),
		"flow raw_decap rss command truncated");

	ret = rte_flow_parser_parse(flow_raw_decap_rss, out, sizeof(outbuf));
	TEST_ASSERT_SUCCESS(ret, "flow raw_decap rss parse failed: %s",
		strerror(-ret));
	TEST_ASSERT_EQUAL(out->command, RTE_FLOW_PARSER_CMD_CREATE,
		"expected CREATE command, got %d", out->command);
	TEST_ASSERT_EQUAL(out->port, 0, "expected port 0, got %u", out->port);
	TEST_ASSERT(out->args.vc.attr.ingress == 1 &&
		out->args.vc.attr.egress == 0,
		"expected ingress=1 egress=0");

	TEST_ASSERT_EQUAL(out->args.vc.pattern_n, 3,
		"expected 3 pattern items, got %u", out->args.vc.pattern_n);
	TEST_ASSERT_EQUAL(out->args.vc.pattern[0].type, RTE_FLOW_ITEM_TYPE_ETH,
		"pattern[0] expected ETH, got %d", out->args.vc.pattern[0].type);
	TEST_ASSERT_EQUAL(out->args.vc.pattern[1].type, RTE_FLOW_ITEM_TYPE_IPV4,
		"pattern[1] expected IPV4, got %d", out->args.vc.pattern[1].type);
	TEST_ASSERT_EQUAL(out->args.vc.pattern[2].type, RTE_FLOW_ITEM_TYPE_END,
		"pattern[2] expected END, got %d", out->args.vc.pattern[2].type);

	TEST_ASSERT_EQUAL(out->args.vc.actions_n, 3,
		"expected 3 action items, got %u", out->args.vc.actions_n);
	TEST_ASSERT_EQUAL(out->args.vc.actions[0].type,
		RTE_FLOW_ACTION_TYPE_RAW_DECAP, "actions[0] not RAW_DECAP");
	raw_decap_action = out->args.vc.actions[0].conf;
	TEST_ASSERT_NOT_NULL(raw_decap_action,
		"raw_decap action configuration missing");
	TEST_ASSERT_NOT_NULL(raw_decap_action->data,
		"raw_decap action data missing");
	TEST_ASSERT(raw_decap_action->size >= sizeof(struct rte_vxlan_hdr),
		"raw_decap action size too small: %zu",
		raw_decap_action->size);
	TEST_ASSERT_EQUAL(out->args.vc.actions[1].type,
		RTE_FLOW_ACTION_TYPE_RSS, "actions[1] not RSS");
	rss_conf = out->args.vc.actions[1].conf;
	TEST_ASSERT_NOT_NULL(rss_conf, "rss action configuration missing");
	TEST_ASSERT_EQUAL(out->args.vc.actions[2].type,
		RTE_FLOW_ACTION_TYPE_END, "actions[2] not END");

	return TEST_SUCCESS;
}

static int
test_flow_parser_cmdline_invalid_args(void)
{
	uint8_t outbuf[sizeof(struct rte_flow_parser_output)];
	int ret;

	/* Test NULL command string */
	ret = rte_flow_parser_parse(NULL, (void *)outbuf, sizeof(outbuf));
	TEST_ASSERT_EQUAL(ret, -EINVAL, "NULL cmd should return -EINVAL");

	/* Test NULL output buffer */
	ret = rte_flow_parser_parse("flow list 0", NULL, sizeof(outbuf));
	TEST_ASSERT_EQUAL(ret, -EINVAL, "NULL output should return -EINVAL");

	/* Test output buffer too small */
	ret = rte_flow_parser_parse("flow list 0", (void *)outbuf,
		sizeof(struct rte_flow_parser_output) - 1);
	TEST_ASSERT_EQUAL(ret, -ENOBUFS, "short output buffer not rejected");

	/* Test zero-length output buffer */
	ret = rte_flow_parser_parse("flow list 0", (void *)outbuf, 0);
	TEST_ASSERT_EQUAL(ret, -ENOBUFS, "zero-length output buffer not rejected");

	return TEST_SUCCESS;
}

static int
test_flow_parser_cmdline_invalid_syntax(void)
{
	static const char *invalid_cmd = "flow invalid 0";
	static const char *wrong_cmd =
		"flow create 0 rule 7"; /* destroy syntax in create */
	static const char *actions_before_pattern =
		"flow create 0 ingress actions drop / end pattern eth / end";
	static const char *missing_actions_keyword =
		"flow create 0 ingress pattern eth / end drop / end";
	static const char *missing_pattern_keyword =
		"flow create 0 ingress actions drop / end";
	static const char *missing_action_separator =
		"flow create 0 ingress pattern eth / end actions drop end";
	static const char *missing_pattern_end =
		"flow create 0 ingress pattern eth / ipv4 actions drop / end";
	static const char *missing_port_id =
		"flow create ingress pattern eth / end actions drop / end";
	static const char *extra_trailing_token =
		"flow create 0 ingress pattern eth / end actions drop / end junk";
	static const char *empty_command = "";
	static const char *whitespace_only = "   ";
	uint8_t outbuf[4096];
	struct rte_flow_parser_output *out = (void *)outbuf;
	int ret;

	ret = rte_flow_parser_parse(invalid_cmd, out, sizeof(outbuf));
	TEST_ASSERT(ret < 0, "unexpected status for invalid cmd: %d", ret);

	ret = rte_flow_parser_parse(wrong_cmd, out, sizeof(outbuf));
	TEST_ASSERT(ret < 0,
		"expected failure for wrong command usage: %d", ret);

	ret = rte_flow_parser_parse(actions_before_pattern, out, sizeof(outbuf));
	TEST_ASSERT(ret < 0,
		"expected failure for actions before pattern: %d", ret);

	ret = rte_flow_parser_parse(missing_actions_keyword, out, sizeof(outbuf));
	TEST_ASSERT(ret < 0,
		"expected failure for missing actions keyword: %d", ret);

	ret = rte_flow_parser_parse(missing_pattern_keyword, out, sizeof(outbuf));
	TEST_ASSERT(ret < 0,
		"expected failure for missing pattern keyword: %d", ret);

	ret = rte_flow_parser_parse(missing_action_separator, out, sizeof(outbuf));
	TEST_ASSERT(ret < 0,
		"expected failure for missing action separator: %d", ret);

	ret = rte_flow_parser_parse(missing_pattern_end, out, sizeof(outbuf));
	TEST_ASSERT(ret < 0,
		"expected failure for missing pattern end: %d", ret);

	ret = rte_flow_parser_parse(missing_port_id, out, sizeof(outbuf));
	TEST_ASSERT(ret < 0,
		"expected failure for missing port id: %d", ret);

	ret = rte_flow_parser_parse(extra_trailing_token, out, sizeof(outbuf));
	TEST_ASSERT(ret < 0,
		"expected failure for extra trailing token: %d", ret);

	ret = rte_flow_parser_parse(empty_command, out, sizeof(outbuf));
	TEST_ASSERT(ret < 0,
		"expected failure for empty command: %d", ret);

	ret = rte_flow_parser_parse(whitespace_only, out, sizeof(outbuf));
	TEST_ASSERT(ret < 0,
		"expected failure for whitespace-only command: %d", ret);

	return TEST_SUCCESS;
}

static int
test_flow_parser_cmdline_port_id(void)
{
	uint8_t outbuf[4096];
	struct rte_flow_parser_output *out = (void *)outbuf;
	int ret;

	/* Test various port IDs */
	ret = rte_flow_parser_parse("flow list 0", out, sizeof(outbuf));
	TEST_ASSERT_SUCCESS(ret, "port 0 parse failed");
	TEST_ASSERT_EQUAL(out->port, 0, "expected port 0, got %u", out->port);

	ret = rte_flow_parser_parse("flow list 1", out, sizeof(outbuf));
	TEST_ASSERT_SUCCESS(ret, "port 1 parse failed");
	TEST_ASSERT_EQUAL(out->port, 1, "expected port 1, got %u", out->port);

	ret = rte_flow_parser_parse("flow list 255", out, sizeof(outbuf));
	TEST_ASSERT_SUCCESS(ret, "port 255 parse failed");
	TEST_ASSERT_EQUAL(out->port, 255, "expected port 255, got %u", out->port);

	return TEST_SUCCESS;
}

/* Cmdline integration tests */

static void
test_dispatch_cb(const struct rte_flow_parser_output *in __rte_unused)
{
}

static cmdline_parse_inst_t test_flow_inst = {
	.f = rte_flow_parser_cmd_flow_cb,
	.data = NULL,
	.help_str = NULL,
	.tokens = { NULL },
};

static int
test_flow_parser_cmdline_register(void)
{
	cmdline_parse_token_hdr_t *tok = NULL;

	rte_flow_parser_cmd_flow_cb(&tok, NULL, &test_flow_inst.tokens[0]);
	TEST_ASSERT_NOT_NULL(tok, "first dynamic token should not be NULL");

	return TEST_SUCCESS;
}

/* Encap/decap setter tests */

static int
test_flow_parser_raw_encap_setter(void)
{
	const struct rte_flow_item *items;
	uint32_t items_n;
	const struct rte_flow_action_raw_encap *conf;
	int ret;

	ret = rte_flow_parser_parse_pattern_str(
		"eth / ipv4 / udp / vxlan / end", &items, &items_n);
	TEST_ASSERT_SUCCESS(ret, "pattern parse failed: %s", strerror(-ret));

	ret = rte_flow_parser_raw_encap_conf_set(0, items, items_n);
	TEST_ASSERT_SUCCESS(ret, "raw_encap_conf_set failed: %s",
		strerror(-ret));

	conf = rte_flow_parser_raw_encap_conf(0);
	TEST_ASSERT_NOT_NULL(conf, "raw_encap config missing after set");
	TEST_ASSERT_NOT_NULL(conf->data, "raw_encap data missing");
	TEST_ASSERT(conf->size > 0, "raw_encap size is 0");
	TEST_ASSERT(conf->size >= 50,
		"raw_encap size too small for eth/ipv4/udp/vxlan: %zu",
		conf->size);

	return TEST_SUCCESS;
}

static int
test_flow_parser_raw_decap_setter(void)
{
	const struct rte_flow_item *items;
	uint32_t items_n;
	const struct rte_flow_action_raw_decap *conf;
	int ret;

	ret = rte_flow_parser_parse_pattern_str(
		"eth / end", &items, &items_n);
	TEST_ASSERT_SUCCESS(ret, "pattern parse failed: %s", strerror(-ret));

	ret = rte_flow_parser_raw_decap_conf_set(0, items, items_n);
	TEST_ASSERT_SUCCESS(ret, "raw_decap_conf_set failed: %s",
		strerror(-ret));

	conf = rte_flow_parser_raw_decap_conf(0);
	TEST_ASSERT_NOT_NULL(conf, "raw_decap config missing after set");
	TEST_ASSERT_NOT_NULL(conf->data, "raw_decap data missing");
	TEST_ASSERT(conf->size >= 14,
		"raw_decap size too small for eth: %zu", conf->size);

	return TEST_SUCCESS;
}

static int
test_flow_parser_raw_setter_boundary(void)
{
	const struct rte_flow_item *items;
	uint32_t items_n;
	int ret;

	ret = rte_flow_parser_parse_pattern_str(
		"eth / end", &items, &items_n);
	TEST_ASSERT_SUCCESS(ret, "pattern parse failed");

	ret = rte_flow_parser_raw_encap_conf_set(RAW_ENCAP_CONFS_MAX_NUM,
		items, items_n);
	TEST_ASSERT(ret < 0, "out-of-range index should fail");

	ret = rte_flow_parser_raw_decap_conf_set(RAW_ENCAP_CONFS_MAX_NUM,
		items, items_n);
	TEST_ASSERT(ret < 0, "out-of-range index should fail");

	return TEST_SUCCESS;
}

static int
test_flow_parser_config_register_identity(void)
{
	struct rte_flow_parser_vxlan_encap_conf local_vxlan = { 0 };
	struct rte_flow_parser_config cfg = { .vxlan_encap = &local_vxlan };

	TEST_ASSERT_SUCCESS(rte_flow_parser_config_register(&cfg),
		"config_register failed");

	/* Write through registered config, verify it's the same object */
	local_vxlan.select_ipv4 = 1;
	local_vxlan.vni[0] = 0xAA;
	TEST_ASSERT_EQUAL(cfg.vxlan_encap->vni[0], 0xAA,
		"registered config not the same object");

	/* Restore test config */
	test_register_config();
	return TEST_SUCCESS;
}

static struct unit_test_suite flow_parser_tests = {
	.suite_name = "flow parser autotest",
	.setup = flow_parser_setup,
	.teardown = NULL,
	.unit_test_cases = {
		/* Cmdline API tests (rte_flow_parser_cmdline.h) */
		TEST_CASE_ST(flow_parser_case_setup, flow_parser_teardown,
			test_flow_parser_cmdline_command_mapping),
		TEST_CASE_ST(flow_parser_case_setup, flow_parser_teardown,
			test_flow_parser_cmdline_invalid_args),
		TEST_CASE_ST(flow_parser_case_setup, flow_parser_teardown,
			test_flow_parser_cmdline_invalid_syntax),
		TEST_CASE_ST(flow_parser_case_setup, flow_parser_teardown,
			test_flow_parser_cmdline_port_id),
		TEST_CASE_ST(flow_parser_case_setup, flow_parser_teardown,
			test_flow_parser_cmdline_indirect_action),
		TEST_CASE_ST(flow_parser_case_setup, flow_parser_teardown,
			test_flow_parser_cmdline_meter),
		TEST_CASE_ST(flow_parser_case_setup, flow_parser_teardown,
			test_flow_parser_cmdline_queue_set_meta),
		TEST_CASE_ST(flow_parser_case_setup, flow_parser_teardown,
			test_flow_parser_cmdline_modify_field_count),
		TEST_CASE_ST(flow_parser_case_setup, flow_parser_teardown,
			test_flow_parser_cmdline_raw_decap_rss),
		/* Cmdline integration tests */
		TEST_CASE_ST(flow_parser_case_setup, flow_parser_teardown,
			test_flow_parser_cmdline_register),
		/* Setter tests */
		TEST_CASE_ST(flow_parser_case_setup, flow_parser_teardown,
			test_flow_parser_raw_encap_setter),
		TEST_CASE_ST(flow_parser_case_setup, flow_parser_teardown,
			test_flow_parser_raw_decap_setter),
		TEST_CASE_ST(flow_parser_case_setup, flow_parser_teardown,
			test_flow_parser_raw_setter_boundary),
		/* Config registration test */
		TEST_CASE_ST(flow_parser_case_setup, flow_parser_teardown,
			test_flow_parser_config_register_identity),
		TEST_CASES_END()
	}
};

static int
test_flow_parser(void)
{
	return unit_test_suite_runner(&flow_parser_tests);
}

REGISTER_FAST_TEST(flow_parser_autotest, NOHUGE_OK, ASAN_OK, test_flow_parser);

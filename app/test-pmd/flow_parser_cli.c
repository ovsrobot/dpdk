/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2016 6WIND S.A.
 * Copyright 2016 Mellanox Technologies, Ltd
 * Copyright 2026 DynaNIC Semiconductors, Ltd.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_string_fns.h>

#include <cmdline_parse.h>
#include <cmdline_parse_string.h>
#include <cmdline_parse_num.h>
#include <rte_hexdump.h>

#include <rte_flow_parser_cmdline.h>

#include "testpmd.h"

/* Application-owned flow parser configuration storage */
struct rte_flow_parser_vxlan_encap_conf testpmd_vxlan_conf;
struct rte_flow_parser_nvgre_encap_conf testpmd_nvgre_conf;
struct rte_flow_parser_l2_encap_conf testpmd_l2_encap_conf;
struct rte_flow_parser_l2_decap_conf testpmd_l2_decap_conf;
struct rte_flow_parser_mplsogre_encap_conf testpmd_mplsogre_encap_conf;
struct rte_flow_parser_mplsogre_decap_conf testpmd_mplsogre_decap_conf;
struct rte_flow_parser_mplsoudp_encap_conf testpmd_mplsoudp_encap_conf;
struct rte_flow_parser_mplsoudp_decap_conf testpmd_mplsoudp_decap_conf;
struct rte_flow_action_conntrack testpmd_conntrack;

static struct rte_flow_parser_raw_encap_data testpmd_raw_encap[RAW_ENCAP_CONFS_MAX_NUM];
static struct rte_flow_parser_raw_decap_data testpmd_raw_decap[RAW_ENCAP_CONFS_MAX_NUM];
static struct rte_flow_parser_ipv6_ext_push_data testpmd_ipv6_push[IPV6_EXT_PUSH_CONFS_MAX_NUM];
static struct rte_flow_parser_ipv6_ext_remove_data testpmd_ipv6_remove[IPV6_EXT_PUSH_CONFS_MAX_NUM];
static struct rte_flow_parser_sample_slot testpmd_sample[RAW_SAMPLE_CONFS_MAX_NUM];

void
testpmd_flow_parser_config_init(void)
{
	/* VXLAN defaults: IPv4, standard port, placeholder addresses */
	testpmd_vxlan_conf = (struct rte_flow_parser_vxlan_encap_conf){
		.select_ipv4 = 1,
		.udp_dst = RTE_BE16(RTE_VXLAN_DEFAULT_PORT),
		.ipv4_src = RTE_IPV4(127, 0, 0, 1),
		.ipv4_dst = RTE_IPV4(255, 255, 255, 255),
		.ipv6_src = RTE_IPV6_ADDR_LOOPBACK,
		.ipv6_dst = RTE_IPV6(0, 0, 0, 0, 0, 0, 0, 0x1111),
		.ip_ttl = 255,
		.eth_dst = { .addr_bytes = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } },
	};
	/* NVGRE defaults: IPv4, placeholder addresses */
	testpmd_nvgre_conf = (struct rte_flow_parser_nvgre_encap_conf){
		.select_ipv4 = 1,
		.ipv4_src = RTE_IPV4(127, 0, 0, 1),
		.ipv4_dst = RTE_IPV4(255, 255, 255, 255),
		.ipv6_src = RTE_IPV6_ADDR_LOOPBACK,
		.ipv6_dst = RTE_IPV6(0, 0, 0, 0, 0, 0, 0, 0x1111),
		.eth_dst = { .addr_bytes = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } },
	};

	struct rte_flow_parser_config cfg = {
		.vxlan_encap = &testpmd_vxlan_conf,
		.nvgre_encap = &testpmd_nvgre_conf,
		.l2_encap = &testpmd_l2_encap_conf,
		.l2_decap = &testpmd_l2_decap_conf,
		.mplsogre_encap = &testpmd_mplsogre_encap_conf,
		.mplsogre_decap = &testpmd_mplsogre_decap_conf,
		.mplsoudp_encap = &testpmd_mplsoudp_encap_conf,
		.mplsoudp_decap = &testpmd_mplsoudp_decap_conf,
		.conntrack = &testpmd_conntrack,
		.raw_encap = { testpmd_raw_encap, RAW_ENCAP_CONFS_MAX_NUM },
		.raw_decap = { testpmd_raw_decap, RAW_ENCAP_CONFS_MAX_NUM },
		.ipv6_ext_push = { testpmd_ipv6_push, IPV6_EXT_PUSH_CONFS_MAX_NUM },
		.ipv6_ext_remove = { testpmd_ipv6_remove, IPV6_EXT_PUSH_CONFS_MAX_NUM },
		.sample = { testpmd_sample, RAW_SAMPLE_CONFS_MAX_NUM },
		.cmd_flow = &cmd_flow,
		.dispatch = testpmd_flow_dispatch,
	};
	rte_flow_parser_config_register(&cfg);
}

struct cmd_show_set_raw_result {
	cmdline_fixed_string_t cmd_show;
	cmdline_fixed_string_t cmd_what;
	cmdline_fixed_string_t cmd_all;
	uint16_t cmd_index;
};

static void
cmd_show_set_raw_parsed(void *parsed_result, struct cmdline *cl, void *data)
{
	struct cmd_show_set_raw_result *res = parsed_result;
	uint16_t index = res->cmd_index;
	const uint8_t *raw_data = NULL;
	size_t raw_size = 0;
	char title[16] = { 0 };
	int all = 0;

	RTE_SET_USED(cl);
	RTE_SET_USED(data);
	if (strcmp(res->cmd_all, "all") == 0) {
		all = 1;
		index = 0;
	} else if (index >= RAW_ENCAP_CONFS_MAX_NUM) {
		fprintf(stderr, "index should be 0-%u\n",
			RAW_ENCAP_CONFS_MAX_NUM - 1);
		return;
	}
	do {
		if (strcmp(res->cmd_what, "raw_encap") == 0) {
			const struct rte_flow_action_raw_encap *conf =
				rte_flow_parser_raw_encap_conf(index);

			if (conf == NULL || conf->data == NULL || conf->size == 0) {
				fprintf(stderr,
					"raw_encap %u not configured\n",
					index);
				goto next;
			}
			raw_data = conf->data;
			raw_size = conf->size;
		} else if (strcmp(res->cmd_what, "raw_decap") == 0) {
			const struct rte_flow_action_raw_decap *conf =
				rte_flow_parser_raw_decap_conf(index);

			if (conf == NULL || conf->data == NULL || conf->size == 0) {
				fprintf(stderr,
					"raw_decap %u not configured\n",
					index);
				goto next;
			}
			raw_data = conf->data;
			raw_size = conf->size;
		}
		snprintf(title, sizeof(title), "\nindex: %u", index);
		rte_hexdump(stdout, title, raw_data, raw_size);
next:
		raw_data = NULL;
		raw_size = 0;
	} while (all && ++index < RAW_ENCAP_CONFS_MAX_NUM);
}

static cmdline_parse_token_string_t cmd_show_set_raw_cmd_show =
	TOKEN_STRING_INITIALIZER(struct cmd_show_set_raw_result,
			cmd_show, "show");
static cmdline_parse_token_string_t cmd_show_set_raw_cmd_what =
	TOKEN_STRING_INITIALIZER(struct cmd_show_set_raw_result,
			cmd_what, "raw_encap#raw_decap");
static cmdline_parse_token_num_t cmd_show_set_raw_cmd_index =
	TOKEN_NUM_INITIALIZER(struct cmd_show_set_raw_result,
			cmd_index, RTE_UINT16);
static cmdline_parse_token_string_t cmd_show_set_raw_cmd_all =
	TOKEN_STRING_INITIALIZER(struct cmd_show_set_raw_result,
			cmd_all, "all");

cmdline_parse_inst_t cmd_flow = {
	.f = rte_flow_parser_cmd_flow_cb,
	.data = NULL,
	.help_str = NULL,
	.tokens = {
		NULL,
	},
};

enum testpmd_set_type {
	TESTPMD_SET_RAW_ENCAP,
	TESTPMD_SET_RAW_DECAP,
	TESTPMD_SET_SAMPLE_ACTIONS,
	TESTPMD_SET_IPV6_EXT_PUSH,
	TESTPMD_SET_IPV6_EXT_REMOVE,
	TESTPMD_SET_UNKNOWN,
};

/*
 * Tokenization-phase subcommand type.
 *
 * During cmdline tokenization the subcmd parse callback runs before the
 * index callback, and during the matching pass (res==NULL) there is no
 * output buffer to write to.  This static carries the subcommand type
 * from parse_subcmd to parse_index so the correct ctx_init variant is
 * called.  The dispatch callback reads from out->command instead.
 */
static enum testpmd_set_type set_tok_subcmd;

static int
testpmd_set_parse_keyword(cmdline_parse_token_hdr_t *tk, const char *buf,
			  void *res, unsigned int ressize)
{
	(void)tk; (void)res; (void)ressize;
	if (strncmp(buf, "set", 3) != 0 || (buf[3] != '\0' && buf[3] != ' '))
		return -1;
	/* Reset the shared parser context so that cmd_flow's prior probe
	 * (which runs before cmd_set_raw) does not leave stale state.
	 */
	rte_flow_parser_set_ctx_init(RTE_FLOW_PARSER_SET_ITEMS_PATTERN,
				     NULL, 0);
	return 3;
}

static int
testpmd_set_complete_keyword_nb(cmdline_parse_token_hdr_t *tk)
{
	(void)tk;
	return 1;
}

static int
testpmd_set_complete_keyword_elt(cmdline_parse_token_hdr_t *tk, int idx,
				 char *dst, unsigned int size)
{
	(void)tk;
	if (idx == 0) {
		strlcpy(dst, "set", size);
		return 0;
	}
	return -1;
}

static int
testpmd_set_help_keyword(cmdline_parse_token_hdr_t *tk, char *buf,
			 unsigned int size)
{
	(void)tk;
	strlcpy(buf, "set", size);
	return 0;
}

static struct cmdline_token_ops testpmd_set_keyword_ops = {
	.parse = testpmd_set_parse_keyword,
	.complete_get_nb = testpmd_set_complete_keyword_nb,
	.complete_get_elt = testpmd_set_complete_keyword_elt,
	.get_help = testpmd_set_help_keyword,
};
static struct cmdline_token_hdr testpmd_set_keyword_hdr = {
	.ops = &testpmd_set_keyword_ops,
	.offset = 0,
};

static const char *const testpmd_set_subcmds[] = {
	"raw_encap", "raw_decap", "sample_actions",
	"ipv6_ext_push", "ipv6_ext_remove", NULL,
};

static int
testpmd_set_parse_subcmd(cmdline_parse_token_hdr_t *tk, const char *buf,
			 void *res, unsigned int ressize)
{
	(void)tk; (void)res; (void)ressize;
	for (int i = 0; testpmd_set_subcmds[i]; i++) {
		int len = strlen(testpmd_set_subcmds[i]);

		if (strncmp(buf, testpmd_set_subcmds[i], len) == 0 &&
		    (buf[len] == '\0' || buf[len] == ' ')) {
			set_tok_subcmd = (enum testpmd_set_type)i;
			return len;
		}
	}
	return -1;
}

static int
testpmd_set_complete_subcmd_nb(cmdline_parse_token_hdr_t *tk)
{
	(void)tk;
	int count = 0;

	while (testpmd_set_subcmds[count])
		count++;
	return count;
}

static int
testpmd_set_complete_subcmd_elt(cmdline_parse_token_hdr_t *tk, int idx,
				char *dst, unsigned int size)
{
	(void)tk;
	if (idx >= 0 && testpmd_set_subcmds[idx] != NULL) {
		strlcpy(dst, testpmd_set_subcmds[idx], size);
		return 0;
	}
	return -1;
}

static int
testpmd_set_help_subcmd(cmdline_parse_token_hdr_t *tk, char *buf,
			unsigned int size)
{
	(void)tk;
	strlcpy(buf,
		"raw_encap|raw_decap|sample_actions|ipv6_ext_push|ipv6_ext_remove",
		size);
	return 0;
}

static struct cmdline_token_ops testpmd_set_subcmd_ops = {
	.parse = testpmd_set_parse_subcmd,
	.complete_get_nb = testpmd_set_complete_subcmd_nb,
	.complete_get_elt = testpmd_set_complete_subcmd_elt,
	.get_help = testpmd_set_help_subcmd,
};
static struct cmdline_token_hdr testpmd_set_subcmd_hdr = {
	.ops = &testpmd_set_subcmd_ops,
	.offset = 0,
};

static int
testpmd_set_parse_index(cmdline_parse_token_hdr_t *tk, const char *buf,
			void *res, unsigned int ressize)
{
	(void)tk;
	char *end;
	unsigned long val = strtoul(buf, &end, 10);
	enum rte_flow_parser_set_item_kind kind;
	void *obj = NULL;

	if (end == buf || val > UINT16_MAX)
		return -1;

	if (res != NULL && ressize >= sizeof(struct rte_flow_parser_output)) {
		struct rte_flow_parser_output *out = res;

		memset(out, 0x00, sizeof(*out));
		memset((uint8_t *)out + sizeof(*out), 0x22,
		       ressize - sizeof(*out));
		out->port = (uint16_t)val;
		out->command = (enum rte_flow_parser_command)set_tok_subcmd;
		out->args.vc.data = (uint8_t *)out + ressize;
		if (set_tok_subcmd == TESTPMD_SET_SAMPLE_ACTIONS)
			out->args.vc.actions = (void *)RTE_ALIGN_CEIL(
				(uintptr_t)(out + 1), sizeof(double));
		else
			out->args.vc.pattern = (void *)RTE_ALIGN_CEIL(
				(uintptr_t)(out + 1), sizeof(double));
		obj = (void *)RTE_ALIGN_CEIL(
			(uintptr_t)(out + 1), sizeof(double));
	}

	if (set_tok_subcmd == TESTPMD_SET_SAMPLE_ACTIONS)
		kind = RTE_FLOW_PARSER_SET_ITEMS_ACTION;
	else if (set_tok_subcmd == TESTPMD_SET_IPV6_EXT_PUSH ||
		 set_tok_subcmd == TESTPMD_SET_IPV6_EXT_REMOVE)
		kind = RTE_FLOW_PARSER_SET_ITEMS_IPV6_EXT;
	else
		kind = RTE_FLOW_PARSER_SET_ITEMS_PATTERN;

	/*
	 * Must be called even when res==NULL (completion/matching pass)
	 * so that the library context is ready for subsequent tokens.
	 */
	rte_flow_parser_set_ctx_init(kind, obj, ressize);

	return end - buf;
}

static int
testpmd_set_help_index(cmdline_parse_token_hdr_t *tk, char *buf,
		       unsigned int size)
{
	(void)tk;
	strlcpy(buf, "UNSIGNED", size);
	return 0;
}

static struct cmdline_token_ops testpmd_set_index_ops = {
	.parse = testpmd_set_parse_index,
	.complete_get_nb = NULL,
	.complete_get_elt = NULL,
	.get_help = testpmd_set_help_index,
};
static struct cmdline_token_hdr testpmd_set_index_hdr = {
	.ops = &testpmd_set_index_ops,
	.offset = 0,
};

static void
testpmd_set_tok(cmdline_parse_token_hdr_t **hdr,
		cmdline_parse_token_hdr_t **hdr_inst)
{
	cmdline_parse_token_hdr_t **tokens = cmd_set_raw.tokens;
	int pos = hdr_inst - tokens;

	switch (pos) {
	case 0:
		*hdr = &testpmd_set_keyword_hdr;
		break;
	case 1:
		*hdr = &testpmd_set_subcmd_hdr;
		break;
	case 2:
		*hdr = &testpmd_set_index_hdr;
		break;
	default:
		rte_flow_parser_set_item_tok(hdr);
		break;
	}
}

static void
testpmd_set_dispatch(struct rte_flow_parser_output *out)
{
	uint16_t idx = out->port;
	enum testpmd_set_type type = (enum testpmd_set_type)out->command;
	int ret = 0;

	switch (type) {
	case TESTPMD_SET_RAW_ENCAP:
		ret = rte_flow_parser_raw_encap_conf_set(idx,
			out->args.vc.pattern, out->args.vc.pattern_n);
		break;
	case TESTPMD_SET_RAW_DECAP:
		ret = rte_flow_parser_raw_decap_conf_set(idx,
			out->args.vc.pattern, out->args.vc.pattern_n);
		break;
	case TESTPMD_SET_SAMPLE_ACTIONS:
		ret = rte_flow_parser_sample_actions_set(idx,
			out->args.vc.actions, out->args.vc.actions_n);
		break;
	case TESTPMD_SET_IPV6_EXT_PUSH:
		ret = rte_flow_parser_ipv6_ext_push_set(idx,
			out->args.vc.pattern, out->args.vc.pattern_n);
		break;
	case TESTPMD_SET_IPV6_EXT_REMOVE:
		ret = rte_flow_parser_ipv6_ext_remove_set(idx,
			out->args.vc.pattern, out->args.vc.pattern_n);
		break;
	default:
		ret = -EINVAL;
		break;
	}
	if (ret != 0)
		fprintf(stderr, "set command failed: %s\n", strerror(-ret));
}

static void
testpmd_cmd_set_raw_cb(void *arg0, struct cmdline *cl, void *arg2)
{
	if (cl == NULL) {
		testpmd_set_tok(arg0, arg2);
		return;
	}
	testpmd_set_dispatch(arg0);
}

cmdline_parse_inst_t cmd_set_raw = {
	.f = testpmd_cmd_set_raw_cb,
	.data = NULL,
	.help_str = "set <raw_encap|raw_decap|sample_actions"
		    "|ipv6_ext_push|ipv6_ext_remove> <index> <items>",
	.tokens = {
		NULL,
	},
};

cmdline_parse_inst_t cmd_show_set_raw = {
	.f = cmd_show_set_raw_parsed,
	.data = NULL,
	.help_str = "show <raw_encap|raw_decap> <index>",
	.tokens = {
		(void *)&cmd_show_set_raw_cmd_show,
		(void *)&cmd_show_set_raw_cmd_what,
		(void *)&cmd_show_set_raw_cmd_index,
		NULL,
	},
};

cmdline_parse_inst_t cmd_show_set_raw_all = {
	.f = cmd_show_set_raw_parsed,
	.data = NULL,
	.help_str = "show <raw_encap|raw_decap> all",
	.tokens = {
		(void *)&cmd_show_set_raw_cmd_show,
		(void *)&cmd_show_set_raw_cmd_what,
		(void *)&cmd_show_set_raw_cmd_all,
		NULL,
	},
};

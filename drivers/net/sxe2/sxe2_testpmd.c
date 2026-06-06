
/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2025, Wuxi Stars Micro System Technologies Co., Ltd.
 */

#ifndef SXE2_TEST
#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>
#include <stdlib.h>
#include <testpmd.h>

#include "sxe2_common_log.h"
#include "sxe2_testpmd_lib.h"

#define SXE2_SWITCH_BUFF_SIZE (4 * 1024 * 1024)

struct cmd_stats_info_show_result {
	cmdline_fixed_string_t sxe2;
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t stats;
	portid_t port_id;
};
cmdline_parse_token_string_t cmd_stats_info_sxe2 =
	TOKEN_STRING_INITIALIZER(struct cmd_stats_info_show_result, sxe2, "sxe2");
cmdline_parse_token_string_t cmd_stats_info_show =
	TOKEN_STRING_INITIALIZER(struct cmd_stats_info_show_result, show, "show");
cmdline_parse_token_string_t cmd_stats_info_stats =
	TOKEN_STRING_INITIALIZER(struct cmd_stats_info_show_result, stats, "stats");
cmdline_parse_token_num_t cmd_stats_info_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_stats_info_show_result, port_id, RTE_UINT16);

struct cmd_flow_rule_result {
	cmdline_fixed_string_t sxe2;
	cmdline_fixed_string_t flow;
	cmdline_fixed_string_t rule;
	cmdline_fixed_string_t dump;
	portid_t port_id;
};
cmdline_parse_token_string_t cmd_flow_rule_sxe2 =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_rule_result, sxe2, "sxe2");
cmdline_parse_token_string_t cmd_flow_rule_flow =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_rule_result, flow, "flow");
cmdline_parse_token_string_t cmd_flow_rule_rule =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_rule_result, rule, "rule");
cmdline_parse_token_string_t cmd_flow_rule_dmp =
	TOKEN_STRING_INITIALIZER(struct cmd_flow_rule_result, dump, "dump");
cmdline_parse_token_num_t cmd_flow_rule_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_flow_rule_result, port_id, RTE_UINT16);

struct cmd_udp_tunnel {
	cmdline_fixed_string_t sxe2;
	cmdline_fixed_string_t tunnel_type;
	cmdline_fixed_string_t action;
	cmdline_fixed_string_t udp_tunnel_port;
	uint16_t               udp_port;
	portid_t               port_id;
};

cmdline_parse_token_string_t cmd_udp_tunnel_sxe2 =
	TOKEN_STRING_INITIALIZER(struct cmd_udp_tunnel, sxe2, "sxe2");
cmdline_parse_token_string_t cmd_udp_tunnel_action =
	TOKEN_STRING_INITIALIZER(struct cmd_udp_tunnel, action, "add#rm#show");
cmdline_parse_token_string_t cmd_udp_tunnel_udp_tunnel_port =
	TOKEN_STRING_INITIALIZER(struct cmd_udp_tunnel, udp_tunnel_port, "udp_tunnel_port");
cmdline_parse_token_string_t cmd_udp_tunnel_tunnel_type =
	TOKEN_STRING_INITIALIZER(struct cmd_udp_tunnel,
	tunnel_type, "vxlan#vxlan-gpe#geneve#gtp-c#gtp-u#pfcp#ecpri#mpls#nvgre#l2tp#teredo");
cmdline_parse_token_num_t cmd_udp_tunnel_udp_port =
	TOKEN_NUM_INITIALIZER(struct cmd_udp_tunnel, udp_port, RTE_UINT16);
cmdline_parse_token_num_t cmd_udp_tunnel_port_id  =
	TOKEN_NUM_INITIALIZER(struct cmd_udp_tunnel, port_id, RTE_UINT16);

struct cmd_sched_result {
	cmdline_fixed_string_t sxe2;
	cmdline_fixed_string_t sched;
	cmdline_fixed_string_t reset;
	portid_t port_id;
};

cmdline_parse_token_string_t cmd_sched_sxe2 =
	 TOKEN_STRING_INITIALIZER(struct cmd_sched_result, sxe2, "sxe2");
cmdline_parse_token_string_t cmd_sched_sched =
	 TOKEN_STRING_INITIALIZER(struct cmd_sched_result, sched, "sched");
cmdline_parse_token_string_t cmd_sched_reset =
	 TOKEN_STRING_INITIALIZER(struct cmd_sched_result, reset, "reset");
cmdline_parse_token_num_t cmd_sched_port_id =
	 TOKEN_NUM_INITIALIZER(struct cmd_sched_result, port_id, RTE_UINT16);

struct cmd_ipsec_result {
	cmdline_fixed_string_t sxe2;
	cmdline_fixed_string_t engin;
	cmdline_fixed_string_t dir;
	cmdline_fixed_string_t op;
	portid_t port_id;
	uint16_t session_id;
	cmdline_fixed_string_t encrypt_algo;
	cmdline_fixed_string_t encrypt_key;
	cmdline_fixed_string_t auth_algo;
	cmdline_fixed_string_t auth_key;
	cmdline_fixed_string_t dst_ip;
	uint16_t sport;
	uint16_t dport;
	uint32_t spi;
};
cmdline_parse_token_string_t cmd_ipsec_mgt_sxe2 =
	TOKEN_STRING_INITIALIZER(struct cmd_ipsec_result, sxe2, "sxe2");
cmdline_parse_token_string_t cmd_ipsec_mgt_module =
	TOKEN_STRING_INITIALIZER(struct cmd_ipsec_result, engin, "ipsec");
cmdline_parse_token_string_t cmd_ipsec_mgt_dir =
	TOKEN_STRING_INITIALIZER(struct cmd_ipsec_result, dir, "egress#ingress");
cmdline_parse_token_string_t cmd_ipsec_mgt_op =
	TOKEN_STRING_INITIALIZER(struct cmd_ipsec_result, op, "add#rm#show");
cmdline_parse_token_num_t cmd_ipsec_mgt_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_ipsec_result, port_id, RTE_UINT16);
cmdline_parse_token_num_t cmd_ipsec_mgt_session_id =
	TOKEN_NUM_INITIALIZER(struct cmd_ipsec_result, session_id, RTE_UINT16);
cmdline_parse_token_string_t cmd_ipsec_mgt_encrypt_algo =
	TOKEN_STRING_INITIALIZER(struct cmd_ipsec_result, encrypt_algo, "aes-cbc#sm4-cbc#null");
cmdline_parse_token_string_t cmd_ipsec_mgt_encrypt_key =
	TOKEN_STRING_INITIALIZER(struct cmd_ipsec_result, encrypt_key, NULL);
cmdline_parse_token_string_t cmd_ipsec_mgt_auth_algo =
	TOKEN_STRING_INITIALIZER(struct cmd_ipsec_result, auth_algo, "sha-hmac#sm3-hmac#null");
cmdline_parse_token_string_t cmd_ipsec_mgt_auth_key =
	TOKEN_STRING_INITIALIZER(struct cmd_ipsec_result, auth_key, NULL);
cmdline_parse_token_string_t cmd_ipsec_mgt_dst_ip =
	TOKEN_STRING_INITIALIZER(struct cmd_ipsec_result, dst_ip, NULL);
cmdline_parse_token_num_t cmd_ipsec_mgt_sport =
	TOKEN_NUM_INITIALIZER(struct cmd_ipsec_result, sport, RTE_UINT16);
cmdline_parse_token_num_t cmd_ipsec_mgt_dport =
	TOKEN_NUM_INITIALIZER(struct cmd_ipsec_result, dport, RTE_UINT16);
cmdline_parse_token_num_t cmd_ipsec_mgt_spi =
	TOKEN_NUM_INITIALIZER(struct cmd_ipsec_result, spi, RTE_UINT32);

struct cmd_ipsec_set_result {
	cmdline_fixed_string_t sxe2;
	cmdline_fixed_string_t engin;
	cmdline_fixed_string_t op;
	cmdline_fixed_string_t type;
	portid_t port_id;
	uint16_t conf_value;
};
cmdline_parse_token_string_t cmd_ipsec_set_sxe2 =
	TOKEN_STRING_INITIALIZER(struct cmd_ipsec_set_result, sxe2, "sxe2");
cmdline_parse_token_string_t cmd_ipsec_set_module =
	TOKEN_STRING_INITIALIZER(struct cmd_ipsec_set_result, engin, "ipsec");
cmdline_parse_token_string_t cmd_ipsec_set_op =
	TOKEN_STRING_INITIALIZER(struct cmd_ipsec_set_result, op, "set#get");
cmdline_parse_token_string_t cmd_ipsec_set_type =
	TOKEN_STRING_INITIALIZER(struct cmd_ipsec_set_result, type, "session-id#esp-hdr-offset");
cmdline_parse_token_num_t cmd_ipsec_set_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_ipsec_set_result, port_id, RTE_UINT16);
cmdline_parse_token_num_t cmd_ipsec_set_value =
	TOKEN_NUM_INITIALIZER(struct cmd_ipsec_set_result, conf_value, RTE_UINT16);

struct cmd_ipsec_flush_result {
	cmdline_fixed_string_t sxe2;
	cmdline_fixed_string_t engin;
	cmdline_fixed_string_t op;
	portid_t port_id;
};
cmdline_parse_token_string_t cmd_ipsec_flush_sxe2 =
	TOKEN_STRING_INITIALIZER(struct cmd_ipsec_flush_result, sxe2, "sxe2");
cmdline_parse_token_string_t cmd_ipsec_flush_module =
	TOKEN_STRING_INITIALIZER(struct cmd_ipsec_flush_result, engin, "ipsec");
cmdline_parse_token_string_t cmd_ipsec_flush_op =
	TOKEN_STRING_INITIALIZER(struct cmd_ipsec_flush_result, op, "flush");
cmdline_parse_token_num_t cmd_ipsec_flush_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_ipsec_flush_result, port_id, RTE_UINT16);

struct cmd_inject_irq {
	cmdline_fixed_string_t sxe2;
	cmdline_fixed_string_t inject;
	cmdline_fixed_string_t irq;
	portid_t port_id;
	cmdline_fixed_string_t type;
};
cmdline_parse_token_string_t cmd_inject_irq_sxe2 =
	TOKEN_STRING_INITIALIZER(struct cmd_inject_irq, sxe2, "sxe2");
cmdline_parse_token_string_t cmd_inject_irq_inject =
	TOKEN_STRING_INITIALIZER(struct cmd_inject_irq, inject, "inject");
cmdline_parse_token_string_t cmd_inject_irq_irq =
	TOKEN_STRING_INITIALIZER(struct cmd_inject_irq, irq, "irq");
cmdline_parse_token_num_t cmd_inject_irq_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_inject_irq, port_id, RTE_UINT16);
cmdline_parse_token_string_t cmd_inject_irq_type =
	TOKEN_STRING_INITIALIZER(struct cmd_inject_irq, type, "reset#lsc");

static void cmd_dump_flow_rule_parsed(void *parsed_result,
				      struct cmdline *cl,
				      __rte_unused void *data)
{
	struct cmd_flow_rule_result *res = parsed_result;
	int                          ret = -1;

	ret = sxe2_flow_rule_dump(res->port_id, cl);
	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		cmdline_printf(cl, "Invalid parameters.\n");
		break;
	case -ENODEV:
		cmdline_printf(cl, "Device doesn't support\n");
		break;
	default:
		cmdline_printf(cl,
			"Failed to switch rule dump,"
			" error: (%s)\n",
			strerror(-ret));
	}
}

static void cmd_udp_tunnel_set_parsed(void *parsed_result,
				      struct cmdline *cl,
				      __rte_unused void *data)
{
	struct cmd_udp_tunnel *res = parsed_result;
	int32_t ret = -1;
	uint8_t action;
	const char *action_str[SXE2_TESTPMD_CMD_UDP_TUNNEL_MAX] = {
		[SXE2_TESTPMD_CMD_UDP_TUNNEL_ADD] = "add",
		[SXE2_TESTPMD_CMD_UDP_TUNNEL_DEL] = "rm",
		[SXE2_TESTPMD_CMD_UDP_TUNNEL_GET] = "show"};

	for (action = 0; action < SXE2_TESTPMD_CMD_UDP_TUNNEL_MAX; action++)
		if (!strcmp(res->action, action_str[action]))
			break;

	if (action >= SXE2_TESTPMD_CMD_UDP_TUNNEL_MAX) {
		cmdline_printf(cl, "Invalid action!\n");
		return;
	}

	ret = sxe2_udp_tunnel_operations(res->port_id, cl, action,
					 res->udp_port,
					 res->tunnel_type);
	if (ret)
		cmdline_printf(cl, "%s udp tunnel port failed, ret = %d\n",
				action_str[action], ret);
}

static void cmd_dump_stats_info_parsed(void *parsed_result,
				       struct cmdline *cl,
				       __rte_unused void *data)
{
	struct cmd_stats_info_show_result *res = parsed_result;
	int ret = -1;

	ret = sxe2_stats_info_show(res->port_id);
	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		cmdline_printf(cl, "Invalid parameters.\n");
		break;
	case -ENODEV:
		cmdline_printf(cl, "Device doesn't support\n");
		break;
	default:
		cmdline_printf(cl,
			"Failed to show stats info,"
			" error: (%s)\n", strerror(-ret));
	}
}

static uint8_t cmd_ipsec_op_get(char *op)
{
	uint8_t i;
	const char *op_type[SXE2_TESTPMD_CMD_IPSEC_OP_MAX] = {
		[SXE2_TESTPMD_CMD_IPSEC_OP_ADD] = "add",
		[SXE2_TESTPMD_CMD_IPSEC_OP_RM] = "rm",
		[SXE2_TESTPMD_CMD_IPSEC_OP_SHOW] = "show",
	};

	for (i = 0; i < SXE2_TESTPMD_CMD_IPSEC_OP_MAX; i++) {
		if (!strcmp(op, op_type[i]))
			break;
	}

	return i;
}

static uint8_t cmd_ipsec_dir_get(char *dir)
{
	uint8_t i;
	const char *dir_type[SXE2_TESTPMD_CMD_IPSEC_DIR_MAX] = {
		[SXE2_TESTPMD_CMD_IPSEC_DIR_EGRESS] = "egress",
		[SXE2_TESTPMD_CMD_IPSEC_DIR_INGRESS] = "ingress"
	};

	for (i = 0; i < SXE2_TESTPMD_CMD_IPSEC_DIR_MAX; i++) {
		if (!strcmp(dir, dir_type[i]))
			break;
	}

	return i;
}

static int sxe2_hex_to_val(char c)
{
	int val = 0;

	if (c >= '0' && c <= '9')
		val = c - '0';
	if (c >= 'A' && c <= 'F')
		val = 10 + c - 'A';
	if (c >= 'a' && c <= 'f')
		val = 10 + c - 'a';
	return val;
}

static void sxe2_hex_to_bytes(uint8_t *enc_key, char *hex_str, uint8_t len)
{
	uint8_t i;
	int high = 0;
	int low = 0;

	for (i = 0; i < len; i++) {
		high = sxe2_hex_to_val(hex_str[2 * i]);
		low = sxe2_hex_to_val(hex_str[2 * i + 1]);
		enc_key[i] = (high << 4) | low;
	}
}

static int32_t cmd_ipsec_add_param_fill(struct sxe2_ipsec_conf_param *param,
					struct cmdline *cl,
					struct cmd_ipsec_result *res)
{
	uint8_t i;
	uint8_t j;
	int32_t ret = -1;
	const char *encrypt_algo[SXE2_TESTPMD_CMD_IPSEC_EN_ALGO_MAX] = {
		[SXE2_TESTPMD_CMD_IPSEC_EN_ALGO_AES_CBC] = "aes-cbc",
		[SXE2_TESTPMD_CMD_IPSEC_EN_ALGO_SM4_CBC] = "sm4-cbc",
		[SXE2_TESTPMD_CMD_IPSEC_EN_ALGO_NULL] = "null"
	};

	const char *auth_algo[SXE2_TESTPMD_CMD_IPSEC_AUTH_ALGO_MAX] = {
		[SXE2_TESTPMD_CMD_IPSEC_AUTH_ALGO_SHA_HMAC] = "sha-hmac",
		[SXE2_TESTPMD_CMD_IPSEC_AUTH_ALGO_SM3_HMAC] = "sm3-hmac",
		[SXE2_TESTPMD_CMD_IPSEC_AUTH_ALGO_NULL] = "null"
	};

	for (i = 0; i < SXE2_TESTPMD_CMD_IPSEC_EN_ALGO_MAX; i++)
		if (!strcmp(res->encrypt_algo, encrypt_algo[i]))
			break;

	if (i >= SXE2_TESTPMD_CMD_IPSEC_EN_ALGO_MAX) {
		cmdline_printf(cl, "Invalid ipsec encrypt algo: %s!\n", res->encrypt_algo);
		ret = -EINVAL;
		goto l_end;
	}

	for (j = 0; j < SXE2_TESTPMD_CMD_IPSEC_AUTH_ALGO_MAX; j++) {
		if (!strcmp(res->auth_algo, auth_algo[j]))
			break;
	}


	if (j >= SXE2_TESTPMD_CMD_IPSEC_AUTH_ALGO_MAX) {
		cmdline_printf(cl, "Invalid ipsec auth algo: %s!\n", res->auth_algo);
		ret = -EINVAL;
		goto l_end;
	}

	param->encrypt_algo = i;
	param->auth_algo = j;
	if (param->encrypt_algo == SXE2_TESTPMD_CMD_IPSEC_EN_ALGO_SM4_CBC)
		param->enc_len = 16;
	else
		param->enc_len = 32;

	sxe2_hex_to_bytes(param->enc_key, res->encrypt_key, param->enc_len);
	if (param->auth_algo != SXE2_TESTPMD_CMD_IPSEC_AUTH_ALGO_NULL) {
		param->auth_len = 32;
		sxe2_hex_to_bytes(param->auth_key, res->auth_key, param->auth_len);
	}

	ret = 0;

l_end:
	return ret;
}

static int32_t cmd_ipsec_egress_op_parsed(struct sxe2_ipsec_conf_param *param,
					  struct cmdline *cl,
					  struct cmd_ipsec_result *res)
{
	int32_t ret = -1;

	switch (param->op) {
	case SXE2_TESTPMD_CMD_IPSEC_OP_ADD:
		ret = cmd_ipsec_add_param_fill(param, cl, res);
		if (ret)
			goto l_end;
		ret = sxe2_ipsec_egress_create(param, cl);
		break;
	case SXE2_TESTPMD_CMD_IPSEC_OP_RM:
		param->session_id = res->session_id;
		ret = sxe2_ipsec_egress_destroy(param, cl);
		break;
	case SXE2_TESTPMD_CMD_IPSEC_OP_SHOW:
		ret = sxe2_ipsec_egress_show(param, cl);
		break;
	default:
		ret = -EINVAL;
		break;
	}

l_end:
	return ret;
}

static int32_t cmd_ipsec_ip_addr_parsed(struct sxe2_ipsec_conf_param *param,
					struct cmdline *cl,
					struct cmd_ipsec_result *res)
{
	int32_t ret = -1;
	struct in_addr addr4;
	struct in6_addr addr6;

	if (inet_pton(AF_INET, res->dst_ip, &addr4) == 1) {
		param->ip_addr.type = RTE_SECURITY_IPSEC_TUNNEL_IPV4;
		param->ip_addr.dst_ipv4 = addr4.s_addr;
		ret = 0;
	} else if (inet_pton(AF_INET6, res->dst_ip, &addr6) == 1) {
		param->ip_addr.type = RTE_SECURITY_IPSEC_TUNNEL_IPV6;
		memcpy(&param->ip_addr.dst_ipv6, &addr6, sizeof(param->ip_addr.dst_ipv6));
		ret = 0;
	} else {
		cmdline_printf(cl, "Invalid ip address: %s!\n", res->dst_ip);
		ret = -EINVAL;
		goto l_end;
	}

l_end:
	return ret;
}

static int32_t cmd_ipsec_ingress_op_parsed(struct sxe2_ipsec_conf_param *param,
					   struct cmdline *cl,
					   struct cmd_ipsec_result *res)
{
	int32_t ret = -1;

	switch (param->op) {
	case SXE2_TESTPMD_CMD_IPSEC_OP_ADD:
		ret = cmd_ipsec_add_param_fill(param, cl, res);
		if (ret)
			goto l_end;
		param->sport = htons(res->sport);
		param->dport = htons(res->dport);
		param->spi = htonl(res->spi);
		ret = cmd_ipsec_ip_addr_parsed(param, cl, res);
		if (ret)
			goto l_end;
		ret = sxe2_ipsec_ingress_create(param, cl);
		break;
	case SXE2_TESTPMD_CMD_IPSEC_OP_RM:
		param->session_id = res->session_id;
		ret = sxe2_ipsec_ingress_destroy(param, cl);
		break;
	case SXE2_TESTPMD_CMD_IPSEC_OP_SHOW:
		ret = sxe2_ipsec_ingress_show(param, cl);
		break;
	default:
		ret = -EINVAL;
		break;
	}

l_end:
	return ret;
}

static int32_t cmd_ipsec_dir_parsed(struct sxe2_ipsec_conf_param *param,
				    struct cmdline *cl,
				    struct cmd_ipsec_result *res)
{
	int32_t ret = -1;

	switch (param->dir) {
	case SXE2_TESTPMD_CMD_IPSEC_DIR_EGRESS:
		ret = cmd_ipsec_egress_op_parsed(param, cl, res);
		break;
	case SXE2_TESTPMD_CMD_IPSEC_DIR_INGRESS:
		ret = cmd_ipsec_ingress_op_parsed(param, cl, res);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static void cmd_ipsec_mgt_parsed(void *parsed_result,
				 struct cmdline *cl,
				 __rte_unused void *data)
{
	struct cmd_ipsec_result *res = parsed_result;
	struct sxe2_ipsec_conf_param param;
	int32_t ret = -1;
	uint8_t dir = 0;
	uint8_t op = 0;

	dir = cmd_ipsec_dir_get(res->dir);
	if (dir >= SXE2_TESTPMD_CMD_IPSEC_DIR_MAX) {
		cmdline_printf(cl, "Invalid ipsec direction: %s!\n", res->dir);
		ret = -EINVAL;
		goto l_end;
	}

	op = cmd_ipsec_op_get(res->op);
	if (op >= SXE2_TESTPMD_CMD_IPSEC_OP_MAX) {
		cmdline_printf(cl, "Invalid ipsec operation: %s!\n", res->op);
		ret = -EINVAL;
		goto l_end;
	}

	memset(&param, 0, sizeof(struct sxe2_ipsec_conf_param));
	param.dir = dir;
	param.op = op;
	param.port_id = res->port_id;
	ret = cmd_ipsec_dir_parsed(&param, cl, res);

	if (ret)
		cmdline_printf(cl, "Command execute failed, ret = %d\n", ret);

l_end:
	return;
}

static void cmd_ipsec_set_parsed(void *parsed_result,
				 struct cmdline *cl,
				 __rte_unused void *data)
{
	struct cmd_ipsec_set_result *res = parsed_result;
	int32_t ret = -1;

	if (!strcmp(res->op, "set"))
		ret = sxe2_ipsec_conf_set(res->port_id, cl, res->type, res->conf_value);
	else if (!strcmp(res->op, "get"))
		ret = sxe2_ipsec_conf_get(res->port_id, cl, res->type);
	else
		cmdline_printf(cl, "Invalid op: %s\n", res->op);

	if (ret)
		cmdline_printf(cl, "Command execute failed, ret = %d\n", ret);
}

static void cmd_ipsec_flush_parsed(void *parsed_result,
				   struct cmdline *cl,
				   __rte_unused void *data)
{
	struct cmd_ipsec_flush_result *res = parsed_result;
	int32_t ret = -1;

	ret = sxe2_ipsec_flush(res->port_id, cl);

	if (ret)
		cmdline_printf(cl, "Command execute failed, ret = %d\n", ret);
}

cmdline_parse_inst_t cmd_flow_rule_dump = {
	.f        = cmd_dump_flow_rule_parsed,
	.data     = NULL,
	.help_str = "sxe2 flow rule dump <port_id>",
	.tokens = {
		(void *)&cmd_flow_rule_sxe2,
		(void *)&cmd_flow_rule_flow,
		(void *)&cmd_flow_rule_rule,
		(void *)&cmd_flow_rule_dmp,
		(void *)&cmd_flow_rule_port_id,
		NULL,
	},
};

cmdline_parse_inst_t cmd_udp_tunnel_set = {
	.f        = cmd_udp_tunnel_set_parsed,
	.data     = NULL,
	.help_str = "sxe2 <port_id> udp_tunnel_port add|rm|show "
			"vxlan|vxlan-gpe|geneve|gtp-c|gtp-u|pfcp|ecpri|mpls|nvgre|l2tp|teredo <udp_port>",
	.tokens = {
		(void *)&cmd_udp_tunnel_sxe2,
		(void *)&cmd_udp_tunnel_port_id,
		(void *)&cmd_udp_tunnel_udp_tunnel_port,
		(void *)&cmd_udp_tunnel_action,
		(void *)&cmd_udp_tunnel_tunnel_type,
		(void *)&cmd_udp_tunnel_udp_port,
		NULL,
	},
};

cmdline_parse_inst_t cmd_stats_mgt = {
	.f        = cmd_dump_stats_info_parsed,
	.data     = NULL,
	.help_str = "sxe2 show stats <port_id>",
	.tokens = {
		(void *)&cmd_stats_info_sxe2,
		(void *)&cmd_stats_info_show,
		(void *)&cmd_stats_info_stats,
		(void *)&cmd_stats_info_port_id,
		NULL,
	},
};

static void cmd_sched_reset_cfg(void *parsed_result,
				struct cmdline *cl,
				__rte_unused void *data)
{
	struct cmd_sched_result *res = parsed_result;
	int32_t ret = -1;

	ret = sxe2_testpmd_sched_reset(res->port_id);
	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		cmdline_printf(cl, "invalid sched ops\n");
		break;
	case -ENOTSUP:
		cmdline_printf(cl, "function not implemented\n");
		break;
	default:
		cmdline_printf(cl, "programming error: (%s)\n",
			strerror(-ret));
	}
}

cmdline_parse_inst_t cmd_sched_reset_cmd = {
	.f        = cmd_sched_reset_cfg,
	.data     = NULL,
	.help_str = "sxe2 sched reset <port_id>",
	.tokens = {
		(void *)&cmd_sched_sxe2,
		(void *)&cmd_sched_sched,
		(void *)&cmd_sched_reset,
		(void *)&cmd_sched_port_id,
		NULL,
	},
};

cmdline_parse_inst_t cmd_ipsec_mgt = {
	.f = cmd_ipsec_mgt_parsed,
	.data = NULL,
	.help_str = "sxe2 ipsec egress|ingress add|rm|show "
	"<port_id> <session_id> aes-cbc|sm4-cbc|null <encrypt_key> sha-hmac|sm3-hmac|null "
	"<auth_key> <dst_ip> <sport> <dport> <spi>",
	.tokens = {
		(void *)&cmd_ipsec_mgt_sxe2,
		(void *)&cmd_ipsec_mgt_module,
		(void *)&cmd_ipsec_mgt_dir,
		(void *)&cmd_ipsec_mgt_op,
		(void *)&cmd_ipsec_mgt_port_id,
		(void *)&cmd_ipsec_mgt_session_id,
		(void *)&cmd_ipsec_mgt_encrypt_algo,
		(void *)&cmd_ipsec_mgt_encrypt_key,
		(void *)&cmd_ipsec_mgt_auth_algo,
		(void *)&cmd_ipsec_mgt_auth_key,
		(void *)&cmd_ipsec_mgt_dst_ip,
		(void *)&cmd_ipsec_mgt_sport,
		(void *)&cmd_ipsec_mgt_dport,
		(void *)&cmd_ipsec_mgt_spi,
		NULL,
	},
};

cmdline_parse_inst_t cmd_ipsec_set = {
	.f = cmd_ipsec_set_parsed,
	.data = NULL,
	.help_str = "sxe2 ipsec set|get esp-hdr-offset|session-id <port_id> <value>",
	.tokens = {
		(void *)&cmd_ipsec_set_sxe2,
		(void *)&cmd_ipsec_set_module,
		(void *)&cmd_ipsec_set_op,
		(void *)&cmd_ipsec_set_type,
		(void *)&cmd_ipsec_set_port_id,
		(void *)&cmd_ipsec_set_value,
		NULL,
	},
};

cmdline_parse_inst_t cmd_ipsec_flush = {
	.f = cmd_ipsec_flush_parsed,
	.data = NULL,
	.help_str = "sxe2 ipsec flush <port_id>.\n",
	.tokens = {
		(void *)&cmd_ipsec_flush_sxe2,
		(void *)&cmd_ipsec_flush_module,
		(void *)&cmd_ipsec_flush_op,
		(void *)&cmd_ipsec_flush_port_id,
		NULL,
	},
};

static struct testpmd_driver_commands sxe2_cmds = {
	.commands = {
		{
			&cmd_udp_tunnel_set,
			"sxe2 udp tunnel port set.\n"
			"Add or remove a customed udp port for specific tunnel protocol\n\n",
		},
			{
			&cmd_sched_reset_cmd,
			"sxe2 sched reset <port_id>.\n"
			"Reset sched node on the port\n\n",
		},
		{
			&cmd_stats_mgt,
			"sxe2 show stats.\n"
			"Dump a runtime sxe2 dev stats on a port\n\n",
		},
		{
			&cmd_ipsec_mgt,
			"sxe2 ipsec <dir> <op> <port_id> <session_id>  <encrypt_algo> <encrypt_key>"
			"<encrypt_len> <auth_algo> <auth_key> <auth_len> <dst_ip> <sport> <dport> <spi>.\n"
			"Create/query/remove ipsec security session\n\n",
		},
		{
			&cmd_ipsec_set,
			"sxe2 ipsec set <port_id> <session_id> <esp_hdr_offset>.\n"
			"Set enabled tx session id or esp offset.\n\n",
		},
		{
			&cmd_ipsec_flush,
			"sxe2 ipsec flush <port_id>.\n"
			"Flush ipsec all configurations\n\n",
		},
		{	NULL, NULL},
	},
};
TESTPMD_ADD_DRIVER_COMMANDS(sxe2_cmds)
#endif

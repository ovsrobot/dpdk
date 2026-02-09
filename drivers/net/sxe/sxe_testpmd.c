/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */
#include <ethdev_driver.h>
#include "sxe_drv_type.h"
#include "sxe_ethdev.h"
#include "rte_pmd_sxe.h"

#include <cmdline_parse_etheraddr.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>

#include "testpmd.h"

static int
vf_tc_min_bw_parse_bw_list(uint8_t *bw_list, uint8_t *tc_num, char *str)
{
	uint32_t size;
	const char *p, *p0 = str;
	char s[256];
	char *end;
	char *str_fld[16];
	uint16_t i;
	int ret;

	p = strchr(p0, '(');
	if (p == NULL) {
		RTE_LOG_LINE(ERR, EAL, "The bandwidth-list should be '(bw1, bw2, ...)'");
		return -1;
	}
	p++;
	p0 = strchr(p, ')');
	if (p0 == NULL) {
		RTE_LOG_LINE(ERR, EAL, "The bandwidth-list should be '(bw1, bw2, ...)'");
		return -1;
	}
	size = p0 - p;
	if (size >= sizeof(s)) {
		RTE_LOG_LINE(ERR, EAL, "The string size exceeds the internal buffer size");
		return -1;
	}
	snprintf(s, sizeof(s), "%.*s", size, p);
	ret = rte_strsplit(s, sizeof(s), str_fld, 16, ',');
	if (ret <= 0) {
		RTE_LOG_LINE(ERR, EAL, "Failed to get the bandwidth list.");
		return -1;
	}
	*tc_num = ret;
	for (i = 0; i < ret; i++)
		bw_list[i] = (uint8_t)strtoul(str_fld[i], &end, 0);

	return 0;
}

struct cmd_vf_tc_bw_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t tc;
	cmdline_fixed_string_t tx;
	cmdline_fixed_string_t min_bw;
	portid_t port_id;
	cmdline_fixed_string_t bw_list;
};

static cmdline_parse_token_string_t cmd_vf_tc_bw_set =
	TOKEN_STRING_INITIALIZER(struct cmd_vf_tc_bw_result,
		set, "set");
static cmdline_parse_token_string_t cmd_vf_tc_bw_tc =
	TOKEN_STRING_INITIALIZER(struct cmd_vf_tc_bw_result,
		tc, "tc");
static cmdline_parse_token_string_t cmd_vf_tc_bw_tx =
	TOKEN_STRING_INITIALIZER(struct cmd_vf_tc_bw_result,
		tx, "tx");
static cmdline_parse_token_string_t cmd_vf_tc_bw_min_bw =
	TOKEN_STRING_INITIALIZER(struct cmd_vf_tc_bw_result,
		min_bw, "min-bandwidth");
static cmdline_parse_token_num_t cmd_vf_tc_bw_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_vf_tc_bw_result,
		port_id, RTE_UINT16);
static cmdline_parse_token_string_t cmd_vf_tc_bw_bw_list =
	TOKEN_STRING_INITIALIZER(struct cmd_vf_tc_bw_result,
		bw_list, NULL);

static void
cmd_tc_min_bw_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_vf_tc_bw_result *res = parsed_result;
	struct rte_port *port;
	uint8_t tc_num;
	uint8_t bw[16];
	int ret = -ENOTSUP;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

	port = &ports[res->port_id];
	if (port->port_status != RTE_PORT_STOPPED) {
		RTE_LOG_LINE(ERR, EAL, "Please stop port %d first", res->port_id);
		return;
	}

	ret = vf_tc_min_bw_parse_bw_list(bw, &tc_num, res->bw_list);
	if (ret)
		return;

	ret = rte_pmd_sxe_tc_bw_set(res->port_id, tc_num, bw);

	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		RTE_LOG_LINE(ERR, EAL, "invalid bandwidth");
		break;
	case -ENODEV:
		RTE_LOG_LINE(ERR, EAL, "invalid port_id %d", res->port_id);
		break;
	case -ENOTSUP:
		RTE_LOG_LINE(ERR, EAL, "function not implemented");
		break;
	default:
		RTE_LOG_LINE(ERR, EAL, "programming error: (%s)", strerror(-ret));
	}
}

static cmdline_parse_inst_t cmd_tc_min_bw = {
	.f = cmd_tc_min_bw_parsed,
	.data = NULL,
	.help_str = "set tc tx min-bandwidth <port_id> <bw1, bw2, ...>",
	.tokens = {
		(void *)&cmd_vf_tc_bw_set,
		(void *)&cmd_vf_tc_bw_tc,
		(void *)&cmd_vf_tc_bw_tx,
		(void *)&cmd_vf_tc_bw_min_bw,
		(void *)&cmd_vf_tc_bw_port_id,
		(void *)&cmd_vf_tc_bw_bw_list,
		NULL,
	},
};

struct led_ctrl_result {
	cmdline_fixed_string_t port;
	uint16_t port_id;
	cmdline_fixed_string_t led;
	cmdline_fixed_string_t action;
};

cmdline_parse_token_string_t cmd_led_ctrl_port =
	TOKEN_STRING_INITIALIZER(struct led_ctrl_result, port, "port");
cmdline_parse_token_num_t cmd_led_ctrl_port_id =
	TOKEN_NUM_INITIALIZER(struct led_ctrl_result, port_id, RTE_UINT16);
cmdline_parse_token_string_t cmd_led_ctrl_led =
	TOKEN_STRING_INITIALIZER(struct led_ctrl_result, led, "led");
cmdline_parse_token_string_t cmd_led_ctrl_action =
	TOKEN_STRING_INITIALIZER(struct led_ctrl_result, action, "on#off");

static void cmd_led_ctrl_parsed(void *parsed_result,
			__rte_unused struct cmdline *cl,
			__rte_unused void *data)
{
	struct led_ctrl_result *res = parsed_result;

	if (strcmp(res->action, "on") == 0)
		rte_eth_led_on(res->port_id);
	else
		rte_eth_led_off(res->port_id);
}

cmdline_parse_inst_t  cmd_led_ctrl = {
	.f = cmd_led_ctrl_parsed,
	.data = NULL,
	.help_str = "port <port_id> led on|off",
	.tokens = {
		(void *)&cmd_led_ctrl_port,
		(void *)&cmd_led_ctrl_port_id,
		(void *)&cmd_led_ctrl_led,
		(void *)&cmd_led_ctrl_action,
		NULL,
	},
};

static struct testpmd_driver_commands sxe_cmds = {
	.commands = {
		{
			&cmd_tc_min_bw,
			"set tc tx min-bandwidth (port_id) (bw1, bw2, ...)\n"
			"	Set all TCs' min bandwidth(%%) for all PF and VFs.\n",
		},
		{
			&cmd_led_ctrl,
			"port <port_id> led on|off\n"
			"	Set led on or off.\n",
		},
		{ NULL, NULL },
	},
};
TESTPMD_ADD_DRIVER_COMMANDS(sxe_cmds)

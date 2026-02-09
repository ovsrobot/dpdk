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
			&cmd_led_ctrl,
			"port <port_id> led on|off\n"
			"	Set led on or off.\n",
		},
		{ NULL, NULL },
	},
};
TESTPMD_ADD_DRIVER_COMMANDS(sxe_cmds)

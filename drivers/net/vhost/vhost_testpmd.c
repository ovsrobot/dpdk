/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Intel Corporation.
 */
#include <rte_eth_vhost.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>

#include "testpmd.h"

struct cmd_tx_poll_result {
	cmdline_fixed_string_t async_vhost;
	cmdline_fixed_string_t tx;
	cmdline_fixed_string_t poll;
	cmdline_fixed_string_t completed;
	cmdline_fixed_string_t what;
};

static cmdline_parse_token_string_t cmd_tx_async_vhost =
	TOKEN_STRING_INITIALIZER(struct cmd_tx_poll_result, async_vhost, "async_vhost");
static cmdline_parse_token_string_t cmd_tx_tx =
	TOKEN_STRING_INITIALIZER(struct cmd_tx_poll_result, tx, "tx");
static cmdline_parse_token_string_t cmd_tx_poll =
	TOKEN_STRING_INITIALIZER(struct cmd_tx_poll_result, poll, "poll");
static cmdline_parse_token_string_t cmd_tx_completed =
	TOKEN_STRING_INITIALIZER(struct cmd_tx_poll_result, completed, "completed");
static cmdline_parse_token_string_t cmd_tx_what =
	TOKEN_STRING_INITIALIZER(struct cmd_tx_poll_result, what, "on#off");

static void
cmd_tx_poll_parsed(void *parsed_result, __rte_unused struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_tx_poll_result *res = parsed_result;

	if (!strcmp(res->what, "on"))
		rte_eth_vhost_async_tx_poll_completed(true);
	else if (!strcmp(res->what, "off"))
		rte_eth_vhost_async_tx_poll_completed(false);
	else
		fprintf(stderr, "Unknown parameter\n");
}

static cmdline_parse_inst_t async_vhost_cmd_tx_poll = {
	.f = cmd_tx_poll_parsed,
	.data = NULL,
	.help_str = "async-vhost tx poll completed on|off",
	.tokens = {
		(void *)&cmd_tx_async_vhost,
		(void *)&cmd_tx_tx,
		(void *)&cmd_tx_poll,
		(void *)&cmd_tx_completed,
		(void *)&cmd_tx_what,
		NULL,
	},
};

static struct testpmd_driver_commands async_vhost_cmds = {
	.commands = {
	{
		&async_vhost_cmd_tx_poll,
		"async_vhost tx poll completed (on|off)\n"
		"    Poll and free DMA completed packets in Tx path.\n",
	},
	{ NULL, NULL },
	},
};

TESTPMD_ADD_DRIVER_COMMANDS(async_vhost_cmds)

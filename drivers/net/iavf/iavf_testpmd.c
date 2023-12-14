/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation.
 */

#include <stdlib.h>

#include <rte_pmd_iavf.h>

#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>

#include "testpmd.h"

struct cmd_enable_tx_lldp_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t tx;
	cmdline_fixed_string_t lldp;
	cmdline_fixed_string_t what;
};

static cmdline_parse_token_string_t cmd_enable_tx_lldp_set =
	TOKEN_STRING_INITIALIZER(struct cmd_enable_tx_lldp_result,
		set, "set");
static cmdline_parse_token_string_t cmd_enable_tx_lldp_tx =
	TOKEN_STRING_INITIALIZER(struct cmd_enable_tx_lldp_result,
		tx, "tx");
static cmdline_parse_token_string_t cmd_enable_tx_lldp_lldp =
	TOKEN_STRING_INITIALIZER(struct cmd_enable_tx_lldp_result,
		lldp, "lldp");
static cmdline_parse_token_string_t cmd_enable_tx_lldp_what =
	TOKEN_STRING_INITIALIZER(struct cmd_enable_tx_lldp_result,
		what, "on#off");

static void
cmd_enable_tx_lldp_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_enable_tx_lldp_result *res = parsed_result;
	const struct rte_mbuf_dynflag iavf_tx_lldp = { .name = { IAVF_TX_LLDP_DYNFLAG } };

	if (strcmp(res->what, "on") == 0)
		rte_mbuf_dynflag_register(&iavf_tx_lldp);
}

static cmdline_parse_inst_t cmd_enable_tx_lldp = {
	.f = cmd_enable_tx_lldp_parsed,
	.data = NULL,
	.help_str = "set iavf tx lldp on|off",
	.tokens = {
		(void *)&cmd_enable_tx_lldp_set,
		(void *)&cmd_enable_tx_lldp_tx,
		(void *)&cmd_enable_tx_lldp_lldp,
		(void *)&cmd_enable_tx_lldp_what,
		NULL,
	},
};

static struct testpmd_driver_commands iavf_cmds = {
	.commands = {
	{
		&cmd_enable_tx_lldp,
		"set tx lldp (on|off)\n"
		"    Set iavf Tx lldp packet(currently only supported on)\n\n",
	},
	{ NULL, NULL },
	},
};
TESTPMD_ADD_DRIVER_COMMANDS(iavf_cmds)

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation.
 */

#include <stdalign.h>
#include <stdlib.h>

#include <rte_pmd_iavf.h>

#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>

#include "iavf.h"
#include "testpmd.h"
#include "iavf_rxtx.h"

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
	const struct rte_mbuf_dynfield iavf_tx_lldp_dynfield = {
		.name = IAVF_TX_LLDP_DYNFIELD,
		.size = sizeof(uint8_t),
		.align = alignof(uint8_t),
		.flags = 0
	};
	int offset;

	if (strncmp(res->what, "on", 2) == 0) {
		offset = rte_mbuf_dynfield_register(&iavf_tx_lldp_dynfield);
		printf("rte_pmd_iavf_tx_lldp_dynfield_offset: %d", offset);
		if (offset < 0)
			fprintf(stderr,
				"rte mbuf dynfield register failed, offset: %d", offset);
	}
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

struct cmd_reset_vf_result {
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t reset_vf;
	portid_t port_id;
};

static cmdline_parse_token_string_t cmd_reset_vf_port =
	TOKEN_STRING_INITIALIZER(struct cmd_reset_vf_result,
		port, "port");
static cmdline_parse_token_string_t cmd_reset_vf_reset_vf =
	TOKEN_STRING_INITIALIZER(struct cmd_reset_vf_result,
		reset_vf, "reset_vf");
static cmdline_parse_token_num_t cmd_reset_vf_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_reset_vf_result,
		port_id, RTE_UINT16);

static void
cmd_reset_vf_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_reset_vf_result *res = parsed_result;
	int ret;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

	ret = rte_pmd_iavf_reset(res->port_id);
	if (ret < 0)
		fprintf(stderr, "Request to reset VF failed for port %u: %s\n",
			res->port_id, rte_strerror(-ret));
	else
		printf("VF reset requested for port %u\n", res->port_id);
}

static cmdline_parse_inst_t cmd_reset_vf = {
	.f = cmd_reset_vf_parsed,
	.data = NULL,
	.help_str = "port reset_vf <port_id>",
	.tokens = {
		(void *)&cmd_reset_vf_port,
		(void *)&cmd_reset_vf_reset_vf,
		(void *)&cmd_reset_vf_port_id,
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
	{
		&cmd_reset_vf,
		"port reset_vf (port_id)\n"
		"    Send a request to the PF to reset the VF\n\n",
	},
	{ NULL, NULL },
	},
};

TESTPMD_ADD_DRIVER_COMMANDS(iavf_cmds)

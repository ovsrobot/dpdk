/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Intel Corporation.
 */

#include <stdlib.h>
#include <stdio.h>

#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>

#include "testpmd.h"
#include "ice_ethdev.h"

/* Fixed size for ICE ddp runtime configure */
#define ICE_BUFF_SIZE	0x000c9000
#define ICE_SWITCH_BUFF_SIZE	(4 * 1024 * 1024)

/* Dump device ddp package, only for ice PF */
struct cmd_ddp_dump_result {
	cmdline_fixed_string_t ddp;
	cmdline_fixed_string_t dump;
	portid_t port_id;
	char filepath[];
};

cmdline_parse_token_string_t cmd_ddp_dump_ddp =
	TOKEN_STRING_INITIALIZER(struct cmd_ddp_dump_result, ddp, "ddp");
cmdline_parse_token_string_t cmd_ddp_dump_dump =
	TOKEN_STRING_INITIALIZER(struct cmd_ddp_dump_result, dump, "dump");
cmdline_parse_token_num_t cmd_ddp_dump_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_ddp_dump_result, port_id, RTE_UINT16);
cmdline_parse_token_string_t cmd_ddp_dump_filepath =
	TOKEN_STRING_INITIALIZER(struct cmd_ddp_dump_result, filepath, NULL);

static void
cmd_ddp_dump_parsed(void *parsed_result,
		    __rte_unused struct cmdline *cl,
		    __rte_unused void *data)
{
	struct cmd_ddp_dump_result *res = parsed_result;
	uint8_t *buff;
	uint32_t size;
	int ret = -ENOTSUP;

	size = ICE_BUFF_SIZE;
	buff = (uint8_t *)malloc(ICE_BUFF_SIZE);
	if (buff) {
		ret = rte_pmd_ice_dump_package(res->port_id, &buff, &size);
		switch (ret) {
		case 0:
			save_file(res->filepath, buff, size);
			break;
		case -EINVAL:
			fprintf(stderr, "Invalid buffer size\n");
			break;
		case -ENOTSUP:
			fprintf(stderr,
				"Device doesn't support "
				"dump DDP runtime configure.\n");
			break;
		default:
			fprintf(stderr,
				"Failed to dump DDP runtime configure,"
				" error: (%s)\n", strerror(-ret));
		}
	}
	free(buff);
}

cmdline_parse_inst_t cmd_ddp_dump = {
	.f = cmd_ddp_dump_parsed,
	.data = NULL,
	.help_str = "ddp dump <port_id> <config_path>",
	.tokens = {
		(void *)&cmd_ddp_dump_ddp,
		(void *)&cmd_ddp_dump_dump,
		(void *)&cmd_ddp_dump_port_id,
		(void *)&cmd_ddp_dump_filepath,
		NULL,
	},
};

struct cmd_ddp_dump_switch_result {
	cmdline_fixed_string_t ddp;
	cmdline_fixed_string_t dump;
	cmdline_fixed_string_t swt;
	portid_t port_id;
	char filepath[];
};

cmdline_parse_token_string_t cmd_ddp_dump_swt_ddp =
	TOKEN_STRING_INITIALIZER(struct cmd_ddp_dump_switch_result, ddp, "ddp");
cmdline_parse_token_string_t cmd_ddp_dump_swt_dump =
	TOKEN_STRING_INITIALIZER(struct cmd_ddp_dump_switch_result, dump, "dump");
cmdline_parse_token_string_t cmd_ddp_dump_swt_switch =
	TOKEN_STRING_INITIALIZER(struct cmd_ddp_dump_switch_result, swt, "switch");
cmdline_parse_token_num_t cmd_ddp_dump_swt_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_ddp_dump_switch_result, port_id, RTE_UINT16);
cmdline_parse_token_string_t cmd_ddp_dump_swt_filepath =
	TOKEN_STRING_INITIALIZER(struct cmd_ddp_dump_switch_result, filepath, NULL);

static void
cmd_ddp_dump_switch_parsed(void *parsed_result,
			   __rte_unused struct cmdline *cl,
			   __rte_unused void *data)
{
	struct cmd_ddp_dump_switch_result *res = parsed_result;
	uint8_t *buff;
	uint32_t size;
	int ret = -ENOTSUP;

	size = ICE_SWITCH_BUFF_SIZE;
	buff = malloc(size);
	if (buff) {
		ret = rte_pmd_ice_dump_switch(res->port_id, &buff, &size);
		switch (ret) {
		case 0:
			save_file(res->filepath, buff, size);
			break;
		case -EINVAL:
			fprintf(stderr, "Invalid buffer size\n");
			break;
		case -ENOTSUP:
			fprintf(stderr,
				"Device doesn't support "
				"dump DDP switch runtime configure.\n");
			break;
		default:
			fprintf(stderr,
				"Failed to dump DDP switch runtime configure,"
				" error: (%s)\n", strerror(-ret));
		}
	}
	free(buff);
}


cmdline_parse_inst_t cmd_ddp_dump_switch = {
	.f = cmd_ddp_dump_switch_parsed,
	.data = NULL,
	.help_str = "ddp dump switch <port_id> <config_path>",
	.tokens = {
		(void *)&cmd_ddp_dump_swt_ddp,
		(void *)&cmd_ddp_dump_swt_dump,
		(void *)&cmd_ddp_dump_swt_switch,
		(void *)&cmd_ddp_dump_swt_port_id,
		(void *)&cmd_ddp_dump_swt_filepath,
		NULL,
	},
};

/* Dump Tx Scheduling Tree configuration, only for ice PF */
struct cmd_txsched_dump_result {
	cmdline_fixed_string_t txsched;
	cmdline_fixed_string_t dump;
	portid_t port_id;
	cmdline_fixed_string_t mode;
	char filepath[];
};

cmdline_parse_token_string_t cmd_txsched_dump_txsched =
	TOKEN_STRING_INITIALIZER(struct cmd_txsched_dump_result, txsched, "txsched");
cmdline_parse_token_string_t cmd_txsched_dump_dump =
	TOKEN_STRING_INITIALIZER(struct cmd_txsched_dump_result, dump, "dump");
cmdline_parse_token_num_t cmd_txsched_dump_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_txsched_dump_result, port_id, RTE_UINT16);
cmdline_parse_token_string_t cmd_txsched_dump_mode =
	TOKEN_STRING_INITIALIZER(struct cmd_txsched_dump_result, mode, "brief#detail");
cmdline_parse_token_string_t cmd_txsched_dump_filepath =
	TOKEN_STRING_INITIALIZER(struct cmd_txsched_dump_result, filepath, NULL);

static void
cmd_txsched_dump_parsed(void *parsed_result,
			__rte_unused struct cmdline *cl,
			__rte_unused void *data)
{
	struct cmd_txsched_dump_result *res = parsed_result;
	bool detail = false;
	FILE *fp;

	if (!strcmp(res->mode, "detail"))
		detail = true;

	fp = fopen(res->filepath, "w");
	if (fp == NULL) {
		fprintf(stderr, "Failed to open file\n");
		return;
	}

	if (rte_pmd_ice_dump_txsched(res->port_id, detail, fp))
		fprintf(stderr, "Failed to dump Tx scheduring runtime configure.\n");
	fclose(fp);
}

cmdline_parse_inst_t cmd_txsched_dump = {
	.f = cmd_txsched_dump_parsed,
	.data = NULL,
	.help_str = "txsched dump <port_id> <brief|detail> <config_path>",
	.tokens = {
		(void *)&cmd_txsched_dump_txsched,
		(void *)&cmd_txsched_dump_dump,
		(void *)&cmd_txsched_dump_port_id,
		(void *)&cmd_txsched_dump_mode,
		(void *)&cmd_txsched_dump_filepath,
		NULL,
	},
};

/* *** configure source prune for ice port *** */
struct cmd_config_src_prune_result {
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t keyword;
	cmdline_fixed_string_t port_all; /* valid if "allports" argument == 1 */
	uint16_t port_id;                /* valid if "allports" argument == 0 */
	cmdline_fixed_string_t item;
	cmdline_fixed_string_t enable;
};

static void cmd_config_pf_src_prune_parsed(void *parsed_result,
					__rte_unused struct cmdline *cl,
					void *allports)
{
	struct cmd_config_src_prune_result *res = parsed_result;
	uint8_t enable;
	uint16_t i;

	if (!strcmp(res->enable, "on"))
		enable = 1;
	else
		enable = 0;

	/* all ports */
	if (allports) {
		RTE_ETH_FOREACH_DEV(i)
			rte_pmd_ice_set_pf_src_prune(i, enable);
	} else {
		rte_pmd_ice_set_pf_src_prune(res->port_id, enable);
	}
}

static cmdline_parse_token_string_t cmd_config_src_prune_port =
	TOKEN_STRING_INITIALIZER(struct cmd_config_src_prune_result, port, "port");
static cmdline_parse_token_string_t cmd_config_src_prune_keyword =
	TOKEN_STRING_INITIALIZER(struct cmd_config_src_prune_result, keyword,
				 "config");
static cmdline_parse_token_string_t cmd_config_src_prune_portall =
	TOKEN_STRING_INITIALIZER(struct cmd_config_src_prune_result, port_all,
				 "all");
static cmdline_parse_token_num_t cmd_config_src_prune_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_config_src_prune_result, port_id,
			      RTE_UINT16);
static cmdline_parse_token_string_t cmd_config_src_prune_item =
	TOKEN_STRING_INITIALIZER(struct cmd_config_src_prune_result,
			item, "ice_source_prune");
static cmdline_parse_token_string_t cmd_config_src_prune_enable =
	TOKEN_STRING_INITIALIZER(struct cmd_config_src_prune_result, enable,
				 "on#off");

static cmdline_parse_inst_t cmd_config_src_prune_all = {
	.f = cmd_config_pf_src_prune_parsed,
	.data = (void *)1,
	.help_str = "port config all ice_source_prune on|off: Set source prune on/off all pf ports.",
	.tokens = {
		(void *)&cmd_config_src_prune_port,
		(void *)&cmd_config_src_prune_keyword,
		(void *)&cmd_config_src_prune_portall,
		(void *)&cmd_config_src_prune_item,
		(void *)&cmd_config_src_prune_enable,
		NULL,
	},
};

static cmdline_parse_inst_t cmd_config_src_prune_specific = {
	.f = cmd_config_pf_src_prune_parsed,
	.data = (void *)0,
	.help_str = "port config <port_id> ice_source_prune on|off: Set source prune on/off specific pf port.",
	.tokens = {
		(void *)&cmd_config_src_prune_port,
		(void *)&cmd_config_src_prune_keyword,
		(void *)&cmd_config_src_prune_port_id,
		(void *)&cmd_config_src_prune_item,
		(void *)&cmd_config_src_prune_enable,
		NULL,
	},
};

static struct testpmd_driver_commands ice_cmds = {
	.commands = {
	{
		&cmd_ddp_dump,
		"ddp dump (port_id) (config_path)\n"
		"    Dump a runtime configure on a port\n\n",

	},
	{
		&cmd_ddp_dump_switch,
		"ddp dump switch (port_id) (config_path)\n"
		"    Dump a runtime switch configure on a port\n\n",

	},
	{
		&cmd_txsched_dump,
		"txsched dump (port_id) <brief|detail> (config_path)\n"
		"    Dump tx scheduling runtime configure on a port\n\n",

	},
		{
		&cmd_config_src_prune_all,
		"port config all ice_source_prune (on|off)\n"
		"    Set source prune on/off pf port all.\n"
	},
	{
		&cmd_config_src_prune_specific,
		"port config (port_id) ice_source_prune (on|off)\n"
		"    Set source prune on/off pf port_id.\n"
	},
	{ NULL, NULL },
	},
};

TESTPMD_ADD_DRIVER_COMMANDS(ice_cmds)

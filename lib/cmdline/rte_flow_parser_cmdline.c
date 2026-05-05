/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2026 DynaNIC Semiconductors, Ltd.
 */

#include <stddef.h>

#include <cmdline_parse.h>
#include <rte_flow_parser_config.h>
#include <rte_flow_parser_internal.h>

#include <eal_export.h>
#include "rte_flow_parser_cmdline.h"

static cmdline_parse_inst_t *local_cmd_flow;
static rte_flow_parser_dispatch_t local_dispatch;

static int
cmd_flow_parse(cmdline_parse_token_hdr_t *hdr, const char *src,
	       void *result, unsigned int size)
{
	(void)hdr;
	return flow_parser_parse_token(src, result, size);
}

static int
cmd_flow_complete_get_nb(cmdline_parse_token_hdr_t *hdr)
{
	(void)hdr;
	return flow_parser_complete_count();
}

static int
cmd_flow_complete_get_elt(cmdline_parse_token_hdr_t *hdr, int index,
			  char *dst, unsigned int size)
{
	(void)hdr;
	return flow_parser_complete_entry(index, dst, size);
}

static int
cmd_flow_get_help(cmdline_parse_token_hdr_t *hdr, char *dst, unsigned int size)
{
	const char *help = NULL;
	const char *name = NULL;

	(void)hdr;
	if (flow_parser_get_help(dst, size, &help, &name) < 0)
		return -1;
	if (local_cmd_flow != NULL)
		local_cmd_flow->help_str = help ? help : name;
	return 0;
}

/** Token definition template. */
static struct cmdline_token_hdr cmd_flow_token_hdr = {
	.ops = &(struct cmdline_token_ops){
		.parse = cmd_flow_parse,
		.complete_get_nb = cmd_flow_complete_get_nb,
		.complete_get_elt = cmd_flow_complete_get_elt,
		.get_help = cmd_flow_get_help,
	},
	.offset = 0,
};

/** Populate the next dynamic token. */
static void
cmd_flow_tok(cmdline_parse_token_hdr_t **hdr,
	     cmdline_parse_token_hdr_t **hdr_inst)
{
	cmdline_parse_token_hdr_t **tokens;

	tokens = local_cmd_flow ? local_cmd_flow->tokens : NULL;
	if (tokens == NULL) {
		*hdr = NULL;
		return;
	}
	/* Reinitialize context before requesting the first token. */
	if ((hdr_inst - tokens) == 0)
		flow_parser_context_init();
	/* No more tokens expected. */
	if (flow_parser_context_is_done()) {
		*hdr = NULL;
		return;
	}
	/* Determine if command should end here. */
	if (flow_parser_check_eol_end()) {
		*hdr = NULL;
		return;
	}
	*hdr = &cmd_flow_token_hdr;
}


int
rte_flow_parser_cmdline_register(cmdline_parse_inst_t *cmd_flow,
				 rte_flow_parser_dispatch_t dispatch)
{
	local_cmd_flow = cmd_flow;
	local_dispatch = dispatch;
	return 0;
}

void
rte_flow_parser_cmd_flow_cb(void *arg0, struct cmdline *cl, void *arg2)
{
	struct rte_flow_parser_output *out;

	if (cl == NULL) {
		cmd_flow_tok(arg0, arg2);
		return;
	}
	/* Convert the raw internal token to public command enum. */
	out = arg0;
	out->command = flow_parser_map_command((int)out->command);
	if (local_dispatch != NULL)
		local_dispatch(out);
}

void
rte_flow_parser_set_item_tok(cmdline_parse_token_hdr_t **hdr)
{
	/* No more tokens after end_set consumed all next entries. */
	if (flow_parser_context_is_done() &&
	    flow_parser_get_command_token() != 0) {
		*hdr = NULL;
		return;
	}
	/* Check for end_set sentinel. */
	if (flow_parser_check_eol_end_set()) {
		*hdr = NULL;
		return;
	}
	*hdr = &cmd_flow_token_hdr;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_flow_parser_cmdline_register, 26.07);
RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_flow_parser_cmd_flow_cb, 26.07);
RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_flow_parser_set_item_tok, 26.07);

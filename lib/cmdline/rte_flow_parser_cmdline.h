/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2016 6WIND S.A.
 * Copyright 2016 Mellanox Technologies, Ltd
 * Copyright 2026 DynaNIC Semiconductors, Ltd.
 */

/**
 * @file
 * Flow Parser Library - Cmdline Integration
 *
 * Provides cmdline dynamic token integration for building testpmd-like
 * interactive command lines with tab completion for flow rules.
 *
 * Requires prior registration via rte_flow_parser_cmdline_register().
 * For non-cmdline usage, rte_flow_parser_config.h and rte_flow_parser.h
 * in lib/ethdev suffice.
 */

#ifndef RTE_FLOW_PARSER_CMDLINE_H
#define RTE_FLOW_PARSER_CMDLINE_H

#include <cmdline_parse.h>
#include <rte_flow_parser_config.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Register cmdline integration for the flow parser.
 *
 * Stores the cmdline instruction instance and dispatch callback used
 * by rte_flow_parser_cmd_flow_cb(). Must be called after
 * rte_flow_parser_config_register().
 *
 * @param cmd_flow
 *   Cmdline instruction instance for flow commands.
 * @param dispatch
 *   Dispatch callback invoked after a command is fully parsed.
 * @return
 *   0 on success, negative errno on failure.
 */
__rte_experimental
int rte_flow_parser_cmdline_register(cmdline_parse_inst_t *cmd_flow,
				     rte_flow_parser_dispatch_t dispatch);

/**
 * Cmdline callback for flow commands.
 *
 * Suitable for direct use as the .f member of a cmdline_parse_inst_t
 * with .tokens[0] = NULL (dynamic token mode). Handles both dynamic
 * token population (called by cmdline internally) and command dispatch
 * (calls the dispatch function registered via
 * rte_flow_parser_cmdline_register()).
 *
 * @param arg0
 *   Token header pointer (when populating tokens) or parsed output
 *   buffer (when dispatching a completed command).
 * @param cl
 *   Cmdline handle; NULL when requesting a dynamic token.
 * @param arg2
 *   Token slot address (when populating tokens) or inst->data.
 */
__rte_experimental
void rte_flow_parser_cmd_flow_cb(void *arg0, struct cmdline *cl, void *arg2);

/**
 * Populate the next dynamic token for SET item parsing.
 * Provides tab completion for pattern/action items.
 * Sets *hdr to NULL when end_set is detected (command complete).
 *
 * @param hdr
 *   Pointer to token header pointer to populate.
 */
__rte_experimental
void rte_flow_parser_set_item_tok(cmdline_parse_token_hdr_t **hdr);

#ifdef __cplusplus
}
#endif

#endif /* RTE_FLOW_PARSER_CMDLINE_H */

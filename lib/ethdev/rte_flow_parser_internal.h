/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2026 DynaNIC Semiconductors, Ltd.
 */

/**
 * @file
 * Flow Parser Library - Internal Interface
 *
 * Functions used by the cmdline adapter in lib/cmdline to access
 * the core parser in lib/ethdev. Not for application use.
 */

#ifndef RTE_FLOW_PARSER_INTERNAL_H
#define RTE_FLOW_PARSER_INTERNAL_H

#include <stdbool.h>
#include <stdint.h>

#include <rte_compat.h>
#include <rte_flow_parser_config.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Parse one token from a flow command string.
 *
 * Advances the parser state by consuming one whitespace-delimited token.
 * This is the core parse step used by both rte_flow_parser_parse() and
 * the cmdline token ops adapter.
 *
 * @param src
 *   Input string positioned at the start of the next token.
 * @param result
 *   Output buffer for the parsed command.
 * @param size
 *   Size of the output buffer.
 * @return
 *   Number of characters consumed on success, -1 on error.
 */
__rte_internal
int flow_parser_parse_token(const char *src, void *result, unsigned int size);

/**
 * Return the number of tab-completion entries for the current token.
 */
__rte_internal
int flow_parser_complete_count(void);

/**
 * Return a tab-completion entry by index.
 *
 * @param index
 *   Entry index (0 to flow_parser_complete_count() - 1).
 * @param buf
 *   Buffer to write the completion string.
 * @param size
 *   Size of @p buf.
 * @return
 *   0 on success, -1 on error.
 */
__rte_internal
int flow_parser_complete_entry(int index, char *buf, unsigned int size);

/**
 * Return help text for the current token.
 *
 * Writes the token type string to @p dst. Returns the token's help
 * text and name via @p help_out and @p name_out for the caller to
 * use (e.g., to update a cmdline instruction's help_str).
 *
 * @param dst
 *   Buffer to write the token type string.
 * @param size
 *   Size of @p dst.
 * @param help_out
 *   If non-NULL, set to the current token's help string (or NULL).
 * @param name_out
 *   If non-NULL, set to the current token's name string.
 * @return
 *   0 on success, -1 on error.
 */
__rte_internal
int flow_parser_get_help(char *dst, unsigned int size,
			 const char **help_out, const char **name_out);

__rte_internal
void flow_parser_context_init(void);

__rte_internal
bool flow_parser_context_is_done(void);

/**
 * Check if the parser is at an end-of-command boundary (PT_END).
 * Used by cmd_flow_tok() to detect when to stop producing tokens.
 */
__rte_internal
bool flow_parser_check_eol_end(void);

__rte_internal
bool flow_parser_check_eol_end_set(void);

/**
 * Map an internal parser token to a public command enum.
 * Used by the cmdline callback to convert ctx->command_token
 * to rte_flow_parser_command before dispatching.
 *
 * @param internal_token
 *   The raw internal token value from the parser context.
 * @return
 *   The corresponding public command identifier.
 */
__rte_internal
enum rte_flow_parser_command flow_parser_map_command(int internal_token);

__rte_internal
int flow_parser_get_command_token(void);

#ifdef __cplusplus
}
#endif

#endif /* RTE_FLOW_PARSER_INTERNAL_H */

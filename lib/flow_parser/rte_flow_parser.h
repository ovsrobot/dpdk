/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2016 6WIND S.A.
 * Copyright 2016 Mellanox Technologies, Ltd
 * Copyright 2026 Dyna-NIC
 */

/**
 * @file
 * Flow Parser Library - Public API
 *
 * This library provides lightweight helpers for parsing testpmd-style flow
 * rule strings into rte_flow C structures. The parsed structures can then
 * be used with rte_flow_create(), rte_flow_validate(), or other rte_flow
 * APIs.
 *
 * Example usage:
 * @code
 * struct rte_flow_attr attr;
 * const struct rte_flow_item *pattern;
 * const struct rte_flow_action *actions;
 * uint32_t pattern_n, actions_n;
 *
 * rte_flow_parser_init(NULL);
 *
 * rte_flow_parser_parse_attr_str("ingress group 1", &attr);
 * rte_flow_parser_parse_pattern_str("eth / ipv4 / end", &pattern, &pattern_n);
 * rte_flow_parser_parse_actions_str("drop / end", &actions, &actions_n);
 *
 * rte_flow_validate(port_id, &attr, pattern, actions, &error);
 * @endcode
 */

#ifndef RTE_FLOW_PARSER_H
#define RTE_FLOW_PARSER_H

#include <stddef.h>
#include <stdint.h>

#include <rte_compat.h>
#include <rte_flow.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rte_flow_parser_ops;

/**
 * Initialize the flow parser library.
 *
 * This function must be called before using any other flow parser functions.
 * For the public API (lightweight helpers), the ops parameter should be NULL.
 *
 * @param ops
 *   Reserved for internal use. Pass NULL for public API usage.
 * @return
 *   0 on success, negative errno on error.
 */
__rte_experimental
int rte_flow_parser_init(const struct rte_flow_parser_ops *ops);

/**
 * Parse flow attributes from a CLI snippet.
 *
 * Parses attribute strings as used inside a flow command, such as
 * "ingress", "egress", "ingress group 1 priority 5", or "transfer".
 *
 * @param src
 *   NUL-terminated attribute string.
 * @param[out] attr
 *   Output attributes structure filled on success.
 * @return
 *   0 on success or a negative errno-style value on error.
 */
__rte_experimental
int rte_flow_parser_parse_attr_str(const char *src, struct rte_flow_attr *attr);

/**
 * Parse a flow pattern from a CLI snippet.
 *
 * Parses pattern strings as used inside a flow command, such as
 * "eth / ipv4 src is 192.168.1.1 / tcp dst is 80 / end".
 *
 * @param src
 *   NUL-terminated pattern string.
 * @param[out] pattern
 *   Output pointer to the parsed pattern array. Points to internal storage
 *   valid until the next parse call on the same thread.
 * @param[out] pattern_n
 *   Number of entries in the pattern array.
 * @return
 *   0 on success or a negative errno-style value on error.
 */
__rte_experimental
int rte_flow_parser_parse_pattern_str(const char *src,
				      const struct rte_flow_item **pattern,
				      uint32_t *pattern_n);

/**
 * Parse flow actions from a CLI snippet.
 *
 * Parses action strings as used inside a flow command, such as
 * "queue index 5 / end", "mark id 42 / drop / end", or "count / rss / end".
 *
 * @param src
 *   NUL-terminated actions string.
 * @param[out] actions
 *   Output pointer to the parsed actions array. Points to internal storage
 *   valid until the next parse call on the same thread.
 * @param[out] actions_n
 *   Number of entries in the actions array.
 * @return
 *   0 on success or a negative errno-style value on error.
 */
__rte_experimental
int rte_flow_parser_parse_actions_str(const char *src,
				      const struct rte_flow_action **actions,
				      uint32_t *actions_n);

#ifdef __cplusplus
}
#endif

#endif /* RTE_FLOW_PARSER_H */

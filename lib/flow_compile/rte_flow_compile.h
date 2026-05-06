/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Stephen Hemminger <stephen@networkplumber.org>
 */

#ifndef RTE_FLOW_COMPILE_H_
#define RTE_FLOW_COMPILE_H_

/**
 * @file
 *
 * Compile a textual flow rule description into the array of
 * ``struct rte_flow_item`` and ``struct rte_flow_action`` accepted by
 * ``rte_flow_create()``.
 *
 * Modeled on ``pcap_compile()`` from libpcap: a single string in,
 * an opaque compiled object out, with human readable errors written
 * to a caller supplied buffer.
 *
 * The grammar is documented in the DPDK Programmer's Guide chapter
 * "Flow rule compiler".  In summary::
 *
 *   rule        ::= attribute* "pattern" item-list "actions" action-list
 *   item-list   ::= item ("/" item)* "/" "end"
 *   action-list ::= action ("/" action)* "/" "end"
 *
 * Example::
 *
 *   ingress group 0 priority 1
 *   pattern eth / ipv4 src is 10.0.0.1 dst is 10.0.0.2 / udp dst is 4789 / end
 *   actions queue index 3 / count / end
 *
 * The compiler depends only on rte_ethdev (rte_flow.h) and the
 * libc; in particular it does not pull in librte_cmdline.
 */

#include <stddef.h>
#include <stdint.h>

#include <rte_compat.h>
#include <rte_flow.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum size, in bytes, of the error buffer passed to
 *  ``rte_flow_compile()``.  Modeled on ``PCAP_ERRBUF_SIZE``.
 */
#define RTE_FLOW_COMPILE_ERRBUF_SIZE 256

/** Opaque handle returned by ``rte_flow_compile()``. */
struct rte_flow_compile;

/**
 * Compile a flow rule string.
 *
 * @param str
 *   Null terminated source text of the flow rule.
 * @param errbuf
 *   Buffer of at least ``RTE_FLOW_COMPILE_ERRBUF_SIZE`` bytes.
 *   On failure a human readable diagnostic of the form
 *   ``"<line>:<column>: <message>"`` is written here.
 *   Must not be NULL.
 *
 * @return
 *   On success, a newly allocated compiled rule.  The caller owns
 *   the returned pointer and must release it with
 *   ``rte_flow_compile_free()``.
 *   On failure, NULL with ``errbuf`` populated and ``rte_errno`` set
 *   to ``EINVAL`` (parse error) or ``ENOMEM``.
 */
__rte_experimental
struct rte_flow_compile *
rte_flow_compile(const char *str, char *errbuf);

/**
 * Free a compiled flow rule.
 *
 * Releases the rule and every buffer it transitively owns
 * (specs, masks, last values, RSS key/queue arrays, etc.).
 *
 * @param fc
 *   Compiled rule, or NULL.
 */
__rte_experimental
void
rte_flow_compile_free(struct rte_flow_compile *fc);

/**
 * Get the parsed attributes (group, priority, direction, ...).
 */
__rte_experimental
const struct rte_flow_attr *
rte_flow_compile_attr(const struct rte_flow_compile *fc);

/**
 * Get the pattern array.
 *
 * @param fc
 *   Compiled rule.
 * @param[out] nitems
 *   If not NULL, receives the number of items including the
 *   trailing ``RTE_FLOW_ITEM_TYPE_END``.
 *
 * @return
 *   Pointer to an array of ``rte_flow_item``s suitable for passing
 *   directly to ``rte_flow_create()``.  The array is owned by ``fc``
 *   and is valid until ``rte_flow_compile_free()`` is called.
 */
__rte_experimental
const struct rte_flow_item *
rte_flow_compile_pattern(const struct rte_flow_compile *fc,
			 unsigned int *nitems);

/**
 * Get the action array.
 *
 * Same ownership rules as ``rte_flow_compile_pattern()``.
 */
__rte_experimental
const struct rte_flow_action *
rte_flow_compile_actions(const struct rte_flow_compile *fc,
			 unsigned int *nactions);

/**
 * Convenience: validate the compiled rule against a port.
 *
 * Equivalent to calling ``rte_flow_validate()`` with the compiled
 * attributes, pattern and actions.
 */
__rte_experimental
int
rte_flow_compile_validate(uint16_t port_id,
			  const struct rte_flow_compile *fc,
			  struct rte_flow_error *error);

/**
 * Convenience: install the compiled rule on a port.
 *
 * Equivalent to calling ``rte_flow_create()`` with the compiled
 * attributes, pattern and actions.
 *
 * @return
 *   The created flow handle, or NULL with ``error`` populated.
 *   The compiled rule itself is not consumed and may be reused
 *   to install the same rule on multiple ports.
 */
__rte_experimental
struct rte_flow *
rte_flow_compile_create(uint16_t port_id,
			const struct rte_flow_compile *fc,
			struct rte_flow_error *error);

#ifdef __cplusplus
}
#endif

#endif /* RTE_FLOW_COMPILE_H_ */

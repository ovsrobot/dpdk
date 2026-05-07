/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Stephen Hemminger <stephen@networkplumber.org>
 */

#ifndef FLOW_COMPILE_PRIV_H_
#define FLOW_COMPILE_PRIV_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <rte_compat.h>
#include <rte_flow.h>

#include "rte_flow_compile.h"

/*
 * Storage for one compiled rule.  Each spec/mask/last/conf payload
 * is its own rte_zmalloc; rte_flow_compile_free() walks the pattern
 * and action arrays and frees each non-NULL slot before freeing the
 * arrays themselves.
 */
struct rte_flow_compile {
	struct rte_flow_attr    attr;
	struct rte_flow_item   *pattern;
	unsigned int            npattern;
	unsigned int            pattern_cap;
	struct rte_flow_action *actions;
	unsigned int            nactions;
	unsigned int            actions_cap;
};

/*
 * Compile context.  Lives only for the duration of one compile call.
 * Bison/flex carry their own state via yyextra and the scanner
 * pointer; what's here is the shared state setters and the error
 * helper need.
 */
struct flow_compile_ctx {
	char                    *errbuf;	/* caller-owned */
	struct rte_flow_compile *out;

	/* Position used by flow_compile_errf() when no token-derived
	 * position is available.  Updated by the lexer's YY_USER_ACTION;
	 * bison's %locations gives semantic actions the precise per-
	 * token position via yylloc.
	 */
	uint16_t                 line;
	uint16_t                 col;

	/* Per-item / per-action tracking of which sub-buffers the
	 * grammar touched.  Reset by begin_item / begin_action; read
	 * by end_item / end_action which free untouched buffers so
	 * the PMD's default-mask logic engages.
	 */
	bool spec_used;
	bool mask_used;
	bool last_used;
	bool conf_used;

	/* Cached descriptors and array slots for the in-progress item
	 * and action.  set_field / set_action_param dereference these
	 * rather than chasing pointers via bison's $<item_p>0 reach-
	 * back (which is fragile in the field_list / param_list
	 * reduction shape used here).
	 */
	const struct flow_item_desc   *cur_item_desc;
	struct rte_flow_item          *cur_item;
	const struct flow_action_desc *cur_action_desc;
	struct rte_flow_action        *cur_action;
};

enum field_kind {
	FK_U8,
	FK_U16,		/* host order */
	FK_U32,		/* host order */
	FK_U64,		/* host order */
	FK_BE16,	/* network order (rte_be16_t) */
	FK_BE32,	/* network order */
	FK_BE64,	/* network order */
	FK_MAC,		/* 6 byte MAC address */
	FK_IPV4,	/* 4 byte IPv4 address (network order) */
	FK_IPV6,	/* 16 byte IPv6 address */
	FK_BYTES,	/* fixed length byte array, accepts hex string */
};

struct field_desc {
	const char *name;
	uint16_t offset;
	uint16_t size;
	enum field_kind kind;
};

struct flow_item_desc {
	const char *name;
	enum rte_flow_item_type type;
	uint16_t spec_size;
	const struct field_desc *fields;
	uint16_t nfields;
};

struct flow_action_desc {
	const char *name;
	enum rte_flow_action_type type;
	uint16_t conf_size;
	const struct field_desc *fields;
	uint16_t nfields;
};

const struct flow_item_desc   *flow_compile_item_lookup(const char *name, size_t len);
const struct flow_action_desc *flow_compile_action_lookup(const char *name, size_t len);
const struct field_desc *flow_compile_field_lookup(const struct field_desc *tbl,
						   uint16_t n,
						   const char *name, size_t len);

/*
 * Diagnostic helper.  Always sets rte_errno = EINVAL and returns -1.
 * Pass line=0, col=0 to use the ctx running position.
 */
int flow_compile_errf_at(struct flow_compile_ctx *cc,
			 uint16_t line, uint16_t col,
			 const char *fmt, ...) __rte_format_printf(4, 5);

#define flow_compile_errf(cc, fmt, ...) \
	flow_compile_errf_at((cc), 0, 0, (fmt), ##__VA_ARGS__)

#endif /* FLOW_COMPILE_PRIV_H_ */

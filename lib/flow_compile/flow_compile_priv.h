/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Stephen Hemminger <stephen@networkplumber.org>
 */

#ifndef FLOW_COMPILE_PRIV_H_
#define FLOW_COMPILE_PRIV_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <rte_flow.h>

#include "rte_flow_compile.h"

/*
 * The lexer recognizes a small set of token classes.  All of the
 * non-trivial classes carry their value in ``union token_value``.
 * Source position is recorded for diagnostics.
 */
enum token_kind {
	TK_EOF = 0,
	TK_SLASH,	/* '/'  */
	TK_COMMA,	/* ','  */
	TK_LBRACE,	/* '{'  */
	TK_RBRACE,	/* '}'  */
	TK_IDENT,	/* keyword or identifier  */
	TK_UINT,	/* decimal or hex integer  */
	TK_IPV4,	/* a.b.c.d  */
	TK_IPV6,	/* xxxx:yyyy:...  */
	TK_MAC,		/* xx:xx:xx:xx:xx:xx  */
	TK_HEXSTR,	/* 0x..., even number of hex digits  */
	TK_STRING,	/* "...."  */
};

/*
 * Tokens own no heap memory; identifiers/strings/hex point into
 * the source text.  Length is explicit so we never rely on NUL
 * termination during scanning.
 */
struct token {
	enum token_kind kind;
	uint16_t line;
	uint16_t col;
	const char *text;	/* start in source string  */
	uint16_t len;		/* length in bytes  */
	union {
		uint64_t u;
		uint8_t  ipv4[4];
		uint8_t  ipv6[16];
		uint8_t  mac[6];
	} v;
};

/*
 * Descriptor for a single field within a flow item or action spec.
 *
 * The default setter handles the common kinds below.  ``set`` may be
 * non-NULL for fields whose layout cannot be expressed as a plain
 * byte range (bitfields, indirect arrays, etc.).
 */
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

struct flow_compile_ctx;	/* forward */

/*
 * Storage for one compiled rule.  Each spec/mask/last/conf payload
 * is its own rte_zmalloc; ``rte_flow_compile_free()`` walks the
 * pattern and action arrays and frees each non-NULL slot before
 * freeing the arrays themselves.
 */
struct rte_flow_compile {
	struct rte_flow_attr  attr;
	struct rte_flow_item *pattern;
	unsigned int          npattern;
	struct rte_flow_action *actions;
	unsigned int          nactions;
};

struct field_desc {
	const char *name;
	uint16_t offset;	/* offset inside spec/mask/last struct */
	uint16_t size;		/* size in bytes (used by FK_BYTES) */
	enum field_kind kind;

	/*
	 * Optional custom setter.  When non-NULL the framework calls
	 * this instead of doing its default copy.
	 *
	 * @param dst      Buffer to write the value into (spec, mask
	 *                 or last, depending on which qualifier the
	 *                 user wrote).
	 * @param mask_dst If non-NULL, the function should additionally
	 *                 set the corresponding mask bits to all-ones,
	 *                 i.e. realize ``is`` semantics.  When NULL,
	 *                 the function writes only ``dst``.
	 * @param value    The token holding the parsed literal.
	 *
	 * @return 0 on success, -1 with cc->errbuf set on failure.
	 */
	int (*set)(struct flow_compile_ctx *cc,
		   void *dst, void *mask_dst,
		   const struct field_desc *fd,
		   const struct token *value);
};

/* One entry per RTE_FLOW_ITEM_TYPE_* we recognize. */
struct flow_item_desc {
	const char *name;
	enum rte_flow_item_type type;
	uint16_t spec_size;	/* sizeof(struct rte_flow_item_<type>); 0 if void */
	const struct field_desc *fields;
	uint16_t nfields;
};

/* One entry per RTE_FLOW_ACTION_TYPE_* we recognize. */
struct flow_action_desc {
	const char *name;
	enum rte_flow_action_type type;
	uint16_t conf_size;	/* sizeof(struct rte_flow_action_<type>); 0 if void */
	const struct field_desc *fields;
	uint16_t nfields;
};

/* Lookup helpers (defined in flow_compile_tables.c). */
const struct flow_item_desc   *flow_compile_item_lookup(const char *name, size_t len);
const struct flow_action_desc *flow_compile_action_lookup(const char *name, size_t len);
const struct field_desc *flow_compile_field_lookup(const struct field_desc *tbl,
						   uint16_t n,
						   const char *name, size_t len);

/*
 * Compile context shared by the lexer, parser and table-driven
 * field setters.  Lives only for the duration of one compile call.
 *
 * The parser is straight-line recursive descent against the current
 * token; there is no token pushback.
 */
struct flow_compile_ctx {
	/* source */
	const char *src;
	const char *cur;
	uint16_t line;
	uint16_t col;

	/* current token (set by flow_compile_lex) */
	struct token tok;

	/* output (errbuf is owned by caller) */
	char *errbuf;

	/* destination compile object */
	struct rte_flow_compile *out;
};

/* Lexer: scan next token into cc->tok.  Returns 0 on success, -1 on
 * lex error (errbuf populated).
 */
int flow_compile_lex(struct flow_compile_ctx *cc);

/* Parser entry point. */
int flow_compile_parse(struct flow_compile_ctx *cc,
		       struct rte_flow_compile *out);

/* Diagnostic helper.  Always sets rte_errno = EINVAL and returns -1. */
int flow_compile_errf(struct flow_compile_ctx *cc, const struct token *at,
		      const char *fmt, ...) __rte_format_printf(3, 4);

#endif /* FLOW_COMPILE_PRIV_H_ */

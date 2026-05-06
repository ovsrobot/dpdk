/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Stephen Hemminger <stephen@networkplumber.org>
 */

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <string.h>

#include <rte_byteorder.h>
#include <rte_errno.h>
#include <rte_malloc.h>

#include "flow_compile_priv.h"

/* ------------------------------------------------------------------ */
/* Token utilities. */

static bool
tok_is_ident(const struct token *t, const char *s)
{
	size_t n = strlen(s);
	return t->kind == TK_IDENT && t->len == n &&
	       memcmp(t->text, s, n) == 0;
}

/* ------------------------------------------------------------------ */
/* Default field setters.
 *
 * Each setter writes the spec buffer.  If ``mask_or_null`` is non-NULL
 * (which it will be when the user wrote ``is`` or ``mask`` or
 * ``prefix``), the same field is written there as well.
 */

static int
write_uint(struct flow_compile_ctx *cc, void *spec, void *mask_or_null,
	   const struct field_desc *fd, uint64_t v, uint64_t maxv,
	   const struct token *at)
{
	if (v > maxv)
		return flow_compile_errf(cc, at,
			"value %" PRIu64 " out of range for field '%s'",
			v, fd->name);

	uint8_t *sp = (uint8_t *)spec + fd->offset;
	switch (fd->kind) {
	case FK_U8:
		*sp = (uint8_t)v;
		break;
	case FK_U16: {
		uint16_t x = (uint16_t)v;
		memcpy(sp, &x, sizeof(x));
		break;
	}
	case FK_U32: {
		uint32_t x = (uint32_t)v;
		memcpy(sp, &x, sizeof(x));
		break;
	}
	case FK_U64:
		memcpy(sp, &v, sizeof(v));
		break;
	case FK_BE16: {
		rte_be16_t x = rte_cpu_to_be_16((uint16_t)v);
		memcpy(sp, &x, sizeof(x));
		break;
	}
	case FK_BE32: {
		rte_be32_t x = rte_cpu_to_be_32((uint32_t)v);
		memcpy(sp, &x, sizeof(x));
		break;
	}
	case FK_BE64: {
		rte_be64_t x = rte_cpu_to_be_64(v);
		memcpy(sp, &x, sizeof(x));
		break;
	}
	default:
		return flow_compile_errf(cc, at,
			"field '%s' does not accept an integer", fd->name);
	}

	if (mask_or_null != NULL)
		memset((uint8_t *)mask_or_null + fd->offset, 0xff, fd->size);
	return 0;
}

/* Decode a single ASCII hex digit.  The token has already been
 * validated by the lexer so we don't need to re-check.
 */
static inline unsigned int
hex_nibble(int c)
{
	if (c <= '9')
		return (unsigned int)(c - '0');
	if (c <= 'F')
		return (unsigned int)(c - 'A' + 10);
	return (unsigned int)(c - 'a' + 10);
}

static int
write_bytes_token(struct flow_compile_ctx *cc, void *spec, void *mask_or_null,
		  const struct field_desc *fd, const struct token *t)
{
	uint8_t *sp = (uint8_t *)spec + fd->offset;

	if (t->kind == TK_HEXSTR) {
		/* token text starts with "0x"; body length must be 2*size */
		size_t body = (size_t)t->len - 2;
		if (body != (size_t)fd->size * 2)
			return flow_compile_errf(cc, t,
				"hex string for '%s' must be %u bytes",
				fd->name, (unsigned int)fd->size);
		const char *p = t->text + 2;
		for (uint16_t i = 0; i < fd->size; i++) {
			unsigned int b = (hex_nibble((unsigned char)p[i * 2]) << 4)
				       |  hex_nibble((unsigned char)p[i * 2 + 1]);
			sp[i] = (uint8_t)b;
		}
	} else if (t->kind == TK_UINT) {
		/* right-aligned big-endian fill */
		uint64_t v = t->v.u;
		for (int i = (int)fd->size - 1; i >= 0; i--) {
			sp[i] = (uint8_t)(v & 0xffu);
			v >>= 8;
		}
		if (v != 0)
			return flow_compile_errf(cc, t,
				"value too large for %u byte field '%s'",
				(unsigned int)fd->size, fd->name);
	} else {
		return flow_compile_errf(cc, t,
			"field '%s' expects an integer or hex string",
			fd->name);
	}

	if (mask_or_null != NULL)
		memset((uint8_t *)mask_or_null + fd->offset, 0xff, fd->size);
	return 0;
}

static int
default_field_set(struct flow_compile_ctx *cc,
		  void *spec, void *mask_or_null,
		  const struct field_desc *fd,
		  const struct token *value)
{
	if (fd->set != NULL)
		return fd->set(cc, spec, mask_or_null, fd, value);

	uint8_t *sp = (uint8_t *)spec + fd->offset;

	switch (fd->kind) {
	case FK_U8:
		if (value->kind != TK_UINT)
			return flow_compile_errf(cc, value,
				"field '%s' expects an integer", fd->name);
		return write_uint(cc, spec, mask_or_null, fd, value->v.u,
				  UINT8_MAX, value);
	case FK_U16:
	case FK_BE16:
		if (value->kind != TK_UINT)
			return flow_compile_errf(cc, value,
				"field '%s' expects an integer", fd->name);
		return write_uint(cc, spec, mask_or_null, fd, value->v.u,
				  UINT16_MAX, value);
	case FK_U32:
		if (value->kind != TK_UINT)
			return flow_compile_errf(cc, value,
				"field '%s' expects an integer", fd->name);
		return write_uint(cc, spec, mask_or_null, fd, value->v.u,
				  UINT32_MAX, value);
	case FK_U64:
	case FK_BE64:
		if (value->kind != TK_UINT)
			return flow_compile_errf(cc, value,
				"field '%s' expects an integer", fd->name);
		return write_uint(cc, spec, mask_or_null, fd, value->v.u,
				  UINT64_MAX, value);
	case FK_BE32:
		if (value->kind == TK_IPV4) {
			memcpy(sp, value->v.ipv4, 4);
			if (mask_or_null != NULL)
				memset((uint8_t *)mask_or_null + fd->offset,
				       0xff, 4);
			return 0;
		}
		if (value->kind == TK_UINT)
			return write_uint(cc, spec, mask_or_null, fd,
					  value->v.u, UINT32_MAX, value);
		return flow_compile_errf(cc, value,
			"field '%s' expects an integer or IPv4 address",
			fd->name);
	case FK_MAC:
		if (value->kind != TK_MAC)
			return flow_compile_errf(cc, value,
				"field '%s' expects a MAC address", fd->name);
		memcpy(sp, value->v.mac, 6);
		if (mask_or_null != NULL)
			memset((uint8_t *)mask_or_null + fd->offset, 0xff, 6);
		return 0;
	case FK_IPV4:
		if (value->kind != TK_IPV4)
			return flow_compile_errf(cc, value,
				"field '%s' expects an IPv4 address",
				fd->name);
		memcpy(sp, value->v.ipv4, 4);
		if (mask_or_null != NULL)
			memset((uint8_t *)mask_or_null + fd->offset, 0xff, 4);
		return 0;
	case FK_IPV6:
		if (value->kind != TK_IPV6)
			return flow_compile_errf(cc, value,
				"field '%s' expects an IPv6 address",
				fd->name);
		memcpy(sp, value->v.ipv6, 16);
		if (mask_or_null != NULL)
			memset((uint8_t *)mask_or_null + fd->offset, 0xff, 16);
		return 0;
	case FK_BYTES:
		return write_bytes_token(cc, spec, mask_or_null, fd, value);
	}
	return flow_compile_errf(cc, value,
		"internal error: unknown field kind for '%s'", fd->name);
}

/*
 * Apply ``prefix N`` (CIDR-style mask helper) to an IPv4 or IPv6 field.
 * Spec is left untouched; only mask is written.  No mask bits are
 * cleared from previously written ones -- last write wins, identical
 * to testpmd.
 */
static int
apply_prefix(struct flow_compile_ctx *cc, void *mask,
	     const struct field_desc *fd, const struct token *value)
{
	if (value->kind != TK_UINT)
		return flow_compile_errf(cc, value,
			"prefix expects an integer");

	uint32_t bits = (uint32_t)value->v.u;
	uint32_t total = fd->size * 8u;
	if (bits > total)
		return flow_compile_errf(cc, value,
			"prefix %u exceeds %u bits for '%s'",
			bits, total, fd->name);

	if (fd->kind != FK_IPV4 && fd->kind != FK_IPV6 &&
	    fd->kind != FK_BE32)
		return flow_compile_errf(cc, value,
			"prefix not supported for field '%s'", fd->name);

	uint8_t *m = (uint8_t *)mask + fd->offset;
	memset(m, 0, fd->size);
	for (uint32_t i = 0; i < bits; i++)
		m[i / 8u] |= (uint8_t)(1u << (7u - (i & 7u)));
	return 0;
}

/* ------------------------------------------------------------------ */
/* Attribute parsing. */

static int
parse_attrs(struct flow_compile_ctx *cc, struct rte_flow_attr *attr)
{
	for (;;) {
		if (cc->tok.kind != TK_IDENT)
			return 0;

		if (tok_is_ident(&cc->tok, "ingress")) {
			attr->ingress = 1;
		} else if (tok_is_ident(&cc->tok, "egress")) {
			attr->egress = 1;
		} else if (tok_is_ident(&cc->tok, "transfer")) {
			attr->transfer = 1;
		} else if (tok_is_ident(&cc->tok, "group")) {
			if (flow_compile_lex(cc) < 0)
				return -1;
			if (cc->tok.kind != TK_UINT ||
			    cc->tok.v.u > UINT32_MAX)
				return flow_compile_errf(cc, &cc->tok,
					"group expects uint32");
			attr->group = (uint32_t)cc->tok.v.u;
		} else if (tok_is_ident(&cc->tok, "priority")) {
			if (flow_compile_lex(cc) < 0)
				return -1;
			if (cc->tok.kind != TK_UINT ||
			    cc->tok.v.u > UINT32_MAX)
				return flow_compile_errf(cc, &cc->tok,
					"priority expects uint32");
			attr->priority = (uint32_t)cc->tok.v.u;
		} else {
			/* not an attribute -- next clause */
			return 0;
		}

		if (flow_compile_lex(cc) < 0)
			return -1;
	}
}

/* ------------------------------------------------------------------ */
/* Item body.  Returns 0 on the trailing slash, -1 on error. */

/*
 * Parse the field list of one item.  Allocates spec/mask/last
 * directly into ``item->spec/mask/last`` so that on failure the
 * partial state is reachable from rte_flow_compile_free() through
 * the caller's pattern array, which performs the cleanup.
 *
 * Buffers that turn out not to be referenced (e.g. only ``spec`` is
 * given, no ``mask`` or ``last``) are freed and the corresponding
 * slot zeroed before successful return so that the PMD's
 * default-mask logic kicks in.
 */
static int
parse_item_fields(struct flow_compile_ctx *cc,
		  const struct flow_item_desc *desc,
		  struct rte_flow_item *item)
{
	if (desc->spec_size > 0) {
		item->spec = rte_zmalloc("flow_compile", desc->spec_size, 0);
		item->mask = rte_zmalloc("flow_compile", desc->spec_size, 0);
		item->last = rte_zmalloc("flow_compile", desc->spec_size, 0);
		if (item->spec == NULL || item->mask == NULL ||
		    item->last == NULL) {
			rte_errno = ENOMEM;
			return -1;
		}
	}
	bool spec_used = false, mask_used = false, last_used = false;

	/* These cast away const for write access; the public API
	 * presents them as const but the parser owns them until
	 * compile completes.
	 */
	void *spec = (void *)(uintptr_t)item->spec;
	void *mask = (void *)(uintptr_t)item->mask;
	void *last = (void *)(uintptr_t)item->last;

	while (cc->tok.kind == TK_IDENT) {
		struct token name = cc->tok;
		const struct field_desc *fd =
			flow_compile_field_lookup(desc->fields, desc->nfields,
						  name.text, name.len);
		if (fd == NULL)
			return flow_compile_errf(cc, &name,
				"unknown field '%.*s' for item '%s'",
				(int)name.len, name.text, desc->name);

		if (flow_compile_lex(cc) < 0)
			return -1;
		if (cc->tok.kind != TK_IDENT)
			return flow_compile_errf(cc, &cc->tok,
				"expected is/spec/last/mask/prefix after '%s'",
				fd->name);

		struct token suffix = cc->tok;
		if (flow_compile_lex(cc) < 0)
			return -1;
		struct token value = cc->tok;

		if (tok_is_ident(&suffix, "is")) {
			if (default_field_set(cc, spec, mask, fd, &value) < 0)
				return -1;
			spec_used = mask_used = true;
		} else if (tok_is_ident(&suffix, "spec")) {
			if (default_field_set(cc, spec, NULL, fd, &value) < 0)
				return -1;
			spec_used = true;
		} else if (tok_is_ident(&suffix, "last")) {
			if (default_field_set(cc, last, NULL, fd, &value) < 0)
				return -1;
			last_used = true;
		} else if (tok_is_ident(&suffix, "mask")) {
			if (default_field_set(cc, mask, NULL, fd, &value) < 0)
				return -1;
			mask_used = true;
		} else if (tok_is_ident(&suffix, "prefix")) {
			if (apply_prefix(cc, mask, fd, &value) < 0)
				return -1;
			mask_used = true;
		} else {
			return flow_compile_errf(cc, &suffix,
				"unknown qualifier '%.*s'",
				(int)suffix.len, suffix.text);
		}

		if (flow_compile_lex(cc) < 0)
			return -1;
	}

	/* Drop unused buffers; the PMD treats NULL as default. */
	if (!spec_used) {
		rte_free(spec);
		item->spec = NULL;
	}
	if (!mask_used) {
		rte_free(mask);
		item->mask = NULL;
	}
	if (!last_used) {
		rte_free(last);
		item->last = NULL;
	}
	return 0;
}

static int
parse_pattern(struct flow_compile_ctx *cc, struct rte_flow_compile *out)
{
	if (!tok_is_ident(&cc->tok, "pattern"))
		return flow_compile_errf(cc, &cc->tok, "expected 'pattern'");
	if (flow_compile_lex(cc) < 0)
		return -1;

	size_t cap = 8;
	out->pattern = rte_calloc("flow_compile_pattern", cap,
				  sizeof(*out->pattern), 0);
	if (out->pattern == NULL) {
		rte_errno = ENOMEM;
		return -1;
	}
	/* From here on, out->pattern is reachable from
	 * rte_flow_compile_free(), which walks [0, out->npattern) and
	 * frees each non-NULL spec/mask/last before freeing the array.
	 * Increment out->npattern only after a slot is fully owned.
	 */

	for (;;) {
		if (cc->tok.kind != TK_IDENT)
			return flow_compile_errf(cc, &cc->tok,
				"expected item name");

		if (tok_is_ident(&cc->tok, "end"))
			break;

		struct token name = cc->tok;
		const struct flow_item_desc *desc =
			flow_compile_item_lookup(name.text, name.len);
		if (desc == NULL)
			return flow_compile_errf(cc, &name,
				"unknown flow item '%.*s'",
				(int)name.len, name.text);

		if (flow_compile_lex(cc) < 0)
			return -1;

		/* Reserve a slot, growing the array if needed.  ``+1``
		 * leaves room for the trailing END sentinel.
		 */
		if (out->npattern + 1 >= cap) {
			cap *= 2;
			struct rte_flow_item *p =
				rte_realloc(out->pattern,
					    cap * sizeof(*p), 0);
			if (p == NULL) {
				rte_errno = ENOMEM;
				return -1;
			}
			out->pattern = p;
		}

		/* Zero the slot before parse_item_fields() touches it
		 * so partial allocations are visible to the cleanup
		 * walker without ever observing garbage in the freshly
		 * grown realloc tail.  Then publish via npattern++.
		 */
		struct rte_flow_item *item = &out->pattern[out->npattern];
		memset(item, 0, sizeof(*item));
		item->type = desc->type;
		out->npattern++;

		if (parse_item_fields(cc, desc, item) < 0)
			return -1;

		if (cc->tok.kind != TK_SLASH)
			return flow_compile_errf(cc, &cc->tok,
				"expected '/' after item '%s'", desc->name);
		if (flow_compile_lex(cc) < 0)
			return -1;
	}

	/* Trailing END.  The reserved capacity always has room
	 * because the loop's growth check leaves +1 spare.
	 */
	struct rte_flow_item *end = &out->pattern[out->npattern];
	memset(end, 0, sizeof(*end));	/* type = END = 0, no buffers */
	out->npattern++;

	if (flow_compile_lex(cc) < 0)
		return -1;	/* consume 'end' */
	return 0;
}

/* ------------------------------------------------------------------ */
/* Action body. */

static int
parse_action_fields(struct flow_compile_ctx *cc,
		    const struct flow_action_desc *desc,
		    struct rte_flow_action *act)
{
	if (desc->conf_size > 0) {
		act->conf = rte_zmalloc("flow_compile", desc->conf_size, 0);
		if (act->conf == NULL) {
			rte_errno = ENOMEM;
			return -1;
		}
	}
	bool conf_used = false;
	void *conf = (void *)(uintptr_t)act->conf;

	while (cc->tok.kind == TK_IDENT &&
	       !tok_is_ident(&cc->tok, "end")) {
		struct token name = cc->tok;
		const struct field_desc *fd =
			flow_compile_field_lookup(desc->fields, desc->nfields,
						  name.text, name.len);
		if (fd == NULL)
			return flow_compile_errf(cc, &name,
				"unknown parameter '%.*s' for action '%s'",
				(int)name.len, name.text, desc->name);

		if (flow_compile_lex(cc) < 0)
			return -1;
		struct token value = cc->tok;
		if (default_field_set(cc, conf, NULL, fd, &value) < 0)
			return -1;
		conf_used = true;

		if (flow_compile_lex(cc) < 0)
			return -1;
	}

	if (!conf_used) {
		rte_free(conf);
		act->conf = NULL;
	}
	return 0;
}

static int
parse_actions(struct flow_compile_ctx *cc, struct rte_flow_compile *out)
{
	if (!tok_is_ident(&cc->tok, "actions"))
		return flow_compile_errf(cc, &cc->tok, "expected 'actions'");
	if (flow_compile_lex(cc) < 0)
		return -1;

	size_t cap = 8;
	out->actions = rte_calloc("flow_compile_actions", cap,
				  sizeof(*out->actions), 0);
	if (out->actions == NULL) {
		rte_errno = ENOMEM;
		return -1;
	}

	for (;;) {
		if (cc->tok.kind != TK_IDENT)
			return flow_compile_errf(cc, &cc->tok,
				"expected action name");

		if (tok_is_ident(&cc->tok, "end"))
			break;

		struct token name = cc->tok;
		const struct flow_action_desc *desc =
			flow_compile_action_lookup(name.text, name.len);
		if (desc == NULL)
			return flow_compile_errf(cc, &name,
				"unknown flow action '%.*s'",
				(int)name.len, name.text);

		if (flow_compile_lex(cc) < 0)
			return -1;

		if (out->nactions + 1 >= cap) {
			cap *= 2;
			struct rte_flow_action *p =
				rte_realloc(out->actions,
					    cap * sizeof(*p), 0);
			if (p == NULL) {
				rte_errno = ENOMEM;
				return -1;
			}
			out->actions = p;
		}

		struct rte_flow_action *act = &out->actions[out->nactions];
		memset(act, 0, sizeof(*act));
		act->type = desc->type;
		out->nactions++;

		if (parse_action_fields(cc, desc, act) < 0)
			return -1;

		if (cc->tok.kind != TK_SLASH)
			return flow_compile_errf(cc, &cc->tok,
				"expected '/' after action '%s'", desc->name);
		if (flow_compile_lex(cc) < 0)
			return -1;
	}

	struct rte_flow_action *end = &out->actions[out->nactions];
	memset(end, 0, sizeof(*end));	/* type = END = 0, no conf */
	out->nactions++;

	if (flow_compile_lex(cc) < 0)
		return -1;	/* consume 'end' */
	return 0;
}

/* ------------------------------------------------------------------ */
/* Top level. */

int
flow_compile_parse(struct flow_compile_ctx *cc, struct rte_flow_compile *out)
{
	if (flow_compile_lex(cc) < 0)
		return -1;

	if (parse_attrs(cc, &out->attr) < 0)
		return -1;
	if (parse_pattern(cc, out) < 0)
		return -1;
	if (parse_actions(cc, out) < 0)
		return -1;

	if (cc->tok.kind != TK_EOF)
		return flow_compile_errf(cc, &cc->tok,
			"unexpected token after rule");
	return 0;
}

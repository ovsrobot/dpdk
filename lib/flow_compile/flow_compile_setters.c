/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Stephen Hemminger <stephen@networkplumber.org>
 *
 * Helpers invoked from the bison semantic actions in flow_compile.y.
 * The grammar drives the high-level structure (item-list, action-list);
 * this file does the table lookup and per-field byte conversion.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <rte_byteorder.h>
#include <rte_errno.h>
#include <rte_malloc.h>

#include "flow_compile_priv.h"
#include "flow_compile.tab.h"		/* struct ident_value, struct flow_value */

/* ------------------------------------------------------------------ */
/* Diagnostics. */

int
flow_compile_errf_at(struct flow_compile_ctx *cc,
		     uint16_t line, uint16_t col,
		     const char *fmt, ...)
{
	if (cc->errbuf[0] != '\0')
		return -1;	/* keep the first error */

	if (line == 0 && col == 0) {
		line = cc->line;
		col  = cc->col;
	}

	int n = snprintf(cc->errbuf, RTE_FLOW_COMPILE_ERRBUF_SIZE,
			 "%u:%u: ", (unsigned int)line, (unsigned int)col);
	if (n < 0)
		n = 0;
	if (n >= (int)RTE_FLOW_COMPILE_ERRBUF_SIZE)
		n = (int)RTE_FLOW_COMPILE_ERRBUF_SIZE - 1;

	va_list ap;
	va_start(ap, fmt);
	vsnprintf(cc->errbuf + n,
		  (size_t)RTE_FLOW_COMPILE_ERRBUF_SIZE - (size_t)n,
		  fmt, ap);
	va_end(ap);

	rte_errno = EINVAL;
	return -1;
}

/* ------------------------------------------------------------------ */

static inline unsigned int
hex_nibble(int c)
{
	if (c <= '9')
		return (unsigned int)(c - '0');
	if (c <= 'F')
		return (unsigned int)(c - 'A' + 10);
	return (unsigned int)(c - 'a' + 10);
}

/* ------------------------------------------------------------------ */
/* Default field setters. */

static int
write_uint(struct flow_compile_ctx *cc,
	   void *spec, void *mask,
	   const struct field_desc *fd,
	   uint64_t v, uint64_t maxv,
	   const struct flow_value *value)
{
	if (v > maxv)
		return flow_compile_errf_at(cc, value->line, value->col,
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
		return flow_compile_errf_at(cc, value->line, value->col,
			"field '%s' does not accept an integer", fd->name);
	}

	if (mask != NULL)
		memset((uint8_t *)mask + fd->offset, 0xff, fd->size);
	return 0;
}

static int
write_bytes(struct flow_compile_ctx *cc,
	    void *spec, void *mask,
	    const struct field_desc *fd,
	    const struct flow_value *value)
{
	uint8_t *sp = (uint8_t *)spec + fd->offset;

	if (value->kind == FV_HEXSTR) {
		const struct ident_value *h = &value->v.hex;
		size_t body = (size_t)h->len - 2;
		if (body != (size_t)fd->size * 2)
			return flow_compile_errf_at(cc, value->line, value->col,
				"hex string for '%s' must be %u bytes",
				fd->name, (unsigned int)fd->size);
		const char *p = h->text + 2;
		for (uint16_t i = 0; i < fd->size; i++) {
			unsigned int b =
				(hex_nibble((unsigned char)p[i * 2]) << 4)
			      |  hex_nibble((unsigned char)p[i * 2 + 1]);
			sp[i] = (uint8_t)b;
		}
	} else if (value->kind == FV_UINT) {
		uint64_t v = value->v.u;
		for (int i = (int)fd->size - 1; i >= 0; i--) {
			sp[i] = (uint8_t)(v & 0xffu);
			v >>= 8;
		}
		if (v != 0)
			return flow_compile_errf_at(cc, value->line, value->col,
				"value too large for %u byte field '%s'",
				(unsigned int)fd->size, fd->name);
	} else {
		return flow_compile_errf_at(cc, value->line, value->col,
			"field '%s' expects an integer or hex string",
			fd->name);
	}

	if (mask != NULL)
		memset((uint8_t *)mask + fd->offset, 0xff, fd->size);
	return 0;
}

static int
default_field_set(struct flow_compile_ctx *cc,
		  void *spec, void *mask,
		  const struct field_desc *fd,
		  const struct flow_value *value)
{
	uint8_t *sp = (uint8_t *)spec + fd->offset;

	switch (fd->kind) {
	case FK_U8:
		if (value->kind != FV_UINT)
			return flow_compile_errf_at(cc, value->line, value->col,
				"field '%s' expects an integer", fd->name);
		return write_uint(cc, spec, mask, fd, value->v.u, UINT8_MAX, value);
	case FK_U16:
	case FK_BE16:
		if (value->kind != FV_UINT)
			return flow_compile_errf_at(cc, value->line, value->col,
				"field '%s' expects an integer", fd->name);
		return write_uint(cc, spec, mask, fd, value->v.u, UINT16_MAX, value);
	case FK_U32:
		if (value->kind != FV_UINT)
			return flow_compile_errf_at(cc, value->line, value->col,
				"field '%s' expects an integer", fd->name);
		return write_uint(cc, spec, mask, fd, value->v.u, UINT32_MAX, value);
	case FK_U64:
	case FK_BE64:
		if (value->kind != FV_UINT)
			return flow_compile_errf_at(cc, value->line, value->col,
				"field '%s' expects an integer", fd->name);
		return write_uint(cc, spec, mask, fd, value->v.u, UINT64_MAX, value);
	case FK_BE32:
		if (value->kind == FV_IPV4) {
			memcpy(sp, value->v.ipv4, 4);
			if (mask != NULL)
				memset((uint8_t *)mask + fd->offset, 0xff, 4);
			return 0;
		}
		if (value->kind == FV_UINT)
			return write_uint(cc, spec, mask, fd, value->v.u,
					  UINT32_MAX, value);
		return flow_compile_errf_at(cc, value->line, value->col,
			"field '%s' expects an integer or IPv4 address",
			fd->name);
	case FK_MAC:
		if (value->kind != FV_MAC)
			return flow_compile_errf_at(cc, value->line, value->col,
				"field '%s' expects a MAC address", fd->name);
		memcpy(sp, value->v.mac, 6);
		if (mask != NULL)
			memset((uint8_t *)mask + fd->offset, 0xff, 6);
		return 0;
	case FK_IPV4:
		if (value->kind != FV_IPV4)
			return flow_compile_errf_at(cc, value->line, value->col,
				"field '%s' expects an IPv4 address", fd->name);
		memcpy(sp, value->v.ipv4, 4);
		if (mask != NULL)
			memset((uint8_t *)mask + fd->offset, 0xff, 4);
		return 0;
	case FK_IPV6:
		if (value->kind != FV_IPV6)
			return flow_compile_errf_at(cc, value->line, value->col,
				"field '%s' expects an IPv6 address", fd->name);
		memcpy(sp, value->v.ipv6, 16);
		if (mask != NULL)
			memset((uint8_t *)mask + fd->offset, 0xff, 16);
		return 0;
	case FK_BYTES:
		return write_bytes(cc, spec, mask, fd, value);
	}
	return flow_compile_errf_at(cc, value->line, value->col,
		"internal error: unknown field kind for '%s'", fd->name);
}

static int
apply_prefix(struct flow_compile_ctx *cc, void *mask,
	     const struct field_desc *fd, const struct flow_value *value)
{
	if (value->kind != FV_UINT)
		return flow_compile_errf_at(cc, value->line, value->col,
			"prefix expects an integer");

	uint32_t bits = (uint32_t)value->v.u;
	uint32_t total = fd->size * 8u;
	if (bits > total)
		return flow_compile_errf_at(cc, value->line, value->col,
			"prefix %u exceeds %u bits for '%s'",
			bits, total, fd->name);

	if (fd->kind != FK_IPV4 && fd->kind != FK_IPV6 &&
	    fd->kind != FK_BE32)
		return flow_compile_errf_at(cc, value->line, value->col,
			"prefix not supported for field '%s'", fd->name);

	uint8_t *m = (uint8_t *)mask + fd->offset;
	memset(m, 0, fd->size);
	for (uint32_t i = 0; i < bits; i++)
		m[i / 8u] |= (uint8_t)(1u << (7u - (i & 7u)));
	return 0;
}

/* ------------------------------------------------------------------ */
/* Attribute application. */

int
flow_compile_apply_attr_uint(struct flow_compile_ctx *cc,
			     const char *which, uint64_t v)
{
	if (v > UINT32_MAX)
		return flow_compile_errf(cc,
			"%s expects uint32, got %" PRIu64, which, v);

	if (strcmp(which, "group") == 0)
		cc->out->attr.group = (uint32_t)v;
	else if (strcmp(which, "priority") == 0)
		cc->out->attr.priority = (uint32_t)v;
	else
		return flow_compile_errf(cc,
			"internal error: unknown attribute '%s'", which);
	return 0;
}

/* ------------------------------------------------------------------ */
/* Item lifecycle. */

int
flow_compile_begin_item(struct flow_compile_ctx *cc,
			const struct ident_value *name)
{
	const struct flow_item_desc *desc =
		flow_compile_item_lookup(name->text, name->len);
	if (desc == NULL)
		return flow_compile_errf(cc,
			"unknown flow item '%.*s'",
			(int)name->len, name->text);

	if (cc->out->npattern + 1 >= cc->out->pattern_cap) {
		unsigned int cap = cc->out->pattern_cap == 0 ? 8 :
				   cc->out->pattern_cap * 2;
		struct rte_flow_item *p = rte_realloc(cc->out->pattern,
				cap * sizeof(*p), 0);
		if (p == NULL) {
			rte_errno = ENOMEM;
			return -1;
		}
		cc->out->pattern = p;
		cc->out->pattern_cap = cap;
	}

	struct rte_flow_item *item = &cc->out->pattern[cc->out->npattern];
	memset(item, 0, sizeof(*item));
	item->type = desc->type;
	cc->out->npattern++;	/* publish so cleanup walker sees it */

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

	cc->cur_item_desc = desc;
	cc->cur_item      = item;
	cc->spec_used = false;
	cc->mask_used = false;
	cc->last_used = false;
	return 0;
}

int
flow_compile_end_item(struct flow_compile_ctx *cc)
{
	struct rte_flow_item *item = cc->cur_item;

	if (!cc->spec_used) {
		rte_free((void *)(uintptr_t)item->spec);
		item->spec = NULL;
	}
	if (!cc->mask_used) {
		rte_free((void *)(uintptr_t)item->mask);
		item->mask = NULL;
	}
	if (!cc->last_used) {
		rte_free((void *)(uintptr_t)item->last);
		item->last = NULL;
	}
	cc->cur_item_desc = NULL;
	cc->cur_item      = NULL;
	return 0;
}

int
flow_compile_set_field(struct flow_compile_ctx *cc,
		       const struct ident_value *field,
		       const struct ident_value *qualifier,
		       const struct flow_value *value)
{
	const struct flow_item_desc *desc = cc->cur_item_desc;
	struct rte_flow_item *item = cc->cur_item;
	if (desc == NULL || item == NULL)
		return flow_compile_errf(cc,
			"internal error: lost item descriptor");

	const struct field_desc *fd =
		flow_compile_field_lookup(desc->fields, desc->nfields,
					  field->text, field->len);
	if (fd == NULL)
		return flow_compile_errf(cc,
			"unknown field '%.*s' for item '%s'",
			(int)field->len, field->text, desc->name);

	void *spec = (void *)(uintptr_t)item->spec;
	void *mask = (void *)(uintptr_t)item->mask;
	void *last = (void *)(uintptr_t)item->last;

	if (qualifier->len == 2 && memcmp(qualifier->text, "is", 2) == 0) {
		cc->spec_used = cc->mask_used = true;
		return default_field_set(cc, spec, mask, fd, value);
	}
	if (qualifier->len == 4 && memcmp(qualifier->text, "spec", 4) == 0) {
		cc->spec_used = true;
		return default_field_set(cc, spec, NULL, fd, value);
	}
	if (qualifier->len == 4 && memcmp(qualifier->text, "last", 4) == 0) {
		cc->last_used = true;
		return default_field_set(cc, last, NULL, fd, value);
	}
	if (qualifier->len == 4 && memcmp(qualifier->text, "mask", 4) == 0) {
		cc->mask_used = true;
		return default_field_set(cc, mask, NULL, fd, value);
	}
	if (qualifier->len == 6 && memcmp(qualifier->text, "prefix", 6) == 0) {
		cc->mask_used = true;
		return apply_prefix(cc, mask, fd, value);
	}

	return flow_compile_errf(cc,
		"internal error: unknown qualifier '%.*s'",
		(int)qualifier->len, qualifier->text);
}

/* ------------------------------------------------------------------ */
/* Action lifecycle. */

int
flow_compile_begin_action(struct flow_compile_ctx *cc,
			  const struct ident_value *name)
{
	const struct flow_action_desc *desc =
		flow_compile_action_lookup(name->text, name->len);
	if (desc == NULL)
		return flow_compile_errf(cc,
			"unknown flow action '%.*s'",
			(int)name->len, name->text);

	if (cc->out->nactions + 1 >= cc->out->actions_cap) {
		unsigned int cap = cc->out->actions_cap == 0 ? 8 :
				   cc->out->actions_cap * 2;
		struct rte_flow_action *p = rte_realloc(cc->out->actions,
				cap * sizeof(*p), 0);
		if (p == NULL) {
			rte_errno = ENOMEM;
			return -1;
		}
		cc->out->actions = p;
		cc->out->actions_cap = cap;
	}

	struct rte_flow_action *act = &cc->out->actions[cc->out->nactions];
	memset(act, 0, sizeof(*act));
	act->type = desc->type;
	cc->out->nactions++;

	if (desc->conf_size > 0) {
		act->conf = rte_zmalloc("flow_compile", desc->conf_size, 0);
		if (act->conf == NULL) {
			rte_errno = ENOMEM;
			return -1;
		}
	}

	cc->cur_action_desc = desc;
	cc->cur_action      = act;
	cc->conf_used = false;
	return 0;
}

int
flow_compile_end_action(struct flow_compile_ctx *cc)
{
	struct rte_flow_action *act = cc->cur_action;

	if (!cc->conf_used) {
		rte_free((void *)(uintptr_t)act->conf);
		act->conf = NULL;
	}
	cc->cur_action_desc = NULL;
	cc->cur_action      = NULL;
	return 0;
}

int
flow_compile_set_action_param(struct flow_compile_ctx *cc,
			      const struct ident_value *name,
			      const struct flow_value *value)
{
	const struct flow_action_desc *desc = cc->cur_action_desc;
	struct rte_flow_action *act = cc->cur_action;
	if (desc == NULL || act == NULL)
		return flow_compile_errf(cc,
			"internal error: lost action descriptor");

	const struct field_desc *fd =
		flow_compile_field_lookup(desc->fields, desc->nfields,
					  name->text, name->len);
	if (fd == NULL)
		return flow_compile_errf(cc,
			"unknown parameter '%.*s' for action '%s'",
			(int)name->len, name->text, desc->name);

	cc->conf_used = true;
	return default_field_set(cc, (void *)(uintptr_t)act->conf,
				 NULL, fd, value);
}

/* ------------------------------------------------------------------ */
/* Append END sentinels at the end of a successful parse.  Both
 * arrays were sized with +1 headroom in begin_item / begin_action,
 * so this never reallocates.
 */
int
flow_compile_finalize(struct flow_compile_ctx *cc)
{
	struct rte_flow_item *iend = &cc->out->pattern[cc->out->npattern];
	memset(iend, 0, sizeof(*iend));
	cc->out->npattern++;

	struct rte_flow_action *aend = &cc->out->actions[cc->out->nactions];
	memset(aend, 0, sizeof(*aend));
	cc->out->nactions++;
	return 0;
}

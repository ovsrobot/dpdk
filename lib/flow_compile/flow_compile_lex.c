/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Stephen Hemminger <stephen@networkplumber.org>
 */

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <rte_errno.h>
#include <rte_ether.h>

#include "flow_compile_priv.h"

/*
 * Diagnostics.
 *
 * On the first error we capture, all subsequent calls become no-ops
 * so that the user sees the *first* problem (which is usually the
 * cause) rather than a cascade.
 */
int
flow_compile_errf(struct flow_compile_ctx *cc, const struct token *at,
		  const char *fmt, ...)
{
	if (cc->errbuf[0] != '\0')
		return -1;	/* keep the first error */

	uint16_t line = at != NULL ? at->line : cc->line;
	uint16_t col  = at != NULL ? at->col  : cc->col;

	int n = snprintf(cc->errbuf, RTE_FLOW_COMPILE_ERRBUF_SIZE,
			 "%u:%u: ", (unsigned int)line, (unsigned int)col);
	if (n < 0)
		n = 0;
	if (n >= (int)RTE_FLOW_COMPILE_ERRBUF_SIZE)
		n = (int)RTE_FLOW_COMPILE_ERRBUF_SIZE - 1;

	va_list ap;
	va_start(ap, fmt);
	vsnprintf(cc->errbuf + n, (size_t)RTE_FLOW_COMPILE_ERRBUF_SIZE - (size_t)n,
		  fmt, ap);
	va_end(ap);

	rte_errno = EINVAL;
	return -1;
}

/* ------------------------------------------------------------------ */
/* Character classes.
 *
 * The grammar is pure ASCII; using <ctype.h> would tie behavior to
 * the active locale.  Inline predicates compile down to a single
 * range comparison.
 */

static inline bool
is_ascii_alpha(int c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static inline bool
is_ascii_alnum(int c)
{
	return is_ascii_alpha(c) || (c >= '0' && c <= '9');
}

static inline bool
is_ascii_space(int c)
{
	return c == ' ' || c == '\t' || c == '\n' ||
	       c == '\r' || c == '\v' || c == '\f';
}

static inline bool
is_word_start(int c)
{
	return is_ascii_alpha(c) || c == '_';
}

/*
 * Characters that can appear inside an unquoted value lexeme.
 * The lexer reads a run of these and then classifies the run.
 *
 * '_' is intentionally absent: identifiers (which are the only
 * tokens that legitimately contain '_') are taken by the
 * alpha-start branch in flow_compile_lex(), so '_' inside a
 * digit-started run can never produce a useful token.
 *
 * '-' is included so that the IEEE 802 / Windows hyphen-separated
 * MAC form (XX-XX-XX-XX-XX-XX) reaches match_mac(), which delegates
 * to rte_ether_unformat_addr() and accepts it.
 */
static inline bool
is_value_cont(int c)
{
	return is_ascii_alnum(c) || c == '.' || c == ':' || c == '-';
}

/* ------------------------------------------------------------------ */
/* Source navigation.  All movement goes through advance() so that
 * line/column tracking is trivially correct, including across CRLF.
 */

static void
advance(struct flow_compile_ctx *cc, size_t n)
{
	for (size_t i = 0; i < n && *cc->cur != '\0'; i++) {
		if (*cc->cur == '\n') {
			cc->line++;
			cc->col = 1;
		} else {
			cc->col++;
		}
		cc->cur++;
	}
}

static void
skip_ws_and_comments(struct flow_compile_ctx *cc)
{
	for (;;) {
		while (*cc->cur != '\0' && is_ascii_space((unsigned char)*cc->cur))
			advance(cc, 1);
		if (*cc->cur == '#') {
			while (*cc->cur != '\0' && *cc->cur != '\n')
				advance(cc, 1);
			continue;
		}
		break;
	}
}

/* ------------------------------------------------------------------ */
/* Classifiers for the value-lexeme run.
 *
 * These never read past ``end``; ``s`` is not required to be NUL
 * terminated within the run.
 */

static inline bool
is_dec_digit(int c)
{
	return c >= '0' && c <= '9';
}

static inline bool
is_hex_digit(int c)
{
	return (c >= '0' && c <= '9') ||
	       (c >= 'a' && c <= 'f') ||
	       (c >= 'A' && c <= 'F');
}

static bool
all_decimal(const char *s, size_t n)
{
	if (n == 0)
		return false;
	for (size_t i = 0; i < n; i++)
		if (!is_dec_digit((unsigned char)s[i]))
			return false;
	return true;
}

static bool
hex_prefixed(const char *s, size_t n, size_t *body_len)
{
	if (n < 3 || s[0] != '0' || (s[1] != 'x' && s[1] != 'X'))
		return false;
	for (size_t i = 2; i < n; i++)
		if (!is_hex_digit((unsigned char)s[i]))
			return false;
	*body_len = n - 2;
	return true;
}

static int
parse_uint(const char *s, size_t n, uint64_t *out)
{
	uint64_t v = 0;
	size_t i = 0;
	int base = 10;

	if (n >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
		base = 16;
		i = 2;
		if (i == n)
			return -1;
	}
	for (; i < n; i++) {
		uint64_t d;
		int c = (unsigned char)s[i];
		if (c >= '0' && c <= '9')
			d = (uint64_t)(c - '0');
		else if (base == 16 && c >= 'a' && c <= 'f')
			d = (uint64_t)(c - 'a' + 10);
		else if (base == 16 && c >= 'A' && c <= 'F')
			d = (uint64_t)(c - 'A' + 10);
		else
			return -1;
		/* overflow check */
		if (v > (UINT64_MAX - d) / (uint64_t)base)
			return -1;
		v = v * (uint64_t)base + d;
	}
	*out = v;
	return 0;
}

/*
 * Hex-only integer parser.  Used by the MAC and IPv6 matchers, where
 * the leading "0x" of the general parse_uint() is implied by context.
 * Caller guarantees n in [1, 16].
 */
static int
parse_hex(const char *s, size_t n, uint64_t *out)
{
	uint64_t v = 0;
	for (size_t i = 0; i < n; i++) {
		int c = (unsigned char)s[i];
		uint64_t d;
		if (c >= '0' && c <= '9')
			d = (uint64_t)(c - '0');
		else if (c >= 'a' && c <= 'f')
			d = (uint64_t)(c - 'a' + 10);
		else if (c >= 'A' && c <= 'F')
			d = (uint64_t)(c - 'A' + 10);
		else
			return -1;
		v = (v << 4) | d;
	}
	*out = v;
	return 0;
}

static bool
match_ipv4(const char *s, size_t n, uint8_t out[4])
{
	int parts = 0;
	uint32_t v = 0;
	size_t i = 0;
	bool in_part = false;

	while (i < n) {
		int c = (unsigned char)s[i];
		if (is_dec_digit(c)) {
			v = v * 10u + (uint32_t)(c - '0');
			if (v > 255u)
				return false;
			in_part = true;
			i++;
		} else if (c == '.') {
			if (!in_part)
				return false;
			out[parts++] = (uint8_t)v;
			if (parts == 4)
				return false;
			v = 0;
			in_part = false;
			i++;
		} else {
			return false;
		}
	}
	if (!in_part || parts != 3)
		return false;
	out[parts] = (uint8_t)v;
	return true;
}

/*
 * Recognize a MAC address in any form ``rte_ether_unformat_addr()``
 * accepts (colon-separated ``xx:xx:xx:xx:xx:xx`` and Cisco dotted
 * ``xxxx.xxxx.xxxx``).  Delegates the actual parsing so behavior
 * stays in lockstep with the rest of DPDK.
 */
static bool
match_mac(const char *s, size_t n, uint8_t out[6])
{
	/* The longest accepted form is the 17-byte colon notation;
	 * Cisco notation is 14 bytes.  Cap at 18 to leave room for the
	 * NUL that rte_ether_unformat_addr() requires.
	 */
	char buf[18];
	if (n >= sizeof(buf))
		return false;
	memcpy(buf, s, n);
	buf[n] = '\0';

	struct rte_ether_addr ea;
	if (rte_ether_unformat_addr(buf, &ea) != 0)
		return false;
	memcpy(out, ea.addr_bytes, RTE_ETHER_ADDR_LEN);
	return true;
}

/*
 * IPv6 textual form per RFC 4291 / RFC 5952.
 *
 * Accepts:
 *   - 8 groups of 1-4 hex digits separated by ':'
 *   - "::" once, replacing one or more zero groups
 *   - mixed form is *not* accepted (no embedded IPv4 dotted-quad).
 *     This matches what the rest of DPDK uses internally.
 */
static bool
match_ipv6(const char *s, size_t n, uint8_t out[16])
{
	uint16_t head[8] = {0};
	uint16_t tail[8] = {0};
	int nh = 0, nt = 0;
	bool seen_dcolon = false;
	size_t i = 0;

	if (n >= 2 && s[0] == ':' && s[1] == ':') {
		seen_dcolon = true;
		i = 2;
	}

	while (i < n) {
		/* read one hex group */
		size_t g0 = i;
		while (i < n && is_hex_digit((unsigned char)s[i]))
			i++;
		size_t glen = i - g0;
		if (glen == 0 || glen > 4)
			return false;
		uint64_t v;
		if (parse_hex(s + g0, glen, &v) < 0 || v > 0xffffu)
			return false;
		uint16_t *dst = seen_dcolon ? tail : head;
		int *cnt = seen_dcolon ? &nt : &nh;
		if (*cnt == 8)
			return false;
		dst[(*cnt)++] = (uint16_t)v;

		if (i == n)
			break;
		if (s[i] != ':')
			return false;
		i++;
		if (i < n && s[i] == ':') {
			if (seen_dcolon)
				return false;
			seen_dcolon = true;
			i++;
			if (i == n)
				break;
		}
	}

	int total = nh + nt;
	if (seen_dcolon) {
		if (total >= 8)
			return false;
	} else {
		if (total != 8)
			return false;
	}

	int gap = 8 - total;
	int p = 0;
	for (int j = 0; j < nh; j++, p++) {
		out[p * 2]     = (uint8_t)(head[j] >> 8);
		out[p * 2 + 1] = (uint8_t)head[j];
	}
	for (int j = 0; j < gap; j++, p++) {
		out[p * 2] = 0;
		out[p * 2 + 1] = 0;
	}
	for (int j = 0; j < nt; j++, p++) {
		out[p * 2]     = (uint8_t)(tail[j] >> 8);
		out[p * 2 + 1] = (uint8_t)tail[j];
	}
	return true;
}

/* ------------------------------------------------------------------ */
/* Quoted string handling.  We support only simple double quoted
 * strings with backslash escaping for backslash and quote.
 */

static int
scan_string(struct flow_compile_ctx *cc, struct token *tk)
{
	tk->kind = TK_STRING;
	tk->line = cc->line;
	tk->col  = cc->col;
	advance(cc, 1);		/* eat opening quote */
	tk->text = cc->cur;

	while (*cc->cur != '\0' && *cc->cur != '"') {
		if (*cc->cur == '\\' && cc->cur[1] != '\0')
			advance(cc, 1);
		advance(cc, 1);
	}
	if (*cc->cur != '"')
		return flow_compile_errf(cc, tk, "unterminated string");
	tk->len = (uint16_t)(cc->cur - tk->text);
	advance(cc, 1);		/* eat closing quote */
	return 0;
}

/* ------------------------------------------------------------------ */
/* Top-level scan. */

int
flow_compile_lex(struct flow_compile_ctx *cc)
{
	skip_ws_and_comments(cc);

	struct token *tk = &cc->tok;
	memset(tk, 0, sizeof(*tk));
	tk->line = cc->line;
	tk->col  = cc->col;
	tk->text = cc->cur;

	int c = (unsigned char)*cc->cur;

	/* Single-character tokens and EOF. */
	switch (c) {
	case '\0':
		tk->kind = TK_EOF;
		return 0;
	case '/':
		tk->kind = TK_SLASH;
		tk->len = 1;
		advance(cc, 1);
		return 0;
	case ',':
		tk->kind = TK_COMMA;
		tk->len = 1;
		advance(cc, 1);
		return 0;
	case '{':
		tk->kind = TK_LBRACE;
		tk->len = 1;
		advance(cc, 1);
		return 0;
	case '}':
		tk->kind = TK_RBRACE;
		tk->len = 1;
		advance(cc, 1);
		return 0;
	case '"':
		return scan_string(cc, tk);
	default:
		break;
	}

	/* Identifier (alpha/_ start, no dots/colons). */
	if (is_word_start(c)) {
		size_t len = 0;
		while (is_ascii_alnum((unsigned char)cc->cur[len]) ||
		       cc->cur[len] == '_')
			len++;
		tk->kind = TK_IDENT;
		tk->len  = (uint16_t)len;
		advance(cc, len);
		return 0;
	}

	/* A value run.  We accept :: as start (IPv6) and digit start
	 * for everything else.
	 */
	if (is_dec_digit(c) || c == ':') {
		size_t len = 0;
		while (is_value_cont((unsigned char)cc->cur[len]))
			len++;
		if (len == 0)
			return flow_compile_errf(cc, NULL,
				"unexpected character '%c'", c);

		/* Classify in order: MAC (rigid shape), IPv4, hex string,
		 * decimal, IPv6.  IPv6 is tried last because a bare hex
		 * group like "1234" is also a valid uint.
		 */
		if (match_mac(cc->cur, len, tk->v.mac)) {
			tk->kind = TK_MAC;
		} else if (match_ipv4(cc->cur, len, tk->v.ipv4)) {
			tk->kind = TK_IPV4;
		} else {
			size_t hex_body;
			if (hex_prefixed(cc->cur, len, &hex_body) &&
			    hex_body > 16) {
				tk->kind = TK_HEXSTR;
			} else if (hex_prefixed(cc->cur, len, &hex_body) ||
				   all_decimal(cc->cur, len)) {
				if (parse_uint(cc->cur, len, &tk->v.u) < 0)
					return flow_compile_errf(cc, NULL,
						"integer out of range");
				tk->kind = TK_UINT;
			} else if (match_ipv6(cc->cur, len, tk->v.ipv6)) {
				tk->kind = TK_IPV6;
			} else {
				return flow_compile_errf(cc, NULL,
					"unrecognized token '%.*s'",
					(int)len, cc->cur);
			}
		}
		tk->len = (uint16_t)len;
		advance(cc, len);
		return 0;
	}

	return flow_compile_errf(cc, NULL, "unexpected character '%c'", c);
}

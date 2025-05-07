/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation.
 * Copyright (c) 2009, Olivier MATZ <zer0@droids-corp.org>
 * All rights reserved.
 */

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <float.h>
#include <math.h>
#include <string.h>
#include <eal_export.h>
#include <rte_string_fns.h>
#include <stdlib.h>

#include "cmdline_parse.h"
#include "cmdline_parse_num.h"

#ifdef RTE_LIBRTE_CMDLINE_DEBUG
#define debug_printf(...) printf(__VA_ARGS__)
#else
#define debug_printf(...) do {} while (0)
#endif

RTE_EXPORT_SYMBOL(cmdline_token_num_ops)
struct cmdline_token_ops cmdline_token_num_ops = {
	.parse = cmdline_parse_num,
	.complete_get_nb = NULL,
	.complete_get_elt = NULL,
	.get_help = cmdline_get_help_num,
};

/* Keep it sync with enum in .h */
static const char * num_help[] = {
	"UINT8", "UINT16", "UINT32", "UINT64",
	"INT8", "INT16", "INT32", "INT64",
	"FLOAT_SINGLE", "FLOAT_DOUBLE"
};

static inline int
add_to_bin(unsigned int c, uint64_t *res)
{
	/* overflow */
	if ((UINT64_MAX - c) / 2 < *res)
		return -1;

	*res = (uint64_t) (*res * 2 + c);
	return 0;
}

static int
check_res_size(struct cmdline_token_num_data *nd, unsigned ressize)
{
	switch (nd->type) {
	case RTE_INT8:
	case RTE_UINT8:
		if (ressize < sizeof(int8_t))
			return -1;
		break;
	case RTE_INT16:
	case RTE_UINT16:
		if (ressize < sizeof(int16_t))
			return -1;
		break;
	case RTE_INT32:
	case RTE_UINT32:
		if (ressize < sizeof(int32_t))
			return -1;
		break;
	case RTE_INT64:
	case RTE_UINT64:
		if (ressize < sizeof(int64_t))
			return -1;
		break;
	case RTE_FLOAT_SINGLE:
		if (ressize < sizeof(float))
			return -1;
		break;
	case RTE_FLOAT_DOUBLE:
		if (ressize < sizeof(double))
			return -1;
		break;
	default:
		return -1;
	}
	return 0;
}

static int
check_parsed_num(enum cmdline_numtype type, int neg, uint64_t uintres)
{
	int lo_ok, hi_ok;

	switch (type) {
	case RTE_UINT8:
		if (neg || uintres > UINT8_MAX)
			return -1;
		return 0;
	case RTE_UINT16:
		if (neg || uintres > UINT16_MAX)
			return -1;
		return 0;
	case RTE_UINT32:
		if (neg || uintres > UINT32_MAX)
			return -1;
		return 0;
	case RTE_UINT64:
		if (neg)
			return -1;
		return 0;
	case RTE_INT8:
		lo_ok = !neg || (int64_t)uintres >= INT8_MIN;
		hi_ok = neg || uintres <= INT8_MAX;
		break;
	case RTE_INT16:
		lo_ok = !neg || (int64_t)uintres >= INT16_MIN;
		hi_ok = neg || uintres <= INT16_MAX;
		break;
	case RTE_INT32:
		lo_ok = !neg || (int64_t)uintres >= INT32_MIN;
		hi_ok = neg || uintres <= INT32_MAX;
		break;
	case RTE_INT64:
		lo_ok = 1; /* always valid */
		hi_ok = neg || uintres <= INT64_MAX;
		break;
	default:
		return -1;
	}
	/* check ranges */
	if (!lo_ok || !hi_ok)
		return -1;
	return 0;
}

static int
parse_num(const char *srcbuf, uint64_t *resptr)
{
	uint64_t uintres;
	char *end;
	int neg = *srcbuf == '-';

	errno = 0;
	if (neg)
		/* for negatives, only support base-10 */
		uintres = (uint64_t)strtoll(srcbuf, &end, 10);
	else
		/* 0 means autodetect base */
		uintres = strtoull(srcbuf, &end, 0);

	if (end == srcbuf || !cmdline_isendoftoken(*end) || errno == ERANGE)
		return -1;
	*resptr = uintres;
	return end - srcbuf;
}

static int
parse_bin(const char *srcbuf, uint64_t *res)
{
	uint64_t uintres = 0;
	enum {
		ERROR,
		START,
		BIN,
		ZERO_OK,
		BIN_OK,
	} st = START;
	const char * buf;
	char c;

	buf = srcbuf;
	c = *buf;
	while (st != ERROR && c && !cmdline_isendoftoken(c)) {
		debug_printf("%c %x -> ", c, c);
		switch (st) {
		case START:
			if (c == '0') {
				st = ZERO_OK;
			}
			else {
				st = ERROR;
			}
			break;

		case ZERO_OK:
			if (c == 'b') {
				st = BIN;
			}
			else {
				st = ERROR;
			}
			break;

		case BIN:
			st = BIN_OK;
			/* fall-through */
		case BIN_OK:
			if (c >= '0' && c <= '1') {
				if (add_to_bin(c - '0', &uintres) < 0)
					st = ERROR;
			}
			else {
				st = ERROR;
			}
			break;
		default:
			debug_printf("not impl ");
			st = ERROR;
		}

		debug_printf("(%"PRIu64")\n", uintres);

		buf ++;
		c = *buf;

		/* token too long */
		if (buf-srcbuf > 127)
			return -1;
	}

	if (st != BIN_OK)
		return -1;

	*res = uintres;
	return buf - srcbuf;
}

/* parse a number */
RTE_EXPORT_SYMBOL(cmdline_parse_num)
int
cmdline_parse_num(cmdline_parse_token_hdr_t *tk, const char *srcbuf, void *res,
	unsigned ressize)
{
	struct cmdline_token_num_data nd;

	if (!tk)
		return -1;

	if (!srcbuf || !*srcbuf)
		return -1;

	memcpy(&nd, &((struct cmdline_token_num *)tk)->num_data, sizeof(nd));

	/* check that we have enough room in res */
	if (res) {
		if (check_res_size(&nd, ressize) < 0)
			return -1;
	}
	/* integer parsing */
	if (nd.type >= RTE_UINT8 && nd.type <= RTE_INT64) {
		int ret, neg = *srcbuf == '-';
		uint64_t uintres;

		/*
		 * for backwards compatibility with previous iterations of
		 * cmdline library, we need to take into account a few things:
		 *
		 * - we only support negatives when they're decimal
		 * - we support binary which isn't supported by C parsers
		 * - strtoull does not do range checks on negative numbers
		 */
		ret = parse_num(srcbuf, &uintres);

		if (ret < 0) {
			/* parse failed, try parsing as binary */
			ret = parse_bin(srcbuf, &uintres);
			if (ret < 0)
				return -1;
		}
		/* check if we're within valid range */
		if (check_parsed_num(nd.type, neg, uintres) < 0)
			return -1;

		switch (nd.type) {
		case RTE_UINT8:
			if (res) *(uint8_t *)res = (uint8_t)uintres;
			break;
		case RTE_UINT16:
			if (res) *(uint16_t *)res = (uint16_t)uintres;
			break;
		case RTE_UINT32:
			if (res) *(uint32_t *)res = (uint32_t)uintres;
			break;
		case RTE_UINT64:
			if (res) *(uint64_t *)res = uintres;
			break;
		case RTE_INT8:
			if (res) *(int8_t *)res = (int8_t)uintres;
			break;
		case RTE_INT16:
			if (res) *(int16_t *)res = (int16_t)uintres;
			break;
		case RTE_INT32:
			if (res) *(int32_t *)res = (int32_t)uintres;
			break;
		case RTE_INT64:
			if (res) *(int64_t *)res = (int64_t)uintres;
			break;
		default:
			return -1;
		}
		return ret;
	/* float parsing */
	} else if (nd.type >= RTE_FLOAT_SINGLE && nd.type <= RTE_FLOAT_DOUBLE) {
		char *end;
		double dres = strtod(srcbuf, &end);

		if (end == srcbuf || !cmdline_isendoftoken(*end) || isinf(dres))
			return -1;

		/* we parsed something, now let's ensure it fits */
		if (nd.type == RTE_FLOAT_SINGLE) {
			float flt = (float)dres;
			if (isinf(flt))
				return -1;
			if (res) *(float *)res = flt;
			return end-srcbuf;
		} else if (nd.type == RTE_FLOAT_DOUBLE) {
			if (res) *(double *)res = dres;
			return end-srcbuf;
		}
	}
	return -1;
}


/* parse an int */
RTE_EXPORT_SYMBOL(cmdline_get_help_num)
int
cmdline_get_help_num(cmdline_parse_token_hdr_t *tk, char *dstbuf, unsigned int size)
{
	struct cmdline_token_num_data nd;
	int ret;

	if (!tk)
		return -1;

	memcpy(&nd, &((struct cmdline_token_num *)tk)->num_data, sizeof(nd));

	/* should not happen.... don't so this test */
	/* if (nd.type >= (sizeof(num_help)/sizeof(const char *))) */
	/* return -1; */

	ret = strlcpy(dstbuf, num_help[nd.type], size);
	if (ret < 0)
		return -1;
	dstbuf[size-1] = '\0';
	return 0;
}

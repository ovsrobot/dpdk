/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation.
 * Copyright (c) 2009, Olivier MATZ <zer0@droids-corp.org>
 * All rights reserved.
 */

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
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
check_res_size(struct cmdline_token_num_data *num_data, unsigned int res_size)
{
	switch (num_data->type) {
	case RTE_INT8:
	case RTE_UINT8:
		if (res_size < sizeof(int8_t))
			return -1;
		break;
	case RTE_INT16:
	case RTE_UINT16:
		if (res_size < sizeof(int16_t))
			return -1;
		break;
	case RTE_INT32:
	case RTE_UINT32:
		if (res_size < sizeof(int32_t))
			return -1;
		break;
	case RTE_INT64:
	case RTE_UINT64:
		if (res_size < sizeof(int64_t))
			return -1;
		break;
	default:
		debug_printf("Wrong number type: %d\n", num_data->type);
		return -1;
	}
	return 0;
}

static int
validate_type(enum cmdline_numtype type)
{
	if (type < RTE_UINT8 || type > RTE_INT64)
		return -1;
	/* ensure no buffer overrun can occur */
	if ((uint64_t) type >= RTE_DIM(num_help))
		return -1;
	return 0;
}

static int
check_parsed_num(enum cmdline_numtype type, int neg, uint64_t uintres)
{
	int lo_ok, hi_ok;

	switch (type) {
	case RTE_UINT8:
		lo_ok = !neg;
		hi_ok = uintres <= UINT8_MAX;
		break;
	case RTE_UINT16:
		lo_ok = !neg;
		hi_ok = uintres <= UINT16_MAX;
		break;
	case RTE_UINT32:
		lo_ok = !neg;
		hi_ok = uintres <= UINT32_MAX;
		break;
	case RTE_UINT64:
		lo_ok = !neg;
		hi_ok = 1; /* can't be out of range if parsed successfully */
		break;
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
		lo_ok = 1; /* can't be out of range if parsed successfully */
		hi_ok = neg || uintres <= INT64_MAX;
		break;
	default:
		debug_printf("Wrong number type\n");
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

	/*
	 * strtoull does not do range checks on negative numbers, so we need to
	 * use strtoll if we know the value we're parsing looks like a negative
	 * one. we use base 0 for both, 0 means autodetect base.
	 */
	errno = 0;
	if (neg)
		uintres = (uint64_t)strtoll(srcbuf, &end, 0);
	else
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
		NEG,
		ZERO_OK,
		BIN_OK,
	} st = START;
	const char * buf;
	char c;
	int neg = 0;

	buf = srcbuf;
	c = *buf;
	while (st != ERROR && c && !cmdline_isendoftoken(c)) {
		debug_printf("%c %x -> ", c, c);
		switch (st) {
		case START:
			if (c == '0') {
				st = ZERO_OK;
			} else if (c == '-') {
				neg = 1;
				st = NEG;
			} else {
				st = ERROR;
			}
			break;

		case NEG:
			if (c == '0')
				st = ZERO_OK;
			else
				st = ERROR;
			break;

		case ZERO_OK:
			if (c == 'b')
				st = BIN;
			else
				st = ERROR;
			break;

		case BIN:
			st = BIN_OK;
			/* fall-through */
		case BIN_OK:
			if (c >= '0' && c <= '1') {
				if (add_to_bin(c - '0', &uintres) < 0)
					st = ERROR;
			} else {
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

	/* was it negative? */
	if (neg)
		uintres = -uintres;

	*res = uintres;
	return buf - srcbuf;
}

static int
write_num(enum cmdline_numtype type, void *res, uint64_t uintres)
{
	switch (type) {
	case RTE_UINT8:
		*(uint8_t *)res = (uint8_t)uintres;
		break;
	case RTE_UINT16:
		*(uint16_t *)res = (uint16_t)uintres;
		break;
	case RTE_UINT32:
		*(uint32_t *)res = (uint32_t)uintres;
		break;
	case RTE_UINT64:
		*(uint64_t *)res = uintres;
		break;
	case RTE_INT8:
		*(int8_t *)res = (int8_t)uintres;
		break;
	case RTE_INT16:
		*(int16_t *)res = (int16_t)uintres;
		break;
	case RTE_INT32:
		*(int32_t *)res = (int32_t)uintres;
		break;
	case RTE_INT64:
		*(int64_t *)res = (int64_t)uintres;
		break;
	default:
		debug_printf("Wrong number type\n");
		return -1;
	}
	return 0;
}

/* parse an int */
RTE_EXPORT_SYMBOL(cmdline_parse_num)
int
cmdline_parse_num(cmdline_parse_token_hdr_t *tk, const char *srcbuf, void *res,
	unsigned int res_size)
{
	struct cmdline_token_num_data num_data;

	if (!tk)
		return -1;

	if (!srcbuf || !*srcbuf)
		return -1;

	memcpy(&num_data, &((struct cmdline_token_num *)tk)->num_data, sizeof(num_data));

	if (validate_type(num_data.type) < 0)
		return -1;

	/* check that we have enough room in res */
	if (res && check_res_size(&num_data, res_size) < 0)
		return -1;

	if (num_data.type >= RTE_UINT8 && num_data.type <= RTE_INT64) {
		int ret, neg = *srcbuf == '-';
		uint64_t uintres;

		/* try parsing as number */
		ret = parse_num(srcbuf, &uintres);

		if (ret < 0) {
			/* parse failed, try parsing as binary */
			ret = parse_bin(srcbuf, &uintres);
			if (ret < 0)
				return -1;
		}
		/* check if we're within valid range */
		if (check_parsed_num(num_data.type, neg, uintres) < 0)
			return -1;

		/* parsing succeeded, write the value if necessary */
		if (res && write_num(num_data.type, res, uintres) < 0)
			return -1;

		return ret;
	}
	return -1;
}

/* parse an int */
RTE_EXPORT_SYMBOL(cmdline_get_help_num)
int
cmdline_get_help_num(cmdline_parse_token_hdr_t *tk, char *dstbuf, unsigned int size)
{
	struct cmdline_token_num_data num_data;
	int ret;

	if (!tk)
		return -1;

	memcpy(&num_data, &((struct cmdline_token_num *)tk)->num_data, sizeof(num_data));

	if (validate_type(num_data.type) < 0)
		return -1;

	ret = strlcpy(dstbuf, num_help[num_data.type], size);
	if (ret < 0)
		return -1;
	dstbuf[size-1] = '\0';
	return 0;
}

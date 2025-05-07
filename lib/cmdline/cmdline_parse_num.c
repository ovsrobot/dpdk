/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation.
 * Copyright (c) 2009, Olivier MATZ <zer0@droids-corp.org>
 * All rights reserved.
 */

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

enum num_parse_state_t {
	START,
	DEC_NEG,
	BIN,
	HEX,
	FLOAT_POS,
	FLOAT_NEG,
	FLOAT_EXP,
	FLOAT_NEG_EXP,

	ERROR,

	FIRST_OK, /* not used */
	ZERO_OK,
	HEX_OK,
	OCTAL_OK,
	BIN_OK,
	DEC_NEG_OK,
	DEC_POS_OK,
	FLOAT_POS_OK,
	FLOAT_NEG_OK,
	FLOAT_EXP_POS_OK,
	FLOAT_EXP_NEG_OK,
};

struct float_parse_state {
	uint64_t dec;
	uint64_t frac;
	uint64_t frac_exp;
	uint64_t exp;
#define FLOAT_FLAG_NEG_RES     (1 << 0)
#define FLOAT_FLAG_NEG_EXP     (1 << 1)
	int flags;
};

/* Keep it sync with enum in .h */
static const char * num_help[] = {
	"UINT8", "UINT16", "UINT32", "UINT64",
	"INT8", "INT16", "INT32", "INT64",
	"SINGLE", "DOUBLE"
};

static inline int
add_to_res(unsigned int c, uint64_t *res, unsigned int base)
{
	/* overflow */
	if ((UINT64_MAX - c) / base < *res)
		return -1;

	*res = (uint64_t) (*res * base + c);
	return 0;
}

static inline int
check_float_result(enum cmdline_numtype res_type, struct float_parse_state *fps,
		void *res)
{
	double dec, frac, exp, result;

	/* extract parts */
	dec = (double) fps->dec;
	frac = (double) fps->frac * pow(10.0, -(double)fps->frac_exp);
	exp = (double) fps->exp;

	/* exponent might be negative */
	if (fps->flags & FLOAT_FLAG_NEG_EXP)
		exp = pow(10.0, -exp);
	else
		exp = pow(10.0, exp);

	/* combine decimal, fractional, and exponent parts */
	result = (dec + frac) * exp;

	/* check for any overflows */
	if (isinf(frac) || isinf(exp) || isinf(result))
		return -1;

	/* result is a valid double */

	/* check if result needs to be negative */
	if (fps->flags & FLOAT_FLAG_NEG_RES)
		result = -result;

	if (res_type == RTE_FLOAT_SINGLE) {
		/* float can overflow from conversion */
		float flt = (float)result;
		if (isinf(flt))
			return -1;
		if (res) *(float *)res = flt;
	} else if (res_type == RTE_FLOAT_DOUBLE) {
		if (res) *(double *)res = result;
	} else {
		return -1;
	}
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

/* parse an int */
RTE_EXPORT_SYMBOL(cmdline_parse_num)
int
cmdline_parse_num(cmdline_parse_token_hdr_t *tk, const char *srcbuf, void *res,
	unsigned ressize)
{
	struct cmdline_token_num_data nd;
	enum num_parse_state_t st = START;
	const char * buf;
	char c;
	uint64_t res1 = 0;
	struct float_parse_state fps = {};

	if (!tk)
		return -1;

	if (!srcbuf || !*srcbuf)
		return -1;

	buf = srcbuf;
	c = *buf;

	memcpy(&nd, &((struct cmdline_token_num *)tk)->num_data, sizeof(nd));

	/* check that we have enough room in res */
	if (res) {
		if (check_res_size(&nd, ressize) < 0)
			return -1;
	}

	while (st != ERROR && c && !cmdline_isendoftoken(c)) {
		debug_printf("%c %x -> ", c, c);
		switch (st) {
		case START:
			if (c == '-') {
				st = DEC_NEG;
			}
			else if (c == '0') {
				st = ZERO_OK;
			}
			else if (c >= '1' && c <= '9') {
				if (add_to_res(c - '0', &res1, 10) < 0)
					st = ERROR;
				else
					st = DEC_POS_OK;
			}
			else  {
				st = ERROR;
			}
			break;

		case ZERO_OK:
			if (c == 'x') {
				st = HEX;
			}
			else if (c == 'b') {
				st = BIN;
			}
			else if (c >= '0' && c <= '7') {
				if (add_to_res(c - '0', &res1, 10) < 0)
					st = ERROR;
				else
					st = OCTAL_OK;
			}
			else if (c == '.') {
				st = FLOAT_POS;
				break;
			}
			else  {
				st = ERROR;
			}
			break;

		case DEC_NEG:
			if (c >= '0' && c <= '9') {
				if (add_to_res(c - '0', &res1, 10) < 0)
					st = ERROR;
				else
					st = DEC_NEG_OK;
			}
			else {
				st = ERROR;
			}
			break;

		case FLOAT_POS:
			if (c >= '0' && c <= '9') {
				if (add_to_res(c - '0', &res1, 10) < 0)
					st = ERROR;
				else {
					st = FLOAT_POS_OK;
					fps.frac_exp++;
				}
			}
			else {
				st = ERROR;
			}
			break;

		case FLOAT_NEG:
			if (c >= '0' && c <= '9') {
				if (add_to_res(c - '0', &res1, 10) < 0)
					st = ERROR;
				else {
					st = FLOAT_NEG_OK;
					fps.frac_exp++;
				}
			}
			else {
				st = ERROR;
			}
			break;

		case FLOAT_EXP:
			if (c >= '0' && c <= '9') {
				if (add_to_res(c - '0', &res1, 10) < 0)
					st = ERROR;
				else
					st = FLOAT_EXP_POS_OK;
			}
			else if (c == '-') {
				st = FLOAT_NEG_EXP;
				fps.flags |= FLOAT_FLAG_NEG_EXP;
			}
			else {
				st = ERROR;
			}
			break;

		case FLOAT_NEG_EXP:
			if (c >= '0' && c <= '9') {
				if (add_to_res(c - '0', &res1, 10) < 0)
					st = ERROR;
				else
					st = FLOAT_EXP_NEG_OK;
			}
			else {
				st = ERROR;
			}
			break;

		case DEC_NEG_OK:
			if (c >= '0' && c <= '9') {
				if (add_to_res(c - '0', &res1, 10) < 0)
					st = ERROR;
			}
			else if (c == '.') {
				fps.dec = res1;
				fps.flags |= FLOAT_FLAG_NEG_RES;
				st = FLOAT_NEG;
				/* erase result */
				res1 = 0;
			} else if (c == 'e' || c == 'E') {
				fps.dec = res1;
				fps.flags |= FLOAT_FLAG_NEG_RES;
				st = FLOAT_EXP;
				/* erase result */
				res1 = 0;
			}
			else {
				st = ERROR;
			}
			break;

		case DEC_POS_OK:
			if (c >= '0' && c <= '9') {
				if (add_to_res(c - '0', &res1, 10) < 0)
					st = ERROR;
			}
			else if (c == '.') {
				fps.dec = res1;
				st = FLOAT_POS;
				/* erase result */
				res1 = 0;
			}
			else if (c == 'e' || c == 'E') {
				fps.dec = res1;
				st = FLOAT_EXP;
				/* erase result */
				res1 = 0;
			}
			else {
				st = ERROR;
			}
			break;

		case FLOAT_POS_OK:
			if (c >= '0' && c <= '9') {
				if (add_to_res(c - '0', &res1, 10) < 0)
					st = ERROR;
				else
					fps.frac_exp++;
			} else if (c == 'e' || c == 'E') {
				fps.frac = res1;
				st = FLOAT_EXP;
				/* erase result */
				res1 = 0;
			} else {
				st = ERROR;
			}
			break;

		case FLOAT_NEG_OK:
			if (c >= '0' && c <= '9') {
				if (add_to_res(c - '0', &res1, 10) < 0)
					st = ERROR;
				else
					fps.frac_exp++;
			} else if (c == 'e' || c == 'E') {
				fps.frac = res1;
				st = FLOAT_EXP;
				/* erase result */
				res1 = 0;
			} else {
				st = ERROR;
			}
			break;

		case FLOAT_EXP_POS_OK:
			/* exponent is always whole */
			if (c >= '0' && c <= '9') {
				if (add_to_res(c - '0', &res1, 10) < 0)
					st = ERROR;
			} else {
				st = ERROR;
			}
			break;

		case FLOAT_EXP_NEG_OK:
			/* exponent is always whole */
			if (c >= '0' && c <= '9') {
				if (add_to_res(c - '0', &res1, 10) < 0)
					st = ERROR;
			} else {
				st = ERROR;
			}
			break;

		case HEX:
			st = HEX_OK;
			/* fall-through */
		case HEX_OK:
			if (c >= '0' && c <= '9') {
				if (add_to_res(c - '0', &res1, 16) < 0)
					st = ERROR;
			}
			else if (c >= 'a' && c <= 'f') {
				if (add_to_res(c - 'a' + 10, &res1, 16) < 0)
					st = ERROR;
			}
			else if (c >= 'A' && c <= 'F') {
				if (add_to_res(c - 'A' + 10, &res1, 16) < 0)
					st = ERROR;
			}
			else {
				st = ERROR;
			}
			break;


		case OCTAL_OK:
			if (c >= '0' && c <= '7') {
				if (add_to_res(c - '0', &res1, 8) < 0)
					st = ERROR;
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
				if (add_to_res(c - '0', &res1, 2) < 0)
					st = ERROR;
			}
			else {
				st = ERROR;
			}
			break;
		default:
			debug_printf("not impl ");

		}

		debug_printf("(%"PRIu64")\n", res1);

		buf ++;
		c = *buf;

		/* token too long */
		if (buf-srcbuf > 127)
			return -1;
	}

	switch (st) {
	case ZERO_OK:
	case DEC_POS_OK:
	case HEX_OK:
	case OCTAL_OK:
	case BIN_OK:
		if (nd.type == RTE_INT8 && res1 <= INT8_MAX) {
			if (res) *(int8_t *)res = (int8_t) res1;
			return buf-srcbuf;
		} else if (nd.type == RTE_INT16 && res1 <= INT16_MAX) {
			if (res) *(int16_t *)res = (int16_t) res1;
			return buf-srcbuf;
		} else if (nd.type == RTE_INT32 && res1 <= INT32_MAX) {
			if (res) *(int32_t *)res = (int32_t) res1;
			return buf-srcbuf;
		} else if (nd.type == RTE_INT64 && res1 <= INT64_MAX) {
			if (res) *(int64_t *)res = (int64_t) res1;
			return buf-srcbuf;
		} else if (nd.type == RTE_UINT8 && res1 <= UINT8_MAX) {
			if (res) *(uint8_t *)res = (uint8_t) res1;
			return buf-srcbuf;
		} else if (nd.type == RTE_UINT16  && res1 <= UINT16_MAX) {
			if (res) *(uint16_t *)res = (uint16_t) res1;
			return buf-srcbuf;
		} else if (nd.type == RTE_UINT32 && res1 <= UINT32_MAX) {
			if (res) *(uint32_t *)res = (uint32_t) res1;
			return buf-srcbuf;
		} else if (nd.type == RTE_UINT64) {
			if (res) *(uint64_t *)res = res1;
			return buf-srcbuf;
		} else if (nd.type == RTE_FLOAT_SINGLE || nd.type == RTE_FLOAT_DOUBLE) {
			/* parsed double from integer */
			fps.dec = res1;
			if (check_float_result(nd.type, &fps, res) < 0)
				return -1;
			return buf-srcbuf;
		} else {
			return -1;
		}
		break;

	case DEC_NEG_OK:
		if (nd.type == RTE_INT8 &&
				res1 <= INT8_MAX + 1) {
			if (res) *(int8_t *)res = (int8_t) (-res1);
			return buf-srcbuf;
		} else if (nd.type == RTE_INT16 &&
				res1 <= (uint16_t)INT16_MAX + 1) {
			if (res) *(int16_t *)res = (int16_t) (-res1);
			return buf-srcbuf;
		} else if (nd.type == RTE_INT32 &&
				res1 <= (uint32_t)INT32_MAX + 1) {
			if (res) *(int32_t *)res = (int32_t) (-res1);
			return buf-srcbuf;
		} else if (nd.type == RTE_INT64 &&
				res1 <= (uint64_t)INT64_MAX + 1) {
			if (res) *(int64_t *)res = (int64_t) (-res1);
			return buf-srcbuf;
		} else if ((nd.type == RTE_FLOAT_SINGLE || nd.type == RTE_FLOAT_DOUBLE) &&
				res1 <= (uint64_t)INT64_MAX + 1) {
			/* parsed double from negative integer */
			fps.dec = res1;
			fps.flags |= FLOAT_FLAG_NEG_RES;
			if (check_float_result(nd.type, &fps, res) < 0)
				return -1;
			return buf-srcbuf;
		} else {
			return -1;
		}
		break;

	case FLOAT_POS_OK:
		if (nd.type == RTE_FLOAT_SINGLE || nd.type == RTE_FLOAT_DOUBLE) {
			fps.frac = res1;

			if (check_float_result(nd.type, &fps, res) < 0)
				return -1;
			return buf-srcbuf;
		} else {
			return -1;
		}
		break;

	case FLOAT_NEG_OK:
		if (nd.type == RTE_FLOAT_SINGLE || nd.type == RTE_FLOAT_DOUBLE) {
			fps.frac = res1;

			if (check_float_result(nd.type, &fps, res) < 0)
				return -1;
			return buf-srcbuf;
		} else {
			return -1;
		}
		break;

	case FLOAT_EXP_POS_OK:
		/* watch for overflow in the exponent */
		if (nd.type == RTE_FLOAT_SINGLE || nd.type == RTE_FLOAT_DOUBLE) {
			fps.exp = res1;

			if (check_float_result(nd.type, &fps, res) < 0)
				return -1;
			return buf-srcbuf;
		} else {
			return -1;
		}
		break;

	case FLOAT_EXP_NEG_OK:
		if (nd.type == RTE_FLOAT_SINGLE || nd.type == RTE_FLOAT_DOUBLE) {
			fps.exp = res1;

			if (check_float_result(nd.type, &fps, res) < 0)
				return -1;
			return buf-srcbuf;
		} else {
			return -1;
		}
		break;
	default:
		debug_printf("error\n");
		return -1;
	}
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

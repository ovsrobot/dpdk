/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Intel Corporation
 */

#include "errno.h"
#include "stdlib.h"
#include "ctype.h"
#include "string.h"
#include "stdbool.h"
#include "stdio.h"

#include <rte_arg_parser.h>
#include <rte_common.h>

#define RTE_ARG_PARSE_TYPE_COREMASK 0
#define RTE_ARG_PARSE_TYPE_CORELIST 1
#define RTE_ARG_PARSE_TYPE_UNKNOWN 2

#define BITS_PER_HEX 4
#define MAX_COREMASK_SIZE ((UINT16_MAX + 1) / BITS_PER_HEX)


struct core_bits {
	uint8_t bits[(UINT16_MAX + 1) / CHAR_BIT];
	uint16_t max_bit_set;
	uint16_t min_bit_set;
	uint32_t total_bits_set;
};


static inline bool
get_core_bit(struct core_bits *mask, uint16_t idx)
{
	return !!(mask->bits[idx / CHAR_BIT] & (1 << (idx % CHAR_BIT)));
}

static inline void
set_core_bit(struct core_bits *mask, uint16_t idx)
{
	if (get_core_bit(mask, idx))
		return;

	mask->bits[idx / CHAR_BIT] |= 1 << (idx % CHAR_BIT);
	/* Update min and max bit if its first time setting a bit */
	if (++(mask->total_bits_set) == 1) {
		mask->min_bit_set = idx;
		mask->max_bit_set = idx;
		return;
	}

	if (idx > mask->max_bit_set)
		mask->max_bit_set = idx;

	if (idx < mask->min_bit_set)
		mask->min_bit_set = idx;
}

static inline uint32_t
corebits_to_array(struct core_bits *mask, uint16_t *cores, size_t max_cores)
{
	uint32_t count = 0;
	for (uint32_t i = mask->min_bit_set; i <= mask->max_bit_set && count < max_cores; i++) {
		if (get_core_bit(mask, i))
			cores[count++] = i;
	}
	return mask->total_bits_set;
}

static int xdigit2val(unsigned char c)
{
	if (isdigit(c))
		return c - '0';
	else if (isupper(c))
		return c - 'A' + 10;
	else
		return c - 'a' + 10;
}

int
rte_arg_parse_corelist(const char *corelist, uint16_t *cores, uint32_t cores_len)
{
	struct core_bits mask = {0};
	int32_t min = -1;
	char *end = NULL;

	min = -1;
	do {
		int64_t idx;
		int32_t max;

		while (isblank(*corelist))
			corelist++;
		if (!isdigit(*corelist))
			return -1;

		errno = 0;
		idx = strtol(corelist, &end, 10);
		if (errno || end == NULL || idx > UINT16_MAX)
			return -1;
		while (isblank(*end))
			end++;
		if (*end == '-')
			min = idx;

		else if (*end == ',' || *end == '\0') {
			if (min == -1)
				min = max = idx;
			else if (min > idx) {
				max = min;
				min = idx;
			} else
				max = idx;

			for (; min <= max; min++)
				set_core_bit(&mask, min);

			min = -1;
		} else
			return -1;
		corelist = end + 1;
	} while (*end != '\0');

	uint32_t total_count = corebits_to_array(&mask, cores, cores_len);

	return total_count;
}

int
rte_arg_parse_coremask(const char *coremask, uint16_t *cores, uint32_t cores_len)
{
	struct core_bits mask = {0};

	/* Remove all blank characters ahead and after .
	 * Remove 0x/0X if exists.
	 */
	while (isblank(*coremask))
		coremask++;
	if (coremask[0] == '0' && ((coremask[1] == 'x') || (coremask[1] == 'X')))
		coremask += 2;

	int32_t i = strlen(coremask);
	while ((i > 0) && isblank(coremask[i - 1]))
		i--;
	if (i == 0 || i > MAX_COREMASK_SIZE)
		return -1;

	uint32_t idx = 0;

	for (i = i - 1; i >= 0; i--) {
		int val;
		char c = coremask[i];

		if (isxdigit(c) == 0)
			return -1;

		val = xdigit2val(c);

		for (uint8_t j = 0; j < BITS_PER_HEX; j++, idx++) {
			if ((1 << j) & val)
				set_core_bit(&mask, idx);
		}
	}

	uint32_t total_count = corebits_to_array(&mask, cores, cores_len);

	return total_count;
}

int
rte_arg_parse_arg_type(const char *core_string)
{
	/* Remove leading whitespace */
	while (isblank(*core_string))
		core_string++;

	/* Check for 0x prefix */
	if (core_string[0] == '0' && tolower(core_string[1]) == 'x') {
		if (core_string[2] != '\0')
			return RTE_ARG_PARSE_TYPE_COREMASK;
		return -1;
	}

	int i = 0, idx = 0;
	/* Check for ',' and '-' and check for A-F */
	do {
		while (isblank(core_string[idx]))
			idx++;

		if (core_string[idx] == ',' || core_string[idx] == '-')
			return RTE_ARG_PARSE_TYPE_CORELIST;

		if (isalpha(core_string[idx])) {
			if (isxdigit(core_string[idx]))
				return RTE_ARG_PARSE_TYPE_COREMASK;
			return -1;
		}
		idx++;
		i++;
	} while (core_string[idx] != '\0');

	/* Check length of core_string if ambiguous as max length of a uint16_t is 5 digits
	 * implying its a coremask.
	 */
	if (i > 5)
		return RTE_ARG_PARSE_TYPE_COREMASK;

	return -1;
}

int
rte_arg_parse_core_string(const char *core_string, uint16_t *cores, uint32_t cores_len,
		int default_type)
{
	if (default_type != RTE_ARG_PARSE_TYPE_COREMASK &&
			default_type != RTE_ARG_PARSE_TYPE_CORELIST) {
		return -1;
	}
	switch (rte_arg_parse_arg_type(core_string)) {
	case RTE_ARG_PARSE_TYPE_COREMASK:
		return rte_arg_parse_coremask(core_string, cores, cores_len);
	case RTE_ARG_PARSE_TYPE_CORELIST:
		return rte_arg_parse_corelist(core_string, cores, cores_len);
	default:
		return default_type == RTE_ARG_PARSE_TYPE_COREMASK ?
			rte_arg_parse_coremask(core_string, cores, cores_len) :
			rte_arg_parse_corelist(core_string, cores, cores_len);
		return -1;
	}
}

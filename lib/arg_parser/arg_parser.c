/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Intel Corporation
 */

#include "errno.h"
#include "stdlib.h"
#include "ctype.h"
#include "string.h"
#include "stdbool.h"

#include <rte_arg_parser.h>
#include <rte_common.h>


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

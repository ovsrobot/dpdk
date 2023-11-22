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

#define BITS_PER_HEX 4
#define MAX_COREMASK_SIZE ((UINT16_MAX+1)/BITS_PER_HEX)


struct core_bits {
	uint8_t bits[(UINT16_MAX + 1)/CHAR_BIT];
	uint16_t max_bit_set;
	uint16_t min_bit_set;
	uint32_t total_bits_set;
};

static inline bool
get_core_bit(struct core_bits *mask, uint16_t idx)
{
	return !!(mask->bits[idx/8] & (1 << (idx % 8)));
}

static inline void
set_core_bit(struct core_bits *mask, uint16_t idx)
{
	if (get_core_bit(mask, idx) == 0) {
		mask->total_bits_set++;

		/* If its the first bit, assign min and max that value */
		if (mask->total_bits_set == 1) {
			mask->min_bit_set = idx;
			mask->max_bit_set = idx;
		}
	}

	mask->bits[idx/8] |= 1 << (idx % 8);

	if (idx > mask->max_bit_set)
		mask->max_bit_set = idx;

	if (idx < mask->min_bit_set)
		mask->min_bit_set = idx;
}

static inline void
corebits_to_array(struct core_bits *mask, uint16_t *cores, size_t max_cores)
{
	uint32_t count = 0;
	for (uint32_t i = mask->min_bit_set; i <= mask->max_bit_set && count < max_cores; i++) {
		if (get_core_bit(mask, i))
			cores[count++] = i;
	}
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
rte_parse_corelist(const char *corelist, uint16_t *cores, uint32_t cores_len)
{
	int32_t min = -1;
	char *end = NULL;

	struct core_bits *mask = malloc(sizeof(struct core_bits));
	memset(mask, 0, sizeof(struct core_bits));

	min = -1;
	do {
		uint32_t idx;
		int32_t max;

		while (isblank(*corelist))
			corelist++;
		if (!isdigit(*corelist))
			return -1;
		errno = 0;
		idx = strtol(corelist, &end, 10);
		if (errno || end == NULL)
			return -1;
		if (idx > UINT16_MAX)
			return -1;
		while (isblank(*end))
			end++;
		if (*end == '-')
			min = idx;

		else if (*end == ',' || *end == '\0') {
			max = idx;
			if (min == -1)
				min = idx;

			/* Swap min and max if min is larger than max */
			if (min > max)
				RTE_SWAP(min, max);

			for (; min <= max; min++)
				set_core_bit(mask, min);

			min = -1;
		} else
			return -1;
		corelist = end + 1;
	} while (*end != '\0');

	corebits_to_array(mask, cores, cores_len);
	uint32_t total_count = mask->total_bits_set;
	free(mask);

	return total_count;
}

int
rte_parse_coremask(const char *coremask, uint16_t *cores, uint32_t cores_len)
{
	struct core_bits *mask = malloc(sizeof(struct core_bits));
	memset(mask, 0, sizeof(struct core_bits));

	/* Remove all blank characters ahead and after .
	 * Remove 0x/0X if exists.
	 */
	while (isblank(*coremask))
		coremask++;
	if (coremask[0] == '0' && ((coremask[1] == 'x')
			|| (coremask[1] == 'X')))
		coremask += 2;

	int32_t i = strlen(coremask);
	while ((i > 0) && isblank(coremask[i - 1]))
		i--;
	if (i == 0 || i > MAX_COREMASK_SIZE)
		return -1;

	uint32_t idx = 0;
	uint8_t j;
	int val;

	for (i = i - 1; i >= 0; i--) {
		char c = coremask[i];

		if (isxdigit(c) == 0)
			return -1;

		val = xdigit2val(c);

		for (j = 0; j < BITS_PER_HEX; j++, idx++) {
			if ((1 << j) & val)
				set_core_bit(mask, idx);
		}
	}

	corebits_to_array(mask, cores, cores_len);
	uint32_t total_count = mask->total_bits_set;
	free(mask);

	return total_count;
}

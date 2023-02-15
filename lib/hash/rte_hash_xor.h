/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Intel Corporation
 */

#ifndef _RTE_HASH_XOR_H_
#define _RTE_HASH_XOR_H_

/**
 * @file
 *
 * RTE XOR Hash
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include <rte_byteorder.h>

#define LEFT8b_MASK rte_cpu_to_be_32(0xff000000)
#define LEFT16b_MASK rte_cpu_to_be_32(0xffff0000)

/**
 * Calculate XOR32 hash on user-supplied byte array.
 *
 * @param data
 *   Data to perform hash on.
 * @param data_len
 *   How many bytes to use to calculate hash value.
 * @param init_val
 *   Value to initialise hash generator.
 * @return
 *   32bit calculated hash value.
 */
static inline uint32_t
rte_hash_xor(const void *data, uint32_t data_len, uint32_t init_val)
{
	unsigned i;
	uintptr_t pd = (uintptr_t) data;
	init_val = rte_cpu_to_be_32(init_val);

	for (i = 0; i < data_len / 4; i++) {
		init_val ^= *(const uint32_t *)pd;
		pd += 4;
	}

	if (data_len & 0x2) {
		init_val ^= *(const uint32_t *)pd & LEFT16b_MASK;
		pd += 2;
	}

	if (data_len & 0x1)
		init_val ^= *(const uint32_t *)pd & LEFT8b_MASK;

	init_val = rte_be_to_cpu_32(init_val);
	return init_val;
}

#ifdef __cplusplus
}
#endif

#endif /* _RTE_HASH_XOR_H_ */

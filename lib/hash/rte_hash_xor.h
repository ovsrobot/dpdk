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
rte_hash_xor32(const void *data, uint32_t data_len, uint32_t init_val)
{
	/* Operate in big endian from here on. */
	/* So we don't need to convert byte orders in the loop. */

	uint64_t hash64 = rte_cpu_to_be_32(init_val);
	const uint8_t *data8 = data;

	uint32_t i;
	for (i = 0; i < data_len / 8; i++) {
		hash64 ^= *(const uint64_t *)data8;
		data8 += 8;
	}

	if (data_len & 0x4) {
		hash64 ^= *(const uint32_t *)data8;
		data8 += 4;
	}

	/* Operate in host endian from here on. */
	/* Because bit shifts only make sense in host endian. */

	uint32_t hash32 = rte_be_to_cpu_32(hash64 ^ (hash64 >> 32));
	uint8_t offset = 0;

	if (data_len & 0x2) {
		hash32 ^= (uint32_t)rte_be_to_cpu_16(*(const uint16_t *)data8) << 16;
		data8 += 2;
		offset += 2;
	}

	if (data_len & 0x1)
		hash32 ^= (uint32_t)(*(const uint8_t *)data8) << (8 * (3 - offset));

	return hash32;
}

#ifdef __cplusplus
}
#endif

#endif /* _RTE_HASH_XOR_H_ */

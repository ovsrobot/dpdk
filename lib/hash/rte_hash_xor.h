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
#include <rte_common.h>

/**
 * The following bytes access helper functions are expected to work
 * without any particular input buffer alignment requirements.
 */

/**
 * @internal
 * Access the next 8 bytes.
 */
static inline uint64_t
rte_hash_access64(const void *data)
{
	uint64_t v;
	memcpy(&v, data, sizeof(v));
	return v;
}

/**
 * @internal
 * Access the next 4 bytes.
 */
static inline uint32_t
rte_hash_access32(const void *data)
{
	uint32_t v;
	memcpy(&v, data, sizeof(v));
	return v;
}

/**
 * @internal
 * Access the next 2 bytes.
 */
static inline uint16_t
rte_hash_access16(const void *data)
{
	uint16_t v;
	memcpy(&v, data, sizeof(v));
	return v;
}

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
	uint32_t hash32 = init_val;
	uint64_t hash64 = 0;

	/* Batch process in 8 bytes for better performance. */
	uint32_t i;
	for (i = 0; i < data_len / 8; i++) {
		hash64 ^= rte_hash_access64(data);
		data = RTE_PTR_ADD(data, 8);
	}

	if (data_len & 0x4) {
		hash64 ^= rte_hash_access32(data);
		data = RTE_PTR_ADD(data, 4);
	}

	/* Deal with remaining (< 4) bytes. */
	uint8_t bit_offset = 0;
	if (data_len & 0x2) {
		hash64 ^= rte_hash_access16(data);
		data = RTE_PTR_ADD(data, 2);
		bit_offset += 16;

	}
	if (data_len & 0x1)
		hash64 ^= (*(const uint8_t *)data) << bit_offset;

	hash32 ^= rte_be_to_cpu_32((uint32_t)hash64 ^ (hash64 >> 32));
	return hash32;
}

#ifdef __cplusplus
}
#endif

#endif /* _RTE_HASH_XOR_H_ */

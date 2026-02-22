/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ByteDance
 */

#ifndef _RTE_CRC_RISCV64_H_
#define _RTE_CRC_RISCV64_H_

#include <stdint.h>

#include <riscv_bitmanip.h>

#include <rte_debug.h>

/*
 * CRC-32C takes a reflected input (bit 7 is the lsb) and produces a reflected
 * output. As reflecting the value we're checksumming is expensive, we instead
 * reflect the polynomial P (0x11EDC6F41) and mu and our CRC32 algorithm.
 *
 * The mu constant is used for a Barrett reduction. It's 2^96 / P (0x11F91CAF6)
 * reflected. Picking 2^96 rather than 2^64 means we can calculate a 64-bit crc
 * using only two multiplications (https://mary.rs/lab/crc32/)
 */
static const uint64_t p = 0x105EC76F1;
static const uint64_t mu = 0x4869EC38DEA713F1UL;

/* Calculate the CRC32C checksum using a Barrett reduction */
static inline uint32_t
crc32c_riscv64(uint64_t data, uint32_t init_val, uint32_t bits)
{
	RTE_ASSERT((bits == 64) || (bits == 32) || (bits == 16) || (bits == 8));

	/* Combine data with the initial value */
	uint64_t crc = (uint64_t)(data ^ init_val) << (64 - bits);

	/*
	 * Multiply by mu, which is 2^96 / P. Division by 2^96 occurs by taking
	 * the lower 64 bits of the result (remember we're inverted)
	 */
	crc = __riscv_clmul_64(crc, mu);
	/* Multiply by P */
	crc = __riscv_clmulh_64(crc, p);

	/* Subtract from original (only needed for smaller sizes) */
	if (bits == 16 || bits == 8)
		crc ^= init_val >> bits;

	return crc;
}

/*
 * Use carryless multiply to perform hash on a value, falling back on the
 * software in case the Zbc extension is not supported
 */
static inline uint32_t
rte_hash_crc_1byte(uint8_t data, uint32_t init_val)
{
	if (likely((rte_hash_crc32_alg & CRC32_RISCV64) != 0))
		return crc32c_riscv64(data, init_val, 8);

	return crc32c_1byte(data, init_val);
}

static inline uint32_t
rte_hash_crc_2byte(uint16_t data, uint32_t init_val)
{
	if (likely((rte_hash_crc32_alg & CRC32_RISCV64) != 0))
		return crc32c_riscv64(data, init_val, 16);

	return crc32c_2bytes(data, init_val);
}

static inline uint32_t
rte_hash_crc_4byte(uint32_t data, uint32_t init_val)
{
	if (likely((rte_hash_crc32_alg & CRC32_RISCV64) != 0))
		return crc32c_riscv64(data, init_val, 32);

	return crc32c_1word(data, init_val);
}

static inline uint32_t
rte_hash_crc_8byte(uint64_t data, uint32_t init_val)
{
	if (likely((rte_hash_crc32_alg & CRC32_RISCV64) != 0))
		return crc32c_riscv64(data, init_val, 64);

	return crc32c_2words(data, init_val);
}

#endif /* _RTE_CRC_RISCV64_H_ */

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2015 Cavium, Inc
 */

#ifndef _HASH_CRC_ARM64_H_
#define _HASH_CRC_ARM64_H_

static inline uint32_t
crc32c_arm64_u8(uint8_t data, uint32_t init_val)
{
	__asm__ volatile(
			"crc32cb %w[crc], %w[crc], %w[value]"
			: [crc] "+r" (init_val)
			: [value] "r" (data));
	return init_val;
}

static inline uint32_t
crc32c_arm64_u16(uint16_t data, uint32_t init_val)
{
	__asm__ volatile(
			"crc32ch %w[crc], %w[crc], %w[value]"
			: [crc] "+r" (init_val)
			: [value] "r" (data));
	return init_val;
}

static inline uint32_t
crc32c_arm64_u32(uint32_t data, uint32_t init_val)
{
	__asm__ volatile(
			"crc32cw %w[crc], %w[crc], %w[value]"
			: [crc] "+r" (init_val)
			: [value] "r" (data));
	return init_val;
}

static inline uint32_t
crc32c_arm64_u64(uint64_t data, uint32_t init_val)
{
	__asm__ volatile(
			"crc32cx %w[crc], %w[crc], %x[value]"
			: [crc] "+r" (init_val)
			: [value] "r" (data));
	return init_val;
}

#endif /* _HASH_CRC_ARM64_H_ */

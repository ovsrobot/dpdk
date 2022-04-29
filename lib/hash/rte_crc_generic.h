/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Marvell.
 */

#ifndef _HASH_CRC_GENERIC_H_
#define _HASH_CRC_GENERIC_H_

/**
 * Software crc32 implementation for 1 byte value.
 *
 * @param data
 *   Data to perform hash on.
 * @param init_val
 *   Value to initialise hash generator.
 * @return
 *   32bit calculated hash value.
 */
static inline uint32_t
rte_hash_crc_1byte(uint8_t data, uint32_t init_val)
{
	return crc32c_1byte(data, init_val);
}

/**
 * Software crc32 implementation for 2 byte value.
 *
 * @param data
 *   Data to perform hash on.
 * @param init_val
 *   Value to initialise hash generator.
 * @return
 *   32bit calculated hash value.
 */
static inline uint32_t
rte_hash_crc_2byte(uint16_t data, uint32_t init_val)
{
	return crc32c_2bytes(data, init_val);
}

/**
 * Software crc32 implementation for 4 byte value.
 *
 * @param data
 *   Data to perform hash on.
 * @param init_val
 *   Value to initialise hash generator.
 * @return
 *   32bit calculated hash value.
 */
static inline uint32_t
rte_hash_crc_4byte(uint32_t data, uint32_t init_val)
{
	return crc32c_1word(data, init_val);
}

/**
 * Software crc32 implementation for 8 byte value.
 *
 * @param data
 *   Data to perform hash on.
 * @param init_val
 *   Value to initialise hash generator.
 * @return
 *   32bit calculated hash value.
 */
static inline uint32_t
rte_hash_crc_8byte(uint64_t data, uint32_t init_val)
{
	return crc32c_2words(data, init_val);
}

#endif

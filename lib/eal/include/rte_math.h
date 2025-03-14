/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2025 Microsoft Corporation
 */

#ifndef _RTE_MATH_H_
#define _RTE_MATH_H_

/**
 * @file
 *
 * Math function definitions for DPDK.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Function that allows performing simple arithmetic operations together with
 * checking whether the operation overflowed.
 * Example of usage:
 *     uint8_t overflow;
 *     uint16_t a, b, result;
 *     a = 1;
 *     b = 2;
 *     overflow = rte_add_overflow(a, b, &result);
 */
#ifdef RTE_TOOLCHAIN_MSVC
#define rte_add_overflow(a, b, res) _Generic((a), \
	uint8_t : _addcarry_u8, \
	uint16_t : _addcarry_u16, \
	uint32_t : _addcarry_u32, \
	uint64_t : _addcarry_u64)(0, a, b, res)
#else
#define rte_add_overflow(a, b, res) _Generic((a), \
	uint8_t : __builtin_add_overflow, \
	uint16_t : __builtin_add_overflow, \
	uint32_t : __builtin_add_overflow, \
	uint64_t : __builtin_add_overflow)(a, b, res)
#endif

#ifdef __cplusplus
}
#endif

#endif

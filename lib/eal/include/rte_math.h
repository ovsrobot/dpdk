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
 * Functions that allow performing simple arithmetic operations together with
 * checking whether the operations overflowed.
 * Example of usage:
 *     uint8_t overflow;
 *     uint16_t a, b, result;
 *     a = 1;
 *     b = 2;
 *     overflow = __rte_add_overflow_u16(a, b, &result);
 */
#ifdef RTE_TOOLCHAIN_MSVC
#define __rte_add_overflow_u8(a, b, res) _addcarry_u8(0, a, b, res)
#define __rte_add_overflow_u16(a, b, res) _addcarry_u16(0, a, b, res)
#define __rte_add_overflow_u32(a, b, res) _addcarry_u32(0, a, b, res)
#else
#define __rte_add_overflow_u8(a, b, res) __builtin_add_overflow(a, b, res)
#define __rte_add_overflow_u16(a, b, res) __builtin_add_overflow(a, b, res)
#define __rte_add_overflow_u32(a, b, res) __builtin_add_overflow(a, b, res)
#endif

#ifdef __cplusplus
}
#endif

#endif

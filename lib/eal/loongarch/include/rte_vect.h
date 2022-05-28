/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Loongson Technology Corporation Limited
 */

#ifndef _RTE_VECT_LOONGARCH_H_
#define _RTE_VECT_LOONGARCH_H_

#include <stdint.h>
#include <sys/param.h>
#include "rte_common.h"
#include "generic/rte_vect.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RTE_VECT_DEFAULT_SIMD_BITWIDTH RTE_VECT_SIMD_256

typedef union xmm {
	int8_t   i8[16];
	int16_t  i16[8];
	int32_t  i32[4];
	int64_t  i64[2];
	uint8_t  u8[16];
	uint16_t u16[8];
	uint32_t u32[4];
	uint64_t u64[2];
	double   pd[2];
} __rte_aligned(16) xmm_t;

#define XMM_SIZE        (sizeof(xmm_t))
#define XMM_MASK        (XMM_SIZE - 1)

typedef union rte_xmm {
	xmm_t x;
	uint8_t  u8[XMM_SIZE / sizeof(uint8_t)];
	uint16_t u16[XMM_SIZE / sizeof(uint16_t)];
	uint32_t u32[XMM_SIZE / sizeof(uint32_t)];
	uint64_t u64[XMM_SIZE / sizeof(uint64_t)];
	double   pd[XMM_SIZE / sizeof(double)];
} __rte_aligned(16) rte_xmm_t;

#ifdef __cplusplus
}
#endif

#endif

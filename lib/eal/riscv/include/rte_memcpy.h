/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 StarFive
 * Copyright(c) 2022 SiFive
 * Copyright(c) 2022 Semihalf
 */

#ifndef RTE_MEMCPY_RISCV_H
#define RTE_MEMCPY_RISCV_H

#include <stdint.h>
#include <string.h>

#include "rte_common.h"
#include <rte_branch_prediction.h>

#include "generic/rte_memcpy.h"

#if defined(RTE_RISCV_FEATURE_V) && !(defined(RTE_RISCV_FEATURE_PREFETCH))
#undef RTE_RISCV_FEATURE_V
#endif

#if defined(RTE_RISCV_FEATURE_V)
#include "rte_cpuflags.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if defined(RTE_RISCV_FEATURE_V)

#define RISCV_VLENB         16
#define MEMCPY_GLIBC        (1U << 0)
#define MEMCPY_RISCV        (1U << 1)
#define ALIGNMENT_MASK_128  0x7F
#define ALIGNMENT_MASK_64   0x3F

static uint8_t memcpy_alg = MEMCPY_GLIBC;


static __rte_always_inline void
memcpy_prefetch64_1(const uint8_t *src, uint8_t *dst)
{
	__asm__ (
		"prefetch.r 64(%0)\n"
		"prefetch.w 64(%1)"
		:: "r"(src), "r"(dst)
	);
}

static __rte_always_inline void
memcpy_prefetch128_1(const uint8_t *src, uint8_t *dst)
{
	__asm__ (
		"prefetch.r 128(%0)\n"
		"prefetch.w 128(%1)"
		:: "r"(src), "r"(dst)
	);
}

static __rte_always_inline void
memcpy_prefetch128_2(const uint8_t *src, uint8_t *dst)
{
	__asm__ (
		"prefetch.r 128(%0);"
		"prefetch.w 128(%1);"
		"prefetch.r 192(%0);"
		"prefetch.w 192(%1)"
		:: "r"(src), "r"(dst)
	);
}


static __rte_always_inline void
_rte_mov32(uint8_t *dst, const uint8_t *src)
{
	uint32_t n = 32;
	asm volatile (
	     "vsetvli t1, %2, e8, m2, ta, ma\n"
	     "vle8.v v2, (%1)\n"
	     "vse8.v v2, (%0)"
	     :: "r"(dst), "r"(src), "r"(n)
	     : "v2", "v3", "t1", "memory"
	 );
}

static __rte_always_inline void
_rte_mov64(uint8_t *dst, const uint8_t *src)
{
	uint32_t n = 64;
	asm volatile (
		"vsetvli t3, %2, e8, m4, ta, ma\n"
		"vle8.v v8, (%1)\n"
		"vse8.v v8, (%0)"
		:: "r"(dst), "r"(src), "r"(n)
		:  "v8", "v9", "v10", "v11", "t3", "memory"
	 );
}

static __rte_always_inline void
_rte_mov128(uint8_t *dst, const uint8_t *src)
{
	uint32_t n = 128;
	asm volatile (
		"vsetvli t4, %2, e8, m8, ta, ma\n"
		"vle8.v v16, (%1)\n"
		"vse8.v v16, (%0)"
		:: "r"(dst), "r"(src), "r"(n)
		: "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "t4", "memory"
	 );
}

static __rte_always_inline void
_rte_mov256(uint8_t *dst, const uint8_t *src)
{
	memcpy_prefetch128_2(src, dst);
	_rte_mov128(dst, src);
	_rte_mov128(dst + 128, src + 128);
}

static __rte_always_inline void
_rte_mov128blocks(uint8_t *dst, const uint8_t *src, size_t n)
{
	asm volatile (
		"prefetch.r 64(%1)\n"
		"prefetch.w 64(%0)\n"
		"prefetch.r 128(%1)\n"
		"prefetch.w 128(%0)\n"
		"prefetch.r 192(%1)\n"
		"prefetch.w 192(%0)\n"
		"prefetch.r 256(%1)\n"
		"prefetch.w 256(%0)\n"
		"prefetch.r 320(%1)\n"
		"prefetch.w 320(%0)\n"
		"prefetch.r 384(%1)\n"
		"prefetch.w 384(%0)\n"
		"prefetch.r 448(%1)\n"
		"prefetch.w 448(%0)\n"
		"prefetch.r 512(%1)\n"
		"li t6, 512\n"
		"3:\n"
		"li t5, 128;"
		"vsetvli zero, t5, e8, m8, ta, ma\n"
		"1:;"
		"bgt %2, t6, 4f\n"
		"j 2f\n"
		"4:\n"
		"prefetch.r 576(%1)\n"
		"prefetch.r 640(%1)\n"
		"2:\n"
		"vle8.v   v16, (%1)\n"
		"add      %1, %1, t5\n"
		"vse8.v   v16, (%0)\n"
		"add      %0, %0, t5\n"
		"sub      %2, %2, t5\n"
		"bnez     %2, 1b"
		: "+r"(dst), "+r"(src), "+r"(n)
		:
		: "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "t5", "t6", "memory"
	);
}

static __rte_always_inline void
_rte_mov(uint8_t *dst, const uint8_t *src, uint32_t n)
{
	asm volatile (
		"1:\n"
		"vsetvli t4, %2, e8, m8, ta, ma\n"
		"vle8.v v16, (%1)\n"
		"add %1, %1, t4\n"
		"vse8.v v16, (%0)\n"
		"add %0, %0, t4\n"
		"sub %2, %2, t4\n"
		"bnez %2, 1b"
		: "+r"(dst), "+r"(src), "+r"(n)
		:
		: "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "t4", "memory"
	 );
}

static __rte_always_inline void
_rte_mov_aligned(uint8_t *dst, const uint8_t *src, uint32_t n)
{
	asm volatile (
		"prefetch.r 128(%1)\n"
		"prefetch.r 192(%1)\n"
		"prefetch.r 256(%1)\n"
		"prefetch.r 320(%1)\n"
		"prefetch.r 384(%1)\n"
		"prefetch.r 448(%1)\n"
		"prefetch.r 512(%1)\n"
		"prefetch.r 576(%1)\n"
		"li t6, 640\n"
		"1:\n"
		"vsetvli t4, %2, e8, m8, ta, ma\n"
		"vle8.v v16, (%1)\n"
		"add %1, %1, t4\n"
		"vse8.v v16, (%0)\n"
		"add %0, %0, t4\n"
		"sub %2, %2, t4\n"
		"blt %2, t6, 3f\n"
		"prefetch.r 512(%1)\n"
		"prefetch.r 576(%1)\n"
		"3:\n"
		"bnez %2, 1b"
		: "+r"(dst), "+r"(src), "+r"(n)
		:
		: "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "t4", "t6", "memory"
	 );
}

static __rte_always_inline void *
_rte_memcpy(uint8_t *dst, const uint8_t *src, size_t n)
{
	void *ret = dst;
	size_t dstofss;
	uint32_t bn;

	if (n <= 384) {
		if (n >= 256) {
			memcpy_prefetch128_2(src, dst);
			n -= 256;
			_rte_mov128(dst, src);
			_rte_mov128((uint8_t *)dst + 128, (const uint8_t *)src + 128);
			src = (const uint8_t *)src + 256;
			dst = (uint8_t *)dst + 256;
		}
		if (n >= 128) {
			memcpy_prefetch128_1(src, dst);
			n -= 128;
			_rte_mov128(dst, src);
			src = (const uint8_t *)src + 128;
			dst = (uint8_t *)dst + 128;
		}

		if (n >= 64) {
			memcpy_prefetch64_1(src, dst);
			n -= 64;
			_rte_mov64(dst, src);
			src = (const uint8_t *)src + 64;
			dst = (uint8_t *)dst + 64;
		}

		if (n > 32) {
			_rte_mov32(dst, src);
			_rte_mov32((uint8_t *)dst - 32 + n,
					(const uint8_t *)src - 32 + n);
			return ret;
		}

		if (n > 0) {
			_rte_mov32((uint8_t *)dst - 32 + n,
					(const uint8_t *)src - 32 + n);
		}
		return ret;
	}

	/**
	 * Make store aligned when copy size exceeds 256 bytes.
	 */
	dstofss = (uintptr_t)dst & ALIGNMENT_MASK_64;
	if (dstofss > 0) {
		dstofss = 64 - dstofss;
		n -= dstofss;
		_rte_mov64(dst, src);
		src = (const uint8_t *)src + dstofss;
		dst = (uint8_t *)dst + dstofss;
	}

	/**
	 * Copy 128-byte blocks
	 */
	if ((uintptr_t)src & ALIGNMENT_MASK_64)	{
		bn = n - (n & ALIGNMENT_MASK_128);
		_rte_mov128blocks(dst, src, bn);
		n = n & ALIGNMENT_MASK_128;
		src = (const uint8_t *)src + bn;
		dst = (uint8_t *)dst + bn;
		_rte_mov(dst, src, n);
	} else
		_rte_mov_aligned(dst, src, n);

	return ret;
}

#endif

/*----------------------api---------------------------------------------------*/
static __rte_always_inline void *
rte_memcpy(void *dst, const void *src, size_t n)
{
#if defined(RTE_RISCV_FEATURE_V)
	if (likely((memcpy_alg == MEMCPY_RISCV) && (n >= 128) && (n < 2048)))
		return _rte_memcpy((uint8_t *)dst, (const uint8_t *)src, n);
#endif
	return memcpy(dst, src, n);
}

static inline void
rte_mov16(uint8_t *dst, const uint8_t *src)
{
	memcpy(dst, src, 16);
}

static inline void
rte_mov32(uint8_t *dst, const uint8_t *src)
{
	memcpy(dst, src, 32);
}

static inline void
rte_mov48(uint8_t *dst, const uint8_t *src)
{
	memcpy(dst, src, 48);
}

static inline void
rte_mov64(uint8_t *dst, const uint8_t *src)
{
	memcpy(dst, src, 64);
}

static inline void
rte_mov128(uint8_t *dst, const uint8_t *src)
{
	memcpy(dst, src, 128);
}

static inline void
rte_mov256(uint8_t *dst, const uint8_t *src)
{
#if defined(RTE_RISCV_FEATURE_V)
	if (likely(memcpy_alg == MEMCPY_RISCV))
		_rte_mov256(dst, src);
	else
#endif
		memcpy(dst, src, 256);
}
/*----------------------------------------------------------------------------*/
#if defined(RTE_RISCV_FEATURE_V)
static inline long
riscv_vlenb(void)
{
	long vlenb;
	asm ("csrr %0, 0xc22" : "=r"(vlenb));
	return vlenb;
}

RTE_INIT(rte_vect_memcpy_init)
{
	long vlenb = riscv_vlenb();
	if (rte_cpu_get_flag_enabled(RTE_CPUFLAG_RISCV_ISA_V) && (vlenb >= RISCV_VLENB))
		memcpy_alg = MEMCPY_RISCV;
}
#endif


#ifdef __cplusplus
}
#endif

#endif /* RTE_MEMCPY_RISCV_H */

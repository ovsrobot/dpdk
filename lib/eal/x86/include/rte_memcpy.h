/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 * Copyright(c) 2022 SmartShare Systems
 */

#ifndef _RTE_MEMCPY_X86_64_H_
#define _RTE_MEMCPY_X86_64_H_

/**
 * @file
 *
 * Functions for SSE/AVX/AVX2/AVX512 implementation of memcpy().
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <rte_vect.h>
#include <rte_common.h>
#include <rte_config.h>
#include <rte_debug.h>

#define RTE_MEMCPY_EX_ARCH_DEFINED
#include "generic/rte_memcpy.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(RTE_TOOLCHAIN_GCC) && (GCC_VERSION >= 100000)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-overflow"
#endif

/**
 * Copy bytes from one location to another. The locations must not overlap.
 *
 * @note This is implemented as a macro, so it's address should not be taken
 * and care is needed as parameter expressions may be evaluated multiple times.
 *
 * @param dst
 *   Pointer to the destination of the data.
 * @param src
 *   Pointer to the source data.
 * @param n
 *   Number of bytes to copy.
 * @return
 *   Pointer to the destination data.
 */
static __rte_always_inline void *
rte_memcpy(void *dst, const void *src, size_t n);

/**
 * Copy bytes from one location to another,
 * locations should not overlap.
 * Use with n <= 15.
 */
static __rte_always_inline void *
rte_mov15_or_less(void *dst, const void *src, size_t n)
{
	/**
	 * Use the following structs to avoid violating C standard
	 * alignment requirements and to avoid strict aliasing bugs
	 */
	struct rte_uint64_alias {
		uint64_t val;
	} __rte_packed __rte_may_alias;
	struct rte_uint32_alias {
		uint32_t val;
	} __rte_packed __rte_may_alias;
	struct rte_uint16_alias {
		uint16_t val;
	} __rte_packed __rte_may_alias;

	void *ret = dst;
	if (n & 8) {
		((struct rte_uint64_alias *)dst)->val =
			((const struct rte_uint64_alias *)src)->val;
		src = (const uint64_t *)src + 1;
		dst = (uint64_t *)dst + 1;
	}
	if (n & 4) {
		((struct rte_uint32_alias *)dst)->val =
			((const struct rte_uint32_alias *)src)->val;
		src = (const uint32_t *)src + 1;
		dst = (uint32_t *)dst + 1;
	}
	if (n & 2) {
		((struct rte_uint16_alias *)dst)->val =
			((const struct rte_uint16_alias *)src)->val;
		src = (const uint16_t *)src + 1;
		dst = (uint16_t *)dst + 1;
	}
	if (n & 1)
		*(uint8_t *)dst = *(const uint8_t *)src;
	return ret;
}

#if defined __AVX512F__ && defined RTE_MEMCPY_AVX512

#define ALIGNMENT_MASK 0x3F

/**
 * AVX512 implementation below
 */

/**
 * Copy 16 bytes from one location to another,
 * locations should not overlap.
 */
static __rte_always_inline void
rte_mov16(uint8_t *dst, const uint8_t *src)
{
	__m128i xmm0;

	xmm0 = _mm_loadu_si128((const __m128i *)src);
	_mm_storeu_si128((__m128i *)dst, xmm0);
}

/**
 * Copy 32 bytes from one location to another,
 * locations should not overlap.
 */
static __rte_always_inline void
rte_mov32(uint8_t *dst, const uint8_t *src)
{
	__m256i ymm0;

	ymm0 = _mm256_loadu_si256((const __m256i *)src);
	_mm256_storeu_si256((__m256i *)dst, ymm0);
}

/**
 * Copy 64 bytes from one location to another,
 * locations should not overlap.
 */
static __rte_always_inline void
rte_mov64(uint8_t *dst, const uint8_t *src)
{
	__m512i zmm0;

	zmm0 = _mm512_loadu_si512((const void *)src);
	_mm512_storeu_si512((void *)dst, zmm0);
}

/**
 * Copy 128 bytes from one location to another,
 * locations should not overlap.
 */
static __rte_always_inline void
rte_mov128(uint8_t *dst, const uint8_t *src)
{
	rte_mov64(dst + 0 * 64, src + 0 * 64);
	rte_mov64(dst + 1 * 64, src + 1 * 64);
}

/**
 * Copy 256 bytes from one location to another,
 * locations should not overlap.
 */
static __rte_always_inline void
rte_mov256(uint8_t *dst, const uint8_t *src)
{
	rte_mov64(dst + 0 * 64, src + 0 * 64);
	rte_mov64(dst + 1 * 64, src + 1 * 64);
	rte_mov64(dst + 2 * 64, src + 2 * 64);
	rte_mov64(dst + 3 * 64, src + 3 * 64);
}

/**
 * Copy 128-byte blocks from one location to another,
 * locations should not overlap.
 */
static __rte_always_inline void
rte_mov128blocks(uint8_t *dst, const uint8_t *src, size_t n)
{
	__m512i zmm0, zmm1;

	while (n >= 128) {
		zmm0 = _mm512_loadu_si512((const void *)(src + 0 * 64));
		n -= 128;
		zmm1 = _mm512_loadu_si512((const void *)(src + 1 * 64));
		src = src + 128;
		_mm512_storeu_si512((void *)(dst + 0 * 64), zmm0);
		_mm512_storeu_si512((void *)(dst + 1 * 64), zmm1);
		dst = dst + 128;
	}
}

/**
 * Copy 512-byte blocks from one location to another,
 * locations should not overlap.
 */
static inline void
rte_mov512blocks(uint8_t *dst, const uint8_t *src, size_t n)
{
	__m512i zmm0, zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7;

	while (n >= 512) {
		zmm0 = _mm512_loadu_si512((const void *)(src + 0 * 64));
		n -= 512;
		zmm1 = _mm512_loadu_si512((const void *)(src + 1 * 64));
		zmm2 = _mm512_loadu_si512((const void *)(src + 2 * 64));
		zmm3 = _mm512_loadu_si512((const void *)(src + 3 * 64));
		zmm4 = _mm512_loadu_si512((const void *)(src + 4 * 64));
		zmm5 = _mm512_loadu_si512((const void *)(src + 5 * 64));
		zmm6 = _mm512_loadu_si512((const void *)(src + 6 * 64));
		zmm7 = _mm512_loadu_si512((const void *)(src + 7 * 64));
		src = src + 512;
		_mm512_storeu_si512((void *)(dst + 0 * 64), zmm0);
		_mm512_storeu_si512((void *)(dst + 1 * 64), zmm1);
		_mm512_storeu_si512((void *)(dst + 2 * 64), zmm2);
		_mm512_storeu_si512((void *)(dst + 3 * 64), zmm3);
		_mm512_storeu_si512((void *)(dst + 4 * 64), zmm4);
		_mm512_storeu_si512((void *)(dst + 5 * 64), zmm5);
		_mm512_storeu_si512((void *)(dst + 6 * 64), zmm6);
		_mm512_storeu_si512((void *)(dst + 7 * 64), zmm7);
		dst = dst + 512;
	}
}

static __rte_always_inline void *
rte_memcpy_generic(void *dst, const void *src, size_t n)
{
	void *ret = dst;
	size_t dstofss;
	size_t bits;

	/**
	 * Copy less than 16 bytes
	 */
	if (n < 16) {
		return rte_mov15_or_less(dst, src, n);
	}

	/**
	 * Fast way when copy size doesn't exceed 512 bytes
	 */
	if (n <= 32) {
		rte_mov16((uint8_t *)dst, (const uint8_t *)src);
		rte_mov16((uint8_t *)dst - 16 + n,
				  (const uint8_t *)src - 16 + n);
		return ret;
	}
	if (n <= 64) {
		rte_mov32((uint8_t *)dst, (const uint8_t *)src);
		rte_mov32((uint8_t *)dst - 32 + n,
				  (const uint8_t *)src - 32 + n);
		return ret;
	}
	if (n <= 512) {
		if (n >= 256) {
			n -= 256;
			rte_mov256((uint8_t *)dst, (const uint8_t *)src);
			src = (const uint8_t *)src + 256;
			dst = (uint8_t *)dst + 256;
		}
		if (n >= 128) {
			n -= 128;
			rte_mov128((uint8_t *)dst, (const uint8_t *)src);
			src = (const uint8_t *)src + 128;
			dst = (uint8_t *)dst + 128;
		}
COPY_BLOCK_128_BACK63:
		if (n > 64) {
			rte_mov64((uint8_t *)dst, (const uint8_t *)src);
			rte_mov64((uint8_t *)dst - 64 + n,
					  (const uint8_t *)src - 64 + n);
			return ret;
		}
		if (n > 0)
			rte_mov64((uint8_t *)dst - 64 + n,
					  (const uint8_t *)src - 64 + n);
		return ret;
	}

	/**
	 * Make store aligned when copy size exceeds 512 bytes
	 */
	dstofss = ((uintptr_t)dst & 0x3F);
	if (dstofss > 0) {
		dstofss = 64 - dstofss;
		n -= dstofss;
		rte_mov64((uint8_t *)dst, (const uint8_t *)src);
		src = (const uint8_t *)src + dstofss;
		dst = (uint8_t *)dst + dstofss;
	}

	/**
	 * Copy 512-byte blocks.
	 * Use copy block function for better instruction order control,
	 * which is important when load is unaligned.
	 */
	rte_mov512blocks((uint8_t *)dst, (const uint8_t *)src, n);
	bits = n;
	n = n & 511;
	bits -= n;
	src = (const uint8_t *)src + bits;
	dst = (uint8_t *)dst + bits;

	/**
	 * Copy 128-byte blocks.
	 * Use copy block function for better instruction order control,
	 * which is important when load is unaligned.
	 */
	if (n >= 128) {
		rte_mov128blocks((uint8_t *)dst, (const uint8_t *)src, n);
		bits = n;
		n = n & 127;
		bits -= n;
		src = (const uint8_t *)src + bits;
		dst = (uint8_t *)dst + bits;
	}

	/**
	 * Copy whatever left
	 */
	goto COPY_BLOCK_128_BACK63;
}

#elif defined __AVX2__

#define ALIGNMENT_MASK 0x1F

/**
 * AVX2 implementation below
 */

/**
 * Copy 16 bytes from one location to another,
 * locations should not overlap.
 */
static __rte_always_inline void
rte_mov16(uint8_t *dst, const uint8_t *src)
{
	__m128i xmm0;

	xmm0 = _mm_loadu_si128((const __m128i *)(const void *)src);
	_mm_storeu_si128((__m128i *)(void *)dst, xmm0);
}

/**
 * Copy 32 bytes from one location to another,
 * locations should not overlap.
 */
static __rte_always_inline void
rte_mov32(uint8_t *dst, const uint8_t *src)
{
	__m256i ymm0;

	ymm0 = _mm256_loadu_si256((const __m256i *)(const void *)src);
	_mm256_storeu_si256((__m256i *)(void *)dst, ymm0);
}

/**
 * Copy 64 bytes from one location to another,
 * locations should not overlap.
 */
static __rte_always_inline void
rte_mov64(uint8_t *dst, const uint8_t *src)
{
	rte_mov32((uint8_t *)dst + 0 * 32, (const uint8_t *)src + 0 * 32);
	rte_mov32((uint8_t *)dst + 1 * 32, (const uint8_t *)src + 1 * 32);
}

/**
 * Copy 128 bytes from one location to another,
 * locations should not overlap.
 */
static __rte_always_inline void
rte_mov128(uint8_t *dst, const uint8_t *src)
{
	rte_mov32((uint8_t *)dst + 0 * 32, (const uint8_t *)src + 0 * 32);
	rte_mov32((uint8_t *)dst + 1 * 32, (const uint8_t *)src + 1 * 32);
	rte_mov32((uint8_t *)dst + 2 * 32, (const uint8_t *)src + 2 * 32);
	rte_mov32((uint8_t *)dst + 3 * 32, (const uint8_t *)src + 3 * 32);
}

/**
 * Copy 256 bytes from one location to another,
 * locations should not overlap.
 */
static __rte_always_inline void
rte_mov256(uint8_t *dst, const uint8_t *src)
{
	rte_mov32((uint8_t *)dst + 0 * 32, (const uint8_t *)src + 0 * 32);
	rte_mov32((uint8_t *)dst + 1 * 32, (const uint8_t *)src + 1 * 32);
	rte_mov32((uint8_t *)dst + 2 * 32, (const uint8_t *)src + 2 * 32);
	rte_mov32((uint8_t *)dst + 3 * 32, (const uint8_t *)src + 3 * 32);
	rte_mov32((uint8_t *)dst + 4 * 32, (const uint8_t *)src + 4 * 32);
	rte_mov32((uint8_t *)dst + 5 * 32, (const uint8_t *)src + 5 * 32);
	rte_mov32((uint8_t *)dst + 6 * 32, (const uint8_t *)src + 6 * 32);
	rte_mov32((uint8_t *)dst + 7 * 32, (const uint8_t *)src + 7 * 32);
}

/**
 * Copy 128-byte blocks from one location to another,
 * locations should not overlap.
 */
static __rte_always_inline void
rte_mov128blocks(uint8_t *dst, const uint8_t *src, size_t n)
{
	__m256i ymm0, ymm1, ymm2, ymm3;

	while (n >= 128) {
		ymm0 = _mm256_loadu_si256((const __m256i *)(const void *)
					  ((const uint8_t *)src + 0 * 32));
		n -= 128;
		ymm1 = _mm256_loadu_si256((const __m256i *)(const void *)
					  ((const uint8_t *)src + 1 * 32));
		ymm2 = _mm256_loadu_si256((const __m256i *)(const void *)
					  ((const uint8_t *)src + 2 * 32));
		ymm3 = _mm256_loadu_si256((const __m256i *)(const void *)
					  ((const uint8_t *)src + 3 * 32));
		src = (const uint8_t *)src + 128;
		_mm256_storeu_si256((__m256i *)(void *)
				    ((uint8_t *)dst + 0 * 32), ymm0);
		_mm256_storeu_si256((__m256i *)(void *)
				    ((uint8_t *)dst + 1 * 32), ymm1);
		_mm256_storeu_si256((__m256i *)(void *)
				    ((uint8_t *)dst + 2 * 32), ymm2);
		_mm256_storeu_si256((__m256i *)(void *)
				    ((uint8_t *)dst + 3 * 32), ymm3);
		dst = (uint8_t *)dst + 128;
	}
}

static __rte_always_inline void *
rte_memcpy_generic(void *dst, const void *src, size_t n)
{
	void *ret = dst;
	size_t dstofss;
	size_t bits;

	/**
	 * Copy less than 16 bytes
	 */
	if (n < 16) {
		return rte_mov15_or_less(dst, src, n);
	}

	/**
	 * Fast way when copy size doesn't exceed 256 bytes
	 */
	if (n <= 32) {
		rte_mov16((uint8_t *)dst, (const uint8_t *)src);
		rte_mov16((uint8_t *)dst - 16 + n,
				(const uint8_t *)src - 16 + n);
		return ret;
	}
	if (n <= 48) {
		rte_mov16((uint8_t *)dst, (const uint8_t *)src);
		rte_mov16((uint8_t *)dst + 16, (const uint8_t *)src + 16);
		rte_mov16((uint8_t *)dst - 16 + n,
				(const uint8_t *)src - 16 + n);
		return ret;
	}
	if (n <= 64) {
		rte_mov32((uint8_t *)dst, (const uint8_t *)src);
		rte_mov32((uint8_t *)dst - 32 + n,
				(const uint8_t *)src - 32 + n);
		return ret;
	}
	if (n <= 256) {
		if (n >= 128) {
			n -= 128;
			rte_mov128((uint8_t *)dst, (const uint8_t *)src);
			src = (const uint8_t *)src + 128;
			dst = (uint8_t *)dst + 128;
		}
COPY_BLOCK_128_BACK31:
		if (n >= 64) {
			n -= 64;
			rte_mov64((uint8_t *)dst, (const uint8_t *)src);
			src = (const uint8_t *)src + 64;
			dst = (uint8_t *)dst + 64;
		}
		if (n > 32) {
			rte_mov32((uint8_t *)dst, (const uint8_t *)src);
			rte_mov32((uint8_t *)dst - 32 + n,
					(const uint8_t *)src - 32 + n);
			return ret;
		}
		if (n > 0) {
			rte_mov32((uint8_t *)dst - 32 + n,
					(const uint8_t *)src - 32 + n);
		}
		return ret;
	}

	/**
	 * Make store aligned when copy size exceeds 256 bytes
	 */
	dstofss = (uintptr_t)dst & 0x1F;
	if (dstofss > 0) {
		dstofss = 32 - dstofss;
		n -= dstofss;
		rte_mov32((uint8_t *)dst, (const uint8_t *)src);
		src = (const uint8_t *)src + dstofss;
		dst = (uint8_t *)dst + dstofss;
	}

	/**
	 * Copy 128-byte blocks
	 */
	rte_mov128blocks((uint8_t *)dst, (const uint8_t *)src, n);
	bits = n;
	n = n & 127;
	bits -= n;
	src = (const uint8_t *)src + bits;
	dst = (uint8_t *)dst + bits;

	/**
	 * Copy whatever left
	 */
	goto COPY_BLOCK_128_BACK31;
}

#else /* __AVX512F__ */

#define ALIGNMENT_MASK 0x0F

/**
 * SSE & AVX implementation below
 */

/**
 * Copy 16 bytes from one location to another,
 * locations should not overlap.
 */
static __rte_always_inline void
rte_mov16(uint8_t *dst, const uint8_t *src)
{
	__m128i xmm0;

	xmm0 = _mm_loadu_si128((const __m128i *)(const void *)src);
	_mm_storeu_si128((__m128i *)(void *)dst, xmm0);
}

/**
 * Copy 32 bytes from one location to another,
 * locations should not overlap.
 */
static __rte_always_inline void
rte_mov32(uint8_t *dst, const uint8_t *src)
{
	rte_mov16((uint8_t *)dst + 0 * 16, (const uint8_t *)src + 0 * 16);
	rte_mov16((uint8_t *)dst + 1 * 16, (const uint8_t *)src + 1 * 16);
}

/**
 * Copy 64 bytes from one location to another,
 * locations should not overlap.
 */
static __rte_always_inline void
rte_mov64(uint8_t *dst, const uint8_t *src)
{
	rte_mov16((uint8_t *)dst + 0 * 16, (const uint8_t *)src + 0 * 16);
	rte_mov16((uint8_t *)dst + 1 * 16, (const uint8_t *)src + 1 * 16);
	rte_mov16((uint8_t *)dst + 2 * 16, (const uint8_t *)src + 2 * 16);
	rte_mov16((uint8_t *)dst + 3 * 16, (const uint8_t *)src + 3 * 16);
}

/**
 * Copy 128 bytes from one location to another,
 * locations should not overlap.
 */
static __rte_always_inline void
rte_mov128(uint8_t *dst, const uint8_t *src)
{
	rte_mov16((uint8_t *)dst + 0 * 16, (const uint8_t *)src + 0 * 16);
	rte_mov16((uint8_t *)dst + 1 * 16, (const uint8_t *)src + 1 * 16);
	rte_mov16((uint8_t *)dst + 2 * 16, (const uint8_t *)src + 2 * 16);
	rte_mov16((uint8_t *)dst + 3 * 16, (const uint8_t *)src + 3 * 16);
	rte_mov16((uint8_t *)dst + 4 * 16, (const uint8_t *)src + 4 * 16);
	rte_mov16((uint8_t *)dst + 5 * 16, (const uint8_t *)src + 5 * 16);
	rte_mov16((uint8_t *)dst + 6 * 16, (const uint8_t *)src + 6 * 16);
	rte_mov16((uint8_t *)dst + 7 * 16, (const uint8_t *)src + 7 * 16);
}

/**
 * Copy 256 bytes from one location to another,
 * locations should not overlap.
 */
static inline void
rte_mov256(uint8_t *dst, const uint8_t *src)
{
	rte_mov16((uint8_t *)dst + 0 * 16, (const uint8_t *)src + 0 * 16);
	rte_mov16((uint8_t *)dst + 1 * 16, (const uint8_t *)src + 1 * 16);
	rte_mov16((uint8_t *)dst + 2 * 16, (const uint8_t *)src + 2 * 16);
	rte_mov16((uint8_t *)dst + 3 * 16, (const uint8_t *)src + 3 * 16);
	rte_mov16((uint8_t *)dst + 4 * 16, (const uint8_t *)src + 4 * 16);
	rte_mov16((uint8_t *)dst + 5 * 16, (const uint8_t *)src + 5 * 16);
	rte_mov16((uint8_t *)dst + 6 * 16, (const uint8_t *)src + 6 * 16);
	rte_mov16((uint8_t *)dst + 7 * 16, (const uint8_t *)src + 7 * 16);
	rte_mov16((uint8_t *)dst + 8 * 16, (const uint8_t *)src + 8 * 16);
	rte_mov16((uint8_t *)dst + 9 * 16, (const uint8_t *)src + 9 * 16);
	rte_mov16((uint8_t *)dst + 10 * 16, (const uint8_t *)src + 10 * 16);
	rte_mov16((uint8_t *)dst + 11 * 16, (const uint8_t *)src + 11 * 16);
	rte_mov16((uint8_t *)dst + 12 * 16, (const uint8_t *)src + 12 * 16);
	rte_mov16((uint8_t *)dst + 13 * 16, (const uint8_t *)src + 13 * 16);
	rte_mov16((uint8_t *)dst + 14 * 16, (const uint8_t *)src + 14 * 16);
	rte_mov16((uint8_t *)dst + 15 * 16, (const uint8_t *)src + 15 * 16);
}

/**
 * Macro for copying unaligned block from one location to another with constant load offset,
 * 47 bytes leftover maximum,
 * locations should not overlap.
 * Requirements:
 * - Store is aligned
 * - Load offset is <offset>, which must be immediate value within [1, 15]
 * - For <src>, make sure <offset> bit backwards & <16 - offset> bit forwards are available for loading
 * - <dst>, <src>, <len> must be variables
 * - __m128i <xmm0> ~ <xmm8> must be pre-defined
 */
#define MOVEUNALIGNED_LEFT47_IMM(dst, src, len, offset)                                                     \
__extension__ ({                                                                                            \
    size_t tmp;                                                                                                \
    while (len >= 128 + 16 - offset) {                                                                      \
        xmm0 = _mm_loadu_si128((const __m128i *)(const void *)((const uint8_t *)src - offset + 0 * 16));                  \
        len -= 128;                                                                                         \
        xmm1 = _mm_loadu_si128((const __m128i *)(const void *)((const uint8_t *)src - offset + 1 * 16));                  \
        xmm2 = _mm_loadu_si128((const __m128i *)(const void *)((const uint8_t *)src - offset + 2 * 16));                  \
        xmm3 = _mm_loadu_si128((const __m128i *)(const void *)((const uint8_t *)src - offset + 3 * 16));                  \
        xmm4 = _mm_loadu_si128((const __m128i *)(const void *)((const uint8_t *)src - offset + 4 * 16));                  \
        xmm5 = _mm_loadu_si128((const __m128i *)(const void *)((const uint8_t *)src - offset + 5 * 16));                  \
        xmm6 = _mm_loadu_si128((const __m128i *)(const void *)((const uint8_t *)src - offset + 6 * 16));                  \
        xmm7 = _mm_loadu_si128((const __m128i *)(const void *)((const uint8_t *)src - offset + 7 * 16));                  \
        xmm8 = _mm_loadu_si128((const __m128i *)(const void *)((const uint8_t *)src - offset + 8 * 16));                  \
        src = (const uint8_t *)src + 128;                                                                   \
        _mm_storeu_si128((__m128i *)(void *)((uint8_t *)dst + 0 * 16), _mm_alignr_epi8(xmm1, xmm0, offset));        \
        _mm_storeu_si128((__m128i *)(void *)((uint8_t *)dst + 1 * 16), _mm_alignr_epi8(xmm2, xmm1, offset));        \
        _mm_storeu_si128((__m128i *)(void *)((uint8_t *)dst + 2 * 16), _mm_alignr_epi8(xmm3, xmm2, offset));        \
        _mm_storeu_si128((__m128i *)(void *)((uint8_t *)dst + 3 * 16), _mm_alignr_epi8(xmm4, xmm3, offset));        \
        _mm_storeu_si128((__m128i *)(void *)((uint8_t *)dst + 4 * 16), _mm_alignr_epi8(xmm5, xmm4, offset));        \
        _mm_storeu_si128((__m128i *)(void *)((uint8_t *)dst + 5 * 16), _mm_alignr_epi8(xmm6, xmm5, offset));        \
        _mm_storeu_si128((__m128i *)(void *)((uint8_t *)dst + 6 * 16), _mm_alignr_epi8(xmm7, xmm6, offset));        \
        _mm_storeu_si128((__m128i *)(void *)((uint8_t *)dst + 7 * 16), _mm_alignr_epi8(xmm8, xmm7, offset));        \
        dst = (uint8_t *)dst + 128;                                                                         \
    }                                                                                                       \
    tmp = len;                                                                                              \
    len = ((len - 16 + offset) & 127) + 16 - offset;                                                        \
    tmp -= len;                                                                                             \
    src = (const uint8_t *)src + tmp;                                                                       \
    dst = (uint8_t *)dst + tmp;                                                                             \
    if (len >= 32 + 16 - offset) {                                                                          \
        while (len >= 32 + 16 - offset) {                                                                   \
            xmm0 = _mm_loadu_si128((const __m128i *)(const void *)((const uint8_t *)src - offset + 0 * 16));              \
            len -= 32;                                                                                      \
            xmm1 = _mm_loadu_si128((const __m128i *)(const void *)((const uint8_t *)src - offset + 1 * 16));              \
            xmm2 = _mm_loadu_si128((const __m128i *)(const void *)((const uint8_t *)src - offset + 2 * 16));              \
            src = (const uint8_t *)src + 32;                                                                \
            _mm_storeu_si128((__m128i *)(void *)((uint8_t *)dst + 0 * 16), _mm_alignr_epi8(xmm1, xmm0, offset));    \
            _mm_storeu_si128((__m128i *)(void *)((uint8_t *)dst + 1 * 16), _mm_alignr_epi8(xmm2, xmm1, offset));    \
            dst = (uint8_t *)dst + 32;                                                                      \
        }                                                                                                   \
        tmp = len;                                                                                          \
        len = ((len - 16 + offset) & 31) + 16 - offset;                                                     \
        tmp -= len;                                                                                         \
        src = (const uint8_t *)src + tmp;                                                                   \
        dst = (uint8_t *)dst + tmp;                                                                         \
    }                                                                                                       \
})

/**
 * Macro for copying unaligned block from one location to another,
 * 47 bytes leftover maximum,
 * locations should not overlap.
 * Use switch here because the aligning instruction requires immediate value for shift count.
 * Requirements:
 * - Store is aligned
 * - Load offset is <offset>, which must be within [1, 15]
 * - For <src>, make sure <offset> bit backwards & <16 - offset> bit forwards are available for loading
 * - <dst>, <src>, <len> must be variables
 * - __m128i <xmm0> ~ <xmm8> used in MOVEUNALIGNED_LEFT47_IMM must be pre-defined
 */
#define MOVEUNALIGNED_LEFT47(dst, src, len, offset)                   \
__extension__ ({                                                      \
    switch (offset) {                                                 \
    case 0x01: MOVEUNALIGNED_LEFT47_IMM(dst, src, n, 0x01); break;    \
    case 0x02: MOVEUNALIGNED_LEFT47_IMM(dst, src, n, 0x02); break;    \
    case 0x03: MOVEUNALIGNED_LEFT47_IMM(dst, src, n, 0x03); break;    \
    case 0x04: MOVEUNALIGNED_LEFT47_IMM(dst, src, n, 0x04); break;    \
    case 0x05: MOVEUNALIGNED_LEFT47_IMM(dst, src, n, 0x05); break;    \
    case 0x06: MOVEUNALIGNED_LEFT47_IMM(dst, src, n, 0x06); break;    \
    case 0x07: MOVEUNALIGNED_LEFT47_IMM(dst, src, n, 0x07); break;    \
    case 0x08: MOVEUNALIGNED_LEFT47_IMM(dst, src, n, 0x08); break;    \
    case 0x09: MOVEUNALIGNED_LEFT47_IMM(dst, src, n, 0x09); break;    \
    case 0x0A: MOVEUNALIGNED_LEFT47_IMM(dst, src, n, 0x0A); break;    \
    case 0x0B: MOVEUNALIGNED_LEFT47_IMM(dst, src, n, 0x0B); break;    \
    case 0x0C: MOVEUNALIGNED_LEFT47_IMM(dst, src, n, 0x0C); break;    \
    case 0x0D: MOVEUNALIGNED_LEFT47_IMM(dst, src, n, 0x0D); break;    \
    case 0x0E: MOVEUNALIGNED_LEFT47_IMM(dst, src, n, 0x0E); break;    \
    case 0x0F: MOVEUNALIGNED_LEFT47_IMM(dst, src, n, 0x0F); break;    \
    default:;                                                         \
    }                                                                 \
})

static __rte_always_inline void *
rte_memcpy_generic(void *dst, const void *src, size_t n)
{
	__m128i xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8;
	void *ret = dst;
	size_t dstofss;
	size_t srcofs;

	/**
	 * Copy less than 16 bytes
	 */
	if (n < 16) {
		return rte_mov15_or_less(dst, src, n);
	}

	/**
	 * Fast way when copy size doesn't exceed 512 bytes
	 */
	if (n <= 32) {
		rte_mov16((uint8_t *)dst, (const uint8_t *)src);
		rte_mov16((uint8_t *)dst - 16 + n, (const uint8_t *)src - 16 + n);
		return ret;
	}
	if (n <= 48) {
		rte_mov32((uint8_t *)dst, (const uint8_t *)src);
		rte_mov16((uint8_t *)dst - 16 + n, (const uint8_t *)src - 16 + n);
		return ret;
	}
	if (n <= 64) {
		rte_mov32((uint8_t *)dst, (const uint8_t *)src);
		rte_mov16((uint8_t *)dst + 32, (const uint8_t *)src + 32);
		rte_mov16((uint8_t *)dst - 16 + n, (const uint8_t *)src - 16 + n);
		return ret;
	}
	if (n <= 128) {
		goto COPY_BLOCK_128_BACK15;
	}
	if (n <= 512) {
		if (n >= 256) {
			n -= 256;
			rte_mov128((uint8_t *)dst, (const uint8_t *)src);
			rte_mov128((uint8_t *)dst + 128, (const uint8_t *)src + 128);
			src = (const uint8_t *)src + 256;
			dst = (uint8_t *)dst + 256;
		}
COPY_BLOCK_255_BACK15:
		if (n >= 128) {
			n -= 128;
			rte_mov128((uint8_t *)dst, (const uint8_t *)src);
			src = (const uint8_t *)src + 128;
			dst = (uint8_t *)dst + 128;
		}
COPY_BLOCK_128_BACK15:
		if (n >= 64) {
			n -= 64;
			rte_mov64((uint8_t *)dst, (const uint8_t *)src);
			src = (const uint8_t *)src + 64;
			dst = (uint8_t *)dst + 64;
		}
COPY_BLOCK_64_BACK15:
		if (n >= 32) {
			n -= 32;
			rte_mov32((uint8_t *)dst, (const uint8_t *)src);
			src = (const uint8_t *)src + 32;
			dst = (uint8_t *)dst + 32;
		}
		if (n > 16) {
			rte_mov16((uint8_t *)dst, (const uint8_t *)src);
			rte_mov16((uint8_t *)dst - 16 + n, (const uint8_t *)src - 16 + n);
			return ret;
		}
		if (n > 0) {
			rte_mov16((uint8_t *)dst - 16 + n, (const uint8_t *)src - 16 + n);
		}
		return ret;
	}

	/**
	 * Make store aligned when copy size exceeds 512 bytes,
	 * and make sure the first 15 bytes are copied, because
	 * unaligned copy functions require up to 15 bytes
	 * backwards access.
	 */
	dstofss = (uintptr_t)dst & 0x0F;
	if (dstofss > 0) {
		dstofss = 16 - dstofss + 16;
		n -= dstofss;
		rte_mov32((uint8_t *)dst, (const uint8_t *)src);
		src = (const uint8_t *)src + dstofss;
		dst = (uint8_t *)dst + dstofss;
	}
	srcofs = ((uintptr_t)src & 0x0F);

	/**
	 * For aligned copy
	 */
	if (srcofs == 0) {
		/**
		 * Copy 256-byte blocks
		 */
		for (; n >= 256; n -= 256) {
			rte_mov256((uint8_t *)dst, (const uint8_t *)src);
			dst = (uint8_t *)dst + 256;
			src = (const uint8_t *)src + 256;
		}

		/**
		 * Copy whatever left
		 */
		goto COPY_BLOCK_255_BACK15;
	}

	/**
	 * For copy with unaligned load
	 */
	MOVEUNALIGNED_LEFT47(dst, src, n, srcofs);

	/**
	 * Copy whatever left
	 */
	goto COPY_BLOCK_64_BACK15;
}

#endif /* __AVX512F__ */

static __rte_always_inline void *
rte_memcpy_aligned(void *dst, const void *src, size_t n)
{
	void *ret = dst;

	/* Copy size < 16 bytes */
	if (n < 16) {
		return rte_mov15_or_less(dst, src, n);
	}

	/* Copy 16 <= size <= 32 bytes */
	if (n <= 32) {
		rte_mov16((uint8_t *)dst, (const uint8_t *)src);
		rte_mov16((uint8_t *)dst - 16 + n,
				(const uint8_t *)src - 16 + n);

		return ret;
	}

	/* Copy 32 < size <= 64 bytes */
	if (n <= 64) {
		rte_mov32((uint8_t *)dst, (const uint8_t *)src);
		rte_mov32((uint8_t *)dst - 32 + n,
				(const uint8_t *)src - 32 + n);

		return ret;
	}

	/* Copy 64 bytes blocks */
	for (; n >= 64; n -= 64) {
		rte_mov64((uint8_t *)dst, (const uint8_t *)src);
		dst = (uint8_t *)dst + 64;
		src = (const uint8_t *)src + 64;
	}

	/* Copy whatever left */
	rte_mov64((uint8_t *)dst - 64 + n,
			(const uint8_t *)src - 64 + n);

	return ret;
}

static __rte_always_inline void *
rte_memcpy(void *dst, const void *src, size_t n)
{
	if (!(((uintptr_t)dst | (uintptr_t)src) & ALIGNMENT_MASK))
		return rte_memcpy_aligned(dst, src, n);
	else
		return rte_memcpy_generic(dst, src, n);
}

/*
 * Advanced/Non-Temporal Memory Operations.
 */

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Workaround for _mm_stream_load_si128() missing const in the parameter.
 */
__rte_experimental
static __rte_always_inline
__m128i _mm_stream_load_si128_const(const __m128i *const mem_addr)
{
	/* GCC 4.5.8 (in RHEL7) doesn't support the #pragma to ignore "-Wdiscarded-qualifiers".
	 * So we explicitly type cast mem_addr and use the #pragma to ignore "-Wcast-qual".
	 */
#if defined(RTE_TOOLCHAIN_GCC)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
#elif defined(RTE_TOOLCHAIN_CLANG)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-qual"
#endif
	return _mm_stream_load_si128((__m128i *)mem_addr);
#if defined(RTE_TOOLCHAIN_GCC)
#pragma GCC diagnostic pop
#elif defined(RTE_TOOLCHAIN_CLANG)
#pragma clang diagnostic pop
#endif
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Memory copy from non-temporal source area.
 *
 * @note
 * Performance is optimal when source pointer is 16 byte aligned.
 *
 * @param dst
 *   Pointer to the destination memory area.
 * @param src
 *   Pointer to the non-temporal source memory area.
 * @param len
 *   Number of bytes to copy.
 * @param flags
 *   Hints for memory access.
 *   Any of the RTE_MEMOPS_F_(LEN|SRC)nnnA flags.
 *   The RTE_MEMOPS_F_SRC_NT flag must be set.
 *   The RTE_MEMOPS_F_DST_NT flag must be clear.
 *   The RTE_MEMOPS_F_DSTnnnA flags are ignored.
 *   Must be constant at build time.
 */
__rte_experimental
static __rte_always_inline
__attribute__((__nonnull__(1, 2)))
#if defined(RTE_TOOLCHAIN_GCC) && (GCC_VERSION >= 100000)
__attribute__((__access__(write_only, 1, 3), __access__(read_only, 2, 3)))
#endif
void rte_memcpy_nts(void *__rte_restrict dst, const void *__rte_restrict src, size_t len,
		const uint64_t flags)
{
	register __m128i    xmm0, xmm1, xmm2, xmm3;

#ifndef RTE_TOOLCHAIN_CLANG /* Clang doesn't support using __builtin_constant_p() like this. */
	RTE_BUILD_BUG_ON(!__builtin_constant_p(flags));
#endif /* !RTE_TOOLCHAIN_CLANG */
	RTE_ASSERT(!(flags & RTE_MEMOPS_F_SRCA_MASK) || rte_is_aligned(src,
			(flags & RTE_MEMOPS_F_SRCA_MASK) >> RTE_MEMOPS_F_SRCA_SHIFT));
	RTE_ASSERT(!(flags & RTE_MEMOPS_F_LENA_MASK) || (len &
			((flags & RTE_MEMOPS_F_LENA_MASK) >> RTE_MEMOPS_F_LENA_SHIFT) - 1) == 0);

	RTE_ASSERT((flags & (RTE_MEMOPS_F_SRC_NT | RTE_MEMOPS_F_DST_NT)) == RTE_MEMOPS_F_SRC_NT);

	if (unlikely(len == 0))
		return;

	/* If source is not 16 byte aligned, then copy first part of data via bounce buffer,
	 * to achieve 16 byte alignment of source pointer.
	 * This invalidates the source, destination and length alignment flags, and
	 * potentially makes the destination pointer unaligned.
	 *
	 * Omitted if source is known to be 16 byte aligned.
	 */
	if (!((flags & RTE_MEMOPS_F_SRCA_MASK) >= RTE_MEMOPS_F_SRC16A)) {
		/* Source is not known to be 16 byte aligned, but might be. */
		/** How many bytes is source offset from 16 byte alignment (floor rounding). */
		const size_t    offset = (uintptr_t)src & 15;

		if (offset) {
			/* Source is not 16 byte aligned. */
			char            buffer[16] __rte_aligned(16);
			/** How many bytes is source away from 16 byte alignment
			 * (ceiling rounding).
			 */
			const size_t    first = 16 - offset;

			xmm0 = _mm_stream_load_si128_const(RTE_PTR_SUB(src, offset));
			_mm_store_si128((void *)buffer, xmm0);

			/* Test for short length.
			 *
			 * Omitted if length is known to be >= 16.
			 */
			if (!(__builtin_constant_p(len) && len >= 16) &&
					unlikely(len <= first)) {
				/* Short length. */
				rte_mov15_or_less(dst, RTE_PTR_ADD(buffer, offset), len);
				return;
			}

			/* Copy until source pointer is 16 byte aligned. */
			rte_mov15_or_less(dst, RTE_PTR_ADD(buffer, offset), first);
			src = RTE_PTR_ADD(src, first);
			dst = RTE_PTR_ADD(dst, first);
			len -= first;
		}
	}

	/* Source pointer is now 16 byte aligned. */
	RTE_ASSERT(rte_is_aligned(src, 16));

	/* Copy large portion of data in chunks of 64 byte. */
	while (len >= 64) {
		xmm0 = _mm_stream_load_si128_const(RTE_PTR_ADD(src, 0 * 16));
		xmm1 = _mm_stream_load_si128_const(RTE_PTR_ADD(src, 1 * 16));
		xmm2 = _mm_stream_load_si128_const(RTE_PTR_ADD(src, 2 * 16));
		xmm3 = _mm_stream_load_si128_const(RTE_PTR_ADD(src, 3 * 16));
		_mm_storeu_si128(RTE_PTR_ADD(dst, 0 * 16), xmm0);
		_mm_storeu_si128(RTE_PTR_ADD(dst, 1 * 16), xmm1);
		_mm_storeu_si128(RTE_PTR_ADD(dst, 2 * 16), xmm2);
		_mm_storeu_si128(RTE_PTR_ADD(dst, 3 * 16), xmm3);
		src = RTE_PTR_ADD(src, 64);
		dst = RTE_PTR_ADD(dst, 64);
		len -= 64;
	}

	/* Copy following 32 and 16 byte portions of data.
	 *
	 * Omitted if source is known to be 16 byte aligned (so the alignment
	 * flags are still valid)
	 * and length is known to be respectively 64 or 32 byte aligned.
	 */
	if (!(((flags & RTE_MEMOPS_F_SRCA_MASK) >= RTE_MEMOPS_F_SRC16A) &&
			((flags & RTE_MEMOPS_F_LENA_MASK) >= RTE_MEMOPS_F_LEN64A)) &&
			(len & 32)) {
		xmm0 = _mm_stream_load_si128_const(RTE_PTR_ADD(src, 0 * 16));
		xmm1 = _mm_stream_load_si128_const(RTE_PTR_ADD(src, 1 * 16));
		_mm_storeu_si128(RTE_PTR_ADD(dst, 0 * 16), xmm0);
		_mm_storeu_si128(RTE_PTR_ADD(dst, 1 * 16), xmm1);
		src = RTE_PTR_ADD(src, 32);
		dst = RTE_PTR_ADD(dst, 32);
	}
	if (!(((flags & RTE_MEMOPS_F_SRCA_MASK) >= RTE_MEMOPS_F_SRC16A) &&
			((flags & RTE_MEMOPS_F_LENA_MASK) >= RTE_MEMOPS_F_LEN32A)) &&
			(len & 16)) {
		xmm2 = _mm_stream_load_si128_const(src);
		_mm_storeu_si128(dst, xmm2);
		src = RTE_PTR_ADD(src, 16);
		dst = RTE_PTR_ADD(dst, 16);
	}

	/* Copy remaining data, 15 byte or less, if any, via bounce buffer.
	 *
	 * Omitted if source is known to be 16 byte aligned (so the alignment
	 * flags are still valid) and length is known to be 16 byte aligned.
	 */
	if (!(((flags & RTE_MEMOPS_F_SRCA_MASK) >= RTE_MEMOPS_F_SRC16A) &&
			((flags & RTE_MEMOPS_F_LENA_MASK) >= RTE_MEMOPS_F_LEN16A)) &&
			(len & 15)) {
		char    buffer[16] __rte_aligned(16);

		xmm3 = _mm_stream_load_si128_const(src);
		_mm_store_si128((void *)buffer, xmm3);
		rte_mov15_or_less(dst, buffer, len & 15);
	}
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Memory copy to non-temporal destination area.
 *
 * @note
 * If the destination and/or length is unaligned, the first and/or last copied
 * bytes will be stored in the destination memory area using temporal access.
 * @note
 * Performance is optimal when destination pointer is 16 byte aligned.
 *
 * @param dst
 *   Pointer to the non-temporal destination memory area.
 * @param src
 *   Pointer to the source memory area.
 * @param len
 *   Number of bytes to copy.
 * @param flags
 *   Hints for memory access.
 *   Any of the RTE_MEMOPS_F_(LEN|DST)nnnA flags.
 *   The RTE_MEMOPS_F_SRC_NT flag must be clear.
 *   The RTE_MEMOPS_F_DST_NT flag must be set.
 *   The RTE_MEMOPS_F_SRCnnnA flags are ignored.
 *   Must be constant at build time.
 */
__rte_experimental
static __rte_always_inline
__attribute__((__nonnull__(1, 2)))
#if defined(RTE_TOOLCHAIN_GCC) && (GCC_VERSION >= 100000)
__attribute__((__access__(write_only, 1, 3), __access__(read_only, 2, 3)))
#endif
void rte_memcpy_ntd(void *__rte_restrict dst, const void *__rte_restrict src, size_t len,
		const uint64_t flags)
{
#ifndef RTE_TOOLCHAIN_CLANG /* Clang doesn't support using __builtin_constant_p() like this. */
	RTE_BUILD_BUG_ON(!__builtin_constant_p(flags));
#endif /* !RTE_TOOLCHAIN_CLANG */
	RTE_ASSERT(!(flags & RTE_MEMOPS_F_DSTA_MASK) || rte_is_aligned(dst,
			(flags & RTE_MEMOPS_F_DSTA_MASK) >> RTE_MEMOPS_F_DSTA_SHIFT));
	RTE_ASSERT(!(flags & RTE_MEMOPS_F_LENA_MASK) || (len &
			((flags & RTE_MEMOPS_F_LENA_MASK) >> RTE_MEMOPS_F_LENA_SHIFT) - 1) == 0);

	RTE_ASSERT((flags & (RTE_MEMOPS_F_SRC_NT | RTE_MEMOPS_F_DST_NT)) == RTE_MEMOPS_F_DST_NT);

	if (unlikely(len == 0))
		return;

	if (((flags & RTE_MEMOPS_F_DSTA_MASK) >= RTE_MEMOPS_F_DST16A) ||
			len >= 16) {
		/* Length >= 16 and/or destination is known to be 16 byte aligned. */
		register __m128i    xmm0, xmm1, xmm2, xmm3;

		/* If destination is not 16 byte aligned, then copy first part of data,
		 * to achieve 16 byte alignment of destination pointer.
		 * This invalidates the source, destination and length alignment flags, and
		 * potentially makes the source pointer unaligned.
		 *
		 * Omitted if destination is known to be 16 byte aligned.
		 */
		if (!((flags & RTE_MEMOPS_F_DSTA_MASK) >= RTE_MEMOPS_F_DST16A)) {
			/* Destination is not known to be 16 byte aligned, but might be. */
			/** How many bytes is destination offset from 16 byte alignment
			 * (floor rounding).
			 */
			const size_t    offset = (uintptr_t)dst & 15;

			if (offset) {
				/* Destination is not 16 byte aligned. */
				/** How many bytes is destination away from 16 byte alignment
				 * (ceiling rounding).
				 */
				const size_t    first = 16 - offset;

				if (((flags & RTE_MEMOPS_F_DSTA_MASK) >= RTE_MEMOPS_F_DST4A) ||
						(offset & 3) == 0) {
					/* Destination is (known to be) 4 byte aligned. */
					int32_t r0, r1, r2;

					/* Copy until destination pointer is 16 byte aligned. */
					if (first & 8) {
						memcpy(&r0, RTE_PTR_ADD(src, 0 * 4), 4);
						memcpy(&r1, RTE_PTR_ADD(src, 1 * 4), 4);
						_mm_stream_si32(RTE_PTR_ADD(dst, 0 * 4), r0);
						_mm_stream_si32(RTE_PTR_ADD(dst, 1 * 4), r1);
						src = RTE_PTR_ADD(src, 8);
						dst = RTE_PTR_ADD(dst, 8);
						len -= 8;
					}
					if (first & 4) {
						memcpy(&r2, src, 4);
						_mm_stream_si32(dst, r2);
						src = RTE_PTR_ADD(src, 4);
						dst = RTE_PTR_ADD(dst, 4);
						len -= 4;
					}
				} else {
					/* Destination is not 4 byte aligned. */
					/* Copy until destination pointer is 16 byte aligned. */
					rte_mov15_or_less(dst, src, first);
					src = RTE_PTR_ADD(src, first);
					dst = RTE_PTR_ADD(dst, first);
					len -= first;
				}
			}
		}

		/* Destination pointer is now 16 byte aligned. */
		RTE_ASSERT(rte_is_aligned(dst, 16));

		/* Copy large portion of data in chunks of 64 byte. */
		while (len >= 64) {
			xmm0 = _mm_loadu_si128(RTE_PTR_ADD(src, 0 * 16));
			xmm1 = _mm_loadu_si128(RTE_PTR_ADD(src, 1 * 16));
			xmm2 = _mm_loadu_si128(RTE_PTR_ADD(src, 2 * 16));
			xmm3 = _mm_loadu_si128(RTE_PTR_ADD(src, 3 * 16));
			_mm_stream_si128(RTE_PTR_ADD(dst, 0 * 16), xmm0);
			_mm_stream_si128(RTE_PTR_ADD(dst, 1 * 16), xmm1);
			_mm_stream_si128(RTE_PTR_ADD(dst, 2 * 16), xmm2);
			_mm_stream_si128(RTE_PTR_ADD(dst, 3 * 16), xmm3);
			src = RTE_PTR_ADD(src, 64);
			dst = RTE_PTR_ADD(dst, 64);
			len -= 64;
		}

		/* Copy following 32 and 16 byte portions of data.
		 *
		 * Omitted if destination is known to be 16 byte aligned (so the alignment
		 * flags are still valid)
		 * and length is known to be respectively 64 or 32 byte aligned.
		 */
		if (!(((flags & RTE_MEMOPS_F_DSTA_MASK) >= RTE_MEMOPS_F_DST16A) &&
				((flags & RTE_MEMOPS_F_LENA_MASK) >= RTE_MEMOPS_F_LEN64A)) &&
				(len & 32)) {
			xmm0 = _mm_loadu_si128(RTE_PTR_ADD(src, 0 * 16));
			xmm1 = _mm_loadu_si128(RTE_PTR_ADD(src, 1 * 16));
			_mm_stream_si128(RTE_PTR_ADD(dst, 0 * 16), xmm0);
			_mm_stream_si128(RTE_PTR_ADD(dst, 1 * 16), xmm1);
			src = RTE_PTR_ADD(src, 32);
			dst = RTE_PTR_ADD(dst, 32);
		}
		if (!(((flags & RTE_MEMOPS_F_DSTA_MASK) >= RTE_MEMOPS_F_DST16A) &&
				((flags & RTE_MEMOPS_F_LENA_MASK) >= RTE_MEMOPS_F_LEN32A)) &&
				(len & 16)) {
			xmm2 = _mm_loadu_si128(src);
			_mm_stream_si128(dst, xmm2);
			src = RTE_PTR_ADD(src, 16);
			dst = RTE_PTR_ADD(dst, 16);
		}
	} else {
		/* Length <= 15, and
		 * destination is not known to be 16 byte aligned (but might be).
		 */
		/* If destination is not 4 byte aligned, then
		 * use normal copy and return.
		 *
		 * Omitted if destination is known to be 4 byte aligned.
		 */
		if (!((flags & RTE_MEMOPS_F_DSTA_MASK) >= RTE_MEMOPS_F_DST4A) &&
				!rte_is_aligned(dst, 4)) {
			/* Destination is not 4 byte aligned. Non-temporal store is unavailable. */
			rte_mov15_or_less(dst, src, len);
			return;
		}
		/* Destination is (known to be) 4 byte aligned. Proceed. */
	}

	/* Destination pointer is now 4 byte (or 16 byte) aligned. */
	RTE_ASSERT(rte_is_aligned(dst, 4));

	/* Copy following 8 and 4 byte portions of data.
	 *
	 * Omitted if destination is known to be 16 byte aligned (so the alignment
	 * flags are still valid)
	 * and length is known to be respectively 16 or 8 byte aligned.
	 */
	if (!(((flags & RTE_MEMOPS_F_DSTA_MASK) >= RTE_MEMOPS_F_DST16A) &&
			((flags & RTE_MEMOPS_F_LENA_MASK) >= RTE_MEMOPS_F_LEN16A)) &&
			(len & 8)) {
		int32_t r0, r1;

		memcpy(&r0, RTE_PTR_ADD(src, 0 * 4), 4);
		memcpy(&r1, RTE_PTR_ADD(src, 1 * 4), 4);
		_mm_stream_si32(RTE_PTR_ADD(dst, 0 * 4), r0);
		_mm_stream_si32(RTE_PTR_ADD(dst, 1 * 4), r1);
		src = RTE_PTR_ADD(src, 8);
		dst = RTE_PTR_ADD(dst, 8);
	}
	if (!(((flags & RTE_MEMOPS_F_DSTA_MASK) >= RTE_MEMOPS_F_DST16A) &&
			((flags & RTE_MEMOPS_F_LENA_MASK) >= RTE_MEMOPS_F_LEN8A)) &&
			(len & 4)) {
		int32_t r2;

		memcpy(&r2, src, 4);
		_mm_stream_si32(dst, r2);
		src = RTE_PTR_ADD(src, 4);
		dst = RTE_PTR_ADD(dst, 4);
	}

	/* Copy remaining 2 and 1 byte portions of data.
	 *
	 * Omitted if destination is known to be 16 byte aligned (so the alignment
	 * flags are still valid)
	 * and length is known to be respectively 4 and 2 byte aligned.
	 */
	if (!(((flags & RTE_MEMOPS_F_DSTA_MASK) >= RTE_MEMOPS_F_DST16A) &&
			((flags & RTE_MEMOPS_F_LENA_MASK) >= RTE_MEMOPS_F_LEN4A)) &&
			(len & 2)) {
		int16_t r3;

		memcpy(&r3, src, 2);
		*(int16_t *)dst = r3;
		src = RTE_PTR_ADD(src, 2);
		dst = RTE_PTR_ADD(dst, 2);
	}
	if (!(((flags & RTE_MEMOPS_F_DSTA_MASK) >= RTE_MEMOPS_F_DST16A) &&
			((flags & RTE_MEMOPS_F_LENA_MASK) >= RTE_MEMOPS_F_LEN2A)) &&
			(len & 1))
		*(char *)dst = *(const char *)src;
}

/**
 * Non-temporal memory copy of 15 or less byte
 * from 16 byte aligned source via bounce buffer.
 * The memory areas must not overlap.
 *
 * @param dst
 *   Pointer to the non-temporal destination memory area.
 * @param src
 *   Pointer to the non-temporal source memory area.
 *   Must be 16 byte aligned.
 * @param len
 *   Only the 4 least significant bits of this parameter are used.
 *   The 4 least significant bits of this holds the number of remaining bytes to copy.
 * @param flags
 *   Hints for memory access.
 */
static __rte_always_inline
__attribute__((__nonnull__(1, 2)))
#if defined(RTE_TOOLCHAIN_GCC) && (GCC_VERSION >= 100000)
__attribute__((__access__(write_only, 1, 3), __access__(read_only, 2, 3)))
#endif
void rte_memcpy_nt_15_or_less_s16a(void *__rte_restrict dst,
		const void *__rte_restrict src, size_t len, const uint64_t flags)
{
	int32_t             buffer[4] __rte_aligned(16);
	register __m128i    xmm0;

#ifndef RTE_TOOLCHAIN_CLANG /* Clang doesn't support using __builtin_constant_p() like this. */
	RTE_BUILD_BUG_ON(!__builtin_constant_p(flags));
#endif /* !RTE_TOOLCHAIN_CLANG */
	RTE_ASSERT(!(flags & RTE_MEMOPS_F_DSTA_MASK) || rte_is_aligned(dst,
			(flags & RTE_MEMOPS_F_DSTA_MASK) >> RTE_MEMOPS_F_DSTA_SHIFT));
	RTE_ASSERT(!(flags & RTE_MEMOPS_F_SRCA_MASK) || rte_is_aligned(src,
			(flags & RTE_MEMOPS_F_SRCA_MASK) >> RTE_MEMOPS_F_SRCA_SHIFT));
	RTE_ASSERT(!(flags & RTE_MEMOPS_F_LENA_MASK) || (len &
			((flags & RTE_MEMOPS_F_LENA_MASK) >> RTE_MEMOPS_F_LENA_SHIFT) - 1) == 0);

	RTE_ASSERT((flags & (RTE_MEMOPS_F_SRC_NT | RTE_MEMOPS_F_DST_NT)) ==
			(RTE_MEMOPS_F_SRC_NT | RTE_MEMOPS_F_DST_NT));
	RTE_ASSERT(rte_is_aligned(src, 16));

	if ((len & 15) == 0)
		return;

	/* Non-temporal load into bounce buffer. */
	xmm0 = _mm_stream_load_si128_const(src);
	_mm_store_si128((void *)buffer, xmm0);

	/* Store from bounce buffer. */
	if (((flags & RTE_MEMOPS_F_DSTA_MASK) >= RTE_MEMOPS_F_DST4A) ||
			rte_is_aligned(dst, 4)) {
		/* Destination is (known to be) 4 byte aligned. */
		src = (const void *)buffer;
		if (len & 8) {
#ifdef RTE_ARCH_X86_64
			if ((flags & RTE_MEMOPS_F_DSTA_MASK) >= RTE_MEMOPS_F_DST8A) {
				/* Destination is known to be 8 byte aligned. */
				_mm_stream_si64(dst, *(const int64_t *)src);
			} else {
#endif /* RTE_ARCH_X86_64 */
				_mm_stream_si32(RTE_PTR_ADD(dst, 0), buffer[0]);
				_mm_stream_si32(RTE_PTR_ADD(dst, 4), buffer[1]);
#ifdef RTE_ARCH_X86_64
			}
#endif /* RTE_ARCH_X86_64 */
			src = RTE_PTR_ADD(src, 8);
			dst = RTE_PTR_ADD(dst, 8);
		}
		if (!((flags & RTE_MEMOPS_F_LENA_MASK) >= RTE_MEMOPS_F_LEN8A) &&
				(len & 4)) {
			_mm_stream_si32(dst, *(const int32_t *)src);
			src = RTE_PTR_ADD(src, 4);
			dst = RTE_PTR_ADD(dst, 4);
		}

		/* Non-temporal store is unavailble for the remaining 3 byte or less. */
		if (!((flags & RTE_MEMOPS_F_LENA_MASK) >= RTE_MEMOPS_F_LEN4A) &&
				(len & 2)) {
			*(int16_t *)dst = *(const int16_t *)src;
			src = RTE_PTR_ADD(src, 2);
			dst = RTE_PTR_ADD(dst, 2);
		}
		if (!((flags & RTE_MEMOPS_F_LENA_MASK) >= RTE_MEMOPS_F_LEN2A) &&
				(len & 1)) {
			*(char *)dst = *(const char *)src;
		}
	} else {
		/* Destination is not 4 byte aligned. Non-temporal store is unavailable. */
		rte_mov15_or_less(dst, (const void *)buffer, len & 15);
	}
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * 16 byte aligned addresses non-temporal memory copy.
 * The memory areas must not overlap.
 *
 * @param dst
 *   Pointer to the non-temporal destination memory area.
 *   Must be 16 byte aligned.
 * @param src
 *   Pointer to the non-temporal source memory area.
 *   Must be 16 byte aligned.
 * @param len
 *   Number of bytes to copy.
 * @param flags
 *   Hints for memory access.
 */
__rte_experimental
static __rte_always_inline
__attribute__((__nonnull__(1, 2)))
#if defined(RTE_TOOLCHAIN_GCC) && (GCC_VERSION >= 100000)
__attribute__((__access__(write_only, 1, 3), __access__(read_only, 2, 3)))
#endif
void rte_memcpy_nt_d16s16a(void *__rte_restrict dst, const void *__rte_restrict src, size_t len,
		const uint64_t flags)
{
	register __m128i    xmm0, xmm1, xmm2, xmm3;

#ifndef RTE_TOOLCHAIN_CLANG /* Clang doesn't support using __builtin_constant_p() like this. */
	RTE_BUILD_BUG_ON(!__builtin_constant_p(flags));
#endif /* !RTE_TOOLCHAIN_CLANG */
	RTE_ASSERT(!(flags & RTE_MEMOPS_F_DSTA_MASK) || rte_is_aligned(dst,
			(flags & RTE_MEMOPS_F_DSTA_MASK) >> RTE_MEMOPS_F_DSTA_SHIFT));
	RTE_ASSERT(!(flags & RTE_MEMOPS_F_SRCA_MASK) || rte_is_aligned(src,
			(flags & RTE_MEMOPS_F_SRCA_MASK) >> RTE_MEMOPS_F_SRCA_SHIFT));
	RTE_ASSERT(!(flags & RTE_MEMOPS_F_LENA_MASK) || (len &
			((flags & RTE_MEMOPS_F_LENA_MASK) >> RTE_MEMOPS_F_LENA_SHIFT) - 1) == 0);

	RTE_ASSERT((flags & (RTE_MEMOPS_F_SRC_NT | RTE_MEMOPS_F_DST_NT)) ==
			(RTE_MEMOPS_F_SRC_NT | RTE_MEMOPS_F_DST_NT));
	RTE_ASSERT(rte_is_aligned(dst, 16));
	RTE_ASSERT(rte_is_aligned(src, 16));

	if (unlikely(len == 0))
		return;

	/* Copy large portion of data in chunks of 64 byte. */
	while (len >= 64) {
		xmm0 = _mm_stream_load_si128_const(RTE_PTR_ADD(src, 0 * 16));
		xmm1 = _mm_stream_load_si128_const(RTE_PTR_ADD(src, 1 * 16));
		xmm2 = _mm_stream_load_si128_const(RTE_PTR_ADD(src, 2 * 16));
		xmm3 = _mm_stream_load_si128_const(RTE_PTR_ADD(src, 3 * 16));
		_mm_stream_si128(RTE_PTR_ADD(dst, 0 * 16), xmm0);
		_mm_stream_si128(RTE_PTR_ADD(dst, 1 * 16), xmm1);
		_mm_stream_si128(RTE_PTR_ADD(dst, 2 * 16), xmm2);
		_mm_stream_si128(RTE_PTR_ADD(dst, 3 * 16), xmm3);
		src = RTE_PTR_ADD(src, 64);
		dst = RTE_PTR_ADD(dst, 64);
		len -= 64;
	}

	/* Copy following 32 and 16 byte portions of data.
	 *
	 * Omitted if length is known to be respectively 64 or 32 byte aligned.
	 */
	if (!((flags & RTE_MEMOPS_F_LENA_MASK) >= RTE_MEMOPS_F_LEN64A) &&
			(len & 32)) {
		xmm0 = _mm_stream_load_si128_const(RTE_PTR_ADD(src, 0 * 16));
		xmm1 = _mm_stream_load_si128_const(RTE_PTR_ADD(src, 1 * 16));
		_mm_stream_si128(RTE_PTR_ADD(dst, 0 * 16), xmm0);
		_mm_stream_si128(RTE_PTR_ADD(dst, 1 * 16), xmm1);
		src = RTE_PTR_ADD(src, 32);
		dst = RTE_PTR_ADD(dst, 32);
	}
	if (!((flags & RTE_MEMOPS_F_LENA_MASK) >= RTE_MEMOPS_F_LEN32A) &&
			(len & 16)) {
		xmm2 = _mm_stream_load_si128_const(src);
		_mm_stream_si128(dst, xmm2);
		src = RTE_PTR_ADD(src, 16);
		dst = RTE_PTR_ADD(dst, 16);
	}

	/* Copy remaining data, 15 byte or less, via bounce buffer.
	 *
	 * Omitted if length is known to be 16 byte aligned.
	 */
	if (!((flags & RTE_MEMOPS_F_LENA_MASK) >= RTE_MEMOPS_F_LEN16A))
		rte_memcpy_nt_15_or_less_s16a(dst, src, len,
				(flags & ~(RTE_MEMOPS_F_DSTA_MASK | RTE_MEMOPS_F_SRCA_MASK)) |
				(((flags & RTE_MEMOPS_F_DSTA_MASK) >= RTE_MEMOPS_F_DST16A) ?
				flags : RTE_MEMOPS_F_DST16A) |
				(((flags & RTE_MEMOPS_F_SRCA_MASK) >= RTE_MEMOPS_F_SRC16A) ?
				flags : RTE_MEMOPS_F_SRC16A));
}

#ifdef RTE_ARCH_X86_64
/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * 8/16 byte aligned destination/source addresses non-temporal memory copy.
 * The memory areas must not overlap.
 *
 * @param dst
 *   Pointer to the non-temporal destination memory area.
 *   Must be 8 byte aligned.
 * @param src
 *   Pointer to the non-temporal source memory area.
 *   Must be 16 byte aligned.
 * @param len
 *   Number of bytes to copy.
 * @param flags
 *   Hints for memory access.
 */
__rte_experimental
static __rte_always_inline
__attribute__((__nonnull__(1, 2)))
#if defined(RTE_TOOLCHAIN_GCC) && (GCC_VERSION >= 100000)
__attribute__((__access__(write_only, 1, 3), __access__(read_only, 2, 3)))
#endif
void rte_memcpy_nt_d8s16a(void *__rte_restrict dst, const void *__rte_restrict src, size_t len,
		const uint64_t flags)
{
	int64_t             buffer[8] __rte_cache_aligned /* at least __rte_aligned(16) */;
	register __m128i    xmm0, xmm1, xmm2, xmm3;

#ifndef RTE_TOOLCHAIN_CLANG /* Clang doesn't support using __builtin_constant_p() like this. */
	RTE_BUILD_BUG_ON(!__builtin_constant_p(flags));
#endif /* !RTE_TOOLCHAIN_CLANG */
	RTE_ASSERT(!(flags & RTE_MEMOPS_F_DSTA_MASK) || rte_is_aligned(dst,
			(flags & RTE_MEMOPS_F_DSTA_MASK) >> RTE_MEMOPS_F_DSTA_SHIFT));
	RTE_ASSERT(!(flags & RTE_MEMOPS_F_SRCA_MASK) || rte_is_aligned(src,
			(flags & RTE_MEMOPS_F_SRCA_MASK) >> RTE_MEMOPS_F_SRCA_SHIFT));
	RTE_ASSERT(!(flags & RTE_MEMOPS_F_LENA_MASK) || (len &
			((flags & RTE_MEMOPS_F_LENA_MASK) >> RTE_MEMOPS_F_LENA_SHIFT) - 1) == 0);

	RTE_ASSERT((flags & (RTE_MEMOPS_F_SRC_NT | RTE_MEMOPS_F_DST_NT)) ==
			(RTE_MEMOPS_F_SRC_NT | RTE_MEMOPS_F_DST_NT));
	RTE_ASSERT(rte_is_aligned(dst, 8));
	RTE_ASSERT(rte_is_aligned(src, 16));

	if (unlikely(len == 0))
		return;

	/* Copy large portion of data in chunks of 64 byte. */
	while (len >= 64) {
		xmm0 = _mm_stream_load_si128_const(RTE_PTR_ADD(src, 0 * 16));
		xmm1 = _mm_stream_load_si128_const(RTE_PTR_ADD(src, 1 * 16));
		xmm2 = _mm_stream_load_si128_const(RTE_PTR_ADD(src, 2 * 16));
		xmm3 = _mm_stream_load_si128_const(RTE_PTR_ADD(src, 3 * 16));
		_mm_store_si128((void *)&buffer[0 * 2], xmm0);
		_mm_store_si128((void *)&buffer[1 * 2], xmm1);
		_mm_store_si128((void *)&buffer[2 * 2], xmm2);
		_mm_store_si128((void *)&buffer[3 * 2], xmm3);
		_mm_stream_si64(RTE_PTR_ADD(dst, 0 * 8), buffer[0]);
		_mm_stream_si64(RTE_PTR_ADD(dst, 1 * 8), buffer[1]);
		_mm_stream_si64(RTE_PTR_ADD(dst, 2 * 8), buffer[2]);
		_mm_stream_si64(RTE_PTR_ADD(dst, 3 * 8), buffer[3]);
		_mm_stream_si64(RTE_PTR_ADD(dst, 4 * 8), buffer[4]);
		_mm_stream_si64(RTE_PTR_ADD(dst, 5 * 8), buffer[5]);
		_mm_stream_si64(RTE_PTR_ADD(dst, 6 * 8), buffer[6]);
		_mm_stream_si64(RTE_PTR_ADD(dst, 7 * 8), buffer[7]);
		src = RTE_PTR_ADD(src, 64);
		dst = RTE_PTR_ADD(dst, 64);
		len -= 64;
	}

	/* Copy following 32 and 16 byte portions of data.
	 *
	 * Omitted if length is known to be respectively 64 or 32 byte aligned.
	 */
	if (!((flags & RTE_MEMOPS_F_LENA_MASK) >= RTE_MEMOPS_F_LEN64A) &&
			(len & 32)) {
		xmm0 = _mm_stream_load_si128_const(RTE_PTR_ADD(src, 0 * 16));
		xmm1 = _mm_stream_load_si128_const(RTE_PTR_ADD(src, 1 * 16));
		_mm_store_si128((void *)&buffer[0 * 2], xmm0);
		_mm_store_si128((void *)&buffer[1 * 2], xmm1);
		_mm_stream_si64(RTE_PTR_ADD(dst, 0 * 8), buffer[0]);
		_mm_stream_si64(RTE_PTR_ADD(dst, 1 * 8), buffer[1]);
		_mm_stream_si64(RTE_PTR_ADD(dst, 2 * 8), buffer[2]);
		_mm_stream_si64(RTE_PTR_ADD(dst, 3 * 8), buffer[3]);
		src = RTE_PTR_ADD(src, 32);
		dst = RTE_PTR_ADD(dst, 32);
	}
	if (!((flags & RTE_MEMOPS_F_LENA_MASK) >= RTE_MEMOPS_F_LEN32A) &&
			(len & 16)) {
		xmm2 = _mm_stream_load_si128_const(src);
		_mm_store_si128((void *)&buffer[2 * 2], xmm2);
		_mm_stream_si64(RTE_PTR_ADD(dst, 0 * 8), buffer[4]);
		_mm_stream_si64(RTE_PTR_ADD(dst, 1 * 8), buffer[5]);
		src = RTE_PTR_ADD(src, 16);
		dst = RTE_PTR_ADD(dst, 16);
	}

	/* Copy remaining data, 15 byte or less, via bounce buffer.
	 *
	 * Omitted if length is known to be 16 byte aligned.
	 */
	if (!((flags & RTE_MEMOPS_F_LENA_MASK) >= RTE_MEMOPS_F_LEN16A))
		rte_memcpy_nt_15_or_less_s16a(dst, src, len,
				(flags & ~(RTE_MEMOPS_F_DSTA_MASK | RTE_MEMOPS_F_SRCA_MASK)) |
				(((flags & RTE_MEMOPS_F_DSTA_MASK) >= RTE_MEMOPS_F_DST8A) ?
				flags : RTE_MEMOPS_F_DST8A) |
				(((flags & RTE_MEMOPS_F_SRCA_MASK) >= RTE_MEMOPS_F_SRC16A) ?
				flags : RTE_MEMOPS_F_SRC16A));
}
#endif /* RTE_ARCH_X86_64 */

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * 4/16 byte aligned destination/source addresses non-temporal memory copy.
 * The memory areas must not overlap.
 *
 * @param dst
 *   Pointer to the non-temporal destination memory area.
 *   Must be 4 byte aligned.
 * @param src
 *   Pointer to the non-temporal source memory area.
 *   Must be 16 byte aligned.
 * @param len
 *   Number of bytes to copy.
 * @param flags
 *   Hints for memory access.
 */
__rte_experimental
static __rte_always_inline
__attribute__((__nonnull__(1, 2)))
#if defined(RTE_TOOLCHAIN_GCC) && (GCC_VERSION >= 100000)
__attribute__((__access__(write_only, 1, 3), __access__(read_only, 2, 3)))
#endif
void rte_memcpy_nt_d4s16a(void *__rte_restrict dst, const void *__rte_restrict src, size_t len,
		const uint64_t flags)
{
	int32_t             buffer[16] __rte_cache_aligned /* at least __rte_aligned(16) */;
	register __m128i    xmm0, xmm1, xmm2, xmm3;

#ifndef RTE_TOOLCHAIN_CLANG /* Clang doesn't support using __builtin_constant_p() like this. */
	RTE_BUILD_BUG_ON(!__builtin_constant_p(flags));
#endif /* !RTE_TOOLCHAIN_CLANG */
	RTE_ASSERT(!(flags & RTE_MEMOPS_F_DSTA_MASK) || rte_is_aligned(dst,
			(flags & RTE_MEMOPS_F_DSTA_MASK) >> RTE_MEMOPS_F_DSTA_SHIFT));
	RTE_ASSERT(!(flags & RTE_MEMOPS_F_SRCA_MASK) || rte_is_aligned(src,
			(flags & RTE_MEMOPS_F_SRCA_MASK) >> RTE_MEMOPS_F_SRCA_SHIFT));
	RTE_ASSERT(!(flags & RTE_MEMOPS_F_LENA_MASK) || (len &
			((flags & RTE_MEMOPS_F_LENA_MASK) >> RTE_MEMOPS_F_LENA_SHIFT) - 1) == 0);

	RTE_ASSERT((flags & (RTE_MEMOPS_F_SRC_NT | RTE_MEMOPS_F_DST_NT)) ==
			(RTE_MEMOPS_F_SRC_NT | RTE_MEMOPS_F_DST_NT));
	RTE_ASSERT(rte_is_aligned(dst, 4));
	RTE_ASSERT(rte_is_aligned(src, 16));

	if (unlikely(len == 0))
		return;

	/* Copy large portion of data in chunks of 64 byte. */
	while (len >= 64) {
		xmm0 = _mm_stream_load_si128_const(RTE_PTR_ADD(src, 0 * 16));
		xmm1 = _mm_stream_load_si128_const(RTE_PTR_ADD(src, 1 * 16));
		xmm2 = _mm_stream_load_si128_const(RTE_PTR_ADD(src, 2 * 16));
		xmm3 = _mm_stream_load_si128_const(RTE_PTR_ADD(src, 3 * 16));
		_mm_store_si128((void *)&buffer[0 * 4], xmm0);
		_mm_store_si128((void *)&buffer[1 * 4], xmm1);
		_mm_store_si128((void *)&buffer[2 * 4], xmm2);
		_mm_store_si128((void *)&buffer[3 * 4], xmm3);
		_mm_stream_si32(RTE_PTR_ADD(dst,  0 * 4), buffer[0]);
		_mm_stream_si32(RTE_PTR_ADD(dst,  1 * 4), buffer[1]);
		_mm_stream_si32(RTE_PTR_ADD(dst,  2 * 4), buffer[2]);
		_mm_stream_si32(RTE_PTR_ADD(dst,  3 * 4), buffer[3]);
		_mm_stream_si32(RTE_PTR_ADD(dst,  4 * 4), buffer[4]);
		_mm_stream_si32(RTE_PTR_ADD(dst,  5 * 4), buffer[5]);
		_mm_stream_si32(RTE_PTR_ADD(dst,  6 * 4), buffer[6]);
		_mm_stream_si32(RTE_PTR_ADD(dst,  7 * 4), buffer[7]);
		_mm_stream_si32(RTE_PTR_ADD(dst,  8 * 4), buffer[8]);
		_mm_stream_si32(RTE_PTR_ADD(dst,  9 * 4), buffer[9]);
		_mm_stream_si32(RTE_PTR_ADD(dst, 10 * 4), buffer[10]);
		_mm_stream_si32(RTE_PTR_ADD(dst, 11 * 4), buffer[11]);
		_mm_stream_si32(RTE_PTR_ADD(dst, 12 * 4), buffer[12]);
		_mm_stream_si32(RTE_PTR_ADD(dst, 13 * 4), buffer[13]);
		_mm_stream_si32(RTE_PTR_ADD(dst, 14 * 4), buffer[14]);
		_mm_stream_si32(RTE_PTR_ADD(dst, 15 * 4), buffer[15]);
		src = RTE_PTR_ADD(src, 64);
		dst = RTE_PTR_ADD(dst, 64);
		len -= 64;
	}

	/* Copy following 32 and 16 byte portions of data.
	 *
	 * Omitted if length is known to be respectively 64 or 32 byte aligned.
	 */
	if (!((flags & RTE_MEMOPS_F_LENA_MASK) >= RTE_MEMOPS_F_LEN64A) &&
			(len & 32)) {
		xmm0 = _mm_stream_load_si128_const(RTE_PTR_ADD(src, 0 * 16));
		xmm1 = _mm_stream_load_si128_const(RTE_PTR_ADD(src, 1 * 16));
		_mm_store_si128((void *)&buffer[0 * 4], xmm0);
		_mm_store_si128((void *)&buffer[1 * 4], xmm1);
		_mm_stream_si32(RTE_PTR_ADD(dst, 0 * 4), buffer[0]);
		_mm_stream_si32(RTE_PTR_ADD(dst, 1 * 4), buffer[1]);
		_mm_stream_si32(RTE_PTR_ADD(dst, 2 * 4), buffer[2]);
		_mm_stream_si32(RTE_PTR_ADD(dst, 3 * 4), buffer[3]);
		_mm_stream_si32(RTE_PTR_ADD(dst, 4 * 4), buffer[4]);
		_mm_stream_si32(RTE_PTR_ADD(dst, 5 * 4), buffer[5]);
		_mm_stream_si32(RTE_PTR_ADD(dst, 6 * 4), buffer[6]);
		_mm_stream_si32(RTE_PTR_ADD(dst, 7 * 4), buffer[7]);
		src = RTE_PTR_ADD(src, 32);
		dst = RTE_PTR_ADD(dst, 32);
	}
	if (!((flags & RTE_MEMOPS_F_LENA_MASK) >= RTE_MEMOPS_F_LEN32A) &&
			(len & 16)) {
		xmm2 = _mm_stream_load_si128_const(src);
		_mm_store_si128((void *)&buffer[2 * 4], xmm2);
		_mm_stream_si32(RTE_PTR_ADD(dst, 0 * 4), buffer[8]);
		_mm_stream_si32(RTE_PTR_ADD(dst, 1 * 4), buffer[9]);
		_mm_stream_si32(RTE_PTR_ADD(dst, 2 * 4), buffer[10]);
		_mm_stream_si32(RTE_PTR_ADD(dst, 3 * 4), buffer[11]);
		src = RTE_PTR_ADD(src, 16);
		dst = RTE_PTR_ADD(dst, 16);
	}

	/* Copy remaining data, 15 byte or less, via bounce buffer.
	 *
	 * Omitted if length is known to be 16 byte aligned.
	 */
	if (!((flags & RTE_MEMOPS_F_LENA_MASK) >= RTE_MEMOPS_F_LEN16A))
		rte_memcpy_nt_15_or_less_s16a(dst, src, len,
				(flags & ~(RTE_MEMOPS_F_DSTA_MASK | RTE_MEMOPS_F_SRCA_MASK)) |
				(((flags & RTE_MEMOPS_F_DSTA_MASK) >= RTE_MEMOPS_F_DST4A) ?
				flags : RTE_MEMOPS_F_DST4A) |
				(((flags & RTE_MEMOPS_F_SRCA_MASK) >= RTE_MEMOPS_F_SRC16A) ?
				flags : RTE_MEMOPS_F_SRC16A));
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * 4 byte aligned addresses (non-temporal) memory copy.
 * The memory areas must not overlap.
 *
 * @param dst
 *   Pointer to the (non-temporal) destination memory area.
 *   Must be 4 byte aligned if using non-temporal store.
 * @param src
 *   Pointer to the (non-temporal) source memory area.
 *   Must be 4 byte aligned if using non-temporal load.
 * @param len
 *   Number of bytes to copy.
 * @param flags
 *   Hints for memory access.
 */
__rte_experimental
static __rte_always_inline
__attribute__((__nonnull__(1, 2)))
#if defined(RTE_TOOLCHAIN_GCC) && (GCC_VERSION >= 100000)
__attribute__((__access__(write_only, 1, 3), __access__(read_only, 2, 3)))
#endif
void rte_memcpy_nt_d4s4a(void *__rte_restrict dst, const void *__rte_restrict src, size_t len,
		const uint64_t flags)
{
	/** How many bytes is source offset from 16 byte alignment (floor rounding). */
	const size_t    offset = (flags & RTE_MEMOPS_F_SRCA_MASK) >= RTE_MEMOPS_F_SRC16A ?
			0 : (uintptr_t)src & 15;

#ifndef RTE_TOOLCHAIN_CLANG /* Clang doesn't support using __builtin_constant_p() like this. */
	RTE_BUILD_BUG_ON(!__builtin_constant_p(flags));
#endif /* !RTE_TOOLCHAIN_CLANG */
	RTE_ASSERT(!(flags & RTE_MEMOPS_F_DSTA_MASK) || rte_is_aligned(dst,
			(flags & RTE_MEMOPS_F_DSTA_MASK) >> RTE_MEMOPS_F_DSTA_SHIFT));
	RTE_ASSERT(!(flags & RTE_MEMOPS_F_SRCA_MASK) || rte_is_aligned(src,
			(flags & RTE_MEMOPS_F_SRCA_MASK) >> RTE_MEMOPS_F_SRCA_SHIFT));
	RTE_ASSERT(!(flags & RTE_MEMOPS_F_LENA_MASK) || (len &
			((flags & RTE_MEMOPS_F_LENA_MASK) >> RTE_MEMOPS_F_LENA_SHIFT) - 1) == 0);

	RTE_ASSERT((flags & (RTE_MEMOPS_F_SRC_NT | RTE_MEMOPS_F_DST_NT)) ==
			(RTE_MEMOPS_F_SRC_NT | RTE_MEMOPS_F_DST_NT));
	RTE_ASSERT(rte_is_aligned(dst, 4));
	RTE_ASSERT(rte_is_aligned(src, 4));

	if (unlikely(len == 0))
		return;

	if (offset == 0) {
		/* Source is 16 byte aligned. */
		/* Copy everything, using upgraded source alignment flags. */
		rte_memcpy_nt_d4s16a(dst, src, len,
				(flags & ~RTE_MEMOPS_F_SRCA_MASK) | RTE_MEMOPS_F_SRC16A);
	} else {
		/* Source is not 16 byte aligned, so make it 16 byte aligned. */
		int32_t             buffer[4] __rte_aligned(16);
		const size_t        first = 16 - offset;
		register __m128i    xmm0;

		/* First, copy first part of data in chunks of 4 byte,
		 * to achieve 16 byte alignment of source.
		 * This invalidates the source, destination and length alignment flags, and
		 * potentially makes the destination pointer 16 byte unaligned/aligned.
		 */

		/** Copy from 16 byte aligned source pointer (floor rounding). */
		xmm0 = _mm_stream_load_si128_const(RTE_PTR_SUB(src, offset));
		_mm_store_si128((void *)buffer, xmm0);

		if (unlikely(len + offset <= 16)) {
			/* Short length. */
			if (((flags & RTE_MEMOPS_F_LENA_MASK) >= RTE_MEMOPS_F_LEN4A) ||
					(len & 3) == 0) {
				/* Length is 4 byte aligned. */
				switch (len) {
				case 1 * 4:
					/* Offset can be 1 * 4, 2 * 4 or 3 * 4. */
					_mm_stream_si32(RTE_PTR_ADD(dst, 0 * 4),
							buffer[offset / 4]);
					break;
				case 2 * 4:
					/* Offset can be 1 * 4 or 2 * 4. */
					_mm_stream_si32(RTE_PTR_ADD(dst, 0 * 4),
							buffer[offset / 4]);
					_mm_stream_si32(RTE_PTR_ADD(dst, 1 * 4),
							buffer[offset / 4 + 1]);
					break;
				case 3 * 4:
					/* Offset can only be 1 * 4. */
					_mm_stream_si32(RTE_PTR_ADD(dst, 0 * 4), buffer[1]);
					_mm_stream_si32(RTE_PTR_ADD(dst, 1 * 4), buffer[2]);
					_mm_stream_si32(RTE_PTR_ADD(dst, 2 * 4), buffer[3]);
					break;
				}
			} else {
				/* Length is not 4 byte aligned. */
				rte_mov15_or_less(dst, RTE_PTR_ADD(buffer, offset), len);
			}
			return;
		}

		switch (first) {
		case 1 * 4:
			_mm_stream_si32(RTE_PTR_ADD(dst, 0 * 4), buffer[3]);
			break;
		case 2 * 4:
			_mm_stream_si32(RTE_PTR_ADD(dst, 0 * 4), buffer[2]);
			_mm_stream_si32(RTE_PTR_ADD(dst, 1 * 4), buffer[3]);
			break;
		case 3 * 4:
			_mm_stream_si32(RTE_PTR_ADD(dst, 0 * 4), buffer[1]);
			_mm_stream_si32(RTE_PTR_ADD(dst, 1 * 4), buffer[2]);
			_mm_stream_si32(RTE_PTR_ADD(dst, 2 * 4), buffer[3]);
			break;
		}

		src = RTE_PTR_ADD(src, first);
		dst = RTE_PTR_ADD(dst, first);
		len -= first;

		/* Source pointer is now 16 byte aligned. */
		RTE_ASSERT(rte_is_aligned(src, 16));

		/* Then, copy the rest, using corrected alignment flags. */
		if (rte_is_aligned(dst, 16))
			rte_memcpy_nt_d16s16a(dst, src, len, (flags &
					~(RTE_MEMOPS_F_DSTA_MASK | RTE_MEMOPS_F_SRCA_MASK |
					RTE_MEMOPS_F_LENA_MASK)) |
					RTE_MEMOPS_F_DST16A | RTE_MEMOPS_F_SRC16A |
					(((flags & RTE_MEMOPS_F_LENA_MASK) >= RTE_MEMOPS_F_LEN4A) ?
					RTE_MEMOPS_F_LEN4A : (flags & RTE_MEMOPS_F_LEN2A)));
#ifdef RTE_ARCH_X86_64
		else if (rte_is_aligned(dst, 8))
			rte_memcpy_nt_d8s16a(dst, src, len, (flags &
					~(RTE_MEMOPS_F_DSTA_MASK | RTE_MEMOPS_F_SRCA_MASK |
					RTE_MEMOPS_F_LENA_MASK)) |
					RTE_MEMOPS_F_DST8A | RTE_MEMOPS_F_SRC16A |
					(((flags & RTE_MEMOPS_F_LENA_MASK) >= RTE_MEMOPS_F_LEN4A) ?
					RTE_MEMOPS_F_LEN4A : (flags & RTE_MEMOPS_F_LEN2A)));
#endif /* RTE_ARCH_X86_64 */
		else
			rte_memcpy_nt_d4s16a(dst, src, len, (flags &
					~(RTE_MEMOPS_F_DSTA_MASK | RTE_MEMOPS_F_SRCA_MASK |
					RTE_MEMOPS_F_LENA_MASK)) |
					RTE_MEMOPS_F_DST4A | RTE_MEMOPS_F_SRC16A |
					(((flags & RTE_MEMOPS_F_LENA_MASK) >= RTE_MEMOPS_F_LEN4A) ?
					RTE_MEMOPS_F_LEN4A : (flags & RTE_MEMOPS_F_LEN2A)));
	}
}

#ifndef RTE_MEMCPY_NT_BUFSIZE

#include <lib/mbuf/rte_mbuf_core.h>

/** Bounce buffer size for non-temporal memcpy.
 *
 * Must be 2^N and >= 128.
 * The actual buffer will be slightly larger, due to added padding.
 * The default is chosen to be able to handle a non-segmented packet.
 */
#define RTE_MEMCPY_NT_BUFSIZE RTE_MBUF_DEFAULT_DATAROOM

#endif  /* RTE_MEMCPY_NT_BUFSIZE */

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Non-temporal memory copy via bounce buffer.
 *
 * @note
 * If the destination and/or length is unaligned, the first and/or last copied
 * bytes will be stored in the destination memory area using temporal access.
 *
 * @param dst
 *   Pointer to the non-temporal destination memory area.
 * @param src
 *   Pointer to the non-temporal source memory area.
 * @param len
 *   Number of bytes to copy.
 *   Must be <= RTE_MEMCPY_NT_BUFSIZE.
 * @param flags
 *   Hints for memory access.
 */
__rte_experimental
static __rte_always_inline
__attribute__((__nonnull__(1, 2)))
#if defined(RTE_TOOLCHAIN_GCC) && (GCC_VERSION >= 100000)
__attribute__((__access__(write_only, 1, 3), __access__(read_only, 2, 3)))
#endif
void rte_memcpy_nt_buf(void *__rte_restrict dst, const void *__rte_restrict src, size_t len,
		const uint64_t flags)
{
	/** Cache line aligned bounce buffer with preceding and trailing padding.
	 *
	 * The preceding padding is one cache line, so the data area itself
	 * is cache line aligned.
	 * The trailing padding is 16 bytes, leaving room for the trailing bytes
	 * of a 16 byte store operation.
	 */
	char			buffer[RTE_CACHE_LINE_SIZE + RTE_MEMCPY_NT_BUFSIZE +  16]
				__rte_cache_aligned;
	/** Pointer to bounce buffer's aligned data area. */
	char		* const buf0 = &buffer[RTE_CACHE_LINE_SIZE];
	void		       *buf;
	/** Number of bytes to copy from source, incl. any extra preceding bytes. */
	size_t			srclen;
	register __m128i	xmm0, xmm1, xmm2, xmm3;

#ifndef RTE_TOOLCHAIN_CLANG /* Clang doesn't support using __builtin_constant_p() like this. */
	RTE_BUILD_BUG_ON(!__builtin_constant_p(flags));
#endif /* !RTE_TOOLCHAIN_CLANG */
	RTE_ASSERT(!(flags & RTE_MEMOPS_F_DSTA_MASK) || rte_is_aligned(dst,
			(flags & RTE_MEMOPS_F_DSTA_MASK) >> RTE_MEMOPS_F_DSTA_SHIFT));
	RTE_ASSERT(!(flags & RTE_MEMOPS_F_SRCA_MASK) || rte_is_aligned(src,
			(flags & RTE_MEMOPS_F_SRCA_MASK) >> RTE_MEMOPS_F_SRCA_SHIFT));
	RTE_ASSERT(!(flags & RTE_MEMOPS_F_LENA_MASK) || (len &
			((flags & RTE_MEMOPS_F_LENA_MASK) >> RTE_MEMOPS_F_LENA_SHIFT) - 1) == 0);

	RTE_ASSERT((flags & (RTE_MEMOPS_F_SRC_NT | RTE_MEMOPS_F_DST_NT)) ==
			(RTE_MEMOPS_F_SRC_NT | RTE_MEMOPS_F_DST_NT));
	RTE_ASSERT(len <= RTE_MEMCPY_NT_BUFSIZE);

	if (unlikely(len == 0))
		return;

	/* Step 1:
	 * Copy data from the source to the bounce buffer's aligned data area,
	 * using aligned non-temporal load from the source,
	 * and unaligned store in the bounce buffer.
	 *
	 * If the source is unaligned, the additional bytes preceding the data will be copied
	 * to the padding area preceding the bounce buffer's aligned data area.
	 * Similarly, if the source data ends at an unaligned address, the additional bytes
	 * trailing the data will be copied to the padding area trailing the bounce buffer's
	 * aligned data area.
	 */

	/* Adjust for extra preceding bytes, unless source is known to be 16 byte aligned. */
	if ((flags & RTE_MEMOPS_F_SRCA_MASK) >= RTE_MEMOPS_F_SRC16A) {
		buf = buf0;
		srclen = len;
	} else {
		/** How many bytes is source offset from 16 byte alignment (floor rounding). */
		const size_t offset = (uintptr_t)src & 15;

		buf = RTE_PTR_SUB(buf0, offset);
		src = RTE_PTR_SUB(src, offset);
		srclen = len + offset;
	}

	/* Copy large portion of data from source to bounce buffer in chunks of 64 byte. */
	while (srclen >= 64) {
		xmm0 = _mm_stream_load_si128_const(RTE_PTR_ADD(src, 0 * 16));
		xmm1 = _mm_stream_load_si128_const(RTE_PTR_ADD(src, 1 * 16));
		xmm2 = _mm_stream_load_si128_const(RTE_PTR_ADD(src, 2 * 16));
		xmm3 = _mm_stream_load_si128_const(RTE_PTR_ADD(src, 3 * 16));
		_mm_storeu_si128(RTE_PTR_ADD(buf, 0 * 16), xmm0);
		_mm_storeu_si128(RTE_PTR_ADD(buf, 1 * 16), xmm1);
		_mm_storeu_si128(RTE_PTR_ADD(buf, 2 * 16), xmm2);
		_mm_storeu_si128(RTE_PTR_ADD(buf, 3 * 16), xmm3);
		src = RTE_PTR_ADD(src, 64);
		buf = RTE_PTR_ADD(buf, 64);
		srclen -= 64;
	}

	/* Copy remaining 32 and 16 byte portions of data from source to bounce buffer.
	 *
	 * Omitted if source is known to be 16 byte aligned (so the length alignment
	 * flags are still valid)
	 * and length is known to be respectively 64 or 32 byte aligned.
	 */
	if (!(((flags & RTE_MEMOPS_F_SRCA_MASK) >= RTE_MEMOPS_F_SRC16A) &&
			((flags & RTE_MEMOPS_F_LENA_MASK) >= RTE_MEMOPS_F_LEN64A)) &&
			(srclen & 32)) {
		xmm0 = _mm_stream_load_si128_const(RTE_PTR_ADD(src, 0 * 16));
		xmm1 = _mm_stream_load_si128_const(RTE_PTR_ADD(src, 1 * 16));
		_mm_storeu_si128(RTE_PTR_ADD(buf, 0 * 16), xmm0);
		_mm_storeu_si128(RTE_PTR_ADD(buf, 1 * 16), xmm1);
		src = RTE_PTR_ADD(src, 32);
		buf = RTE_PTR_ADD(buf, 32);
	}
	if (!(((flags & RTE_MEMOPS_F_SRCA_MASK) >= RTE_MEMOPS_F_SRC16A) &&
			((flags & RTE_MEMOPS_F_LENA_MASK) >= RTE_MEMOPS_F_LEN32A)) &&
			(srclen & 16)) {
		xmm2 = _mm_stream_load_si128_const(src);
		_mm_storeu_si128(buf, xmm2);
		src = RTE_PTR_ADD(src, 16);
		buf = RTE_PTR_ADD(buf, 16);
	}
	/* Copy any trailing bytes of data from source to bounce buffer.
	 *
	 * Omitted if source is known to be 16 byte aligned (so the length alignment
	 * flags are still valid)
	 * and length is known to be 16 byte aligned.
	 */
	if (!(((flags & RTE_MEMOPS_F_SRCA_MASK) >= RTE_MEMOPS_F_SRC16A) &&
			((flags & RTE_MEMOPS_F_LENA_MASK) >= RTE_MEMOPS_F_LEN16A)) &&
			(srclen & 15)) {
		xmm3 = _mm_stream_load_si128_const(src);
		_mm_storeu_si128(buf, xmm3);
	}

	/* Step 2:
	 * Copy from the aligned bounce buffer to the non-temporal destination.
	 */
	rte_memcpy_ntd(dst, buf0, len,
			(flags & ~(RTE_MEMOPS_F_SRC_NT | RTE_MEMOPS_F_SRCA_MASK)) |
			(RTE_CACHE_LINE_SIZE << RTE_MEMOPS_F_SRCA_SHIFT));
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Non-temporal memory copy.
 * The memory areas must not overlap.
 *
 * @note
 * If the destination and/or length is unaligned, some copied bytes will be
 * stored in the destination memory area using temporal access.
 *
 * @param dst
 *   Pointer to the non-temporal destination memory area.
 * @param src
 *   Pointer to the non-temporal source memory area.
 * @param len
 *   Number of bytes to copy.
 * @param flags
 *   Hints for memory access.
 */
__rte_experimental
static __rte_always_inline
__attribute__((__nonnull__(1, 2)))
#if defined(RTE_TOOLCHAIN_GCC) && (GCC_VERSION >= 100000)
__attribute__((__access__(write_only, 1, 3), __access__(read_only, 2, 3)))
#endif
void rte_memcpy_nt_generic(void *__rte_restrict dst, const void *__rte_restrict src, size_t len,
		const uint64_t flags)
{
#ifndef RTE_TOOLCHAIN_CLANG /* Clang doesn't support using __builtin_constant_p() like this. */
	RTE_BUILD_BUG_ON(!__builtin_constant_p(flags));
#endif /* !RTE_TOOLCHAIN_CLANG */

	while (len > RTE_MEMCPY_NT_BUFSIZE) {
		rte_memcpy_nt_buf(dst, src, RTE_MEMCPY_NT_BUFSIZE,
				(flags & ~RTE_MEMOPS_F_LENA_MASK) | RTE_MEMOPS_F_LEN128A);
		dst = RTE_PTR_ADD(dst, RTE_MEMCPY_NT_BUFSIZE);
		src = RTE_PTR_ADD(src, RTE_MEMCPY_NT_BUFSIZE);
		len -= RTE_MEMCPY_NT_BUFSIZE;
	}
	rte_memcpy_nt_buf(dst, src, len, flags);
}

/* Implementation. Refer to function declaration for documentation. */
__rte_experimental
static __rte_always_inline
__attribute__((__nonnull__(1, 2)))
#if defined(RTE_TOOLCHAIN_GCC) && (GCC_VERSION >= 100000)
__attribute__((__access__(write_only, 1, 3), __access__(read_only, 2, 3)))
#endif
void rte_memcpy_ex(void *__rte_restrict dst, const void *__rte_restrict src, size_t len,
		const uint64_t flags)
{
#ifndef RTE_TOOLCHAIN_CLANG /* Clang doesn't support using __builtin_constant_p() like this. */
	RTE_BUILD_BUG_ON(!__builtin_constant_p(flags));
#endif /* !RTE_TOOLCHAIN_CLANG */
	RTE_ASSERT(!(flags & RTE_MEMOPS_F_DSTA_MASK) || rte_is_aligned(dst,
			(flags & RTE_MEMOPS_F_DSTA_MASK) >> RTE_MEMOPS_F_DSTA_SHIFT));
	RTE_ASSERT(!(flags & RTE_MEMOPS_F_SRCA_MASK) || rte_is_aligned(src,
			(flags & RTE_MEMOPS_F_SRCA_MASK) >> RTE_MEMOPS_F_SRCA_SHIFT));
	RTE_ASSERT(!(flags & RTE_MEMOPS_F_LENA_MASK) || (len &
			((flags & RTE_MEMOPS_F_LENA_MASK) >> RTE_MEMOPS_F_LENA_SHIFT) - 1) == 0);

	if ((flags & (RTE_MEMOPS_F_DST_NT | RTE_MEMOPS_F_SRC_NT)) ==
			(RTE_MEMOPS_F_DST_NT | RTE_MEMOPS_F_SRC_NT)) {
		/* Copy between non-temporal source and destination. */
		if ((flags & RTE_MEMOPS_F_DSTA_MASK) >= RTE_MEMOPS_F_DST16A &&
				(flags & RTE_MEMOPS_F_SRCA_MASK) >= RTE_MEMOPS_F_SRC16A)
			rte_memcpy_nt_d16s16a(dst, src, len, flags);
#ifdef RTE_ARCH_X86_64
		else if ((flags & RTE_MEMOPS_F_DSTA_MASK) >= RTE_MEMOPS_F_DST8A &&
				(flags & RTE_MEMOPS_F_SRCA_MASK) >= RTE_MEMOPS_F_SRC16A)
			rte_memcpy_nt_d8s16a(dst, src, len, flags);
#endif /* RTE_ARCH_X86_64 */
		else if ((flags & RTE_MEMOPS_F_DSTA_MASK) >= RTE_MEMOPS_F_DST4A &&
				(flags & RTE_MEMOPS_F_SRCA_MASK) >= RTE_MEMOPS_F_SRC16A)
			rte_memcpy_nt_d4s16a(dst, src, len, flags);
		else if ((flags & RTE_MEMOPS_F_DSTA_MASK) >= RTE_MEMOPS_F_DST4A &&
				(flags & RTE_MEMOPS_F_SRCA_MASK) >= RTE_MEMOPS_F_SRC4A)
			rte_memcpy_nt_d4s4a(dst, src, len, flags);
		else if (len <= RTE_MEMCPY_NT_BUFSIZE)
			rte_memcpy_nt_buf(dst, src, len, flags);
		else
			rte_memcpy_nt_generic(dst, src, len, flags);
	} else if (flags & RTE_MEMOPS_F_SRC_NT) {
		/* Copy from non-temporal source. */
		rte_memcpy_nts(dst, src, len, flags);
	} else if (flags & RTE_MEMOPS_F_DST_NT) {
		/* Copy to non-temporal destination. */
		rte_memcpy_ntd(dst, src, len, flags);
	} else
		rte_memcpy(dst, src, len);
}

#undef ALIGNMENT_MASK

#if defined(RTE_TOOLCHAIN_GCC) && (GCC_VERSION >= 100000)
#pragma GCC diagnostic pop
#endif

#ifdef __cplusplus
}
#endif

#endif /* _RTE_MEMCPY_X86_64_H_ */

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
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
	uintptr_t dstu = (uintptr_t)dst;
	uintptr_t srcu = (uintptr_t)src;
	void *ret = dst;
	size_t dstofss;
	size_t bits;

	/**
	 * Copy less than 16 bytes
	 */
	if (n < 16) {
		if (n & 0x01) {
			*(uint8_t *)dstu = *(const uint8_t *)srcu;
			srcu = (uintptr_t)((const uint8_t *)srcu + 1);
			dstu = (uintptr_t)((uint8_t *)dstu + 1);
		}
		if (n & 0x02) {
			*(uint16_t *)dstu = *(const uint16_t *)srcu;
			srcu = (uintptr_t)((const uint16_t *)srcu + 1);
			dstu = (uintptr_t)((uint16_t *)dstu + 1);
		}
		if (n & 0x04) {
			*(uint32_t *)dstu = *(const uint32_t *)srcu;
			srcu = (uintptr_t)((const uint32_t *)srcu + 1);
			dstu = (uintptr_t)((uint32_t *)dstu + 1);
		}
		if (n & 0x08)
			*(uint64_t *)dstu = *(const uint64_t *)srcu;
		return ret;
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
 * Copy 128-byte blocks from one location to another,
 * locations should not overlap.
 */
static __rte_always_inline void
rte_mov128blocks(uint8_t *dst, const uint8_t *src, size_t n)
{
	__m256i ymm0, ymm1, ymm2, ymm3;

	while (n >= 128) {
		ymm0 = _mm256_loadu_si256((const __m256i *)((const uint8_t *)src + 0 * 32));
		n -= 128;
		ymm1 = _mm256_loadu_si256((const __m256i *)((const uint8_t *)src + 1 * 32));
		ymm2 = _mm256_loadu_si256((const __m256i *)((const uint8_t *)src + 2 * 32));
		ymm3 = _mm256_loadu_si256((const __m256i *)((const uint8_t *)src + 3 * 32));
		src = (const uint8_t *)src + 128;
		_mm256_storeu_si256((__m256i *)((uint8_t *)dst + 0 * 32), ymm0);
		_mm256_storeu_si256((__m256i *)((uint8_t *)dst + 1 * 32), ymm1);
		_mm256_storeu_si256((__m256i *)((uint8_t *)dst + 2 * 32), ymm2);
		_mm256_storeu_si256((__m256i *)((uint8_t *)dst + 3 * 32), ymm3);
		dst = (uint8_t *)dst + 128;
	}
}

#if defined RTE_MEMCPY_AMDEPYC2

/**
 * Copy 16 bytes from one location to another,
 * with temporal stores
 */
static __rte_always_inline void
rte_copy16_ts(uint8_t *dst, uint8_t *src)
{
	__m128i var128;

	var128 = _mm_stream_load_si128((__m128i *)src);
	_mm_storeu_si128((__m128i *)dst, var128);
}

/**
 * Copy 32 bytes from one location to another,
 * with temporal stores
 */
static __rte_always_inline void
rte_copy32_ts(uint8_t *dst, uint8_t *src)
{
	__m256i ymm0;

	ymm0 = _mm256_stream_load_si256((const __m256i *)src);
	_mm256_storeu_si256((__m256i *)dst, ymm0);
}

/**
 * Copy 64 bytes from one location to another,
 * with temporal stores
 */
static __rte_always_inline void
rte_copy64_ts(uint8_t *dst, uint8_t *src)
{
	rte_copy32_ts(dst + 0 * 32, src + 0 * 32);
	rte_copy32_ts(dst + 1 * 32, src + 1 * 32);
}

/**
 * Copy 128 bytes from one location to another,
 * with temporal stores
 */
static __rte_always_inline void
rte_copy128_ts(uint8_t *dst, uint8_t *src)
{
	rte_copy32_ts(dst + 0 * 32, src + 0 * 32);
	rte_copy32_ts(dst + 1 * 32, src + 1 * 32);
	rte_copy32_ts(dst + 2 * 32, src + 2 * 32);
	rte_copy32_ts(dst + 3 * 32, src + 3 * 32);
}

/**
 * Copy len bytes from one location to another,
 * with temporal stores 16B aligned
 */
static __rte_always_inline void *
rte_memcpy_aligned_tstore16_generic(void *dst, void *src, int len)
{
	void *dest = dst;

	while (len >= 128) {
		rte_copy128_ts((uint8_t *)dst, (uint8_t *)src);
		dst = (uint8_t *)dst + 128;
		src = (uint8_t *)src + 128;
		len -= 128;
	}
	while (len >= 64) {
		rte_copy64_ts((uint8_t *)dst, (uint8_t *)src);
		dst = (uint8_t *)dst + 64;
		src = (uint8_t *)src + 64;
		len -= 64;
	}
	while (len >= 32) {
		rte_copy32_ts((uint8_t *)dst, (uint8_t *)src);
		dst = (uint8_t *)dst + 32;
		src = (uint8_t *)src + 32;
		len -= 32;
	}
	if (len >= 16) {
		rte_copy16_ts((uint8_t *)dst, (uint8_t *)src);
		dst = (uint8_t *)dst + 16;
		src = (uint8_t *)src + 16;
		len -= 16;
	}
	if (len >= 8) {
		*(uint64_t *)dst = *(const uint64_t *)src;
		dst = (uint8_t *)dst + 8;
		src = (uint8_t *)src + 8;
		len -= 8;
	}
	if (len >= 4) {
		*(uint32_t *)dst = *(const uint32_t *)src;
		dst = (uint8_t *)dst + 4;
		src = (uint8_t *)src + 4;
		len -= 4;
	}
	if (len != 0) {
		dst = (uint8_t *)dst - (4 - len);
		src = (uint8_t *)src - (4 - len);
		*(uint32_t *)dst = *(const uint32_t *)src;
	}

	return dest;
}

static __rte_always_inline void *
rte_memcpy_aligned_ntload_tstore16_amdepyc2(void *dst,
					    const void *src,
					    size_t size)
{
	asm volatile goto("movq %0, %%rsi\n\t"
	"movq %1, %%rdi\n\t"
	"movq %2, %%rdx\n\t"
	"cmpq   $(128), %%rdx\n\t"
	"jb     202f\n\t"
	"201:\n\t"
	"vmovntdqa (%%rsi), %%ymm0\n\t"
	"vmovntdqa 32(%%rsi), %%ymm1\n\t"
	"vmovntdqa 64(%%rsi), %%ymm2\n\t"
	"vmovntdqa 96(%%rsi), %%ymm3\n\t"
	"vmovdqu  %%ymm0, (%%rdi)\n\t"
	"vmovdqu  %%ymm1, 32(%%rdi)\n\t"
	"vmovdqu  %%ymm2, 64(%%rdi)\n\t"
	"vmovdqu  %%ymm3, 96(%%rdi)\n\t"
	"addq   $128, %%rsi\n\t"
	"addq   $128, %%rdi\n\t"
	"subq   $128, %%rdx\n\t"
	"jz     %l[done]\n\t"
	"cmpq   $128, %%rdx\n\t" /*Vector Size 32B.  */
	"jae    201b\n\t"
	"202:\n\t"
	"cmpq   $64, %%rdx\n\t"
	"jb     203f\n\t"
	"vmovntdqa (%%rsi), %%ymm0\n\t"
	"vmovntdqa 32(%%rsi), %%ymm1\n\t"
	"vmovdqu  %%ymm0, (%%rdi)\n\t"
	"vmovdqu  %%ymm1, 32(%%rdi)\n\t"
	"addq   $64, %%rsi\n\t"
	"addq   $64, %%rdi\n\t"
	"subq   $64, %%rdx\n\t"
	"jz     %l[done]\n\t"
	"203:\n\t"
	"cmpq   $32, %%rdx\n\t"
	"jb     204f\n\t"
	"vmovntdqa (%%rsi), %%ymm0\n\t"
	"vmovdqu  %%ymm0, (%%rdi)\n\t"
	"addq   $32, %%rsi\n\t"
	"addq   $32, %%rdi\n\t"
	"subq   $32, %%rdx\n\t"
	"jz     %l[done]\n\t"
	"204:\n\t"
	"cmpb   $16, %%dl\n\t"
	"jb     205f\n\t"
	"vmovntdqa (%%rsi), %%xmm0\n\t"
	"vmovdqu  %%xmm0, (%%rdi)\n\t"
	"addq   $16, %%rsi\n\t"
	"addq   $16, %%rdi\n\t"
	"subq   $16, %%rdx\n\t"
	"jz     %l[done]\n\t"
	"205:\n\t"
	"cmpb   $2, %%dl\n\t"
	"jb     208f\n\t"
	"cmpb   $4, %%dl\n\t"
	"jbe    207f\n\t"
	"cmpb   $8, %%dl\n\t"
	"jbe    206f\n\t"
	"movq   -8(%%rsi,%%rdx), %%rcx\n\t"
	"movq   (%%rsi), %%rsi\n\t"
	"movq   %%rcx, -8(%%rdi,%%rdx)\n\t"
	"movq   %%rsi, (%%rdi)\n\t"
	"jmp    %l[done]\n\t"
	"206:\n\t"
	"movl   -4(%%rsi,%%rdx), %%ecx\n\t"
	"movl   (%%rsi), %%esi\n\t"
	"movl   %%ecx, -4(%%rdi,%%rdx)\n\t"
	"movl   %%esi, (%%rdi)\n\t"
	"jmp    %l[done]\n\t"
	"207:\n\t"
	"movzwl -2(%%rsi,%%rdx), %%ecx\n\t"
	"movzwl (%%rsi), %%esi\n\t"
	"movw   %%cx, -2(%%rdi,%%rdx)\n\t"
	"movw   %%si, (%%rdi)\n\t"
	"jmp    %l[done]\n\t"
	"208:\n\t"
	"movzbl (%%rsi), %%ecx\n\t"
	"movb   %%cl, (%%rdi)"
	:
	: "r"(src), "r"(dst), "r"(size)
	: "rcx", "rdx", "rsi", "rdi", "ymm0", "ymm1", "ymm2", "ymm3", "memory"
	: done
	);
done:
	return dst;
}

static __rte_always_inline void *
rte_memcpy_generic(void *dst, const void *src, size_t len)
{
	asm goto("movq	%0, %%rsi\n\t"
	"movq	%1, %%rdi\n\t"
	"movq	%2, %%rdx\n\t"
	"movq    %%rdi, %%rax\n\t"
	"cmp     $32, %%rdx\n\t"
	"jb      101f\n\t"
	"cmp     $(32 * 2), %%rdx\n\t"
	"ja      108f\n\t"
	"vmovdqu   (%%rsi), %%ymm0\n\t"
	"vmovdqu   -32(%%rsi,%%rdx), %%ymm1\n\t"
	"vmovdqu   %%ymm0, (%%rdi)\n\t"
	"vmovdqu   %%ymm1, -32(%%rdi,%%rdx)\n\t"
	"vzeroupper\n\t"
	"jmp %l[done]\n\t"
	"101:\n\t"
	/* Less than 1 VEC.  */
	"cmpb    $32, %%dl\n\t"
	"jae     103f\n\t"
	"cmpb    $16, %%dl\n\t"
	"jae     104f\n\t"
	"cmpb    $8, %%dl\n\t"
	"jae     105f\n\t"
	"cmpb    $4, %%dl\n\t"
	"jae     106f\n\t"
	"cmpb    $1, %%dl\n\t"
	"ja      107f\n\t"
	"jb      102f\n\t"
	"movzbl  (%%rsi), %%ecx\n\t"
	"movb    %%cl, (%%rdi)\n\t"
	"102:\n\t"
	"jmp %l[done]\n\t"
	"103:\n\t"
	/* From 32 to 63.  No branch when size == 32.  */
	"vmovdqu (%%rsi), %%ymm0\n\t"
	"vmovdqu -32(%%rsi,%%rdx), %%ymm1\n\t"
	"vmovdqu %%ymm0, (%%rdi)\n\t"
	"vmovdqu %%ymm1, -32(%%rdi,%%rdx)\n\t"
	"vzeroupper\n\t"
	"jmp %l[done]\n\t"
	/* From 16 to 31.  No branch when size == 16.  */
	"104:\n\t"
	"vmovdqu (%%rsi), %%xmm0\n\t"
	"vmovdqu -16(%%rsi,%%rdx), %%xmm1\n\t"
	"vmovdqu %%xmm0, (%%rdi)\n\t"
	"vmovdqu %%xmm1, -16(%%rdi,%%rdx)\n\t"
	"jmp %l[done]\n\t"
	"105:\n\t"
	/* From 8 to 15.  No branch when size == 8.  */
	"movq    -8(%%rsi,%%rdx), %%rcx\n\t"
	"movq    (%%rsi), %%rsi\n\t"
	"movq    %%rcx, -8(%%rdi,%%rdx)\n\t"
	"movq    %%rsi, (%%rdi)\n\t"
	"jmp %l[done]\n\t"
	"106:\n\t"
	/* From 4 to 7.  No branch when size == 4.  */
	"movl    -4(%%rsi,%%rdx), %%ecx\n\t"
	"movl    (%%rsi), %%esi\n\t"
	"movl    %%ecx, -4(%%rdi,%%rdx)\n\t"
	"movl    %%esi, (%%rdi)\n\t"
	"jmp %l[done]\n\t"
	"107:\n\t"
	/* From 2 to 3.  No branch when size == 2.  */
	"movzwl  -2(%%rsi,%%rdx), %%ecx\n\t"
	"movzwl  (%%rsi), %%esi\n\t"
	"movw    %%cx, -2(%%rdi,%%rdx)\n\t"
	"movw    %%si, (%%rdi)\n\t"
	"jmp %l[done]\n\t"
	"108:\n\t"
	/* More than 2 * VEC and there may be overlap between destination */
	/* and source.  */
	"cmpq    $(32 * 8), %%rdx\n\t"
	"ja      111f\n\t"
	"cmpq    $(32 * 4), %%rdx\n\t"
	"jb      109f\n\t"
	/* Copy from 4 * VEC to 8 * VEC, inclusively. */
	"vmovdqu   (%%rsi), %%ymm0\n\t"
	"vmovdqu   32(%%rsi), %%ymm1\n\t"
	"vmovdqu   (32 * 2)(%%rsi), %%ymm2\n\t"
	"vmovdqu   (32 * 3)(%%rsi), %%ymm3\n\t"
	"vmovdqu   -32(%%rsi,%%rdx), %%ymm4\n\t"
	"vmovdqu   -(32 * 2)(%%rsi,%%rdx), %%ymm5\n\t"
	"vmovdqu   -(32 * 3)(%%rsi,%%rdx), %%ymm6\n\t"
	"vmovdqu   -(32 * 4)(%%rsi,%%rdx), %%ymm7\n\t"
	"vmovdqu   %%ymm0, (%%rdi)\n\t"
	"vmovdqu   %%ymm1, 32(%%rdi)\n\t"
	"vmovdqu   %%ymm2, (32 * 2)(%%rdi)\n\t"
	"vmovdqu   %%ymm3, (32 * 3)(%%rdi)\n\t"
	"vmovdqu   %%ymm4, -32(%%rdi,%%rdx)\n\t"
	"vmovdqu   %%ymm5, -(32 * 2)(%%rdi,%%rdx)\n\t"
	"vmovdqu   %%ymm6, -(32 * 3)(%%rdi,%%rdx)\n\t"
	"vmovdqu   %%ymm7, -(32 * 4)(%%rdi,%%rdx)\n\t"
	"vzeroupper\n\t"
	"jmp %l[done]\n\t"
	"109:\n\t"
	/* Copy from 2 * VEC to 4 * VEC. */
	"vmovdqu   (%%rsi), %%ymm0\n\t"
	"vmovdqu   32(%%rsi), %%ymm1\n\t"
	"vmovdqu   -32(%%rsi,%%rdx), %%ymm2\n\t"
	"vmovdqu   -(32 * 2)(%%rsi,%%rdx), %%ymm3\n\t"
	"vmovdqu   %%ymm0, (%%rdi)\n\t"
	"vmovdqu   %%ymm1, 32(%%rdi)\n\t"
	"vmovdqu   %%ymm2, -32(%%rdi,%%rdx)\n\t"
	"vmovdqu   %%ymm3, -(32 * 2)(%%rdi,%%rdx)\n\t"
	"vzeroupper\n\t"
	"110:\n\t"
	"jmp %l[done]\n\t"
	"111:\n\t"
	"cmpq    %%rsi, %%rdi\n\t"
	"ja      113f\n\t"
	/* Source == destination is less common.  */
	"je      110b\n\t"
	/* Load the first VEC and last 4 * VEC to
	 * support overlapping addresses.
	 */
	"vmovdqu   (%%rsi), %%ymm4\n\t"
	"vmovdqu   -32(%%rsi, %%rdx), %%ymm5\n\t"
	"vmovdqu   -(32 * 2)(%%rsi, %%rdx), %%ymm6\n\t"
	"vmovdqu   -(32 * 3)(%%rsi, %%rdx), %%ymm7\n\t"
	"vmovdqu   -(32 * 4)(%%rsi, %%rdx), %%ymm8\n\t"
	/* Save start and stop of the destination buffer.  */
	"movq    %%rdi, %%r11\n\t"
	"leaq    -32(%%rdi, %%rdx), %%rcx\n\t"
	/* Align destination for aligned stores in the loop.  Compute */
	/* how much destination is misaligned.  */
	"movq    %%rdi, %%r8\n\t"
	"andq    $(32 - 1), %%r8\n\t"
	/* Get the negative of offset for alignment.  */
	"subq    $32, %%r8\n\t"
	/* Adjust source.  */
	"subq    %%r8, %%rsi\n\t"
	/* Adjust destination which should be aligned now.  */
	"subq    %%r8, %%rdi\n\t"
	/* Adjust length.  */
	"addq    %%r8, %%rdx\n\t"
	/* Check non-temporal store threshold.  */
	"cmpq	 $(1024*1024), %%rdx\n\t"
	"ja      115f\n\t"
	"112:\n\t"
	/* Copy 4 * VEC a time forward.  */
	"vmovdqu   (%%rsi), %%ymm0\n\t"
	"vmovdqu   32(%%rsi), %%ymm1\n\t"
	"vmovdqu   (32 * 2)(%%rsi), %%ymm2\n\t"
	"vmovdqu   (32 * 3)(%%rsi), %%ymm3\n\t"
	"addq    $(32 * 4), %%rsi\n\t"
	"subq    $(32 * 4), %%rdx\n\t"
	"vmovdqa   %%ymm0, (%%rdi)\n\t"
	"vmovdqa   %%ymm1, 32(%%rdi)\n\t"
	"vmovdqa   %%ymm2, (32 * 2)(%%rdi)\n\t"
	"vmovdqa   %%ymm3, (32 * 3)(%%rdi)\n\t"
	"addq    $(32 * 4), %%rdi\n\t"
	"cmpq    $(32 * 4), %%rdx\n\t"
	"ja      112b\n\t"
	/* Store the last 4 * VEC.  */
	"vmovdqu   %%ymm5, (%%rcx)\n\t"
	"vmovdqu   %%ymm6, -32(%%rcx)\n\t"
	"vmovdqu   %%ymm7, -(32 * 2)(%%rcx)\n\t"
	"vmovdqu   %%ymm8, -(32 * 3)(%%rcx)\n\t"
	/* Store the first VEC.  */
	"vmovdqu   %%ymm4, (%%r11)\n\t"
	"vzeroupper\n\t"
	"jmp %l[done]\n\t"
	"113:\n\t"
	/* Load the first 4*VEC and last VEC to support overlapping addresses.*/
	"vmovdqu   (%%rsi), %%ymm4\n\t"
	"vmovdqu   32(%%rsi), %%ymm5\n\t"
	"vmovdqu   (32 * 2)(%%rsi), %%ymm6\n\t"
	"vmovdqu   (32 * 3)(%%rsi), %%ymm7\n\t"
	"vmovdqu   -32(%%rsi,%%rdx), %%ymm8\n\t"
	/* Save stop of the destination buffer.  */
	"leaq    -32(%%rdi, %%rdx), %%r11\n\t"
	/* Align destination end for aligned stores in the loop.  Compute */
	/* how much destination end is misaligned.  */
	"leaq    -32(%%rsi, %%rdx), %%rcx\n\t"
	"movq    %%r11, %%r9\n\t"
	"movq    %%r11, %%r8\n\t"
	"andq    $(32 - 1), %%r8\n\t"
	/* Adjust source.  */
	"subq    %%r8, %%rcx\n\t"
	/* Adjust the end of destination which should be aligned now.  */
	"subq    %%r8, %%r9\n\t"
	/* Adjust length.  */
	"subq    %%r8, %%rdx\n\t"
	 /* Check non-temporal store threshold.  */
	"cmpq	 $(1024*1024), %%rdx\n\t"
	"ja      117f\n\t"
	"114:\n\t"
	/* Copy 4 * VEC a time backward.  */
	"vmovdqu   (%%rcx), %%ymm0\n\t"
	"vmovdqu   -32(%%rcx), %%ymm1\n\t"
	"vmovdqu   -(32 * 2)(%%rcx), %%ymm2\n\t"
	"vmovdqu   -(32 * 3)(%%rcx), %%ymm3\n\t"
	"subq    $(32 * 4), %%rcx\n\t"
	"subq    $(32 * 4), %%rdx\n\t"
	"vmovdqa   %%ymm0, (%%r9)\n\t"
	"vmovdqa   %%ymm1, -32(%%r9)\n\t"
	"vmovdqa   %%ymm2, -(32 * 2)(%%r9)\n\t"
	"vmovdqa   %%ymm3, -(32 * 3)(%%r9)\n\t"
	"subq    $(32 * 4), %%r9\n\t"
	"cmpq    $(32 * 4), %%rdx\n\t"
	"ja      114b\n\t"
	/* Store the first 4 * VEC. */
	"vmovdqu   %%ymm4, (%%rdi)\n\t"
	"vmovdqu   %%ymm5, 32(%%rdi)\n\t"
	"vmovdqu   %%ymm6, (32 * 2)(%%rdi)\n\t"
	"vmovdqu   %%ymm7, (32 * 3)(%%rdi)\n\t"
	/* Store the last VEC. */
	"vmovdqu   %%ymm8, (%%r11)\n\t"
	"vzeroupper\n\t"
	"jmp %l[done]\n\t"

	"115:\n\t"
	/* Don't use non-temporal store if there is overlap between */
	/* destination and source since destination may be in cache */
	/* when source is loaded. */
	"leaq    (%%rdi, %%rdx), %%r10\n\t"
	"cmpq    %%r10, %%rsi\n\t"
	"jb      112b\n\t"
	"116:\n\t"
	/* Copy 4 * VEC a time forward with non-temporal stores.  */
	"prefetcht0 (32*4*2)(%%rsi)\n\t"
	"prefetcht0 (32*4*2 + 64)(%%rsi)\n\t"
	"prefetcht0 (32*4*3)(%%rsi)\n\t"
	"prefetcht0 (32*4*3 + 64)(%%rsi)\n\t"
	"vmovdqu   (%%rsi), %%ymm0\n\t"
	"vmovdqu   32(%%rsi), %%ymm1\n\t"
	"vmovdqu   (32 * 2)(%%rsi), %%ymm2\n\t"
	"vmovdqu   (32 * 3)(%%rsi), %%ymm3\n\t"
	"addq    $(32*4), %%rsi\n\t"
	"subq    $(32*4), %%rdx\n\t"
	"vmovntdq  %%ymm0, (%%rdi)\n\t"
	"vmovntdq  %%ymm1, 32(%%rdi)\n\t"
	"vmovntdq  %%ymm2, (32 * 2)(%%rdi)\n\t"
	"vmovntdq  %%ymm3, (32 * 3)(%%rdi)\n\t"
	"addq    $(32*4), %%rdi\n\t"
	"cmpq    $(32*4), %%rdx\n\t"
	"ja      116b\n\t"
	"sfence\n\t"
	/* Store the last 4 * VEC.  */
	"vmovdqu   %%ymm5, (%%rcx)\n\t"
	"vmovdqu   %%ymm6, -32(%%rcx)\n\t"
	"vmovdqu   %%ymm7, -(32 * 2)(%%rcx)\n\t"
	"vmovdqu   %%ymm8, -(32 * 3)(%%rcx)\n\t"
	/* Store the first VEC.  */
	"vmovdqu   %%ymm4, (%%r11)\n\t"
	"vzeroupper\n\t"
	"jmp %l[done]\n\t"
	"117:\n\t"
	/* Don't use non-temporal store if there is overlap between */
	/* destination and source since destination may be in cache */
	/* when source is loaded.  */
	"leaq    (%%rcx, %%rdx), %%r10\n\t"
	"cmpq    %%r10, %%r9\n\t"
	"jb      114b\n\t"
	"118:\n\t"
	/* Copy 4 * VEC a time backward with non-temporal stores. */
	"prefetcht0 (-32 * 4 * 2)(%%rcx)\n\t"
	"prefetcht0 (-32 * 4 * 2 - 64)(%%rcx)\n\t"
	"prefetcht0 (-32 * 4 * 3)(%%rcx)\n\t"
	"prefetcht0 (-32 * 4 * 3 - 64)(%%rcx)\n\t"
	"vmovdqu   (%%rcx), %%ymm0\n\t"
	"vmovdqu   -32(%%rcx), %%ymm1\n\t"
	"vmovdqu   -(32 * 2)(%%rcx), %%ymm2\n\t"
	"vmovdqu   -(32 * 3)(%%rcx), %%ymm3\n\t"
	"subq    $(32*4), %%rcx\n\t"
	"subq    $(32*4), %%rdx\n\t"
	"vmovntdq  %%ymm0, (%%r9)\n\t"
	"vmovntdq  %%ymm1, -32(%%r9)\n\t"
	"vmovntdq  %%ymm2, -(32 * 2)(%%r9)\n\t"
	"vmovntdq  %%ymm3, -(32 * 3)(%%r9)\n\t"
	"subq    $(32 * 4), %%r9\n\t"
	"cmpq    $(32 * 4), %%rdx\n\t"
	"ja      118b\n\t"
	"sfence\n\t"
	/* Store the first 4 * VEC.  */
	"vmovdqu   %%ymm4, (%%rdi)\n\t"
	"vmovdqu   %%ymm5, 32(%%rdi)\n\t"
	"vmovdqu   %%ymm6, (32 * 2)(%%rdi)\n\t"
	"vmovdqu   %%ymm7, (32 * 3)(%%rdi)\n\t"
	/* Store the last VEC.  */
	"vmovdqu   %%ymm8, (%%r11)\n\t"
	"vzeroupper\n\t"
	"jmp %l[done]"
	:
	: "r"(src), "r"(dst), "r"(len)
	: "rax", "rcx", "rdx", "rdi", "rsi", "r8", "r9", "r10", "r11", "r12", "ymm0",
	"ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7", "ymm8", "memory"
	: done
	);
done:
	return dst;
}

#else
static __rte_always_inline void *
rte_memcpy_generic(void *dst, const void *src, size_t n)
{
	uintptr_t dstu = (uintptr_t)dst;
	uintptr_t srcu = (uintptr_t)src;
	void *ret = dst;
	size_t dstofss;
	size_t bits;

	/**
	 * Copy less than 16 bytes
	 */
	if (n < 16) {
		if (n & 0x01) {
			*(uint8_t *)dstu = *(const uint8_t *)srcu;
			srcu = (uintptr_t)((const uint8_t *)srcu + 1);
			dstu = (uintptr_t)((uint8_t *)dstu + 1);
		}
		if (n & 0x02) {
			*(uint16_t *)dstu = *(const uint16_t *)srcu;
			srcu = (uintptr_t)((const uint16_t *)srcu + 1);
			dstu = (uintptr_t)((uint16_t *)dstu + 1);
		}
		if (n & 0x04) {
			*(uint32_t *)dstu = *(const uint32_t *)srcu;
			srcu = (uintptr_t)((const uint32_t *)srcu + 1);
			dstu = (uintptr_t)((uint32_t *)dstu + 1);
		}
		if (n & 0x08) {
			*(uint64_t *)dstu = *(const uint64_t *)srcu;
		}
		return ret;
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

#endif /* RTE_MEMCPY_AMDEPYC2 */

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

	xmm0 = _mm_loadu_si128((const __m128i *)(const __m128i *)src);
	_mm_storeu_si128((__m128i *)dst, xmm0);
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
        xmm0 = _mm_loadu_si128((const __m128i *)((const uint8_t *)src - offset + 0 * 16));                  \
        len -= 128;                                                                                         \
        xmm1 = _mm_loadu_si128((const __m128i *)((const uint8_t *)src - offset + 1 * 16));                  \
        xmm2 = _mm_loadu_si128((const __m128i *)((const uint8_t *)src - offset + 2 * 16));                  \
        xmm3 = _mm_loadu_si128((const __m128i *)((const uint8_t *)src - offset + 3 * 16));                  \
        xmm4 = _mm_loadu_si128((const __m128i *)((const uint8_t *)src - offset + 4 * 16));                  \
        xmm5 = _mm_loadu_si128((const __m128i *)((const uint8_t *)src - offset + 5 * 16));                  \
        xmm6 = _mm_loadu_si128((const __m128i *)((const uint8_t *)src - offset + 6 * 16));                  \
        xmm7 = _mm_loadu_si128((const __m128i *)((const uint8_t *)src - offset + 7 * 16));                  \
        xmm8 = _mm_loadu_si128((const __m128i *)((const uint8_t *)src - offset + 8 * 16));                  \
        src = (const uint8_t *)src + 128;                                                                   \
        _mm_storeu_si128((__m128i *)((uint8_t *)dst + 0 * 16), _mm_alignr_epi8(xmm1, xmm0, offset));        \
        _mm_storeu_si128((__m128i *)((uint8_t *)dst + 1 * 16), _mm_alignr_epi8(xmm2, xmm1, offset));        \
        _mm_storeu_si128((__m128i *)((uint8_t *)dst + 2 * 16), _mm_alignr_epi8(xmm3, xmm2, offset));        \
        _mm_storeu_si128((__m128i *)((uint8_t *)dst + 3 * 16), _mm_alignr_epi8(xmm4, xmm3, offset));        \
        _mm_storeu_si128((__m128i *)((uint8_t *)dst + 4 * 16), _mm_alignr_epi8(xmm5, xmm4, offset));        \
        _mm_storeu_si128((__m128i *)((uint8_t *)dst + 5 * 16), _mm_alignr_epi8(xmm6, xmm5, offset));        \
        _mm_storeu_si128((__m128i *)((uint8_t *)dst + 6 * 16), _mm_alignr_epi8(xmm7, xmm6, offset));        \
        _mm_storeu_si128((__m128i *)((uint8_t *)dst + 7 * 16), _mm_alignr_epi8(xmm8, xmm7, offset));        \
        dst = (uint8_t *)dst + 128;                                                                         \
    }                                                                                                       \
    tmp = len;                                                                                              \
    len = ((len - 16 + offset) & 127) + 16 - offset;                                                        \
    tmp -= len;                                                                                             \
    src = (const uint8_t *)src + tmp;                                                                       \
    dst = (uint8_t *)dst + tmp;                                                                             \
    if (len >= 32 + 16 - offset) {                                                                          \
        while (len >= 32 + 16 - offset) {                                                                   \
            xmm0 = _mm_loadu_si128((const __m128i *)((const uint8_t *)src - offset + 0 * 16));              \
            len -= 32;                                                                                      \
            xmm1 = _mm_loadu_si128((const __m128i *)((const uint8_t *)src - offset + 1 * 16));              \
            xmm2 = _mm_loadu_si128((const __m128i *)((const uint8_t *)src - offset + 2 * 16));              \
            src = (const uint8_t *)src + 32;                                                                \
            _mm_storeu_si128((__m128i *)((uint8_t *)dst + 0 * 16), _mm_alignr_epi8(xmm1, xmm0, offset));    \
            _mm_storeu_si128((__m128i *)((uint8_t *)dst + 1 * 16), _mm_alignr_epi8(xmm2, xmm1, offset));    \
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
	uintptr_t dstu = (uintptr_t)dst;
	uintptr_t srcu = (uintptr_t)src;
	void *ret = dst;
	size_t dstofss;
	size_t srcofs;

	/**
	 * Copy less than 16 bytes
	 */
	if (n < 16) {
		if (n & 0x01) {
			*(uint8_t *)dstu = *(const uint8_t *)srcu;
			srcu = (uintptr_t)((const uint8_t *)srcu + 1);
			dstu = (uintptr_t)((uint8_t *)dstu + 1);
		}
		if (n & 0x02) {
			*(uint16_t *)dstu = *(const uint16_t *)srcu;
			srcu = (uintptr_t)((const uint16_t *)srcu + 1);
			dstu = (uintptr_t)((uint16_t *)dstu + 1);
		}
		if (n & 0x04) {
			*(uint32_t *)dstu = *(const uint32_t *)srcu;
			srcu = (uintptr_t)((const uint32_t *)srcu + 1);
			dstu = (uintptr_t)((uint32_t *)dstu + 1);
		}
		if (n & 0x08) {
			*(uint64_t *)dstu = *(const uint64_t *)srcu;
		}
		return ret;
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

	/* Copy size <= 16 bytes */
	if (n < 16) {
		if (n & 0x01) {
			*(uint8_t *)dst = *(const uint8_t *)src;
			src = (const uint8_t *)src + 1;
			dst = (uint8_t *)dst + 1;
		}
		if (n & 0x02) {
			*(uint16_t *)dst = *(const uint16_t *)src;
			src = (const uint16_t *)src + 1;
			dst = (uint16_t *)dst + 1;
		}
		if (n & 0x04) {
			*(uint32_t *)dst = *(const uint32_t *)src;
			src = (const uint32_t *)src + 1;
			dst = (uint32_t *)dst + 1;
		}
		if (n & 0x08)
			*(uint64_t *)dst = *(const uint64_t *)src;

		return ret;
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

#if defined __AVX2__ && defined(RTE_MEMCPY_AMDEPYC2)
static __rte_always_inline void *
rte_memcpy_aligned_tstore16(void *dst, void *src, int len)
{
	return rte_memcpy_aligned_ntload_tstore16_amdepyc2(dst, src, len);
}
#endif

#if defined(RTE_TOOLCHAIN_GCC) && (GCC_VERSION >= 100000)
#pragma GCC diagnostic pop
#endif

#ifdef __cplusplus
}
#endif

#endif /* _RTE_MEMCPY_X86_64_H_ */

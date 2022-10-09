/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 * Copyright(c) 2022 SmartShare Systems
 */

#ifndef _RTE_MEMCPY_H_
#define _RTE_MEMCPY_H_

/**
 * @file
 *
 * Functions for vectorised implementation of memcpy().
 */

#include <rte_common.h>
#include <rte_compat.h>

/**
 * Copy 16 bytes from one location to another using optimised
 * instructions. The locations should not overlap.
 *
 * @param dst
 *   Pointer to the destination of the data.
 * @param src
 *   Pointer to the source data.
 */
static inline void
rte_mov16(uint8_t *dst, const uint8_t *src);

/**
 * Copy 32 bytes from one location to another using optimised
 * instructions. The locations should not overlap.
 *
 * @param dst
 *   Pointer to the destination of the data.
 * @param src
 *   Pointer to the source data.
 */
static inline void
rte_mov32(uint8_t *dst, const uint8_t *src);

#ifdef __DOXYGEN__

/**
 * Copy 48 bytes from one location to another using optimised
 * instructions. The locations should not overlap.
 *
 * @param dst
 *   Pointer to the destination of the data.
 * @param src
 *   Pointer to the source data.
 */
static inline void
rte_mov48(uint8_t *dst, const uint8_t *src);

#endif /* __DOXYGEN__ */

/**
 * Copy 64 bytes from one location to another using optimised
 * instructions. The locations should not overlap.
 *
 * @param dst
 *   Pointer to the destination of the data.
 * @param src
 *   Pointer to the source data.
 */
static inline void
rte_mov64(uint8_t *dst, const uint8_t *src);

/**
 * Copy 128 bytes from one location to another using optimised
 * instructions. The locations should not overlap.
 *
 * @param dst
 *   Pointer to the destination of the data.
 * @param src
 *   Pointer to the source data.
 */
static inline void
rte_mov128(uint8_t *dst, const uint8_t *src);

/**
 * Copy 256 bytes from one location to another using optimised
 * instructions. The locations should not overlap.
 *
 * @param dst
 *   Pointer to the destination of the data.
 * @param src
 *   Pointer to the source data.
 */
static inline void
rte_mov256(uint8_t *dst, const uint8_t *src);

#ifdef __DOXYGEN__

/**
 * Copy bytes from one location to another. The locations must not overlap.
 *
 * @note This is implemented as a macro, so it's address should not be taken
 * and care is needed as parameter expressions may be evaluated multiple times.
 *
 * @note For x86 platforms to enable the AVX-512 memcpy implementation, set
 * -DRTE_MEMCPY_AVX512 macro in CFLAGS, or define the RTE_MEMCPY_AVX512 macro
 * explicitly in the source file before including the rte_memcpy header file.
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
static void *
rte_memcpy(void *dst, const void *src, size_t n);

#endif /* __DOXYGEN__ */

/*
 * Advanced/Non-Temporal Memory Operations Flags.
 */

/** Length alignment hint mask. */
#define RTE_MEMOPS_F_LENA_MASK  (UINT64_C(0xFE) << 0)
/** Length alignment hint shift. */
#define RTE_MEMOPS_F_LENA_SHIFT 0
/** Hint: Length is 2 byte aligned. */
#define RTE_MEMOPS_F_LEN2A      (UINT64_C(2) << 0)
/** Hint: Length is 4 byte aligned. */
#define RTE_MEMOPS_F_LEN4A      (UINT64_C(4) << 0)
/** Hint: Length is 8 byte aligned. */
#define RTE_MEMOPS_F_LEN8A      (UINT64_C(8) << 0)
/** Hint: Length is 16 byte aligned. */
#define RTE_MEMOPS_F_LEN16A     (UINT64_C(16) << 0)
/** Hint: Length is 32 byte aligned. */
#define RTE_MEMOPS_F_LEN32A     (UINT64_C(32) << 0)
/** Hint: Length is 64 byte aligned. */
#define RTE_MEMOPS_F_LEN64A     (UINT64_C(64) << 0)
/** Hint: Length is 128 byte aligned. */
#define RTE_MEMOPS_F_LEN128A    (UINT64_C(128) << 0)

/** Prefer non-temporal access to source memory area.
 */
#define RTE_MEMOPS_F_SRC_NT     (UINT64_C(1) << 8)
/** Source address alignment hint mask. */
#define RTE_MEMOPS_F_SRCA_MASK  (UINT64_C(0xFE) << 8)
/** Source address alignment hint shift. */
#define RTE_MEMOPS_F_SRCA_SHIFT 8
/** Hint: Source address is 2 byte aligned. */
#define RTE_MEMOPS_F_SRC2A      (UINT64_C(2) << 8)
/** Hint: Source address is 4 byte aligned. */
#define RTE_MEMOPS_F_SRC4A      (UINT64_C(4) << 8)
/** Hint: Source address is 8 byte aligned. */
#define RTE_MEMOPS_F_SRC8A      (UINT64_C(8) << 8)
/** Hint: Source address is 16 byte aligned. */
#define RTE_MEMOPS_F_SRC16A     (UINT64_C(16) << 8)
/** Hint: Source address is 32 byte aligned. */
#define RTE_MEMOPS_F_SRC32A     (UINT64_C(32) << 8)
/** Hint: Source address is 64 byte aligned. */
#define RTE_MEMOPS_F_SRC64A     (UINT64_C(64) << 8)
/** Hint: Source address is 128 byte aligned. */
#define RTE_MEMOPS_F_SRC128A    (UINT64_C(128) << 8)

/** Prefer non-temporal access to destination memory area.
 *
 * On x86 architecture:
 * Remember to call rte_wmb() after a sequence of copy operations.
 */
#define RTE_MEMOPS_F_DST_NT     (UINT64_C(1) << 16)
/** Destination address alignment hint mask. */
#define RTE_MEMOPS_F_DSTA_MASK  (UINT64_C(0xFE) << 16)
/** Destination address alignment hint shift. */
#define RTE_MEMOPS_F_DSTA_SHIFT 16
/** Hint: Destination address is 2 byte aligned. */
#define RTE_MEMOPS_F_DST2A      (UINT64_C(2) << 16)
/** Hint: Destination address is 4 byte aligned. */
#define RTE_MEMOPS_F_DST4A      (UINT64_C(4) << 16)
/** Hint: Destination address is 8 byte aligned. */
#define RTE_MEMOPS_F_DST8A      (UINT64_C(8) << 16)
/** Hint: Destination address is 16 byte aligned. */
#define RTE_MEMOPS_F_DST16A     (UINT64_C(16) << 16)
/** Hint: Destination address is 32 byte aligned. */
#define RTE_MEMOPS_F_DST32A     (UINT64_C(32) << 16)
/** Hint: Destination address is 64 byte aligned. */
#define RTE_MEMOPS_F_DST64A     (UINT64_C(64) << 16)
/** Hint: Destination address is 128 byte aligned. */
#define RTE_MEMOPS_F_DST128A    (UINT64_C(128) << 16)

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Advanced/non-temporal memory copy.
 * The memory areas must not overlap.
 *
 * @param dst
 *   Pointer to the destination memory area.
 * @param src
 *   Pointer to the source memory area.
 * @param len
 *   Number of bytes to copy.
 * @param flags
 *   Hints for memory access.
 *   Any of the RTE_MEMOPS_F_(SRC|DST)_NT, RTE_MEMOPS_F_(LEN|SRC|DST)nnnA flags.
 *   Must be constant at build time.
 */
__rte_experimental
static __rte_always_inline
__attribute__((__nonnull__(1, 2)))
#if defined(RTE_TOOLCHAIN_GCC) && (GCC_VERSION >= 100000)
__attribute__((__access__(write_only, 1, 3), __access__(read_only, 2, 3)))
#endif
void rte_memcpy_ex(void *__rte_restrict dst, const void *__rte_restrict src, size_t len,
		const uint64_t flags);

#ifndef RTE_MEMCPY_EX_ARCH_DEFINED

/* Fallback implementation, if no arch-specific implementation is provided. */
__rte_experimental
static __rte_always_inline
__attribute__((__nonnull__(1, 2)))
#if defined(RTE_TOOLCHAIN_GCC) && (GCC_VERSION >= 100000)
__attribute__((__access__(write_only, 1, 3), __access__(read_only, 2, 3)))
#endif
void rte_memcpy_ex(void *__rte_restrict dst, const void *__rte_restrict src, size_t len,
		const uint64_t flags)
{
	RTE_SET_USED(flags);
	memcpy(dst, src, len);
}

#endif /* RTE_MEMCPY_EX_ARCH_DEFINED */

#endif /* _RTE_MEMCPY_H_ */

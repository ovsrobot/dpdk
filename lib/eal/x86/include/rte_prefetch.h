/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#ifndef _RTE_PREFETCH_X86_64_H_
#define _RTE_PREFETCH_X86_64_H_

#ifdef RTE_TOOLCHAIN_MSVC
#include <emmintrin.h>
#endif

#include <rte_compat.h>
#include <rte_common.h>
#include "generic/rte_prefetch.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline void rte_prefetch0(const volatile void *p)
{
#ifdef RTE_TOOLCHAIN_MSVC
	_mm_prefetch((const char *)(uintptr_t)p, _MM_HINT_T0);
#else
	/* 0 indicates intention to read, 3 sets target cache level to L1. See
	 * GCC docs where these integer constants are described in more detail:
	 *  https://gcc.gnu.org/onlinedocs/gcc/Other-Builtins.html
	 */
	__builtin_prefetch((const void *)(uintptr_t)p, 0, 3);
#endif
}

static inline void rte_prefetch1(const volatile void *p)
{
#ifdef RTE_TOOLCHAIN_MSVC
	_mm_prefetch((const char *)(uintptr_t)p, _MM_HINT_T1);
#else
	/* 0 indicates intention to read, 2 sets target cache level to L2. See
	 * GCC docs where these integer constants are described in more detail:
	 *  https://gcc.gnu.org/onlinedocs/gcc/Other-Builtins.html
	 */
	__builtin_prefetch((const void *)(uintptr_t)p, 0, 2);
#endif
}

static inline void rte_prefetch2(const volatile void *p)
{
#ifdef RTE_TOOLCHAIN_MSVC
	_mm_prefetch((const char *)(uintptr_t)p, _MM_HINT_T2);
#else
	/* 0 indicates intention to read, 1 sets target cache level to L3. See
	 * GCC docs where these integer constants are described in more detail:
	 *  https://gcc.gnu.org/onlinedocs/gcc/Other-Builtins.html
	 */
	__builtin_prefetch((const void *)(uintptr_t)p, 0, 1);
#endif
}

static inline void rte_prefetch_non_temporal(const volatile void *p)
{
#ifdef RTE_TOOLCHAIN_MSVC
	_mm_prefetch((const char *)(uintptr_t)p, _MM_HINT_NTA);
#else
	/* 0 indicates intention to read, 1 sets target cache level to L3. See
	 * GCC docs where these integer constants are described in more detail:
	 *  https://gcc.gnu.org/onlinedocs/gcc/Other-Builtins.html
	 */
	__builtin_prefetch((const void *)(uintptr_t)p, 0, 0);
#endif
}

__rte_experimental
static inline void
rte_cldemote(const volatile void *p)
{
#ifdef RTE_TOOLCHAIN_MSVC
	_mm_cldemote((const void *)(uintptr_t)p);
#else
	/*
	 * We use raw byte codes for now as only the newest compiler
	 * versions support this instruction natively.
	 */
	asm volatile(".byte 0x0f, 0x1c, 0x06" :: "S" (p));
#endif
}

#ifdef __cplusplus
}
#endif

#endif /* _RTE_PREFETCH_X86_64_H_ */

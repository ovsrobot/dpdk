/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#ifndef _RTE_PREFETCH_X86_64_H_
#define _RTE_PREFETCH_X86_64_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <emmintrin.h>

#include <rte_compat.h>
#include <rte_common.h>
#include "generic/rte_prefetch.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"

static inline void rte_prefetch0(const volatile void *p)
{
	_mm_prefetch((const void *)p, _MM_HINT_T0);
}

static inline void rte_prefetch1(const volatile void *p)
{
	_mm_prefetch((const void *)p, _MM_HINT_T1);
}

static inline void rte_prefetch2(const volatile void *p)
{
	_mm_prefetch((const void *)p, _MM_HINT_T2);
}

static inline void rte_prefetch_non_temporal(const volatile void *p)
{
	_mm_prefetch((const void *)p, _MM_HINT_NTA);
}

#pragma GCC diagnostic pop

#ifndef RTE_TOOLCHAIN_MSVC
/*
 * We use raw byte codes for now as only the newest compiler
 * versions support this instruction natively.
 */
__rte_experimental
static inline void
rte_cldemote(const volatile void *p)
{
	asm volatile(".byte 0x0f, 0x1c, 0x06" :: "S" (p));
}
#else
__rte_experimental
static inline void
rte_cldemote(const volatile void *p)
{
	_mm_cldemote(p);
}
#endif


#ifdef __cplusplus
}
#endif

#endif /* _RTE_PREFETCH_X86_64_H_ */

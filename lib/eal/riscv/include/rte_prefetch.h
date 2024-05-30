/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2014 IBM Corporation
 * Copyright(c) 2022 StarFive
 * Copyright(c) 2022 SiFive
 * Copyright(c) 2022 Semihalf
 */

#ifndef RTE_PREFETCH_RISCV_H
#define RTE_PREFETCH_RISCV_H

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_compat.h>
#include <rte_common.h>

#ifdef RTE_RISCV_ZICBOP
#define RTE_PREFETCH_WRITE_ARCH_DEFINED
#endif

#include "generic/rte_prefetch.h"

/*
 * Modern versions of GCC & Clang will emit prefetch instructions for
 * __builtin_prefetch when the Zicbop extension is present.
 * The RTE_RISCV_ZICBOP option controls whether we emit them manually for older
 * compilers that may not have the support to assemble them.
 */
static inline void rte_prefetch0(const volatile void *p)
{
#ifndef RTE_RISCV_ZICBOP
	/* by default __builtin_prefetch prepares for a read */
	__builtin_prefetch((const void *)p);
#else
	/* prefetch.r 0(a0) */
	register const volatile void *a0 asm("a0") = p;
	asm volatile (".int 0x00156013" : : "r" (a0));
#endif
}

/*
 * The RISC-V Zicbop extension doesn't have instructions to prefetch to only a
 * subset of cache levels, so fallback to rte_prefetch0
 */
static inline void rte_prefetch1(const volatile void *p)
{
	rte_prefetch0(p);
}
static inline void rte_prefetch2(const volatile void *p)
{
	rte_prefetch0(p);
}

static inline void rte_prefetch_non_temporal(const volatile void *p)
{
	/* non-temporal version not available, fallback to rte_prefetch0 */
	rte_prefetch0(p);
}

__rte_experimental
static inline void
rte_cldemote(const volatile void *p)
{
	RTE_SET_USED(p);
}

#ifdef RTE_RISCV_ZICBOP
__rte_experimental
static inline void
rte_prefetch0_write(const void *p)
{
	/* prefetch.w 0(a0) */
	register const void *a0 asm("a0") = p;
	asm volatile (".int 0x00356013" : : "r" (a0));
}

/*
 * The RISC-V Zicbop extension doesn't have instructions to prefetch to only a
 * subset of cache levels, so fallback to rte_prefetch0_write
 */
__rte_experimental
static inline void
rte_prefetch1_write(const void *p)
{
	rte_prefetch0_write(p);
}
__rte_experimental
static inline void
rte_prefetch2_write(const void *p)
{
	rte_prefetch0_write(p);
}
#endif /* RTE_RISCV_ZICBOP */

#ifdef __cplusplus
}
#endif

#endif /* RTE_PREFETCH_RISCV_H */

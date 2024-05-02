/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 StarFive
 * Copyright(c) 2022 SiFive
 * Copyright(c) 2022 Semihalf
 */

#ifndef RTE_PAUSE_RISCV_H
#define RTE_PAUSE_RISCV_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef RTE_RISCV_ZAWRS
#define RTE_WAIT_UNTIL_EQUAL_ARCH_DEFINED
#endif

#include <rte_debug.h>

#include "rte_atomic.h"

#include "generic/rte_pause.h"

static inline void rte_pause(void)
{
	/* Insert pause hint directly to be compatible with old compilers.
	 * This will work even on platforms without Zihintpause extension
	 * because this is a FENCE hint instruction which evaluates to NOP.
	 */
	asm volatile(".int 0x0100000F" : : : "memory");
}

#ifdef RTE_RISCV_ZAWRS

/*
 * Atomic load from an address, it returns either a sign-extended word or
 * doubleword and creates a 'reservation set' containing the read memory
 * location. When someone else writes to the reservation set, it is invalidated,
 * causing any stalled WRS instructions to resume.
 *
 * Address needs to be naturally aligned.
 */
#define __RTE_RISCV_LR_32(src, dst, memorder) do {                \
	if ((memorder) == rte_memory_order_relaxed) {             \
		asm volatile("lr.w %0, (%1)"                      \
				: "=r" (dst)                      \
				: "r" (src)                       \
				: "memory");                      \
	} else {                                                  \
		asm volatile("lr.w.aq %0, (%1)"                   \
				: "=r" (dst)                      \
				: "r" (src)                       \
				: "memory");                      \
	} } while (0)
#define __RTE_RISCV_LR_64(src, dst, memorder) do {                \
	if ((memorder) == rte_memory_order_relaxed) {             \
		asm volatile("lr.d %0, (%1)"                      \
				: "=r" (dst)                      \
				: "r" (src)                       \
				: "memory");                      \
	} else {                                                  \
		asm volatile("lr.d.aq %0, (%1)"                   \
				: "=r" (dst)                      \
				: "r" (src)                       \
				: "memory");                      \
	} } while (0)

/*
 * There's not a RISC-V atomic load primitive for halfwords, so cast up to a
 * _naturally aligned_ word and extract the halfword we want
 */
#define __RTE_RISCV_LR_16(src, dst, memorder) do {                      \
	uint32_t word;                                                  \
	__RTE_RISCV_LR_32(((uintptr_t)(src) & (~3)), word, (memorder)); \
	if ((size_t)(src) & 3)                                          \
		(dst) = (typeof(dst))(word >> 16);                      \
	else                                                            \
		(dst) = (typeof(dst))(word & 0xFFFF);                   \
} while (0)

#define __RTE_RISCV_LR(src, dst, memorder, size) {                \
	RTE_BUILD_BUG_ON(size != 16 && size != 32 && size != 64); \
	if (size == 16)                                           \
		__RTE_RISCV_LR_16(src, dst, memorder);            \
	else if (size == 32)                                      \
		__RTE_RISCV_LR_32(src, dst, memorder);            \
	else if (size == 64)                                      \
		__RTE_RISCV_LR_64(src, dst, memorder);            \
}

/*
 * Wait-on-Reservation-Set extension instruction, it stalls execution until the
 * reservation set is invalidated or an interrupt is observed.
 * A loop is likely still needed as it may stop stalling arbitrarily.
 */
#define __RTE_RISCV_WRS_NTO() { asm volatile("wrs.nto" : : : "memory"); }

static __rte_always_inline void
rte_wait_until_equal_16(volatile uint16_t *addr, uint16_t expected,
		int memorder)
{
	uint16_t value;

	RTE_ASSERT(memorder == rte_memory_order_acquire ||
		memorder == rte_memory_order_relaxed);
	RTE_ASSERT(((size_t)addr & 1) == 0);

	__RTE_RISCV_LR_16(addr, value, memorder);
	while (value != expected) {
		__RTE_RISCV_WRS_NTO();
		__RTE_RISCV_LR_16(addr, value, memorder);
	}
}

static __rte_always_inline void
rte_wait_until_equal_32(volatile uint32_t *addr, uint32_t expected,
		int memorder)
{
	uint32_t value;

	RTE_ASSERT(memorder == rte_memory_order_acquire ||
		memorder == rte_memory_order_relaxed);
	RTE_ASSERT(((size_t)addr & 3) == 0);

	__RTE_RISCV_LR_32(addr, value, memorder);
	while (value != expected) {
		__RTE_RISCV_WRS_NTO();
		__RTE_RISCV_LR_32(addr, value, memorder);
	}
}

static __rte_always_inline void
rte_wait_until_equal_64(volatile uint64_t *addr, uint64_t expected,
		int memorder)
{
	uint64_t value;

	RTE_ASSERT(memorder == rte_memory_order_acquire ||
		memorder == rte_memory_order_relaxed);
	RTE_ASSERT(((size_t)addr & 7) == 0);

	__RTE_RISCV_LR_64(addr, value, memorder);
	while (value != expected) {
		__RTE_RISCV_WRS_NTO();
		__RTE_RISCV_LR_64(addr, value, memorder);
	}
}

#define RTE_WAIT_UNTIL_MASKED(addr, mask, cond, expected, memorder) do { \
	RTE_BUILD_BUG_ON(!__builtin_constant_p(memorder));               \
	RTE_BUILD_BUG_ON(memorder != rte_memory_order_acquire &&         \
		memorder != rte_memory_order_relaxed);                   \
	RTE_ASSERT(((size_t)(addr) & (sizeof(*(addr)) - 1)) != 0);       \
	const uint32_t size = sizeof(*(addr)) << 3;                      \
	typeof(*(addr)) expected_value = (expected);                     \
	typeof(*(addr)) value;                                           \
	__RTE_RISCV_LR((addr), value, memorder, size);                   \
	while (!((value & (mask)) cond expected_value)) {                \
		__RTE_RISCV_WRS_NTO();                                   \
		__RTE_RISCV_LR((addr), value, memorder, size);           \
	}                                                                \
} while (0)

#endif /* RTE_RISCV_ZAWRS */

#ifdef __cplusplus
}
#endif

#endif /* RTE_PAUSE_RISCV_H */

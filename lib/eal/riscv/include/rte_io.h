/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016 Cavium, Inc
 * Copyright(c) 2022 StarFive
 * Copyright(c) 2022 SiFive
 * Copyright(c) 2022 Semihalf
 * Copyright(c) 2026 Dangshiwei
 */

#ifndef _RTE_IO_RISCV_H_
#define _RTE_IO_RISCV_H_

#include <stdint.h>

#define RTE_OVERRIDE_IO_H

#include "generic/rte_io.h"
#include <rte_compat.h>
#include "rte_atomic.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Unlike ARM64 which is a strong-ordered architecture, RISC-V is a
 * weak-ordered architecture. The "memory" clobber is added to the relaxed
 * variants to prevent the compiler from reordering these accesses with
 * respect to other memory operations, while still omitting the hardware
 * fence instructions.
 */

/* relaxed read */

static __rte_always_inline uint8_t
rte_read8_relaxed(const volatile void *addr)
{
	uint8_t val;
	asm volatile("lbu %0, 0(%1)" : "=r"(val) : "r"(addr) : "memory");
	return val;
}

static __rte_always_inline uint16_t
rte_read16_relaxed(const volatile void *addr)
{
	uint16_t val;
	asm volatile("lhu %0, 0(%1)" : "=r"(val) : "r"(addr) : "memory");
	return val;
}

static __rte_always_inline uint32_t
rte_read32_relaxed(const volatile void *addr)
{
	uint32_t val;
#ifdef RTE_ARCH_64
	/* lwu is RV64-only: zero-extends to avoid sign-bit pollution */
	asm volatile("lwu %0, 0(%1)" : "=r"(val) : "r"(addr) : "memory");
#else
	/* on RV32, lw is full-width, no extension needed */
	asm volatile("lw %0, 0(%1)" : "=r"(val) : "r"(addr) : "memory");
#endif
	return val;
}

#ifdef RTE_ARCH_64
static __rte_always_inline uint64_t
rte_read64_relaxed(const volatile void *addr)
{
	uint64_t val;
	asm volatile("ld %0, 0(%1)" : "=r"(val) : "r"(addr) : "memory");
	return val;
}
#endif

/* relaxed write */

static __rte_always_inline void
rte_write8_relaxed(uint8_t val, volatile void *addr)
{
	asm volatile("sb %1, 0(%0)" : : "r"(addr), "r"(val) : "memory");
}

static __rte_always_inline void
rte_write16_relaxed(uint16_t val, volatile void *addr)
{
	asm volatile("sh %1, 0(%0)" : : "r"(addr), "r"(val) : "memory");
}

static __rte_always_inline void
rte_write32_relaxed(uint32_t val, volatile void *addr)
{
	asm volatile("sw %1, 0(%0)" : : "r"(addr), "r"(val) : "memory");
}

#ifdef RTE_ARCH_64
static __rte_always_inline void
rte_write64_relaxed(uint64_t val, volatile void *addr)
{
	asm volatile("sd %1, 0(%0)" : : "r"(addr), "r"(val) : "memory");
}
#endif

/* read with I/O memory barrier */

static __rte_always_inline uint8_t
rte_read8(const volatile void *addr)
{
	uint8_t val = rte_read8_relaxed(addr);
	rte_io_rmb();
	return val;
}

static __rte_always_inline uint16_t
rte_read16(const volatile void *addr)
{
	uint16_t val = rte_read16_relaxed(addr);
	rte_io_rmb();
	return val;
}

static __rte_always_inline uint32_t
rte_read32(const volatile void *addr)
{
	uint32_t val = rte_read32_relaxed(addr);
	rte_io_rmb();
	return val;
}

#ifdef RTE_ARCH_64
static __rte_always_inline uint64_t
rte_read64(const volatile void *addr)
{
	uint64_t val = rte_read64_relaxed(addr);
	rte_io_rmb();
	return val;
}
#endif

/* write with I/O memory barrier */

static __rte_always_inline void
rte_write8(uint8_t val, volatile void *addr)
{
	rte_io_wmb();
	rte_write8_relaxed(val, addr);
}

static __rte_always_inline void
rte_write16(uint16_t val, volatile void *addr)
{
	rte_io_wmb();
	rte_write16_relaxed(val, addr);
}

static __rte_always_inline void
rte_write32(uint32_t val, volatile void *addr)
{
	rte_io_wmb();
	rte_write32_relaxed(val, addr);
}

#ifdef RTE_ARCH_64
static __rte_always_inline void
rte_write64(uint64_t val, volatile void *addr)
{
	rte_io_wmb();
	rte_write64_relaxed(val, addr);
}
#endif

/*
 * RISC-V currently has no write-combining store instructions.
 * Fall back to normal write.
 */
__rte_experimental
static __rte_always_inline void
rte_write32_wc(uint32_t val, volatile void *addr)
{
	rte_write32(val, addr);
}

__rte_experimental
static __rte_always_inline void
rte_write32_wc_relaxed(uint32_t val, volatile void *addr)
{
	rte_write32_relaxed(val, addr);
}

#ifdef __cplusplus
}
#endif

#endif /* _RTE_IO_RISCV_H_ */

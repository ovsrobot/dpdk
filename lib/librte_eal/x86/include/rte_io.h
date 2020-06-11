/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016 Cavium, Inc
 */

#ifndef _RTE_IO_X86_H_
#define _RTE_IO_X86_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "generic/rte_io.h"

/**
 * Write a 32-bit value to I/O device memory address *addr*.
 * Uses MOVDIRI instruction to perform a direct-store operation using WC
 * memory write protocol.
 *
 * @param value
 *  Value to write
 * @param addr
 *  I/O memory address to write the value to
 */
static __rte_always_inline void
rte_write32_wc(uint32_t value, volatile void *addr)
{
	asm volatile("sfence\n\t"
		/* MOVDIRI */
		".byte 0x40, 0x0f, 0x38, 0xf9, 0x02"
		:
		: "a" (value), "d" (addr));
}

#ifdef __cplusplus
}
#endif

#endif /* _RTE_IO_X86_H_ */

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#ifndef _RTE_POWER_INTRINSIC_X86_64_H_
#define _RTE_POWER_INTRINSIC_X86_64_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_atomic.h>
#include <rte_common.h>

#include "generic/rte_power_intrinsics.h"

/**
 * Monitor specific address for changes. This will cause the CPU to enter an
 * architecture-defined optimized power state until either the specified
 * memory address is written to, or a certain TSC timestamp is reached.
 *
 * Additionally, an `expected` 64-bit value and 64-bit mask are provided. If
 * mask is non-zero, the current value pointed to by the `p` pointer will be
 * checked against the expected value, and if they match, the entering of
 * optimized power state may be aborted.
 *
 * This function uses UMONITOR/UMWAIT instructions. For more information about
 * their usage, please refer to Intel(R) 64 and IA-32 Architectures Software
 * Developer's Manual.
 *
 * @param p
 *   Address to monitor for changes. Must be aligned on an 64-byte boundary.
 * @param expected_value
 *   Before attempting the monitoring, the `p` address may be read and compared
 *   against this value. If `value_mask` is zero, this step will be skipped.
 * @param value_mask
 *   The 64-bit mask to use to extract current value from `p`.
 * @param state
 *   Architecture-dependent optimized power state number. Can be 0 (C0.2) or
 *   1 (C0.1).
 * @param tsc_timestamp
 *   Maximum TSC timestamp to wait for.
 *
 * @return
 *   - 1 if wakeup was due to TSC timeout expiration.
 *   - 0 if wakeup was due to memory write or other reasons.
 */
static inline int rte_power_monitor(const volatile void *p,
		const uint64_t expected_value, const uint64_t value_mask,
		const uint32_t state, const uint64_t tsc_timestamp)
{
	const uint32_t tsc_l = (uint32_t)tsc_timestamp;
	const uint32_t tsc_h = (uint32_t)(tsc_timestamp >> 32);
	/* the rflags need match native register size */
#ifdef RTE_ARCH_I686
	uint32_t rflags;
#else
	uint64_t rflags;
#endif
	/*
	 * we're using raw byte codes for now as only the newest compiler
	 * versions support this instruction natively.
	 */

	/* set address for UMONITOR */
	asm volatile(".byte 0xf3, 0x0f, 0xae, 0xf7;"
			:
			: "D"(p));

	if (value_mask) {
		const uint64_t cur_value = *(const volatile uint64_t *)p;
		const uint64_t masked = cur_value & value_mask;
		/* if the masked value is already matching, abort */
		if (masked == expected_value)
			return 0;
	}
	/* execute UMWAIT */
	asm volatile(".byte 0xf2, 0x0f, 0xae, 0xf7;\n"
		/*
		 * UMWAIT sets CF flag in RFLAGS, so PUSHF to push them
		 * onto the stack, then pop them back into `rflags` so that
		 * we can read it.
		 */
		"pushf;\n"
		"pop %0;\n"
		: "=r"(rflags)
		: "D"(state), "a"(tsc_l), "d"(tsc_h));

	/* we're interested in the first bit (the carry flag) */
	return rflags & 0x1;
}

/**
 * Enter an architecture-defined optimized power state until a certain TSC
 * timestamp is reached.
 *
 * This function uses TPAUSE instruction. For more information about its usage,
 * please refer to Intel(R) 64 and IA-32 Architectures Software Developer's
 * Manual.
 *
 * @param state
 *   Architecture-dependent optimized power state number. Can be 0 (C0.2) or
 *   1 (C0.1).
 * @param tsc_timestamp
 *   Maximum TSC timestamp to wait for.
 *
 * @return
 *   - 1 if wakeup was due to TSC timeout expiration.
 *   - 0 if wakeup was due to other reasons.
 */
static inline int rte_power_pause(const uint32_t state,
		const uint64_t tsc_timestamp)
{
	const uint32_t tsc_l = (uint32_t)tsc_timestamp;
	const uint32_t tsc_h = (uint32_t)(tsc_timestamp >> 32);
	/* the rflags need match native register size */
#ifdef RTE_ARCH_I686
	uint32_t rflags;
#else
	uint64_t rflags;
#endif

	/* execute TPAUSE */
	asm volatile(".byte 0x66, 0x0f, 0xae, 0xf7;\n"
		     /*
		      * TPAUSE sets CF flag in RFLAGS, so PUSHF to push them
		      * onto the stack, then pop them back into `rflags` so that
		      * we can read it.
		      */
		     "pushf;\n"
		     "pop %0;\n"
		     : "=r"(rflags)
		     : "D"(state), "a"(tsc_l), "d"(tsc_h));

	/* we're interested in the first bit (the carry flag) */
	return rflags & 0x1;
}

#ifdef __cplusplus
}
#endif

#endif /* _RTE_POWER_INTRINSIC_X86_64_H_ */

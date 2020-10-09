/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#ifndef _RTE_POWER_INTRINSIC_H_
#define _RTE_POWER_INTRINSIC_H_

#include <inttypes.h>

/**
 * @file
 * Advanced power management operations.
 *
 * This file define APIs for advanced power management,
 * which are architecture-dependent.
 */

/**
 * Monitor specific address for changes. This will cause the CPU to enter an
 * architecture-defined optimized power state until either the specified
 * memory address is written to, a certain TSC timestamp is reached, or other
 * reasons cause the CPU to wake up.
 *
 * Additionally, an `expected` 64-bit value and 64-bit mask are provided. If
 * mask is non-zero, the current value pointed to by the `p` pointer will be
 * checked against the expected value, and if they match, the entering of
 * optimized power state may be aborted.
 *
 * @param p
 *   Address to monitor for changes. Must be aligned on an 64-byte boundary.
 * @param expected_value
 *   Before attempting the monitoring, the `p` address may be read and compared
 *   against this value. If `value_mask` is zero, this step will be skipped.
 * @param value_mask
 *   The 64-bit mask to use to extract current value from `p`.
 * @param tsc_timestamp
 *   Maximum TSC timestamp to wait for. Note that the wait behavior is
 *   architecture-dependent.
 *
 * @return
 *   - 0 on success
 *   - -ENOTSUP if not supported
 */
static inline void rte_power_monitor(const volatile void *p,
		const uint64_t expected_value, const uint64_t value_mask,
		const uint64_t tsc_timestamp);

/**
 * Enter an architecture-defined optimized power state until a certain TSC
 * timestamp is reached.
 *
 * @param tsc_timestamp
 *   Maximum TSC timestamp to wait for. Note that the wait behavior is
 *   architecture-dependent.
 *
 * @return
 *   Architecture-dependent return value.
 */
static inline void rte_power_pause(const uint64_t tsc_timestamp);

#endif /* _RTE_POWER_INTRINSIC_H_ */

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#ifndef _RTE_POWER_INTRINSIC_PPC_H_
#define _RTE_POWER_INTRINSIC_PPC_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_atomic.h>
#include <rte_common.h>

#include "generic/rte_power_intrinsics.h"

/**
 * This function is not supported on PPC64.
 *
 * @param p
 *   Address to monitor for changes. Must be aligned on an 64-byte boundary.
 * @param expected_value
 *   Before attempting the monitoring, the `p` address may be read and compared
 *   against this value. If `value_mask` is zero, this step will be skipped.
 * @param value_mask
 *   The 64-bit mask to use to extract current value from `p`.
 * @param tsc_timestamp
 *   Maximum TSC timestamp to wait for.
 *
 * @return
 *   - 0 on success
 */
static inline void rte_power_monitor(const volatile void *p,
		const uint64_t expected_value, const uint64_t value_mask,
		const uint64_t tsc_timestamp)
{
	RTE_SET_USED(p);
	RTE_SET_USED(expected_value);
	RTE_SET_USED(value_mask);
	RTE_SET_USED(tsc_timestamp);
}

/**
 * This function is not supported on PPC64.
 *
 * @param tsc_timestamp
 *   Maximum TSC timestamp to wait for.
 *
 * @return
 *   - 1 if wakeup was due to TSC timeout expiration.
 *   - 0 if wakeup was due to other reasons.
 */
static inline void rte_power_pause(const uint64_t tsc_timestamp)
{
	RTE_SET_USED(tsc_timestamp);
}

#ifdef __cplusplus
}
#endif

#endif /* _RTE_POWER_INTRINSIC_PPC_H_ */

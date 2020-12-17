/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#ifndef _RTE_POWER_INTRINSIC_PPC_H_
#define _RTE_POWER_INTRINSIC_PPC_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>

#include "generic/rte_power_intrinsics.h"

/**
 * This function is not supported on PPC64.
 */
void
rte_power_monitor(const struct rte_power_monitor_cond *pmc,
		const uint64_t tsc_timestamp)
{
	RTE_SET_USED(pmc);
	RTE_SET_USED(tsc_timestamp);
}

/**
 * This function is not supported on PPC64.
 */
void
rte_power_monitor_sync(const struct rte_power_monitor_cond *pmc,
		const uint64_t tsc_timestamp, rte_spinlock_t *lck)
{
	RTE_SET_USED(pmc);
	RTE_SET_USED(tsc_timestamp);
	RTE_SET_USED(lck);
}

/**
 * This function is not supported on PPC64.
 */
void
rte_power_pause(const uint64_t tsc_timestamp)
{
	RTE_SET_USED(tsc_timestamp);
}

#ifdef __cplusplus
}
#endif

#endif /* _RTE_POWER_INTRINSIC_PPC_H_ */

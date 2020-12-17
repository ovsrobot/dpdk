/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#ifndef _RTE_POWER_INTRINSIC_ARM_H_
#define _RTE_POWER_INTRINSIC_ARM_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>

#include "generic/rte_power_intrinsics.h"

/**
 * This function is not supported on ARM.
 */
void
rte_power_monitor(const struct rte_power_monitor_cond *pmc,
		const uint64_t tsc_timestamp)
{
	RTE_SET_USED(pmc);
	RTE_SET_USED(tsc_timestamp);
}

/**
 * This function is not supported on ARM.
 */
void
rte_power_pause(const uint64_t tsc_timestamp)
{
	RTE_SET_USED(tsc_timestamp);
}

/**
 * This function is not supported on ARM.
 */
void
rte_power_monitor_wakeup(const unsigned int lcore_id)
{
	RTE_SET_USED(lcore_id);
}

#ifdef __cplusplus
}
#endif

#endif /* _RTE_POWER_INTRINSIC_ARM_H_ */

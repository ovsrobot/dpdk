/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Marvell.
 */

#ifndef _RTE_PMU_PMC_X86_H_
#define _RTE_PMU_PMC_X86_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>

static __rte_always_inline uint64_t
rte_pmu_pmc_read(int index)
{
	uint64_t low, high;

	asm volatile(
		"rdpmc\n"
		: "=a" (low), "=d" (high)
		: "c" (index)
	);

	return low | (high << 32);
}
#define rte_pmu_pmc_read rte_pmu_pmc_read

#ifdef __cplusplus
}
#endif

#endif /* _RTE_PMU_PMC_X86_H_ */

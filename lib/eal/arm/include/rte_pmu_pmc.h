/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Marvell.
 */

#ifndef _RTE_PMU_PMC_ARM_H_
#define _RTE_PMU_PMC_ARM_H_

#ifdef __cplusplus
extern "C" {
#endif

static __rte_always_inline uint64_t
rte_pmu_pmc_read(int index)
{
	uint64_t val;

	if (index == 31) {
		/* CPU Cycles (0x11) must be read via pmccntr_el0 */
		asm volatile("mrs %0, pmccntr_el0" : "=r" (val));
	} else {
		asm volatile(
			"msr pmselr_el0, %x0\n"
			"mrs %0, pmxevcntr_el0\n"
			: "=r" (val)
			: "rZ" (index)
		);
	}

	return val;
}
#define rte_pmu_pmc_read rte_pmu_pmc_read

#ifdef __cplusplus
}
#endif

#endif /* _RTE_PMU_PMC_ARM_H_ */

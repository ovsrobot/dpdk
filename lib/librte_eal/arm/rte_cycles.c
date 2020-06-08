/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2015 Cavium, Inc
 */

#include "eal_private.h"
#include "rte_cycles.h"

uint64_t
get_tsc_freq_arch(void)
{
#if defined RTE_ARCH_ARM64 && !defined RTE_ARM_EAL_RDTSC_USE_PMU
	return __rte_rd_generic_cntr_freq();
#elif defined RTE_ARCH_ARM64 && defined RTE_ARM_EAL_RDTSC_USE_PMU
	/* Use the generic counter ticks to calculate the PMU
	 * cycle frequency.
	 */
	uint64_t gcnt_ticks;
	uint64_t start_ticks, cur_ticks;
	uint64_t start_pmu_cycles, end_pmu_cycles;

	/* Number of ticks for 1/10 second */
	gcnt_ticks = __rte_rd_generic_cntr_freq() / 10;

	start_ticks = __rte_rd_generic_cntr_precise();
	start_pmu_cycles = rte_rdtsc_precise();
	do {
		cur_ticks = __rte_rd_generic_cntr();
	} while ((cur_ticks - start_ticks) < gcnt_ticks);
	end_pmu_cycles = rte_rdtsc_precise();

	return ((end_pmu_cycles - start_pmu_cycles) * 10);
#else
	return 0;
#endif
}

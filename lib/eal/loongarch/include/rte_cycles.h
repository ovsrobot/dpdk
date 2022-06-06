/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Loongson Technology Corporation Limited
 */

#ifndef _RTE_CYCLES_LOONGARCH_H_
#define _RTE_CYCLES_LOONGARCH_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "generic/rte_cycles.h"

static inline uint64_t
get_cycle_count(void)
{
	uint64_t count;

	__asm__ __volatile__ (
		"rdtime.d %[cycles], $zero\n"
		: [cycles] "=r" (count)
		::
		);
	return count;
}

/**
 * Read the time base register.
 *
 * @return
 *   The time base for this lcore.
 */
static inline uint64_t
rte_rdtsc(void)
{
	return get_cycle_count();
}

static inline uint64_t
rte_rdtsc_precise(void)
{
	rte_mb();
	return rte_rdtsc();
}

static inline uint64_t
rte_get_tsc_cycles(void) { return rte_rdtsc(); }

#ifdef __cplusplus
}
#endif

#endif /* _RTE_CYCLES_LOONGARCH_H_ */

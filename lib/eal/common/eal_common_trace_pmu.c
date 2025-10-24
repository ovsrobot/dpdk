/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2025 Marvell International Ltd.
 */

#include <rte_common.h>

#include "eal_trace_pmu.h"

#ifdef RTE_LIB_PMU

#include <eal_export.h>
#include <rte_pmu.h>
#include <rte_trace_point_register.h>
#include <rte_eal_trace.h>

void
trace_pmu_args_apply(const char *arg)
{
	static bool once;

	if (!once) {
		if (rte_pmu_init())
			return;
		once = true;
	}

	rte_pmu_add_events_by_pattern(arg);
}

void
trace_pmu_args_free(void)
{
	rte_pmu_fini();
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(__rte_pmu_trace_read, 25.11)
RTE_TRACE_POINT_REGISTER(rte_pmu_trace_read,
	lib.pmu.read)

#else /* !RTE_LIB_PMU */

void trace_pmu_args_apply(const char *arg __rte_unused) { return; }
void trace_pmu_args_free(void) { return; }

#endif /* RTE_LIB_PMU */

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#include <pthread.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <time.h>
#include "sxe_types.h"
#include "sxe_common.h"

#define SXE_SEC_TO_MS(sec) ((sec) * 1000ULL)

#define SXE_NSEC_PER_MS		  1000000

RTE_ATOMIC(uint64_t) sxe_trace_id;

u64 sxe_time_get_real_ms(void)
{
	u64 ms = 0;
	struct timespec ts;
	s32 ret = clock_gettime(CLOCK_MONOTONIC, &ts);
	if (ret < 0)
		goto l_end;

	ms = SXE_SEC_TO_MS(ts.tv_sec) + ts.tv_nsec / SXE_NSEC_PER_MS;

l_end:
	return ms;
}

void sxe_trace_id_gen(void)
{
	sxe_trace_id = 0;
	return;
}

u64 sxe_trace_id_get(void)
{
	return rte_atomic_fetch_add_explicit((uint64_t __rte_atomic *)&sxe_trace_id,
			1, rte_memory_order_relaxed);
}

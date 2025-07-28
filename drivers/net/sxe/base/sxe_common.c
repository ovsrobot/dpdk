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

#define SXE_TRACE_ID_COUNT_MASK  0x00000000000000FFLLU
#define SXE_TRACE_ID_TID_MASK	0x0000000000FFFF00LLU
#define SXE_TRACE_ID_TIME_MASK   0x00FFFFFFFF000000LLU
#define SXE_TRACE_ID_FLAG		0xFF00000000000000LLU

#define SXE_TRACE_ID_COUNT_SHIFT 0
#define SXE_TRACE_ID_TID_SHIFT   8
#define SXE_TRACE_ID_TIME_SHIFT  24

#define SXE_SEC_TO_MS(sec) ((sec) * 1000ULL)
#define SXE_SEC_TO_NS(sec) ((sec) * 1000000000ULL)

#define SXE_USEC_PER_MS		  1000000

u64 sxe_trace_id;

u64 sxe_time_get_real_ms(void)
{
	u64 ms = 0;
	struct timespec ts;
	s32 ret = clock_gettime(CLOCK_MONOTONIC, &ts);
	if (ret < 0)
		goto l_end;

	ms = SXE_SEC_TO_MS(ts.tv_sec) + ts.tv_nsec / SXE_USEC_PER_MS;

l_end:
	return ms;
}

u64 sxe_trace_id_gen(void)
{
	u64 tid	   = (u64)getpid() + ((u64)pthread_self() << 20);
	u64 index	 = 0;
	u64 timestamp = sxe_time_get_real_ms();

	sxe_trace_id = (SXE_TRACE_ID_FLAG)
		| ((timestamp << SXE_TRACE_ID_TIME_SHIFT) & SXE_TRACE_ID_TIME_MASK)
		| ((tid << SXE_TRACE_ID_TID_SHIFT) & SXE_TRACE_ID_TID_MASK)
		| ((index << SXE_TRACE_ID_COUNT_SHIFT) & SXE_TRACE_ID_COUNT_MASK);
	return sxe_trace_id;
}

void sxe_trace_id_clean(void)
{
	sxe_trace_id = 0;
}

u64 sxe_trace_id_get(void)
{
	return sxe_trace_id++;
}

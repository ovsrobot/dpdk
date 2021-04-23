/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Microsoft Corporation
 */

#ifndef _CONFIG_H_
#define _CONFIG_H_

#include <rte_os_shim.h>

#ifdef CLOCK_MONOTONIC_RAW /* Defined in glibc bits/time.h */
#define CLOCK_TYPE_ID CLOCK_MONOTONIC_RAW
#else
#define CLOCK_TYPE_ID CLOCK_MONOTONIC
#endif

#define NS_PER_SEC 1E9

#ifdef RTE_EXEC_ENV_WINDOWS

/* Identifier for system-wide realtime clock. */
#define CLOCK_REALTIME			0
/* Monotonic system-wide clock. */
#define CLOCK_MONOTONIC			1
/* High-resolution timer from the CPU. */
#define CLOCK_PROCESS_CPUTIME_ID	2
/* Thread-specific CPU-time clock. */
#define CLOCK_THREAD_CPUTIME_ID		3

typedef int clockid_t;

#ifndef clock_gettime
#define clock_gettime _clock_gettime
#endif

static int
_clock_gettime(clockid_t clock_id, struct timespec* tp)
{
	LARGE_INTEGER pf, pc;
	LONGLONG nsec;

	switch (clock_id) {
	case CLOCK_REALTIME:
		if (timespec_get(tp, TIME_UTC) != TIME_UTC)
			return -1;

		return 0;
	case CLOCK_MONOTONIC:
		if (QueryPerformanceFrequency(&pf) == 0)
			return -1;

		if (QueryPerformanceCounter(&pc) == 0)
			return -1;

		nsec = pc.QuadPart * NS_PER_SEC / pf.QuadPart;
		tp->tv_sec = nsec / NS_PER_SEC;
		tp->tv_nsec = nsec - tp->tv_sec * NS_PER_SEC;

		return 0;
	default:
		return -1;
	}
}

#endif /* RTE_EXEC_ENV_WINDOWS */

#endif /* _CONFIG_H_ */

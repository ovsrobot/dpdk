/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef _RTE_OS_SHIM_
#define _RTE_OS_SHIM_

#include <stdio.h>
#include <time.h>

#include <rte_os.h>
#include <rte_windows.h>

/**
 * @file
 * @internal
 * Provides semi-standard OS facilities by convenient names.
 */

#ifndef PATH_MAX
#define PATH_MAX _MAX_PATH
#endif

#define strdup(str) _strdup(str)
#define strtok_r(str, delim, saveptr) strtok_s(str, delim, saveptr)
#ifndef RTE_TOOLCHAIN_GCC
#define strcasecmp(s1, s2) _stricmp(s1, s2)
#define strncasecmp(s1, s2, count) _strnicmp(s1, s2, count)
#endif

#define open(...) _open(__VA_ARGS__)
#define read(fd, buf, n) _read(fd, buf, n)
#define write(fd, buf, n) _write(fd, buf, n)
#define close(fd) _close(fd)
#define unlink(path) _unlink(path)

#define IPVERSION	4

#define IPPROTO_IPIP	4
#define IPPROTO_GRE	47
#ifdef RTE_TOOLCHAIN_GCC
#define IPPROTO_SCTP	132
#endif

#ifndef IPDEFTTL
#define IPDEFTTL 64
#endif

#ifndef S_ISREG
#define S_ISREG(mode)  (((mode) & S_IFMT) == S_IFREG)
#endif

#ifdef RTE_TOOLCHAIN_GCC

#define TIME_UTC 1

static inline int
rte_timespec_get(struct timespec *now, int base)
{
	/* 100ns ticks from 1601-01-01 to 1970-01-01 */
	static const uint64_t EPOCH = 116444736000000000ULL;
	static const uint64_t TICKS_PER_SEC = 10000000;
	static const uint64_t NS_PER_TICK = 100;

	FILETIME ft;
	uint64_t ticks;

	if (base != TIME_UTC)
		return 0;

	GetSystemTimePreciseAsFileTime(&ft);
	ticks = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
	ticks -= EPOCH;
	now->tv_sec = ticks / TICKS_PER_SEC;
	now->tv_nsec = (ticks - now->tv_sec * TICKS_PER_SEC) * NS_PER_TICK;
	return base;
}

#define timespec_get(ts, base) rte_timespec_get(ts, base)

#endif /* RTE_TOOLCHAIN_GCC */

/* Identifier for system-wide realtime clock. */
#define CLOCK_REALTIME                  0
/* Monotonic system-wide clock. */
#define CLOCK_MONOTONIC                 1

typedef int clockid_t;

static inline int
rte_clock_gettime(clockid_t clock_id, struct timespec *tp)
{
	const int NS_PER_SEC = 1E9;
	LARGE_INTEGER pf, pc;
	LONGLONG nsec;

	switch (clock_id) {
	case CLOCK_REALTIME:
		if (timespec_get(tp, TIME_UTC) != TIME_UTC)
			return -1;
		return 0;
	case CLOCK_MONOTONIC:
		QueryPerformanceFrequency(&pf);
		QueryPerformanceCounter(&pc);

		nsec = pc.QuadPart * NS_PER_SEC / pf.QuadPart;
		tp->tv_sec = nsec / NS_PER_SEC;
		tp->tv_nsec = nsec - tp->tv_sec * NS_PER_SEC;
		return 0;
	default:
		return -1;
	}
}
#define clock_gettime(clock_id, tp) rte_clock_gettime(clock_id, tp)

static inline struct tm *
rte_localtime_r(const time_t *timer, struct tm *buf)
{
	if (localtime_s(buf, timer) == 0)
		return buf;
	else
		return NULL;
}
#define localtime_r(timer, buf) rte_localtime_r(timer, buf)

/* print to allocated string */
static inline int
rte_vasprintf(char **strp, const char *fmt, va_list ap)
{
	char *str;
	int len, ret;

	*strp = NULL;

	/* determine size of buffer needed */
	len = _vscprintf(fmt, ap);
	if (len < 0)
		return -1;

	len += 1;	/* for nul termination */
	str = malloc(len);
	if (str == NULL)
		return -1;

	ret = vsnprintf(str, len, fmt, ap);
	if (ret < 0) {
		free(str);
		return -1;
	} else {
		*strp = str;
		return ret;
	}
}
#define vasprintf(strp, fmt, ap) rte_vasprintf(strp, fmt, ap)

static inline int
rte_asprintf(char **strp, const char *fmt, ...)
{
	int ret;

	va_list ap;

	va_start(ap, fmt);
	ret = rte_vasprintf(strp, fmt, ap);
	va_end(ap);

	return ret;
}

#define asprintf(strp, fmt, ...) rte_asprintf(strp, fmt, __VA_ARGS__)
#endif /* _RTE_OS_SHIM_ */

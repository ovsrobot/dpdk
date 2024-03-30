/* SPDX-License-Identifier: BSD-3-Clause */
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <rte_common.h>

#ifdef RTE_EXEC_ENV_WINDOWS
#include <rte_os_shim.h>
#endif

#include "log_internal.h"
#include "log_private.h"

static enum {
	LOG_TIMESTAMP_NONE = 0,
	LOG_TIMESTAMP_TIME,	/* time since start */
	LOG_TIMESTAMP_DELTA,	/* time since last message */
	LOG_TIMESTAMP_RELTIME,  /* relative time since last message */
	LOG_TIMESTAMP_CTIME,	/* Unix standard time format */
	LOG_TIMESTAMP_ISO,	/* ISO8601 time format */
} log_time_format;

static struct {
	struct timespec started;   /* when log was initialized */
	struct timespec previous;  /* when last msg was printed */
} log_time;

/* Set the log timestamp format */
int
eal_log_timestamp(const char *str)
{
	if (str == NULL)
		log_time_format = LOG_TIMESTAMP_TIME;
	else if (strcmp(str, "notime") == 0)
		log_time_format = LOG_TIMESTAMP_NONE;
	else if (strcmp(str, "reltime") == 0)
		log_time_format = LOG_TIMESTAMP_RELTIME;
	else if (strcmp(str, "delta") == 0)
		log_time_format = LOG_TIMESTAMP_DELTA;
	else if (strcmp(str, "ctime") == 0)
		log_time_format =  LOG_TIMESTAMP_CTIME;
	else if (strcmp(str, "iso") == 0)
		log_time_format = LOG_TIMESTAMP_ISO;
	else
		return -1;

	return 0;
}

bool
log_timestamp_enabled(void)
{
	return log_time_format != LOG_TIMESTAMP_NONE;
}

/* Subtract two timespec values and handle wraparound */
static struct timespec
timespec_sub(const struct timespec *t0, const struct timespec *t1)
{
	struct timespec ts;

	ts.tv_sec = t0->tv_sec - t1->tv_sec;
	ts.tv_nsec = t0->tv_nsec - t1->tv_nsec;
	if (ts.tv_nsec < 0) {
		ts.tv_sec--;
		ts.tv_nsec += 1000000000L;
	}
	return ts;
}

/*
 * Format current timespec into ISO8601 format.
 * Surprisingly, can't just use strftime() for this;
 * since want microseconds and the timezone offset format differs.
 */
static ssize_t
format_iso8601(char *tsbuf, size_t tsbuflen, const struct timespec *now)
{
	struct tm *tm, tbuf;
	char dbuf[64]; /* "2024-05-01T22:11:00" */
	char zbuf[16] = { }; /* "+0800" */

	tm = localtime_r(&now->tv_sec, &tbuf);

	/* make "2024-05-01T22:11:00,123456+0100" */
	if (strftime(dbuf, sizeof(dbuf), "%Y-%m-%dT%H:%M:%S", tm) == 0)
		return 0;

	/* convert timezone to +hhmm */
	if (strftime(zbuf, sizeof(zbuf), "%z", tm) == 0)
		return 0;

	/* the result for strftime is "+hhmm" but ISO wants "+hh:mm" */
	return snprintf(tsbuf, tsbuflen, "%s,%06lu%.3s:%.2s",
			dbuf, now->tv_nsec / 1000u,
			zbuf, zbuf + 3);
}

/*
 * Make a timestamp where if the minute, hour or day has
 * changed from the last message, then print abbreviated
 * "Month day hour:minute" format.
 * Otherwise print delta from last printed message as +sec.usec
 */
static ssize_t
format_reltime(char *tsbuf, size_t tsbuflen, const struct timespec *now)
{
	struct tm *tm, tbuf;
	static struct tm last_tm;
	struct timespec delta;

	tm = localtime_r(&now->tv_sec, &tbuf);
	delta = timespec_sub(now, &log_time.previous);
	log_time.previous = *now;

	/* if minute, day, hour hasn't changed then print delta */
	if (tm->tm_min != last_tm.tm_min ||
	    tm->tm_hour != last_tm.tm_hour ||
	    tm->tm_yday != last_tm.tm_yday) {
		last_tm = *tm;
		return strftime(tsbuf, tsbuflen, "%b%d %H:%M", tm);
	} else {
		return snprintf(tsbuf, tsbuflen, "+%3lu.%06lu",
				(unsigned long)delta.tv_sec,
				(unsigned long)delta.tv_nsec / 1000u);
	}
}

/* Format up a timestamp based on current format */
ssize_t
log_timestamp(char *tsbuf, size_t tsbuflen)
{
	struct timespec now, delta;

	switch (log_time_format) {
	case LOG_TIMESTAMP_NONE:
		return 0;

	case LOG_TIMESTAMP_TIME:
		if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
			return 0;

		delta = timespec_sub(&now, &log_time.started);

		return snprintf(tsbuf, tsbuflen, "%6lu.%06lu",
				(unsigned long)delta.tv_sec,
				(unsigned long)delta.tv_nsec / 1000u);

	case LOG_TIMESTAMP_DELTA:
		if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
			return 0;

		delta = timespec_sub(&now, &log_time.previous);
		log_time.previous = now;

		return snprintf(tsbuf, tsbuflen, "<%6lu.%06lu>",
				(unsigned long)delta.tv_sec,
				(unsigned long)delta.tv_nsec / 1000u);

	case LOG_TIMESTAMP_RELTIME:
		if (clock_gettime(CLOCK_REALTIME, &now) < 0)
			return 0;

		return format_reltime(tsbuf, tsbuflen, &now);

	case LOG_TIMESTAMP_CTIME:
		if (clock_gettime(CLOCK_REALTIME, &now) < 0)
			return 0;

		/* trncate to remove newline from ctime result */
		return snprintf(tsbuf, tsbuflen, "%.24s", ctime(&now.tv_sec));

	case LOG_TIMESTAMP_ISO:
		if (clock_gettime(CLOCK_REALTIME, &now) < 0)
			return 0;

		return format_iso8601(tsbuf, tsbuflen, &now);
	}

	return 0;
}

/* print timestamp before message */
int
log_print_with_timestamp(FILE *f, uint32_t level, const char *format, va_list ap)
{
	char tsbuf[128];

	if (log_timestamp(tsbuf, sizeof(tsbuf)) > 0)
		fprintf(f, "[%s] ", tsbuf);

	return log_print(f, level, format, ap);
}

RTE_INIT_PRIO(log_timestamp_init, LOG)
{
	clock_gettime(CLOCK_MONOTONIC, &log_time.started);
	log_time.previous = log_time.started;
}

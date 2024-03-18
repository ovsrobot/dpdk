/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <rte_log.h>

#include "log_internal.h"

static bool timestamp_enabled;
static struct timespec log_started;

void
eal_log_enable_timestamp(void)
{
	timestamp_enabled = true;
	clock_gettime(CLOCK_MONOTONIC, &log_started);
}

/*
 * default log function
 */
static ssize_t
console_log_write(__rte_unused void *c, const char *buf, size_t size)
{
	struct timespec ts;
	ssize_t ret;

	if (timestamp_enabled) {
		clock_gettime(CLOCK_MONOTONIC, &ts);
		ts.tv_sec -= log_started.tv_sec;
		ts.tv_nsec -= log_started.tv_nsec;
		if (ts.tv_nsec < 0) {
			--ts.tv_sec;
			ts.tv_nsec += 1000000000ul;
		}

		ret = fprintf(stderr, "[%8lu.%06lu] %.*s",
			      ts.tv_sec, ts.tv_nsec / 1000u,
			      (int) size, buf);
	} else {
		ret = fwrite(buf, 1, size, stderr);
	}
	fflush(stderr);

	/* Syslog error levels are from 0 to 7, so subtract 1 to convert */
	syslog(rte_log_cur_msg_loglevel() - 1, "%.*s", (int)size, buf);

	return ret;
}

static int
console_log_close(__rte_unused void *c)
{
	closelog();
	return 0;
}

static cookie_io_functions_t console_log_func = {
	.write = console_log_write,
	.close = console_log_close,
};

/*
 * set the log to default function, called during eal init process,
 * once memzones are available.
 */
int
eal_log_init(const char *id, int facility)
{
	FILE *log_stream;

	/* skip if user has already setup a log stream */
	if (eal_log_get_default())
		return 0;

	log_stream = fopencookie(NULL, "w+", console_log_func);
	if (log_stream == NULL)
		return -1;

	openlog(id, LOG_NDELAY | LOG_PID, facility);

	eal_log_set_default(log_stream);

	return 0;
}

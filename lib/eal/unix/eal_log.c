/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <rte_log.h>

#include "eal_log.h"
#include "eal_private.h"

static struct timespec log_start_time;

/*
 * default log function
 */
static ssize_t
console_log_write(__rte_unused void *c, const char *buf, size_t size)
{
	const struct internal_config *internal_conf =
		eal_get_internal_configuration();
	ssize_t ret;

	/* add optional timestamp for stderr */
	if (internal_conf->log_timestamp) {
		struct iovec iov[2];
		struct timespec ts;
		char tbuf[64];

		/* format up monotonic timestamp */
		clock_gettime(CLOCK_MONOTONIC, &ts);
		ts.tv_sec -= log_start_time.tv_sec;
		ts.tv_nsec -= log_start_time.tv_nsec;
		if (ts.tv_nsec < 0) {
			--ts.tv_sec;
			ts.tv_nsec += 1000000000ul;
		}

		/* use writev to put timestamp and buf in same operation */
		iov[0].iov_base = tbuf;
		iov[0].iov_len  = snprintf(tbuf, sizeof(tbuf), "[%8lu.%06lu] ",
					   ts.tv_sec, ts.tv_nsec / 1000u);

		/* casts are to unconstify the buf */
		iov[1].iov_base = (void *)(uintptr_t)buf;
		iov[1].iov_len = size;
		ret = writev(STDERR_FILENO, iov, 2);
	} else {
		/* write on stderr */
		ret = fwrite(buf, 1, size, stderr);
		fflush(stderr);
	}

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

	clock_gettime(CLOCK_MONOTONIC, &log_start_time);

	log_stream = fopencookie(NULL, "w+", console_log_func);
	if (log_stream == NULL)
		return -1;

	openlog(id, LOG_NDELAY | LOG_PID, facility);

	eal_log_set_default(log_stream);

	return 0;
}

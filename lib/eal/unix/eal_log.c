/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <getopt.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <rte_log.h>

#include "eal_log.h"
#include "eal_internal_cfg.h"
#include "eal_options.h"
#include "eal_private.h"

/*
 * default log function
 */
static ssize_t
console_log_write(void *c, const char *buf, size_t size)
{
	const struct internal_config *internal_conf = c;
	ssize_t ret;

	/* add optional timestamp for stderr */
	if (internal_conf->log_timestamp) {
		struct iovec iov[2];
		struct timespec ts;
		char tbuf[64];

		/* format up monotonic timestamp */
		clock_gettime(CLOCK_MONOTONIC, &ts);
		ts.tv_sec -= internal_conf->log_start_time.tv_sec;
		ts.tv_nsec -= internal_conf->log_start_time.tv_nsec;
		if (ts.tv_nsec < 0) {
			--ts.tv_sec;
			ts.tv_nsec += 1000000000ul;
		}

		/* use writev to put timestamp and buf in single operation */
		iov[0].iov_base = tbuf;
		iov[0].iov_len  = snprintf(tbuf, sizeof(tbuf), "[%8lu.%06lu] ",
					   ts.tv_sec, ts.tv_nsec / 1000u);

		/* casts are to unconstify the buf */
		iov[1].iov_base = (void *)(uintptr_t)buf;
		iov[1].iov_len = size;
		ret = writev(STDERR_FILENO, iov, 2);
	} else {
		ret = write(STDERR_FILENO, buf, size);
	}

	/* Syslog error levels are from 0 to 7, so subtract 1 to convert */
	syslog(rte_log_cur_msg_loglevel() - 1, "%.*s", (int)size, buf);

#ifdef RTE_EXEC_ENV_LINUX
	/* Handle glibc quirk: write function should return the number of bytes
	 * copied from buf, or 0 on error. (The function must not return a negative value.)
	 * FreeBSD expects that write function behaves like write(2).
	 */
	if (ret < 0)
		ret = 0;
#endif

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
 * Parse the arguments for --log-level and --syslog
 */
int
eal_log_level_parse(int argc, char *const argv[])
{
	struct internal_config *internal_conf = eal_get_internal_configuration();
	int option_index, opt;
	const int old_optind = optind;
	const int old_optopt = optopt;
	const int old_opterr = opterr;
	char * const old_optarg = optarg;
#ifdef RTE_EXEC_ENV_FREEBSD
	const int old_optrset = optreset;
#endif

	optind = 1;
	opterr = 0;
#ifdef RTE_EXEC_ENV_FREEBSD
	optreset = 1;
#endif

	while ((opt = getopt_long(argc, argv, eal_short_options,
				  eal_long_options, &option_index)) != EOF) {

		switch (opt) {
		case OPT_SYSLOG_NUM:
		case OPT_LOG_LEVEL_NUM:
		case OPT_LOG_TIMESTAMP_NUM:
			if (eal_parse_common_option(opt, optarg, internal_conf) < 0)
				return -1;
			break;
		case '?':
			/* getopt is not happy, stop right now */
			goto out;
		default:
			continue;
		}
	}
out:
	/* restore getopt lib */
	optind = old_optind;
	optopt = old_optopt;
	optarg = old_optarg;
	opterr = old_opterr;
#ifdef RTE_EXEC_ENV_FREEBSD
	optreset = old_optreset;
#endif
	return 0;
}

/*
 * set the log to default function, called during eal init process,
 * once memzones are available.
 */
int
eal_log_init(const char *id, int facility)
{
	struct internal_config *internal_conf = eal_get_internal_configuration();
	FILE *log_stream;

	/* has user has already setup a log stream */
	if (eal_log_get_default())
		return 0;

	if (internal_conf->process_type == RTE_PROC_PRIMARY &&
	    internal_conf->log_timestamp) {
		if (clock_gettime(CLOCK_MONOTONIC, &internal_conf->log_start_time) < 0)
			return -1;
	}

	log_stream = fopencookie(internal_conf, "w+", console_log_func);
	if (log_stream == NULL)
		return -1;

	openlog(id, LOG_NDELAY | LOG_PID, facility);

	eal_log_set_default(log_stream);

	return 0;
}

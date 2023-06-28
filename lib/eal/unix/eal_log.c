/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <getopt.h>
#include <stdio.h>
#include <sys/types.h>
#include <syslog.h>

#include <rte_log.h>

#include "eal_log.h"
#include "eal_internal_cfg.h"
#include "eal_options.h"
#include "eal_private.h"

/*
 * default log function
 */
static ssize_t
console_log_write(__rte_unused void *c, const char *buf, size_t size)
{
	ssize_t ret;

	/* write on stderr */
	ret = fwrite(buf, 1, size, stderr);
	fflush(stderr);

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
	char * const old_optarg = optarg;
#ifdef RTE_EXEC_ENV_FREEBSD
	const int old_optrset = optreset;
#endif

	optind = 1;
#ifdef RTE_EXEC_ENV_FREEBSD
	optreset = 1;
#endif

	while ((opt = getopt_long(argc, argv, eal_short_options,
				  eal_long_options, &option_index)) != EOF) {

		switch (opt) {
		case OPT_LOG_LEVEL_NUM:
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
	FILE *log_stream;

	log_stream = fopencookie(NULL, "w+", console_log_func);
	if (log_stream == NULL)
		return -1;

	openlog(id, LOG_NDELAY | LOG_PID, facility);

	eal_log_set_default(log_stream);

	return 0;
}

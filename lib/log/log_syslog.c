/* SPDX-License-Identifier: BSD-3-Clause */
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

#include <rte_common.h>
#include <rte_log.h>

#include "log_internal.h"
#include "log_private.h"

static enum {
	LOG_SYSLOG_NONE = 0,	/* do not use syslog */
	LOG_SYSLOG_AUTO,	/* use syslog only if not a terminal */
	LOG_SYSLOG_ALWAYS,	/* always use syslog */
	LOG_SYSLOG_BOTH,	/* log to both syslog and stderr */
} log_syslog_opt;

int
eal_log_syslog(const char *str)
{
	if (str == NULL || strcmp(str, "auto") == 0)
		log_syslog_opt = LOG_SYSLOG_AUTO;
	else if (strcmp(str, "both") == 0)
		log_syslog_opt = LOG_SYSLOG_BOTH;
	else if (strcmp(str, "always") == 0)
		log_syslog_opt = LOG_SYSLOG_ALWAYS;
	else
		return -1;
	return 0;
}

bool
log_syslog_enabled(bool is_terminal)
{
	switch (log_syslog_opt) {
	default:
		return false;

	case LOG_SYSLOG_ALWAYS:
	case LOG_SYSLOG_BOTH:
		return true;

	case LOG_SYSLOG_AUTO:
		return !is_terminal;
	}
}

/*
 * When syslog is used, the log stream is redirected to a
 * pseudo FILE handle that calls these functions.
 */
static ssize_t
syslog_log_write(__rte_unused void *c, const char *buf, size_t size)
{
	/* Syslog error levels are from 0 to 7, so subtract 1 to convert */
	syslog(rte_log_cur_msg_loglevel() - 1, "%.*s", (int)size, buf);
	return size;
}

static int
syslog_log_close(__rte_unused void *c)
{
	closelog();
	return 0;
}

static cookie_io_functions_t syslog_log_func = {
	.write = syslog_log_write,
	.close = syslog_log_close,
};

void
log_syslog_open(const char *id, bool is_terminal)
{
	int flags = LOG_NDELAY | LOG_PID;

	if (log_syslog_opt == LOG_SYSLOG_BOTH)
		flags |= LOG_PERROR;

	openlog(id, flags, is_terminal ? LOG_USER : LOG_DAEMON);

	/* redirect other log messages to syslog as well */
	FILE *log_stream = fopencookie(NULL, "w", syslog_log_func);
	if (log_stream != NULL)
		rte_openlog_stream(log_stream);
}

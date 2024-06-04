/* SPDX-License-Identifier: BSD-3-Clause */

#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <rte_common.h>
#include <rte_log.h>

#ifdef RTE_EXEC_ENV_WINDOWS
#include <rte_os_shim.h>
#endif

#include "log_internal.h"
#include "log_private.h"

enum  {
	LOG_COLOR_AUTO = 0,	/* default */
	LOG_COLOR_NEVER,
	LOG_COLOR_ALWAYS,
} log_color_mode;

enum color {
	COLOR_NONE,
	COLOR_RED,
	COLOR_GREEN,
	COLOR_YELLOW,
	COLOR_BLUE,
	COLOR_MAGENTA,
	COLOR_CYAN,
	COLOR_WHITE,
	COLOR_BOLD,
	COLOR_CLEAR,
};

/* Standard terminal escape codes for colors and bold */
static const char * const color_code[] = {
	[COLOR_NONE]	= "",
	[COLOR_RED]	= "\033[31m",
	[COLOR_GREEN]	= "\033[32m",
	[COLOR_YELLOW]	= "\033[33m",
	[COLOR_BLUE]	= "\033[34m",
	[COLOR_MAGENTA] = "\033[35m",
	[COLOR_CYAN]    = "\033[36m",
	[COLOR_WHITE]	= "\033[37m",
	[COLOR_BOLD]	= "\033[1m",
	[COLOR_CLEAR]	= "\033[0m",
};

__rte_format_printf(3, 4)
static int
color_fprintf(FILE *out, enum color color, const char *fmt, ...)
{
	va_list args;
	int ret = 0;

	va_start(args, fmt);
	ret = fprintf(out, "%s", color_code[color]);
	ret += vfprintf(out, fmt, args);
	ret += fprintf(out, "%s", color_code[COLOR_CLEAR]);
	va_end(args);

	return ret;
}

/*
 * Controls whether color is enabled:
 * modes are:
 *   always - enable color output regardless
 *   auto - enable if stderr is a terminal
 *   never - color output is disabled.
 */
int
eal_log_color(const char *mode)
{
	if (mode == NULL || strcmp(mode, "always") == 0)
		log_color_mode = LOG_COLOR_ALWAYS;
	else if (strcmp(mode, "never") == 0)
		log_color_mode = LOG_COLOR_NEVER;
	else if (strcmp(mode, "auto") == 0)
		log_color_mode = LOG_COLOR_AUTO;
	else
		return -1;

	return 0;
}

bool
log_color_enabled(bool is_terminal)
{
	switch (log_color_mode) {
	default:
	case LOG_COLOR_NEVER:
		return false;
	case LOG_COLOR_ALWAYS:
		return true;
	case LOG_COLOR_AUTO:
		return is_terminal;
	}
}

int
color_print(FILE *f, const char *format, va_list ap)
{
	const int level = rte_log_cur_msg_loglevel();
	char *cp, *msg;
	char buf[LINE_MAX];
	int ret = 0;

	vsnprintf(buf, LINE_MAX, format, ap);
	msg = buf;

	/*
	 * use convention that first part of message (up to the ':' character)
	 * is the subsystem id and should be highlighted.
	 */
	cp = strchr(msg, ':');
	if (cp) {
		/* print first part in yellow */
		ret = color_fprintf(f, COLOR_YELLOW, "%.*s",
				    (int)(cp - msg + 1), msg);
		msg = cp + 1;
	}

	if (level <= 0 || level >= (int)RTE_LOG_INFO)
		ret += fprintf(f, "%s", msg);
	else if (level >= (int)RTE_LOG_ERR)
		ret += color_fprintf(f, COLOR_BOLD, "%s", msg);
	else
		ret += color_fprintf(f, COLOR_RED, "%s", msg);

	return ret;
}

int
color_print_with_timestamp(FILE *f, const char *format, va_list ap)
{
	char tsbuf[128];

	if (log_timestamp(tsbuf, sizeof(tsbuf)) > 0)
		color_fprintf(f, COLOR_GREEN, "[%s] ", tsbuf);

	return color_print(f, format, ap);
}

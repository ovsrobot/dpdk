/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <regex.h>
#include <fnmatch.h>
#include <sys/queue.h>
#include <unistd.h>

#ifdef RTE_EXEC_ENV_WINDOWS
#include <rte_os_shim.h>
#else
#include <syslog.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#endif

#include <rte_common.h>
#include <rte_log.h>
#include <rte_per_lcore.h>

#include "log_internal.h"

struct rte_log_dynamic_type {
	const char *name;
	uint32_t loglevel;
};

enum eal_log_time_format {
	EAL_LOG_TIMESTAMP_NONE = 0,
	EAL_LOG_TIMESTAMP_TIME,		/* time since start */
	EAL_LOG_TIMESTAMP_DELTA,	/* time since last message */
	EAL_LOG_TIMESTAMP_RELTIME,
	EAL_LOG_TIMESTAMP_CTIME,
	EAL_LOG_TIMESTAMP_ISO,
};

enum eal_log_syslog {
	EAL_LOG_SYSLOG_NONE = 0,	/* do not use syslog */
	EAL_LOG_SYSLOG_AUTO,		/* use syslog only if not a terminal */
	EAL_LOG_SYSLOG_ALWAYS,		/* always use syslog */
	EAL_LOG_SYSLOG_BOTH,		/* log to both syslog and stderr */
};

enum eal_log_color {
	EAL_LOG_COLOR_AUTO = 0,	/* default */
	EAL_LOG_COLOR_NEVER,
	EAL_LOG_COLOR_ALWAYS,
};

typedef int (*log_print_t)(FILE *f, uint32_t level, const char *fmt, va_list ap);
static int log_print(FILE *f, uint32_t level, const char *format, va_list ap);


/** The rte_log structure. */
static struct rte_logs {
	uint32_t type;  /**< Bitfield with enabled logs. */
	uint32_t level; /**< Log level. */
	FILE *file;     /**< Output file set by rte_openlog_stream, or NULL. */
#ifndef RTE_EXEC_ENV_WINDOWS
	enum eal_log_syslog syslog_opt;
	int journal_fd;
#endif
	log_print_t print_func;

	enum eal_log_color color_mode;
	enum eal_log_time_format time_format;
	struct timespec started;   /* when log was initialized */
	struct timespec previous;  /* when last msg was printed */

	size_t dynamic_types_len;
	struct rte_log_dynamic_type *dynamic_types;
} rte_logs = {
	.type = UINT32_MAX,
	.level = RTE_LOG_DEBUG,
	.print_func = log_print,
};

struct rte_eal_opt_loglevel {
	/** Next list entry */
	TAILQ_ENTRY(rte_eal_opt_loglevel) next;
	/** Compiled regular expression obtained from the option */
	regex_t re_match;
	/** Globbing pattern option */
	char *pattern;
	/** Log level value obtained from the option */
	uint32_t level;
};

TAILQ_HEAD(rte_eal_opt_loglevel_list, rte_eal_opt_loglevel);

/** List of valid EAL log level options */
static struct rte_eal_opt_loglevel_list opt_loglevel_list =
	TAILQ_HEAD_INITIALIZER(opt_loglevel_list);

/* Stream to use for logging if rte_logs.file is NULL */
static FILE *default_log_stream;

/**
 * This global structure stores some information about the message
 * that is currently being processed by one lcore
 */
struct log_cur_msg {
	uint32_t loglevel; /**< log level - see rte_log.h */
	uint32_t logtype;  /**< log type  - see rte_log.h */
};

 /* per core log */
static RTE_DEFINE_PER_LCORE(struct log_cur_msg, log_cur_msg);

/* Change the stream that will be used by logging system */
int
rte_openlog_stream(FILE *f)
{
	if (rte_logs.file != NULL)
		fclose(rte_logs.file);

	rte_logs.file = f;
	rte_logs.print_func = log_print;
	return 0;
}

FILE *
rte_log_get_stream(void)
{
	FILE *f = rte_logs.file;

	if (f == NULL) {
		/*
		 * Grab the current value of stderr here, rather than
		 * just initializing default_log_stream to stderr. This
		 * ensures that we will always use the current value
		 * of stderr, even if the application closes and
		 * reopens it.
		 */
		return default_log_stream != NULL ? default_log_stream : stderr;
	}
	return f;
}

/* Set global log level */
void
rte_log_set_global_level(uint32_t level)
{
	rte_logs.level = (uint32_t)level;
}

/* Get global log level */
uint32_t
rte_log_get_global_level(void)
{
	return rte_logs.level;
}

int
rte_log_get_level(uint32_t type)
{
	if (type >= rte_logs.dynamic_types_len)
		return -1;

	return rte_logs.dynamic_types[type].loglevel;
}

bool
rte_log_can_log(uint32_t logtype, uint32_t level)
{
	int log_level;

	if (level > rte_log_get_global_level())
		return false;

	log_level = rte_log_get_level(logtype);
	if (log_level < 0)
		return false;

	if (level > (uint32_t)log_level)
		return false;

	return true;
}

static void
logtype_set_level(uint32_t type, uint32_t level)
{
	uint32_t current = rte_logs.dynamic_types[type].loglevel;

	if (current != level) {
		rte_logs.dynamic_types[type].loglevel = level;
		RTE_LOG(DEBUG, EAL, "%s log level changed from %s to %s\n",
			rte_logs.dynamic_types[type].name == NULL ?
				"" : rte_logs.dynamic_types[type].name,
			eal_log_level2str(current),
			eal_log_level2str(level));
	}
}

int
rte_log_set_level(uint32_t type, uint32_t level)
{
	if (type >= rte_logs.dynamic_types_len)
		return -1;
	if (level > RTE_LOG_MAX)
		return -1;

	logtype_set_level(type, level);

	return 0;
}

/* set log level by regular expression */
int
rte_log_set_level_regexp(const char *regex, uint32_t level)
{
	regex_t r;
	size_t i;

	if (level > RTE_LOG_MAX)
		return -1;

	if (regcomp(&r, regex, 0) != 0)
		return -1;

	for (i = 0; i < rte_logs.dynamic_types_len; i++) {
		if (rte_logs.dynamic_types[i].name == NULL)
			continue;
		if (regexec(&r, rte_logs.dynamic_types[i].name, 0,
				NULL, 0) == 0)
			logtype_set_level(i, level);
	}

	regfree(&r);

	return 0;
}

/*
 * Save the type string and the loglevel for later dynamic
 * logtypes which may register later.
 */
static int
log_save_level(uint32_t priority, const char *regex, const char *pattern)
{
	struct rte_eal_opt_loglevel *opt_ll = NULL;

	opt_ll = malloc(sizeof(*opt_ll));
	if (opt_ll == NULL)
		goto fail;

	opt_ll->level = priority;

	if (regex) {
		opt_ll->pattern = NULL;
		if (regcomp(&opt_ll->re_match, regex, 0) != 0)
			goto fail;
	} else if (pattern) {
		opt_ll->pattern = strdup(pattern);
		if (opt_ll->pattern == NULL)
			goto fail;
	} else
		goto fail;

	TAILQ_INSERT_HEAD(&opt_loglevel_list, opt_ll, next);
	return 0;
fail:
	free(opt_ll);
	return -1;
}

int
eal_log_save_regexp(const char *regex, uint32_t level)
{
	return log_save_level(level, regex, NULL);
}

/* set log level based on globbing pattern */
int
rte_log_set_level_pattern(const char *pattern, uint32_t level)
{
	size_t i;

	if (level > RTE_LOG_MAX)
		return -1;

	for (i = 0; i < rte_logs.dynamic_types_len; i++) {
		if (rte_logs.dynamic_types[i].name == NULL)
			continue;

		if (fnmatch(pattern, rte_logs.dynamic_types[i].name, 0) == 0)
			logtype_set_level(i, level);
	}

	return 0;
}

int
eal_log_save_pattern(const char *pattern, uint32_t level)
{
	return log_save_level(level, NULL, pattern);
}

/* get the current loglevel for the message being processed */
int rte_log_cur_msg_loglevel(void)
{
	return RTE_PER_LCORE(log_cur_msg).loglevel;
}

/* get the current logtype for the message being processed */
int rte_log_cur_msg_logtype(void)
{
	return RTE_PER_LCORE(log_cur_msg).logtype;
}

static int
log_lookup(const char *name)
{
	size_t i;

	for (i = 0; i < rte_logs.dynamic_types_len; i++) {
		if (rte_logs.dynamic_types[i].name == NULL)
			continue;
		if (strcmp(name, rte_logs.dynamic_types[i].name) == 0)
			return i;
	}

	return -1;
}

static int
log_register(const char *name, uint32_t level)
{
	struct rte_log_dynamic_type *new_dynamic_types;
	int id;

	id = log_lookup(name);
	if (id >= 0)
		return id;

	new_dynamic_types = realloc(rte_logs.dynamic_types,
		sizeof(struct rte_log_dynamic_type) *
		(rte_logs.dynamic_types_len + 1));
	if (new_dynamic_types == NULL)
		return -ENOMEM;
	rte_logs.dynamic_types = new_dynamic_types;

	id = rte_logs.dynamic_types_len;
	memset(&rte_logs.dynamic_types[id], 0,
		sizeof(rte_logs.dynamic_types[id]));
	rte_logs.dynamic_types[id].name = strdup(name);
	if (rte_logs.dynamic_types[id].name == NULL)
		return -ENOMEM;
	logtype_set_level(id, level);

	rte_logs.dynamic_types_len++;

	return id;
}

/* register an extended log type */
int
rte_log_register(const char *name)
{
	return log_register(name, RTE_LOG_INFO);
}

/* Register an extended log type and try to pick its level from EAL options */
int
rte_log_register_type_and_pick_level(const char *name, uint32_t level_def)
{
	struct rte_eal_opt_loglevel *opt_ll;
	uint32_t level = level_def;

	TAILQ_FOREACH(opt_ll, &opt_loglevel_list, next) {
		if (opt_ll->level > RTE_LOG_MAX)
			continue;

		if (opt_ll->pattern) {
			if (fnmatch(opt_ll->pattern, name, 0) == 0)
				level = opt_ll->level;
		} else {
			if (regexec(&opt_ll->re_match, name, 0, NULL, 0) == 0)
				level = opt_ll->level;
		}
	}

	return log_register(name, level);
}

struct logtype {
	uint32_t log_id;
	const char *logtype;
};

static const struct logtype logtype_strings[] = {
	{RTE_LOGTYPE_EAL,        "lib.eal"},

	{RTE_LOGTYPE_USER1,      "user1"},
	{RTE_LOGTYPE_USER2,      "user2"},
	{RTE_LOGTYPE_USER3,      "user3"},
	{RTE_LOGTYPE_USER4,      "user4"},
	{RTE_LOGTYPE_USER5,      "user5"},
	{RTE_LOGTYPE_USER6,      "user6"},
	{RTE_LOGTYPE_USER7,      "user7"},
	{RTE_LOGTYPE_USER8,      "user8"}
};

/* Logging should be first initializer (before drivers and bus) */
RTE_INIT_PRIO(log_init, LOG)
{
	uint32_t i;

	clock_gettime(CLOCK_MONOTONIC, &rte_logs.started);
	rte_logs.previous = rte_logs.started;

	rte_log_set_global_level(RTE_LOG_DEBUG);

	rte_logs.dynamic_types = calloc(RTE_LOGTYPE_FIRST_EXT_ID,
		sizeof(struct rte_log_dynamic_type));
	if (rte_logs.dynamic_types == NULL)
		return;

	/* register legacy log types */
	for (i = 0; i < RTE_DIM(logtype_strings); i++) {
		rte_logs.dynamic_types[logtype_strings[i].log_id].name =
			strdup(logtype_strings[i].logtype);
		logtype_set_level(logtype_strings[i].log_id, RTE_LOG_INFO);
	}

	rte_logs.dynamic_types_len = RTE_LOGTYPE_FIRST_EXT_ID;
}

const char *
eal_log_level2str(uint32_t level)
{
	switch (level) {
	case 0: return "disabled";
	case RTE_LOG_EMERG: return "emergency";
	case RTE_LOG_ALERT: return "alert";
	case RTE_LOG_CRIT: return "critical";
	case RTE_LOG_ERR: return "error";
	case RTE_LOG_WARNING: return "warning";
	case RTE_LOG_NOTICE: return "notice";
	case RTE_LOG_INFO: return "info";
	case RTE_LOG_DEBUG: return "debug";
	default: return "unknown";
	}
}

static int
log_type_compare(const void *a, const void *b)
{
	const struct rte_log_dynamic_type *type_a = a;
	const struct rte_log_dynamic_type *type_b = b;

	if (type_a->name == NULL && type_b->name == NULL)
		return 0;
	if (type_a->name == NULL)
		return -1;
	if (type_b->name == NULL)
		return 1;
	return strcmp(type_a->name, type_b->name);
}

/* Dump name of each logtype, one per line. */
void
rte_log_list_types(FILE *out, const char *prefix)
{
	struct rte_log_dynamic_type *sorted_types;
	const size_t type_size = sizeof(rte_logs.dynamic_types[0]);
	const size_t type_count = rte_logs.dynamic_types_len;
	const size_t total_size = type_size * type_count;
	size_t type;

	sorted_types = malloc(total_size);
	if (sorted_types == NULL) {
		/* no sorting - unlikely */
		sorted_types = rte_logs.dynamic_types;
	} else {
		memcpy(sorted_types, rte_logs.dynamic_types, total_size);
		qsort(sorted_types, type_count, type_size, log_type_compare);
	}

	for (type = 0; type < type_count; ++type) {
		if (sorted_types[type].name == NULL)
			continue;
		fprintf(out, "%s%s\n", prefix, sorted_types[type].name);
	}

	if (sorted_types != rte_logs.dynamic_types)
		free(sorted_types);
}

/* dump global level and registered log types */
void
rte_log_dump(FILE *f)
{
	size_t i;

	fprintf(f, "global log level is %s\n",
		eal_log_level2str(rte_log_get_global_level()));

	for (i = 0; i < rte_logs.dynamic_types_len; i++) {
		if (rte_logs.dynamic_types[i].name == NULL)
			continue;
		fprintf(f, "id %zu: %s, level is %s\n",
			i, rte_logs.dynamic_types[i].name,
			eal_log_level2str(rte_logs.dynamic_types[i].loglevel));
	}
}

/*
 * Generates a log message The message will be sent in the stream
 * defined by the previous call to rte_openlog_stream().
 */
int
rte_vlog(uint32_t level, uint32_t logtype, const char *format, va_list ap)
{
	FILE *f = rte_log_get_stream();
	int ret;

	if (logtype >= rte_logs.dynamic_types_len)
		return -1;
	if (!rte_log_can_log(logtype, level))
		return 0;

	/* save loglevel and logtype in a global per-lcore variable */
	RTE_PER_LCORE(log_cur_msg).loglevel = level;
	RTE_PER_LCORE(log_cur_msg).logtype = logtype;

	ret = (*rte_logs.print_func)(f, level, format, ap);
	fflush(f);
	return ret;
}

/*
 * Generates a log message The message will be sent in the stream
 * defined by the previous call to rte_openlog_stream().
 * No need to check level here, done by rte_vlog().
 */
int
rte_log(uint32_t level, uint32_t logtype, const char *format, ...)
{
	va_list ap;
	int ret;

	va_start(ap, format);
	ret = rte_vlog(level, logtype, format, ap);
	va_end(ap);
	return ret;
}

/* Placeholder */
int
eal_log_syslog(const char *str)
{
#ifdef RTE_EXEC_ENV_WINDOWS
	RTE_SET_USED(str);
	return -1;
#else
	if (str == NULL || strcmp(str, "auto") == 0)
		/* log to syslog only if stderr is not a terminal */
		rte_logs.syslog_opt = EAL_LOG_SYSLOG_AUTO;
	else if (strcmp(str, "both") == 0)
		rte_logs.syslog_opt = EAL_LOG_SYSLOG_BOTH;
	else if (strcmp(str, "always") == 0)
		rte_logs.syslog_opt = EAL_LOG_SYSLOG_ALWAYS;
	else
		return -1;
	return 0;
#endif
}

/* Set the log timestamp format */
int
eal_log_timestamp(const char *str)
{
	if (str == NULL)
		rte_logs.time_format = EAL_LOG_TIMESTAMP_TIME;
	else if (strcmp(str, "notime") == 0)
		rte_logs.time_format = EAL_LOG_TIMESTAMP_NONE;
	else if (strcmp(str, "reltime") == 0)
		rte_logs.time_format = EAL_LOG_TIMESTAMP_RELTIME;
	else if (strcmp(str, "delta") == 0)
		rte_logs.time_format = EAL_LOG_TIMESTAMP_DELTA;
	else if (strcmp(str, "ctime") == 0)
		rte_logs.time_format =  EAL_LOG_TIMESTAMP_CTIME;
	else if (strcmp(str, "iso") == 0)
		rte_logs.time_format = EAL_LOG_TIMESTAMP_ISO;
	else
		return -1;

	return 0;
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


/* Format current timespec into ISO8601 format */
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
	delta = timespec_sub(now, &rte_logs.previous);
	rte_logs.previous = *now;

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
static ssize_t
format_timestamp(char *tsbuf, size_t tsbuflen)
{
	struct timespec now, delta;

	switch (rte_logs.time_format) {
	case EAL_LOG_TIMESTAMP_NONE:
		return 0;

	case EAL_LOG_TIMESTAMP_TIME:
		if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
			return 0;

		delta = timespec_sub(&now, &rte_logs.started);

		return snprintf(tsbuf, tsbuflen, "%6lu.%06lu",
				(unsigned long)delta.tv_sec,
				(unsigned long)delta.tv_nsec / 1000u);

	case EAL_LOG_TIMESTAMP_DELTA:
		if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
			return 0;

		delta = timespec_sub(&now, &rte_logs.previous);
		rte_logs.previous = now;

		return snprintf(tsbuf, tsbuflen, "<%6lu.%06lu>",
				(unsigned long)delta.tv_sec,
				(unsigned long)delta.tv_nsec / 1000u);

	case EAL_LOG_TIMESTAMP_RELTIME:
		if (clock_gettime(CLOCK_REALTIME, &now) < 0)
			return 0;

		return format_reltime(tsbuf, tsbuflen, &now);

	case EAL_LOG_TIMESTAMP_CTIME:
		if (clock_gettime(CLOCK_REALTIME, &now) < 0)
			return 0;

		/* trncate to remove newline from ctime result */
		return snprintf(tsbuf, tsbuflen, "%.24s", ctime(&now.tv_sec));

	case EAL_LOG_TIMESTAMP_ISO:
		if (clock_gettime(CLOCK_REALTIME, &now) < 0)
			return 0;

		return format_iso8601(tsbuf, tsbuflen, &now);
	}

	return 0;
}

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
	COLOR_CLEAR
};

static const char * const color_code[] = {
	[COLOR_NONE]	= "",
	[COLOR_RED]	= "\e[31m",
	[COLOR_GREEN]	= "\e[32m",
	[COLOR_YELLOW]	= "\e[33m",
	[COLOR_BLUE]	= "\e[34m",
	[COLOR_MAGENTA] = "\e[35m",
	[COLOR_CYAN]    = "\e[36m",
	[COLOR_WHITE]	= "\e[37m",
	[COLOR_BOLD]	= "\e[1m",
	[COLOR_CLEAR]	= "\e[0m",
};

__rte_format_printf(3, 4)
static int color_fprintf(FILE *out, enum color color, const char *fmt, ...)
{
	va_list args;
	int ret = 0;

	va_start(args, fmt);
	ret = fprintf(out, "%s", color_code[color]);
	ret += vfprintf(out, fmt, args);
	ret += fprintf(out, "%s", color_code[COLOR_CLEAR]);

	return ret;
}

static ssize_t
color_log_write(FILE *f, int level, char *msg)
{
	char *cp;
	ssize_t ret = 0;

	/*
	 * use convention that first part of message (up to the ':' character)
	 * is the subsystem id and should be highlighted.
	 */
	cp = strchr(msg, ':');
	if (cp) {
		/* print first part in yellow */
		ret = color_fprintf(stderr, COLOR_YELLOW, "%.*s",
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

/* default log print function */
__rte_format_printf(3, 0)
static int
log_print(FILE *f, uint32_t level __rte_unused,
	  const char *format, va_list ap)
{
	return vfprintf(f, format, ap);
}

/* print timestamp before message */
__rte_format_printf(3, 0)
static int
log_print_with_timestamp(FILE *f, uint32_t level,
			 const char *format, va_list ap)
{
	char tsbuf[128];

	if (format_timestamp(tsbuf, sizeof(tsbuf)) > 0)
		fprintf(f, "[%s] ", tsbuf);

	return log_print(f, level, format, ap);
}

#ifndef RTE_EXEC_ENV_WINDOWS
static bool
using_syslog(bool is_terminal)
{
	switch (rte_logs.syslog_opt) {
	default:
		return false;

	case EAL_LOG_SYSLOG_ALWAYS:
	case EAL_LOG_SYSLOG_BOTH:
		return true;

	case EAL_LOG_SYSLOG_AUTO:
		return !is_terminal;
	}
}

/*
 * wrapper for log stream to put messages into syslog
 * useful for cases like:
 *   rte_hex_dump(rte_get_log_stream(), ...)
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

/*
 * send message using journal protocol to journald
 */
static int
journal_send(uint32_t level, const char *buf, size_t len)
{
	struct iovec iov[3];
	char msg[] = "MESSAGE=";
	char prio[32];
	int ret;

	iov[0].iov_base = msg;
	iov[0].iov_len = strlen(msg);

	iov[1].iov_base = (char *)(uintptr_t)buf;
	iov[1].iov_len = len;

	/* priority value between 0 ("emerg") and 7 ("debug") */
	iov[2].iov_base = prio;
	iov[2].iov_len = snprintf(prio, sizeof(prio),
				  "PRIORITY=%i\n", level - 1);

	ret = writev(rte_logs.journal_fd, iov, 3);
	return ret;
}

__rte_format_printf(3, 0)
static int
journal_print(FILE *f __rte_unused, uint32_t level, const char *format, va_list ap)
{
	char buf[BUFSIZ];
	size_t len;

	len = vsnprintf(buf, sizeof(buf), format, ap);
	if (len == 0)
		return 0;

	/* check for truncation */
	if (len >= sizeof(buf) - 1)
		len = sizeof(buf) - 1;

	/* check that message ends with newline, if not add one */
	if (buf[len - 1] != '\n')
		buf[len++] = '\n';

	return journal_send(level, buf, len);
}

/* wrapper for log stream to put messages into journal */
static ssize_t
journal_log_write(__rte_unused void *c, const char *buf, size_t size)
{
	return journal_send(rte_log_cur_msg_loglevel(), buf, size);
}

static cookie_io_functions_t journal_log_func = {
	.write = journal_log_write,
};

/*
 * Check if stderr is going to system journal.
 * This is the documented way to handle systemd journal
 *
 * See: https://systemd.io/JOURNAL_NATIVE_PROTOCOL/
 *
 */
static bool
is_journal(int fd)
{
	char *jenv, *endp = NULL;
	struct stat st;
	unsigned long dev, ino;

	jenv = getenv("JOURNAL_STREAM");
	if (jenv == NULL)
		return false;

	if (fstat(fd, &st) < 0)
		return false;

	/* systemd sets colon-separated list of device and inode number */
	dev = strtoul(jenv, &endp, 10);
	if (endp == NULL || *endp != ':')
		return false;	/* missing colon */

	ino = strtoul(endp + 1, NULL, 10);

	return dev == st.st_dev && ino == st.st_ino;
}

/* Connect to systemd's journal service */
static int
open_journal(const char *id)
{
	char *syslog_id = NULL;
	struct sockaddr_un sun = {
		.sun_family = AF_UNIX,
		.sun_path = "/run/systemd/journal/socket",
	};
	ssize_t len;
	int s;

	s = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (s < 0)
		return -1;

	if (connect(s, (struct sockaddr *)&sun, sizeof(sun)) < 0)
		goto error;

	/* Send syslog identifier as first message */
	len = asprintf(&syslog_id, "SYSLOG_IDENTIFIER=%s\n", id);
	if (len == 0)
		goto error;

	if (write(s, syslog_id, len) != len)
		goto error;

	free(syslog_id);

	/* redirect other log messages to journal */
	FILE *log_stream = fopencookie(NULL, "w", journal_log_func);
	if (log_stream != NULL)
		default_log_stream = log_stream;

	return s;

error:
	free(syslog_id);
	close(s);
	return -1;
}

static void
log_open_syslog(const char *id, bool is_terminal)
{
	int flags = LOG_NDELAY | LOG_PID;

#ifdef LOG_PERROR
	if (rte_logs.syslog_opt == EAL_LOG_SYSLOG_BOTH)
		flags |= LOG_PERROR;
#endif
	openlog(id, flags, is_terminal ? LOG_USER : LOG_DAEMON);

	/* redirect other log messages to syslog as well */
	FILE *log_stream = fopencookie(NULL, "w", syslog_log_func);
	if (log_stream != NULL)
		default_log_stream = log_stream;
}
#endif

__rte_format_printf(3, 0)
static int
color_print(FILE *f, uint32_t level, const char *format, va_list ap)
{
	char *buf = NULL;
	int ret;

	/* need to make temporary buffer for color scan */
	ret = vasprintf(&buf, format, ap);
	if (ret > 0) {
		ret = color_log_write(f, level, buf);
		free(buf);
		return ret;
	}

	/* if vasprintf fails, print without color */
	return log_print(f, level, format, ap);
}

__rte_format_printf(3, 0)
static int
color_print_with_timestamp(FILE *f, uint32_t level,
			   const char *format, va_list ap)
{
	char tsbuf[128];

	if (format_timestamp(tsbuf, sizeof(tsbuf)) > 0)
		color_fprintf(f, COLOR_GREEN, "[%s] ", tsbuf);

	return color_print(f, level, format, ap);
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
		rte_logs.color_mode = EAL_LOG_COLOR_ALWAYS;
	else if (strcmp(mode, "never") == 0)
		rte_logs.color_mode = EAL_LOG_COLOR_NEVER;
	else if (strcmp(mode, "auto") == 0)
		rte_logs.color_mode = EAL_LOG_COLOR_AUTO;
	else
		return -1;

	return 0;
}

static inline bool
use_color(bool is_terminal)
{
	switch (rte_logs.color_mode) {
	default:
	case EAL_LOG_COLOR_NEVER:
		return false;
	case EAL_LOG_COLOR_ALWAYS:
		return true;
	case EAL_LOG_COLOR_AUTO:
		return is_terminal;
	}

}

/* Choose how log output is directed */
static void
log_output_selection(const char *id)
{
	bool is_terminal = isatty(STDERR_FILENO);

#ifdef RTE_EXEC_ENV_WINDOWS
	RTE_SET_USED(id);
#else
	/* If stderr is redirected to systemd journal then upgrade */
	if (!is_terminal && is_journal(STDERR_FILENO)) {
		int jfd = open_journal(id);

		if (jfd < 0) {
			RTE_LOG_LINE(NOTICE, EAL, "Cannot connect to journal: %s",
				     strerror(errno));
		} else {
			rte_logs.print_func = journal_print;
			return;
		}
	}

	if (using_syslog(is_terminal)) {
		log_open_syslog(id, is_terminal);
		return;
	}
#endif

	if (use_color(is_terminal)) {
		if (rte_logs.time_format == EAL_LOG_TIMESTAMP_NONE)
			rte_logs.print_func = color_print;
		else
			rte_logs.print_func = color_print_with_timestamp;
	} else {
		if (rte_logs.time_format == EAL_LOG_TIMESTAMP_NONE)
			rte_logs.print_func = log_print;
		else
			rte_logs.print_func = log_print_with_timestamp;
	}

}

/*
 * Called by rte_eal_init
 */
void
eal_log_init(const char *id)
{
	rte_logs.print_func = log_print;
	default_log_stream = stderr;

	log_output_selection(id);

#if RTE_LOG_DP_LEVEL >= RTE_LOG_DEBUG
	RTE_LOG(NOTICE, EAL,
		"Debug dataplane logs available - lower performance\n");
#endif
}

/*
 * Called by eal_cleanup
 */
void
rte_eal_log_cleanup(void)
{
	FILE *log_stream = rte_log_get_stream();

	/* don't close stderr on the application */
	if (log_stream != stderr)
		fclose(log_stream);

	rte_logs.file = NULL;
}

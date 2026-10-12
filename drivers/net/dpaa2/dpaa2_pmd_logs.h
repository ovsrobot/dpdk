/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2017 NXP
 */

#ifndef _DPAA2_PMD_LOGS_H_
#define _DPAA2_PMD_LOGS_H_

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <rte_common.h>
#include <rte_log.h>

extern int dpaa2_logtype_pmd;
#define RTE_LOGTYPE_DPAA2_NET dpaa2_logtype_pmd

#define DPAA2_PMD_LOG(level, ...) \
	RTE_LOG_LINE(level, DPAA2_NET, __VA_ARGS__)

#define DPAA2_PMD_DEBUG(...) \
	RTE_LOG_LINE_PREFIX(DEBUG, DPAA2_NET, "%s(): ", __func__, __VA_ARGS__)

#define PMD_INIT_FUNC_TRACE() DPAA2_PMD_DEBUG(">>")

#define DPAA2_PMD_CRIT(fmt, ...) \
	DPAA2_PMD_LOG(CRIT, fmt, ## __VA_ARGS__)
#define DPAA2_PMD_INFO(fmt, ...) \
	DPAA2_PMD_LOG(INFO, fmt, ## __VA_ARGS__)
#define DPAA2_PMD_ERR(fmt, ...) \
	DPAA2_PMD_LOG(ERR, fmt, ## __VA_ARGS__)
#define DPAA2_PMD_WARN(fmt, ...) \
	DPAA2_PMD_LOG(WARNING, fmt, ## __VA_ARGS__)

/* DP Logs, toggled out at compile time if level lower than current level */
#define DPAA2_PMD_DP_LOG(level, ...) \
	RTE_LOG_DP_LINE(level, DPAA2_NET, __VA_ARGS__)

#define DPAA2_PMD_DP_DEBUG(fmt, ...) \
	DPAA2_PMD_DP_LOG(DEBUG, fmt, ## __VA_ARGS__)
#define DPAA2_PMD_DP_INFO(fmt, ...) \
	DPAA2_PMD_DP_LOG(INFO, fmt, ## __VA_ARGS__)
#define DPAA2_PMD_DP_WARN(fmt, ...) \
	DPAA2_PMD_DP_LOG(WARNING, fmt, ## __VA_ARGS__)

/** Maximum length of a single debug dump line. */
#define DPAA2_DUMP_LINE_SIZE 512

/**
 * Append formatted text to the per-thread debug dump line buffer.
 *
 * The parse result and flow dump helpers build a line from several
 * fragments, so the text is accumulated here and handed to the regular
 * logging framework one complete line at a time. This keeps the dump
 * readable without writing to stdout or stderr from the driver.
 *
 * Carriage returns and newlines terminate a line and are not logged.
 */
static inline void
dpaa2_dump_print(const char *fmt, ...) __rte_format_printf(1, 2);

static inline void
dpaa2_dump_print(const char *fmt, ...)
{
	static __thread char line[DPAA2_DUMP_LINE_SIZE];
	static __thread size_t used;
	size_t start, i;
	va_list ap;
	int len;

	va_start(ap, fmt);
	len = vsnprintf(line + used, sizeof(line) - used, fmt, ap);
	va_end(ap);

	if (len > 0) {
		used += (size_t)len;
		/* Output was truncated, keep the buffer consistent. */
		if (used >= sizeof(line))
			used = sizeof(line) - 1;
	}

	/* Log every complete line held in the buffer. */
	start = 0;
	for (i = 0; i < used; i++) {
		if (line[i] != '\n' && line[i] != '\r')
			continue;
		line[i] = '\0';
		if (i != start)
			DPAA2_PMD_DEBUG("%s", &line[start]);
		start = i + 1;
	}

	if (start) {
		used -= start;
		memmove(line, &line[start], used);
	}

	/* Flush a full buffer even without a line terminator. */
	if (used >= sizeof(line) - 1) {
		line[used] = '\0';
		DPAA2_PMD_DEBUG("%s", line);
		used = 0;
	}
}

#endif /* _DPAA2_PMD_LOGS_H_ */

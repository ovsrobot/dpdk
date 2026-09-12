/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Stephen Hemminger
 */

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_log.h>
#include <rte_sysfs.h>

#include <eal_export.h>
#include "eal_private.h"

/* build the path from the format, then read the first line of that file */
static int
sysfs_read_line(char *buf, size_t buflen, const char *format, va_list ap)
{
	char path[PATH_MAX];
	FILE *f;
	int len;

	len = vsnprintf(path, sizeof(path), format, ap);
	if (len < 0 || len >= (int)sizeof(path)) {
		EAL_LOG(ERR, "sysfs path too long");
		return -1;
	}

	f = fopen(path, "r");
	if (f == NULL) {
		/*
		 * A missing attribute is normal: callers probe for optional
		 * ones such as max_vfs or numa_node. Anything else, such as
		 * a permission problem, is worth reporting.
		 */
		if (errno == ENOENT)
			EAL_LOG(DEBUG, "cannot open %s: %s", path, strerror(errno));
		else
			EAL_LOG(ERR, "cannot open %s: %s", path, strerror(errno));
		return -1;
	}

	if (fgets(buf, buflen, f) == NULL) {
		EAL_LOG(ERR, "cannot read %s", path);
		fclose(f);
		return -1;
	}
	fclose(f);

	/* sysfs values are newline terminated, strip it */
	*strchrnul(buf, '\n') = '\0';

	return 0;
}

RTE_EXPORT_INTERNAL_SYMBOL(rte_sysfs_vparse_uint)
int
rte_sysfs_vparse_uint(unsigned long *val, const char *format, va_list ap)
{
	const char *start;
	char buf[BUFSIZ];
	unsigned long tmp;
	char *end;

	if (sysfs_read_line(buf, sizeof(buf), format, ap) < 0)
		return -1;

	/*
	 * strtoul() skips leading whitespace and then silently negates a
	 * leading '-', so " -1" would come back as ULONG_MAX. Look for the
	 * sign past any whitespace: attributes that are really signed, such
	 * as numa_node, must use rte_sysfs_parse_int() instead.
	 */
	start = buf;
	while (isspace((unsigned char)*start))
		++start;

	errno = 0;
	tmp = strtoul(start, &end, 0);
	if (end == start || *end != '\0' || errno != 0 || *start == '-') {
		EAL_LOG(ERR, "cannot parse sysfs value '%s'", buf);
		return -1;
	}

	*val = tmp;
	return 0;
}

RTE_EXPORT_INTERNAL_SYMBOL(rte_sysfs_parse_uint)
int
rte_sysfs_parse_uint(unsigned long *val, const char *format, ...)
{
	va_list ap;
	int ret;

	va_start(ap, format);
	ret = rte_sysfs_vparse_uint(val, format, ap);
	va_end(ap);

	return ret;
}

RTE_EXPORT_INTERNAL_SYMBOL(rte_sysfs_parse_int)
int
rte_sysfs_parse_int(long *val, const char *format, ...)
{
	char buf[BUFSIZ];
	va_list ap;
	char *end;
	long tmp;
	int ret;

	va_start(ap, format);
	ret = sysfs_read_line(buf, sizeof(buf), format, ap);
	va_end(ap);
	if (ret < 0)
		return -1;

	errno = 0;
	tmp = strtol(buf, &end, 0);
	if (end == buf || *end != '\0' || errno != 0) {
		EAL_LOG(ERR, "cannot parse sysfs value '%s'", buf);
		return -1;
	}

	*val = tmp;
	return 0;
}

RTE_EXPORT_INTERNAL_SYMBOL(rte_sysfs_parse_string)
int
rte_sysfs_parse_string(char *buf, size_t buflen, const char *format, ...)
{
	va_list ap;
	int ret;

	va_start(ap, format);
	ret = sysfs_read_line(buf, buflen, format, ap);
	va_end(ap);

	return ret;
}

RTE_EXPORT_INTERNAL_SYMBOL(rte_sysfs_write_string)
int
rte_sysfs_write_string(const char *str, const char *format, ...)
{
	char path[PATH_MAX];
	va_list ap;
	FILE *f;
	int len;

	va_start(ap, format);
	len = vsnprintf(path, sizeof(path), format, ap);
	va_end(ap);
	if (len < 0 || len >= (int)sizeof(path)) {
		EAL_LOG(ERR, "sysfs path too long");
		return -1;
	}

	f = fopen(path, "w");
	if (f == NULL) {
		if (errno == ENOENT)
			EAL_LOG(DEBUG, "cannot open %s: %s", path, strerror(errno));
		else
			EAL_LOG(ERR, "cannot open %s: %s", path, strerror(errno));
		return -1;
	}

	if (fputs(str, f) < 0) {
		EAL_LOG(ERR, "cannot write '%s' to %s", str, path);
		fclose(f);
		return -1;
	}

	/* errors on a sysfs write are reported at close time */
	if (fclose(f) != 0) {
		EAL_LOG(ERR, "cannot write '%s' to %s: %s", str, path, strerror(errno));
		return -1;
	}

	return 0;
}

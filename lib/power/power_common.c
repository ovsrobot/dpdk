/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include <eal_export.h>
#include <rte_log.h>
#include <rte_string_fns.h>
#include <rte_lcore.h>
#include <rte_sysfs.h>

#include "power_common.h"

RTE_EXPORT_INTERNAL_SYMBOL(rte_power_logtype)
RTE_LOG_REGISTER_DEFAULT(rte_power_logtype, INFO);

#define POWER_SYSFILE_SCALING_DRIVER   \
		"/sys/devices/system/cpu/cpu%u/cpufreq/scaling_driver"
#define POWER_SYSFILE_GOVERNOR  \
		"/sys/devices/system/cpu/cpu%u/cpufreq/scaling_governor"

RTE_EXPORT_INTERNAL_SYMBOL(cpufreq_check_scaling_driver)
int
cpufreq_check_scaling_driver(const char *driver_name)
{
	unsigned int lcore_id = 0; /* always check core 0 */
	char readbuf[PATH_MAX];

	/*
	 * Check if scaling driver matches what we expect.
	 * If there is no driver at all, or it can't be read,
	 * consider the system unsupported.
	 */
	if (rte_sysfs_parse_string(readbuf, sizeof(readbuf),
			POWER_SYSFILE_SCALING_DRIVER, lcore_id) < 0)
		return 0;

	/* does the driver name match? */
	if (strncmp(readbuf, driver_name, sizeof(readbuf)) != 0)
		return 0;

	/*
	 * We might have a situation where the driver is supported, but we don't
	 * have permissions to do frequency scaling. This error should not be
	 * handled here, so consider the system to support scaling for now.
	 */
	return 1;
}

RTE_EXPORT_INTERNAL_SYMBOL(open_core_sysfs_file)
int
open_core_sysfs_file(FILE **f, const char *mode, const char *format, ...)
{
	char fullpath[PATH_MAX];
	va_list ap;
	FILE *tmpf;

	va_start(ap, format);
	vsnprintf(fullpath, sizeof(fullpath), format, ap);
	va_end(ap);
	tmpf = fopen(fullpath, mode);
	*f = tmpf;
	if (tmpf == NULL)
		return -1;

	return 0;
}

RTE_EXPORT_INTERNAL_SYMBOL(power_sysfs_read_u32)
int
power_sysfs_read_u32(uint32_t *val, const char *format, ...)
{
	unsigned long tmp;
	va_list ap;
	int ret;

	va_start(ap, format);
	ret = rte_sysfs_vparse_uint(&tmp, format, ap);
	va_end(ap);
	if (ret < 0)
		return -1;

	*val = tmp;
	return 0;
}

RTE_EXPORT_INTERNAL_SYMBOL(read_core_sysfs_u32)
int
read_core_sysfs_u32(FILE *f, uint32_t *val)
{
	char buf[BUFSIZ];
	uint32_t fval;
	char *s;

	s = fgets(buf, sizeof(buf), f);
	if (s == NULL)
		return -1;

	/* fgets puts null terminator in, but do this just in case */
	buf[BUFSIZ - 1] = '\0';

	/* strip off any terminating newlines */
	*strchrnul(buf, '\n') = '\0';

	fval = strtoul(buf, NULL, POWER_CONVERT_TO_DECIMAL);

	/* write the value */
	*val = fval;

	return 0;
}

RTE_EXPORT_INTERNAL_SYMBOL(read_core_sysfs_s)
int
read_core_sysfs_s(FILE *f, char *buf, unsigned int len)
{
	char *s;

	s = fgets(buf, len, f);
	if (s == NULL)
		return -1;

	/* fgets puts null terminator in, but do this just in case */
	buf[len - 1] = '\0';

	/* strip off any terminating newlines */
	*strchrnul(buf, '\n') = '\0';

	return 0;
}

RTE_EXPORT_INTERNAL_SYMBOL(write_core_sysfs_s)
int
write_core_sysfs_s(FILE *f, const char *str)
{
	int ret;

	ret = fseek(f, 0, SEEK_SET);
	if (ret != 0)
		return -1;

	ret = fputs(str, f);
	if (ret < 0)
		return -1;

	/* flush the output */
	ret = fflush(f);
	if (ret != 0)
		return -1;

	return 0;
}

/**
 * It is to check the current scaling governor by reading sys file, and then
 * set it into 'performance' if it is not by writing the sys file. The original
 * governor will be saved for rolling back.
 */
RTE_EXPORT_INTERNAL_SYMBOL(power_set_governor)
int
power_set_governor(unsigned int lcore_id, const char *new_governor,
		char *orig_governor, size_t orig_governor_len)
{
	FILE *f_governor = NULL;
	int ret = -1;
	char buf[BUFSIZ];

	open_core_sysfs_file(&f_governor, "rw+", POWER_SYSFILE_GOVERNOR,
			lcore_id);
	if (f_governor == NULL) {
		POWER_LOG(ERR, "failed to open %s",
				POWER_SYSFILE_GOVERNOR);
		goto out;
	}

	ret = read_core_sysfs_s(f_governor, buf, sizeof(buf));
	if (ret < 0) {
		POWER_LOG(ERR, "Failed to read %s",
				POWER_SYSFILE_GOVERNOR);
		goto out;
	}

	/* Save the original governor, if it was provided */
	if (orig_governor)
		rte_strscpy(orig_governor, buf, orig_governor_len);

	/* Check if current governor is already what we want */
	if (strcmp(buf, new_governor) == 0) {
		ret = 0;
		POWER_DEBUG_LOG("Power management governor of lcore %u is "
				"already %s", lcore_id, new_governor);
		goto out;
	}

	/* Write the new governor */
	ret = write_core_sysfs_s(f_governor, new_governor);
	if (ret < 0) {
		POWER_LOG(ERR, "Failed to write %s",
				POWER_SYSFILE_GOVERNOR);
		goto out;
	}

	ret = 0;
	POWER_LOG(INFO, "Power management governor of lcore %u has been "
			"set to '%s' successfully", lcore_id, new_governor);
out:
	if (f_governor != NULL)
		fclose(f_governor);

	return ret;
}

RTE_EXPORT_INTERNAL_SYMBOL(power_get_lcore_mapped_cpu_id)
int power_get_lcore_mapped_cpu_id(uint32_t lcore_id, uint32_t *cpu_id)
{
	rte_cpuset_t lcore_cpus;
	uint32_t cpu;

	lcore_cpus = rte_lcore_cpuset(lcore_id);
	if (CPU_COUNT(&lcore_cpus) != 1) {
		POWER_LOG(ERR,
			"Power library does not support lcore %u mapping to %u CPUs",
			lcore_id, CPU_COUNT(&lcore_cpus));
		return -1;
	}

	for (cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		if (CPU_ISSET(cpu, &lcore_cpus))
			break;
	}
	*cpu_id = cpu;

	return 0;
}

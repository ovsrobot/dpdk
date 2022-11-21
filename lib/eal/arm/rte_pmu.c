/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell International Ltd.
 */

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <rte_bitops.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_pmu.h>

#include "pmu_private.h"

#define PERF_USER_ACCESS_PATH "/proc/sys/kernel/perf_user_access"

static int restore_uaccess;

static int
read_attr_int(const char *path, int *val)
{
	char buf[BUFSIZ];
	int ret, fd;

	fd = open(path, O_RDONLY);
	if (fd == -1)
		return -errno;

	ret = read(fd, buf, sizeof(buf));
	if (ret == -1) {
		close(fd);

		return -errno;
	}

	*val = strtol(buf, NULL, 10);
	close(fd);

	return 0;
}

static int
write_attr_int(const char *path, int val)
{
	char buf[BUFSIZ];
	int num, ret, fd;

	fd = open(path, O_WRONLY);
	if (fd == -1)
		return -errno;

	num = snprintf(buf, sizeof(buf), "%d", val);
	ret = write(fd, buf, num);
	if (ret == -1) {
		close(fd);

		return -errno;
	}

	close(fd);

	return 0;
}

int
pmu_arch_init(void)
{
	int ret;

	ret = read_attr_int(PERF_USER_ACCESS_PATH, &restore_uaccess);
	if (ret) {
		RTE_LOG(ERR, EAL, "failed to read %s\n", PERF_USER_ACCESS_PATH);

		return ret;
	}

	ret = write_attr_int(PERF_USER_ACCESS_PATH, 1);
	if (ret) {
		RTE_LOG(ERR, EAL, "failed to enable perf user access\n"
			"try enabling manually 'echo 1 > %s'\n",
			PERF_USER_ACCESS_PATH);

		return ret;
	}

	return 0;
}

void
pmu_arch_fini(void)
{
	write_attr_int(PERF_USER_ACCESS_PATH, restore_uaccess);
}

void
pmu_arch_fixup_config(uint64_t config[3])
{
	/* select 64 bit counters */
	config[1] |= RTE_BIT64(0);
	/* enable userspace access */
	config[1] |= RTE_BIT64(1);
}

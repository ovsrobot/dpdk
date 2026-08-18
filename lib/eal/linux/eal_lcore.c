/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <unistd.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include <rte_argparse.h>
#include <rte_log.h>

#include "eal_private.h"
#include "eal_filesystem.h"
#include "eal_thread.h"

#define SYS_CPU_DIR "/sys/devices/system/cpu/cpu%u"
#define SYS_CPU_POSSIBLE_PATH "/sys/devices/system/cpu/possible"
#define CORE_ID_FILE "topology/core_id"
#define NUMA_NODE_PATH "/sys/devices/system/node"

static int
eal_cpu_possible(rte_cpuset_t *cpuset)
{
	char cpu_list[BUFSIZ];
	FILE *f;

	f = fopen(SYS_CPU_POSSIBLE_PATH, "r");
	if (f == NULL)
		return -1;
	if (fgets(cpu_list, sizeof(cpu_list), f) == NULL ||
			strchr(cpu_list, '\n') == NULL) {
		fclose(f);
		return -1;
	}
	fclose(f);
	cpu_list[strcspn(cpu_list, "\n")] = '\0';

	return rte_argparse_parse_type(cpu_list,
		RTE_ARGPARSE_VALUE_TYPE_CORELIST, cpuset);
}

/* Check if a cpu is present by the presence of the cpu information for it */
int
eal_cpu_detected(unsigned lcore_id)
{
	char path[PATH_MAX];
	int len = snprintf(path, sizeof(path), SYS_CPU_DIR
		"/"CORE_ID_FILE, lcore_id);
	if (len <= 0 || (unsigned)len >= sizeof(path))
		return 0;
	if (access(path, F_OK) != 0)
		return 0;

	return 1;
}

/*
 * Get CPU socket id (NUMA node) for a logical core.
 *
 * This searches each nodeX directories in /sys for the symlink for the given
 * lcore_id and returns the numa node where the lcore is found. If lcore is not
 * found on any numa node, returns zero.
 */
unsigned
eal_cpu_socket_id(unsigned lcore_id)
{
	unsigned socket;

	for (socket = 0; socket < RTE_MAX_NUMA_NODES; socket++) {
		char path[PATH_MAX];

		snprintf(path, sizeof(path), "%s/node%u/cpu%u", NUMA_NODE_PATH,
				socket, lcore_id);
		if (access(path, F_OK) == 0)
			return socket;
	}
	return 0;
}

/* Get the cpu core id value from the /sys/.../cpuX core_id value */
unsigned
eal_cpu_core_id(unsigned lcore_id)
{
	char path[PATH_MAX];
	unsigned long id;

	int len = snprintf(path, sizeof(path), SYS_CPU_DIR "/%s", lcore_id, CORE_ID_FILE);
	if (len <= 0 || (unsigned)len >= sizeof(path))
		goto err;
	if (eal_parse_sysfs_value(path, &id) != 0)
		goto err;
	return (unsigned)id;

err:
	EAL_LOG(ERR, "Error reading core id value from %s "
			"for lcore %u - assuming core 0", SYS_CPU_DIR, lcore_id);
	return 0;
}

size_t
eal_cpu_max(void)
{
	rte_cpuset_t possible_cpus;
	int cpu_id;

	if (eal_cpu_possible(&possible_cpus) == 0) {
		for (cpu_id = CPU_SETSIZE - 1; cpu_id >= 0; cpu_id--) {
			if (CPU_ISSET(cpu_id, &possible_cpus))
				return cpu_id + 1;
		}
	}

	EAL_LOG(WARNING, "Cannot read possible CPU IDs from %s, falling back to CPU_SETSIZE",
			SYS_CPU_POSSIBLE_PATH);
	return CPU_SETSIZE;
}

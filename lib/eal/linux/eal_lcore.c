/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <unistd.h>
#include <limits.h>
#include <inttypes.h>

#include <rte_log.h>

#include "eal_private.h"
#include "eal_filesystem.h"
#include "eal_thread.h"

#define PROC_STATUS "/proc/%u/status"
#define SYS_CPU_DIR "/sys/devices/system/cpu/cpu%u"
#define CORE_ID_FILE "topology/core_id"
#define NUMA_NODE_PATH "/sys/devices/system/node"

static cpu_set_t *cpus_allowed;

/*
 * Initialize allowed cpus from /proc/<pid>status
 * The cpus allowed is a subset of available lcores on the system
 * which maybe restricted by cgroups
 */
static void
get_allowed_cpus(cpu_set_t *set)
{
	const char cpus_allowed[] = "Cpus_allowed:";
	const size_t setsize = CPU_ALLOC_SIZE(RTE_MAX_LCORE);
	char path[PATH_MAX];
	char line[LINE_MAX];
	FILE *f;

	CPU_ZERO_S(setsize, set);

	snprintf(path, sizeof(path), PROC_STATUS, getpid());
	f = fopen(path, "r");
	if (f == NULL) {
		EAL_LOG(ERR, "%s(): cannot open %s: %s",
			__func__, path, strerror(errno));
		return;
	}

	while (fgets(line, sizeof(line), f)) {
		char *cp;
		unsigned int cpu;

		if (strncmp(line, cpus_allowed, sizeof(cpus_allowed) - 1))
			continue;

		cp = line + sizeof(cpus_allowed);

		while(*cp && isspace(*cp))
			++cp;

		for (cpu = 0; cpu < RTE_MAX_LCORE; cpu += 32) {
			uint32_t cpu_mask;
			unsigned int i;

			if (*cp == '\0')
				break;

			if (sscanf(cp, "%" SCNx32, &cpu_mask) != 1) {
				EAL_LOG(NOTICE, "%s(): can not parse: %s",
					__func__, line);
				goto error;
			}
			for (i = 0; i < 32; i++) {
				if (cpu_mask & (1u << i))
					CPU_SET_S(cpu + i, setsize, set);
			}

			cp = strchr(cp, ',');
			if (cp == NULL)
				break;
			cp += 1; /* skip the comma */
		}
	}

error:
	fclose(f);
}

/* Check if a cpu can be used by looking at /proc/<pid>/status */
int
eal_cpu_detected(unsigned int lcore_id)
{
	char path[PATH_MAX];
	int len;

	if (cpus_allowed == NULL) {
		cpus_allowed = CPU_ALLOC(RTE_MAX_LCORE);

		if (cpus_allowed == NULL) {
			EAL_LOG(ERR, "%s(): cannot allocate cpuset", __func__);
			return 0;
		}
		get_allowed_cpus(cpus_allowed);
	}

	/* skip cpus blocked by cgroup */
	if (!CPU_ISSET(lcore_id, cpus_allowed))
		return 0;

	len = snprintf(path, sizeof(path), SYS_CPU_DIR "/"CORE_ID_FILE, lcore_id);
	if (len <= 0 || (unsigned)len >= sizeof(path))
		return 0;

	return access(path, F_OK) == 0;
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

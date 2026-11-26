/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <sched.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/sysctl.h>

#include <rte_log.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_common.h>
#include <rte_debug.h>

#include "eal_private.h"
#include "eal_thread.h"

/* No topology information available on FreeBSD including NUMA info */
unsigned
eal_cpu_core_id(__rte_unused unsigned lcore_id)
{
	return 0;
}

size_t
eal_cpu_max(void)
{
	static int ncpu = -1;
	int mib[2] = {CTL_HW, HW_NCPU};
	size_t len = sizeof(ncpu);

	if (ncpu < 0) {
		if (sysctl(mib, 2, &ncpu, &len, NULL, 0) != 0) {
			EAL_LOG(ERR, "sysctl failed to get number of CPUs: %s", strerror(errno));
			return CPU_SETSIZE;  /* fallback to CPU_SETSIZE */
		}
		EAL_LOG(INFO, "Sysctl reports %d cpus", ncpu);
	}
	return (size_t)ncpu;
}

unsigned
eal_cpu_socket_id(__rte_unused unsigned cpu_id)
{
	return 0;
}

/* Check if a cpu is present by the presence of the
 * cpu information for it.
 */
int
eal_cpu_detected(unsigned lcore_id)
{
	const unsigned int ncpus = eal_cpu_max();
	return lcore_id < ncpus;
}

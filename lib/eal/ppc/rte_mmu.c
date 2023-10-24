/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) IBM Corporation 2023
 */

#include "stdio.h"
#include "string.h"
#include "rte_log.h"
#include <linux/eal_linux_private.h>

bool
eal_mmu_supported_linux_arch(void)
{
	static const char proc_cpuinfo[] = "/proc/cpuinfo";
	static const char str_mmu[] = "MMU";
	static const char str_radix[] = "Radix";
	static const char err_msg[] = "DPDK on PPC64 requires radix-mmu";
	char buf[512];
	char *ret = NULL;
	FILE *f = fopen(proc_cpuinfo, "r");

	if (f == NULL) {
		RTE_LOG(ERR, EAL, "Cannot open %s\n", proc_cpuinfo);
		return false;
	}

	/*
	 * Example "MMU" in /proc/cpuinfo:
	 * ...
	 * model	: 8335-GTW
	 * machine	: PowerNV 8335-GTW
	 * firmware	: OPAL
	 * MMU		: Radix
	 * ... or ...
	 * model        : IBM,9009-22A
	 * machine      : CHRP IBM,9009-22A
	 * MMU          : Hash
	 */
	while (fgets(buf, sizeof(buf), f) != NULL) {
		ret = strstr(buf, str_mmu);
		if (ret == NULL)
			continue;
		ret += sizeof(str_mmu) - 1;
		ret = strchr(ret, ':');
		if (ret == NULL)
			continue;
		ret = strstr(ret, str_radix);
		break;
	}
	fclose(f);

	if (ret == NULL) {
		fprintf(stderr, "EAL: FATAL: %s\n", err_msg);
		RTE_LOG(ERR, EAL, "%s\n", err_msg);
	}
	return (ret != NULL);
}

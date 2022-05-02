/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) IBM Corporation 2019.
 */

#ifdef __GLIBC__
#include <sys/platform/ppc.h>
#else
#include <string.h>
#include <stdio.h>
#endif

#include "eal_private.h"

uint64_t
get_tsc_freq_arch(void)
{
#ifdef __GLIBC__
	return __ppc_get_timebase_freq();
#else
	static uint64_t base;
	if (!base) {
		FILE *f = fopen("/proc/cpuinfo", "rb");
		if (f) {
			ssize_t nr;
			/* virtually always big enough to hold the line */
			char buf[512];
			while (fgets(buf, sizeof(buf), f)) {
				char *ret = strstr(buf, "timebase");
				if (!ret) {
					continue;
				}
				ret += sizeof("timebase") - 1;
				ret = strchr(ret, ':');
				if (!ret) {
					continue;
				}
				base = strtoul(ret + 1, 0, 10);
				break;
			}
			fclose(f);
		}
	}
	return base;;
#endif
}

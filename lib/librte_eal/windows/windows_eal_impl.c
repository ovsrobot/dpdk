/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Datapath Limited
 */

#include "eal_windows.h"

pid_t
getpid()
{
	return GetCurrentProcessId();
}

void
RTE_CPU_FILL(cpu_set_t *pdestset)
{
	SYSTEM_INFO system_info;
	memset(&system_info, 0, sizeof(system_info));

	GetSystemInfo(&system_info);

	int masked_so_far = 0;
	int index = 0;
	do{
		unsigned char mask = 0xFF;

		if ((masked_so_far + 8) > system_info.dwNumberOfProcessors){
			int mask_shift = (masked_so_far + 8) - system_info.dwNumberOfProcessors;
			mask = mask >> mask_shift;
		}

		pdestset->cpuset[index] = mask;

		masked_so_far += 8;
		index++;
	} while (masked_so_far < system_info.dwNumberOfProcessors);
}

void
RTE_CPU_ANDNOT(cpu_set_t *dst, cpu_set_t *src)
{
	int set_index;
	for (set_index = 0;
	     set_index < _countof(dst->cpuset);
	     set_index++){
		dst->cpuset[set_index] = ~(dst->cpuset[set_index] & src->cpuset[set_index]);
	}
}

void
RTE_CPU_COPY(cpu_set_t *from, cpu_set_t *to)
{
	memcpy(to, from, sizeof(cpu_set_t));
}

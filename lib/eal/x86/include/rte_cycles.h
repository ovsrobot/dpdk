/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation.
 * Copyright(c) 2013 6WIND S.A.
 */

#ifndef _RTE_CYCLES_X86_64_H_
#define _RTE_CYCLES_X86_64_H_

#ifdef RTE_TOOLCHAIN_MSVC
#include <intrin.h>
#else
#include <x86intrin.h>
#endif

#include "generic/rte_cycles.h"

#ifdef RTE_LIBRTE_EAL_VMWARE_TSC_MAP_SUPPORT
/* Global switch to use VMWARE mapping of TSC instead of RDTSC */
extern int rte_cycles_vmware_tsc_map;
#include <rte_branch_prediction.h>
#endif
#include <rte_common.h>
#include <rte_config.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline uint64_t
rte_rdtsc(void)
{
#ifdef RTE_LIBRTE_EAL_VMWARE_TSC_MAP_SUPPORT
	union {
		uint64_t tsc_64;
		struct {
			uint32_t lo_32;
			uint32_t hi_32;
		};
	} tsc;

	if (unlikely(rte_cycles_vmware_tsc_map)) {
		/* ecx = 0x10000 corresponds to the physical TSC for VMware */
		asm volatile("rdpmc" :
		             "=a" (tsc.lo_32),
		             "=d" (tsc.hi_32) :
		             "c"(0x10000));
		return tsc.tsc_64;
	}
#endif
	return __rdtsc();
}

static inline uint64_t
rte_rdtsc_precise(void)
{
	rte_mb();
	return rte_rdtsc();
}

static inline uint64_t
rte_get_tsc_cycles(void) { return rte_rdtsc(); }

#ifdef __cplusplus
}
#endif

#endif /* _RTE_CYCLES_X86_64_H_ */

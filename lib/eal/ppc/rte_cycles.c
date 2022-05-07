/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) IBM Corporation 2019.
 */

#include <features.h>
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
	return no_ppc_get_timebase_freq();
#endif
}

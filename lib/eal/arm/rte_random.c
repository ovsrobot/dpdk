/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Arm Limited
 */

#include "arm_acle.h"
#include "rte_common.h"
#include "rte_random.h"
#include <errno.h>

int
rte_trand(uint64_t *val)
{
#if defined __ARM_FEATURE_RNG
	int ret = __rndr(val);
	return (ret == 0) ? 0 : -ENODATA;
#else
	RTE_SET_USED(val);
	return -ENOTSUP;
#endif
}

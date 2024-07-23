/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Arm Limited
 */

#include "rte_common.h"
#include "rte_random.h"
#include <errno.h>

int
rte_trand(uint64_t *val)
{
	RTE_SET_USED(val);
	return -ENOTSUP;
}

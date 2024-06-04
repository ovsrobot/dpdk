/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#ifndef _RTE_POWER_INTRINSIC_ARM_H_
#define _RTE_POWER_INTRINSIC_ARM_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>

#include "generic/rte_power_intrinsics.h"

struct rte_power_monitor_info {
	uint16_t init_done:1,   /* Initialization status bit */
		wfet_en:1,	/* FEAT_WFET enabled bit */
		reserved:14;	/* Reserved */
};

#ifdef __cplusplus
}
#endif

#endif /* _RTE_POWER_INTRINSIC_ARM_H_ */

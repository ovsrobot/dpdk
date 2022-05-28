/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Loongson Technology Corporation Limited
 */

#ifndef _RTE_PAUSE_LOONGARCH_H_
#define _RTE_PAUSE_LOONGARCH_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "rte_atomic.h"

#include "generic/rte_pause.h"

static inline void rte_pause(void)
{
}

#ifdef __cplusplus
}
#endif

#endif /* _RTE_PAUSE_LOONGARCH_H_ */

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2013-2015 Intel Corporation
 */

#ifndef _FM10K_LOGS_H_
#define _FM10K_LOGS_H_

#include <rte_log.h>

extern int fm10k_logtype_init;
#define RTE_LOGTYPE_FM10K_INIT fm10k_logtype_init
#define PMD_INIT_LOG(level, fmt, args...) \
	RTE_LOG_LINE(level, FM10K_INIT, "%s(): " fmt, __func__, ##args)

#define PMD_INIT_FUNC_TRACE() PMD_INIT_LOG(DEBUG, " >>")

#ifdef RTE_ETHDEV_DEBUG_RX
extern int fm10k_logtype_rx;
#define RTE_LOGTYPE_FM10K_RX fm10k_logtype_rx
#define PMD_RX_LOG(level, fmt, args...) \
	RTE_LOG_LINE(level, FM10K_RX, "%s(): " fmt, __func__, ## args)
#else
#define PMD_RX_LOG(level, fmt, args...) do { } while (0)
#endif

#ifdef RTE_ETHDEV_DEBUG_TX
extern int fm10k_logtype_tx;
#define RTE_LOGTYPE_FM10K_TX fm10k_logtype_tx
#define PMD_TX_LOG(level, fmt, args...) \
	RTE_LOG_LINE(level, FM10K_TX, "%s(): " fmt, __func__, ## args)
#else
#define PMD_TX_LOG(level, fmt, args...) do { } while (0)
#endif

extern int fm10k_logtype_driver;
#define RTE_LOGTYPE_FM10K_DRIVER fm10k_logtype_driver
#define PMD_DRV_LOG(level, fmt, args...) \
	RTE_LOG_LINE(level, FM10K_DRIVER, "%s(): " fmt, __func__, ## args)

#endif /* _FM10K_LOGS_H_ */

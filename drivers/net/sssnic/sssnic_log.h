/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#ifndef _SSSNIC_LOG_H_
#define _SSSNIC_LOG_H_

#include <rte_log.h>

extern int sssnic_logtype_driver;
extern int sssnic_logtype_init;

#define SSSNIC_LOG_NAME "sssnic"
#define PMD_DRV_LOG(level, fmt, args...)                                       \
	rte_log(RTE_LOG_##level, sssnic_logtype_driver,                        \
		SSSNIC_LOG_NAME ": " fmt "\n", ##args)
#define PMD_INIT_LOG(level, fmt, args...)                                      \
	rte_log(RTE_LOG_##level, sssnic_logtype_init, "%s(): " fmt "\n",       \
		__func__, ##args)

#define SSSNIC_DEBUG(fmt, args...)                                             \
	PMD_DRV_LOG(DEBUG, "[%s():%d] " fmt, __func__, __LINE__, ##args)

/*
 * Trace driver init and uninit.
 */
#define PMD_INIT_FUNC_TRACE() PMD_INIT_LOG(DEBUG, " >>")

#ifdef RTE_ETHDEV_DEBUG_RX
extern int sssnic_logtype_rx;
#define SSSNIC_RX_LOG(level, fmt, args...)                                     \
	rte_log(RTE_LOG_##level, sssnic_logtype_rx,                            \
		"sssnic_rx: [%s():%d] " fmt "\n", __func__, __LINE__, ##args)
#else
#define SSSNIC_RX_LOG(level, fmt, args...)                                     \
	do {                                                                   \
	} while (0)
#endif /*RTE_ETHDEV_DEBUG_RX*/

#ifdef RTE_ETHDEV_DEBUG_TX
extern int sssnic_logtype_tx;
#define SSSNIC_TX_LOG(level, fmt, args...)                                     \
	rte_log(RTE_LOG_##level, sssnic_logtype_rx,                            \
		"sssnic_tx: [%s():%d] " fmt "\n", __func__, __LINE__, ##args)
#else
#define SSSNIC_TX_LOG(level, fmt, args...)                                     \
	do {                                                                   \
	} while (0)
#endif /*RTE_ETHDEV_DEBUG_TX*/

#endif /*_SSSNIC_LOG_H_*/

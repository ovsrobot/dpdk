/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Realtek Corporation. All rights reserved
 */

#ifndef _R8169_LOGS_H_
#define _R8169_LOGS_H_

#include <rte_log.h>

extern int r8169_logtype_init;
extern int r8169_logtype_driver;
#ifdef RTE_ETHDEV_DEBUG_RX
extern int r8169_logtype_rx;
#endif
#ifdef RTE_ETHDEV_DEBUG_TX
extern int r8169_logtype_tx;
#endif

#define RTE_LOGTYPE_R8169_INIT   r8169_logtype_init
#define RTE_LOGTYPE_R8169_RX     r8169_logtype_rx
#define RTE_LOGTYPE_R8169_TX     r8169_logtype_tx
#define RTE_LOGTYPE_R8169_DRIVER r8169_logtype_driver

#define PMD_INIT_LOG(level, fmt, args...) \
	RTE_LOG_DP(level, R8169_INIT, "%s(): " fmt "\n", __func__, ## args)

#define PMD_INIT_FUNC_TRACE() PMD_INIT_LOG(DEBUG, " >>")

#ifdef RTE_ETHDEV_DEBUG_RX
#define PMD_RX_LOG(level, fmt, args...) \
	RTE_LOG_DP_LINE(level, R8169_RX, "%s(): " fmt, __func__, ## args)
#else
#define PMD_RX_LOG(level, fmt, args...) do { } while (0)
#endif

#ifdef RTE_ETHDEV_DEBUG_TX
#define PMD_TX_LOG(level, fmt, args...) \
	RTE_LOG_DP_LINE(level, R8169_TX, "%s(): " fmt, __func__, ## args)
#else
#define PMD_TX_LOG(level, fmt, args...) do { } while (0)
#endif

#define PMD_DRV_LOG(level, fmt, args...) \
	RTE_LOG_DP_LINE(level, R8169_DRIVER, "%s(): " fmt, __func__, ## args)

#endif /* _R8169_LOGS_H_ */

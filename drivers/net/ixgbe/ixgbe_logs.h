/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#ifndef _IXGBE_LOGS_H_
#define _IXGBE_LOGS_H_

extern int ixgbe_logtype_init;
#define RTE_LOGTYPE_IXGBE_INIT ixgbe_logtype_init
#define PMD_INIT_LOG(level, fmt, args...) \
	RTE_LOG_LINE(level, IXGBE_INIT, "%s(): " fmt, __func__, ##args)

#define PMD_INIT_FUNC_TRACE() PMD_INIT_LOG(DEBUG, " >>")

#ifdef RTE_ETHDEV_DEBUG_RX
extern int ixgbe_logtype_rx;
#define RTE_LOGTYPE_IXGBE_RX ixgbe_logtype_rx
#define PMD_RX_LOG(level, fmt, args...) \
	RTE_LOG_LINE(level, IXGBE_RX, "%s(): " fmt, __func__, ## args)
#else
#define PMD_RX_LOG(level, fmt, args...) do { } while (0)
#endif

#ifdef RTE_ETHDEV_DEBUG_TX
extern int ixgbe_logtype_tx;
#define RTE_LOGTYPE_IXGBE_TX ixgbe_logtype_tx
#define PMD_TX_LOG(level, fmt, args...) \
	RTE_LOG_LINE(level, IXGBE_TX, "%s(): " fmt, __func__, ## args)
#else
#define PMD_TX_LOG(level, fmt, args...) do { } while (0)
#endif

extern int ixgbe_logtype_driver;
#define RTE_LOGTYPE_IXGBE_DRIVER ixgbe_logtype_driver
#define PMD_DRV_LOG(level, fmt, args...) \
	RTE_LOG_LINE(level, IXGBE_DRIVER, "%s(): " fmt, __func__, ## args)

#endif /* _IXGBE_LOGS_H_ */

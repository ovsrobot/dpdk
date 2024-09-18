/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 Yunsilicon Technology Co., Ltd.
 */

#ifndef _XSC_LOG_H_
#define _XSC_LOG_H_

#include <rte_log.h>

extern int xsc_logtype_init;
extern int xsc_logtype_driver;
#define RTE_LOGTYPE_XSC_INIT xsc_logtype_init
#define RTE_LOGTYPE_XSC_DRV xsc_logtype_driver


#define PMD_INIT_LOG(level, ...) \
	RTE_LOG_LINE_PREFIX(level, XSC_INIT, "%s(): ", __func__, __VA_ARGS__)


#define PMD_INIT_FUNC_TRACE() PMD_INIT_LOG(DEBUG, " >>")

#ifdef RTE_ETHDEV_DEBUG_RX
extern int xsc_logtype_rx;
#define RTE_LOGTYPE_XSC_RX xsc_logtype_rx
#define PMD_RX_LOG(level, ...) \
	RTE_LOG_LINE_PREFIX(level, XSC_RX, "%s(): ", __func__, __VA_ARGS__)
#else
#define PMD_RX_LOG(level, ...) do { } while (0)
#endif

#ifdef RTE_ETHDEV_DEBUG_TX
extern int xsc_logtype_tx;
#define RTE_LOGTYPE_XSC_TX xsc_logtype_tx
#define PMD_TX_LOG(level, ...) \
	RTE_LOG_LINE_PREFIX(level, XSC_TX, "%s(): ", __func__, __VA_ARGS__)
#else
#define PMD_TX_LOG(level, ...) do { } while (0)
#endif

#define PMD_DRV_LOG_RAW(level, ...) \
	RTE_LOG_LINE_PREFIX(level, XSC_DRV, "%s(): ", __func__, __VA_ARGS__)

#define PMD_DRV_LOG(level, ...) \
	PMD_DRV_LOG_RAW(level, __VA_ARGS__)

#endif /* _XSC_LOG_H_ */

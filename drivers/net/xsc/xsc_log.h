/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 Yunsilicon Technology Co., Ltd.
 */

#ifndef _XSC_LOG_H_
#define _XSC_LOG_H_

#include <rte_log.h>

extern int xsc_logtype_init;
extern int xsc_logtype_driver;

#define PMD_INIT_LOG(level, fmt, ...) \
	rte_log(RTE_LOG_ ## level, xsc_logtype_init, "%s(): " fmt "\n", \
		__func__, ##__VA_ARGS__)

#define PMD_INIT_FUNC_TRACE() PMD_INIT_LOG(DEBUG, " >>")

#ifdef RTE_ETHDEV_DEBUG_RX
extern int xsc_logtype_rx;
#define PMD_RX_LOG(level, fmt, ...)			\
	rte_log(RTE_LOG_ ## level, xsc_logtype_rx,	\
		"%s(): " fmt "\n", __func__, ##__VA_ARGS__)
#else
#define PMD_RX_LOG(level, fmt, ...) do { } while (0)
#endif

#ifdef RTE_ETHDEV_DEBUG_TX
extern int xsc_logtype_tx;
#define PMD_TX_LOG(level, fmt, ...)			\
	rte_log(RTE_LOG_ ## level, xsc_logtype_tx,	\
		"%s(): " fmt "\n", __func__, ##__VA_ARGS__)
#else
#define PMD_TX_LOG(level, fmt, ...) do { } while (0)
#endif

#define PMD_DRV_LOG_RAW(level, fmt, ...) \
	rte_log(RTE_LOG_ ## level, xsc_logtype_driver, "%s(): " fmt, \
		__func__, ##__VA_ARGS__)

#define PMD_DRV_LOG(level, fmt, ...) \
	PMD_DRV_LOG_RAW(level, fmt "\n", ##__VA_ARGS__)

#endif /* _XSC_LOG_H_ */

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2020 Beijing WangXun Technology Co., Ltd.
 * Copyright(c) 2010-2017 Intel Corporation
 */

#ifndef _NGBE_LOGS_H_
#define _NGBE_LOGS_H_

/*
 * PMD_USER_LOG: for user
 */
extern int ngbe_logtype_init;
#define PMD_INIT_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, ngbe_logtype_init, \
		"%s(): " fmt "\n", __func__, ##args)

extern int ngbe_logtype_driver;
#define PMD_DRV_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, ngbe_logtype_driver, \
		"%s(): " fmt "\n", __func__, ##args)

#ifdef RTE_ETHDEV_DEBUG_RX
extern int ngbe_logtype_rx;
#define PMD_RX_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, ngbe_logtype_rx,	\
		"%s(): " fmt "\n", __func__, ##args)
#else
#define PMD_RX_LOG(level, fmt, args...) do { } while (0)
#endif

#ifdef RTE_ETHDEV_DEBUG_TX
extern int ngbe_logtype_tx;
#define PMD_TX_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, ngbe_logtype_tx,	\
		"%s(): " fmt "\n", __func__, ##args)
#else
#define PMD_TX_LOG(level, fmt, args...) do { } while (0)
#endif

#define TLOG_DEBUG(fmt, args...)  PMD_DRV_LOG(DEBUG, fmt, ##args)

#define DEBUGOUT(fmt, args...)    TLOG_DEBUG(fmt, ##args)
#define PMD_INIT_FUNC_TRACE()     TLOG_DEBUG(" >>")
#define DEBUGFUNC(fmt)            TLOG_DEBUG(fmt)

#endif /* _NGBE_LOGS_H_ */

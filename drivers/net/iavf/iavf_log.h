/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Intel Corporation
 */

#ifndef _IAVF_LOG_H_
#define _IAVF_LOG_H_

extern int iavf_logtype_init;
#define RTE_LOGTYPE_IAVF_INIT iavf_logtype_init
#define PMD_INIT_LOG(level, fmt, args...) \
	RTE_LOG_LINE(level, IAVF_INIT, "%s(): " fmt, \
		__func__, ## args)
#define PMD_INIT_FUNC_TRACE() PMD_INIT_LOG(DEBUG, " >>")

extern int iavf_logtype_driver;
#define RTE_LOGTYPE_IAVF_DRIVER iavf_logtype_driver
#define PMD_DRV_LOG(level, fmt, args...) \
	RTE_LOG_LINE(level, IAVF_DRIVER, "%s(): " fmt, \
		__func__, ## args)
#define PMD_DRV_FUNC_TRACE() PMD_DRV_LOG(DEBUG, " >>")


#ifdef RTE_ETHDEV_DEBUG_RX
extern int iavf_logtype_rx;
#define RTE_LOGTYPE_IAVF_RX iavf_logtype_rx
#define PMD_RX_LOG(level, fmt, args...)			\
	RTE_LOG_LINE(level, IAVF_RX,	\
		"%s(): " fmt, __func__, ## args)
#else
#define PMD_RX_LOG(level, fmt, args...) do { } while (0)
#endif

#ifdef RTE_ETHDEV_DEBUG_TX
extern int iavf_logtype_tx;
#define RTE_LOGTYPE_IAVF_TX iavf_logtype_tx
#define PMD_TX_LOG(level, fmt, args...)			\
	RTE_LOG_LINE(level, IAVF_TX,	\
		"%s(): " fmt, __func__, ## args)
#else
#define PMD_TX_LOG(level, fmt, args...) do { } while (0)
#endif

#endif /* _IAVF_LOG_H_ */

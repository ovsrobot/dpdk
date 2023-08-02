#ifndef __RNP_LOGS_H__
#define __RNP_LOGS_H__
/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Mucse IC Design Ltd.
 */
extern int rnp_init_logtype;

#define RNP_PMD_INIT_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_##level, rnp_init_logtype, \
		"%s() " fmt, __func__, ##args)
#define PMD_INIT_FUNC_TRACE() RNP_PMD_INIT_LOG(DEBUG, " >>")
extern int rnp_drv_logtype;
#define RNP_PMD_DRV_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_##level, rnp_drv_logtype, \
		"%s() " fmt, __func__, ##args)
#define PMD_DRV_LOG_RAW(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, rnp_drv_logtype, "%s(): " fmt, \
			__func__, ## args)
#define PMD_DRV_LOG(level, fmt, args...) \
	PMD_DRV_LOG_RAW(level, fmt "\n", ## args)

#define RNP_PMD_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_##level, rnp_drv_logtype, \
			"rnp_net: (%d) " fmt, __LINE__, ##args)
#ifdef RTE_LIBRTE_RNP_DEBUG_RX
extern int rnp_rx_logtype;
#define RNP_PMD_RX_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, rnp_rx_logtype, \
		"%s(): " fmt "\n", __func__, ##args)
#else
#define RNP_PMD_RX_LOG(level, fmt, args...) do { } while (0)
#endif

#ifdef RTE_LIBRTE_RNP_DEBUG_TX
extern int rnp_tx_logtype;
#define PMD_TX_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, rnp_tx_logtype,    \
		"%s(): " fmt "\n", __func__, ##args)
#else
#define PMD_TX_LOG(level, fmt, args...) do { } while (0)
#endif

#endif /* __RNP_LOGS_H__ */

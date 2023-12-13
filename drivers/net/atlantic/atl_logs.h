/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Aquantia Corporation
 */
#ifndef ATL_LOGS_H
#define ATL_LOGS_H

#include <rte_log.h>

extern int atl_logtype_init;

#define PMD_INIT_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, atl_logtype_init, \
		"%s(): " fmt "\n", __func__, ##args)

#define PMD_INIT_FUNC_TRACE() PMD_INIT_LOG(DEBUG, " >>")

extern int atl_logtype_driver;
#define PMD_DRV_LOG_RAW(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, atl_logtype_driver, "%s(): " fmt, \
		__func__, ## args)

#define PMD_DRV_LOG(level, fmt, args...) \
	rte_log_dp(RTE_LOG_ ## level, atl_logtype_driver, fmt "\n", \
		   ## args)

#define PMD_RX_LOG(level, fmt, args...) \
	PMD_DRV_LOG(level, fmt, ## args)

#define PMD_TX_LOG(level, fmt, args...) \
	PMD_DRV_LOG(level, fmt, ## args)

#endif

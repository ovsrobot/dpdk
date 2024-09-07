/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Cavium, Inc
 */

#ifndef _CPT_PMD_LOGS_H_
#define _CPT_PMD_LOGS_H_

#include <rte_log.h>

/*
 * This file defines log macros
 */

/*
 * otx*_cryptodev.h file would define the CPT_LOGTYPE macro for the
 * platform.
 */
#define RTE_LOGTYPE_CPT CPT_LOGTYPE

#define CPT_PMD_DRV_LOG(level, fmt, args...) \
	RTE_LOG_LINE(level, CPT, "%s(): " fmt, __func__, ## args)

#define CPT_PMD_INIT_FUNC_TRACE() CPT_PMD_DRV_LOG(DEBUG, " >>")

#define CPT_LOG_INFO(fmt, args...) \
	CPT_PMD_DRV_LOG(INFO, fmt, ## args)
#define CPT_LOG_WARN(fmt, args...) \
	CPT_PMD_DRV_LOG(WARNING, fmt, ## args)
#define CPT_LOG_ERR(fmt, args...) \
	CPT_PMD_DRV_LOG(ERR, fmt, ## args)

/*
 * DP logs, toggled out at compile time if level lower than current level.
 */
#define CPT_LOG_DP(level, fmt, args...) \
	RTE_LOG_DP_LINE(level, CPT, fmt, ## args)

#define CPT_LOG_DP_DEBUG(fmt, args...) \
	CPT_LOG_DP(DEBUG, fmt, ## args)
#define CPT_LOG_DP_INFO(fmt, args...) \
	CPT_LOG_DP(INFO, fmt, ## args)
#define CPT_LOG_DP_WARN(fmt, args...) \
	CPT_LOG_DP(WARNING, fmt, ## args)
#define CPT_LOG_DP_ERR(fmt, args...) \
	CPT_LOG_DP(ERR, fmt, ## args)

#endif /* _CPT_PMD_LOGS_H_ */

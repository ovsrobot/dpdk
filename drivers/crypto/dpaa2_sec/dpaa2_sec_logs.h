/* SPDX-License-Identifier: BSD-3-Clause
 *
 *   Copyright (c) 2016 Freescale Semiconductor, Inc. All rights reserved.
 *   Copyright 2016,2019 NXP
 *
 */

#ifndef _DPAA2_SEC_LOGS_H_
#define _DPAA2_SEC_LOGS_H_

extern int dpaa2_logtype_sec;
#define RTE_LOGTYPE_DPAA2_SEC dpaa2_logtype_sec

#define DPAA2_SEC_LOG(level, fmt, args...) \
	RTE_LOG_LINE(level, DPAA2_SEC, fmt, ## args)

#define DPAA2_SEC_DEBUG(fmt, args...) \
	RTE_LOG_LINE(DEBUG, DPAA2_SEC, "%s(): " fmt, __func__, ## args)

#define PMD_INIT_FUNC_TRACE() DPAA2_SEC_DEBUG(">>")

#define DPAA2_SEC_INFO(fmt, args...) \
	DPAA2_SEC_LOG(INFO, fmt, ## args)
#define DPAA2_SEC_ERR(fmt, args...) \
	DPAA2_SEC_LOG(ERR, fmt, ## args)
#define DPAA2_SEC_WARN(fmt, args...) \
	DPAA2_SEC_LOG(WARNING, fmt, ## args)

/* DP Logs, toggled out at compile time if level lower than current level */
#define DPAA2_SEC_DP_LOG(level, fmt, args...) \
	RTE_LOG_DP_LINE(level, DPAA2_SEC, fmt, ## args)

#define DPAA2_SEC_DP_DEBUG(fmt, args...) \
	DPAA2_SEC_DP_LOG(DEBUG, fmt, ## args)
#define DPAA2_SEC_DP_INFO(fmt, args...) \
	DPAA2_SEC_DP_LOG(INFO, fmt, ## args)
#define DPAA2_SEC_DP_WARN(fmt, args...) \
	DPAA2_SEC_DP_LOG(WARNING, fmt, ## args)
#define DPAA2_SEC_DP_ERR(fmt, args...) \
		DPAA2_SEC_DP_LOG(ERR, fmt, ## args)


#endif /* _DPAA2_SEC_LOGS_H_ */

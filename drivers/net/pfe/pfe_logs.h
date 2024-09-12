/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2019 NXP
 */

#ifndef _PFE_LOGS_H_
#define _PFE_LOGS_H_

extern int pfe_logtype_pmd;
#define RTE_LOGTYPE_PFE_NET pfe_logtype_pmd

/* PMD related logs */
#define PFE_PMD_LOG(level, ...) \
	 RTE_LOG_LINE_PREFIX(level, PFE_NET, "%s()", __func__, __VA_ARGS__)

#define PMD_INIT_FUNC_TRACE() PFE_PMD_LOG(DEBUG, " >>")

#define PFE_PMD_DEBUG(fmt, args...) \
	PFE_PMD_LOG(DEBUG, fmt, ## args)
#define PFE_PMD_ERR(fmt, args...) \
	PFE_PMD_LOG(ERR, fmt, ## args)
#define PFE_PMD_INFO(fmt, args...) \
	PFE_PMD_LOG(INFO, fmt, ## args)

#define PFE_PMD_WARN(fmt, args...) \
	PFE_PMD_LOG(WARNING, fmt, ## args)

/* DP Logs, toggled out at compile time if level lower than current level */
#define PFE_DP_LOG(level, ...) \
	RTE_LOG_DP_LINE(level, PFE_NET, __VA_ARGS__)

#endif /* _PFE_LOGS_H_ */

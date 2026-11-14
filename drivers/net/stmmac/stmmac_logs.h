/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2026 Qualcomm Technologies, Inc.
 */

#ifndef _STMMAC_LOGS_H_
#define _STMMAC_LOGS_H_

#include <rte_log.h>

extern int stmmac_logtype_pmd;
#define RTE_LOGTYPE_STMMAC_NET stmmac_logtype_pmd

#define STMMAC_PMD_LOG(level, ...) \
	RTE_LOG_LINE_PREFIX(level, STMMAC_NET, "%s()", __func__, __VA_ARGS__)

#define STMMAC_PMD_DEBUG(fmt, ...) \
	STMMAC_PMD_LOG(DEBUG, fmt, ## __VA_ARGS__)
#define STMMAC_PMD_ERR(fmt, ...) \
	STMMAC_PMD_LOG(ERR, fmt, ## __VA_ARGS__)
#define STMMAC_PMD_INFO(fmt, ...) \
	STMMAC_PMD_LOG(INFO, fmt, ## __VA_ARGS__)
#define STMMAC_PMD_WARN(fmt, ...) \
	STMMAC_PMD_LOG(WARNING, fmt, ## __VA_ARGS__)

#endif /* _STMMAC_LOGS_H_ */

/* SPDX-License-Identifier: BSD-3-Clause
 *
 *   Copyright 2017 NXP
 *
 */

#ifndef _DPAA_LOGS_H_
#define _DPAA_LOGS_H_

#include <rte_log.h>

extern int dpaa_logtype_bus;
#define RTE_LOGTYPE_DPAA_BUS dpaa_logtype_bus

#define DPAA_BUS_LOG(level, fmt, args...) \
	RTE_LOG_LINE(level, DPAA_BUS, fmt, ## args)

#ifdef RTE_LIBRTE_DPAA_DEBUG_BUS
#define DPAA_BUS_HWWARN(cond, fmt, args...) \
	do {\
		if (cond) \
			DPAA_BUS_LOG(DEBUG, "WARN: " fmt, ##args); \
	} while (0)
#else
#define DPAA_BUS_HWWARN(cond, fmt, args...) do { } while (0)
#endif

#define DPAA_BUS_DEBUG(fmt, args...) \
	RTE_LOG_LINE(DEBUG, DPAA_BUS, "%s(): " fmt, __func__, ## args)

#define BUS_INIT_FUNC_TRACE() DPAA_BUS_DEBUG(" >>")

#define DPAA_BUS_INFO(fmt, args...) \
	DPAA_BUS_LOG(INFO, fmt, ## args)
#define DPAA_BUS_ERR(fmt, args...) \
	DPAA_BUS_LOG(ERR, fmt, ## args)
#define DPAA_BUS_WARN(fmt, args...) \
	DPAA_BUS_LOG(WARNING, fmt, ## args)

#endif /* _DPAA_LOGS_H_ */

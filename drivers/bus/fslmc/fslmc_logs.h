/* SPDX-License-Identifier: BSD-3-Clause
 *
 *   Copyright 2016 NXP
 *
 */

#ifndef _FSLMC_LOGS_H_
#define _FSLMC_LOGS_H_

extern int dpaa2_logtype_bus;
#define RTE_LOGTYPE_DPAA2_BUS dpaa2_logtype_bus

#define DPAA2_BUS_LOG(level, fmt, args...) \
	RTE_LOG_LINE(level, DPAA2_BUS, fmt, ## args)

/* Debug logs are with Function names */
#define DPAA2_BUS_DEBUG(fmt, args...) \
	RTE_LOG_LINE(DEBUG, DPAA2_BUS, "%s(): " fmt, __func__, ## args)

#define DPAA2_BUS_INFO(fmt, args...) \
	DPAA2_BUS_LOG(INFO, fmt, ## args)
#define DPAA2_BUS_ERR(fmt, args...) \
	DPAA2_BUS_LOG(ERR, fmt, ## args)
#define DPAA2_BUS_WARN(fmt, args...) \
	DPAA2_BUS_LOG(WARNING, fmt, ## args)

#endif /* _FSLMC_LOGS_H_ */

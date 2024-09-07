/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Intel Corporation
 */

#ifndef _OPDL_LOGS_H_
#define _OPDL_LOGS_H_

#include <rte_log.h>

extern int opdl_logtype_driver;
#define RTE_LOGTYPE_OPDL opdl_logtype_driver

#define PMD_DRV_LOG(level, fmt, args...) \
	RTE_LOG_LINE(level, OPDL, "%s(): " fmt, __func__, ## args)

#endif /* _OPDL_LOGS_H_ */

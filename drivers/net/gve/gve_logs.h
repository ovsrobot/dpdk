/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Intel Corporation
 */

#ifndef _GVE_LOGS_H_
#define _GVE_LOGS_H_

extern int gve_logtype_driver;
#define RTE_LOGTYPE_GVE_DRIVER gve_logtype_driver

#define PMD_DRV_LOG(level, fmt, args...) \
	RTE_LOG_LINE(level, GVE_DRIVER, "%s(): " fmt, __func__, ## args)

#endif

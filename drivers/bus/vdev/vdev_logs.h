/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Intel Corporation
 */

#ifndef _VDEV_LOGS_H_
#define _VDEV_LOGS_H_

#include <rte_log.h>

extern int vdev_logtype_bus;
#define RTE_LOGTYPE_VDEV_BUS vdev_logtype_bus

#define VDEV_LOG(level, fmt, args...) \
	RTE_LOG_LINE(level, VDEV_BUS, "%s(): " fmt, \
		__func__, ##args)

#endif /* _VDEV_LOGS_H_ */

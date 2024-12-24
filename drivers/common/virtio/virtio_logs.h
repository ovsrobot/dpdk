/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#ifndef _VIRTIO_LOGS_H_
#define _VIRTIO_LOGS_H_

#include <inttypes.h>

#include <rte_log.h>

extern int virtio_logtype_init;
#define RTE_LOGTYPE_VIRTIO_INIT virtio_logtype_init
#define PMD_INIT_LOG(level, ...) \
	RTE_LOG_LINE_PREFIX(level, VIRTIO_INIT, "%s(): ", __func__, __VA_ARGS__)

#define PMD_INIT_FUNC_TRACE() PMD_INIT_LOG(DEBUG, " >>")

extern int virtio_logtype_driver;
#define RTE_LOGTYPE_VIRTIO_DRIVER virtio_logtype_driver
#define PMD_DRV_LOG(level, ...) \
	RTE_LOG_LINE_PREFIX(level, VIRTIO_DRIVER, "%s(): ", __func__, __VA_ARGS__)

#endif /* _VIRTIO_LOGS_H_ */

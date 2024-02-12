/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Intel Corporation
 */

#ifndef _STACK_PVT_H_
#define _STACK_PVT_H_

#include <rte_log.h>

extern int stack_logtype;
#define RTE_LOGTYPE_STACK stack_logtype

#define STACK_LOG(level, fmt, ...) \
	RTE_LOG_LINE(level, STACK, "%s(): "fmt, __func__, ## __VA_ARGS__)

#define STACK_LOG_ERR(fmt, ...) \
	STACK_LOG(ERR, fmt, ## __VA_ARGS__)

#define STACK_LOG_WARN(fmt, ...) \
	STACK_LOG(WARNING, fmt, ## __VA_ARGS__)

#define STACK_LOG_INFO(fmt, ...) \
	STACK_LOG(INFO, fmt, ## __VA_ARGS__)

#endif /* _STACK_PVT_H_ */

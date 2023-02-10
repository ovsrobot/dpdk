/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <rte_log.h>

extern int sched_logtype;

#define SCHED_LOG(level, fmt, args...)			\
	rte_log(RTE_LOG_ ## level, sched_logtype,	\
		"%s(): " fmt "\n", __func__, ##args)

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation.
 * Copyright 2014 6WIND S.A.
 */

extern int mempool_logtype;

#define MEMPOOL_LOG(level, fmt, args...)		\
	rte_log(RTE_LOG_ ## level, mempool_logtype,	\
		"%s(): " fmt "\n", __func__, ##args)

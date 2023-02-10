/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Vladimir Medvedkin <medvedkinv@gmail.com>
 * Copyright(c) 2019 Intel Corporation
 */

extern int rib_logtype;
#define RIB_LOG(level, fmt, args...)			\
	rte_log(RTE_LOG_ ## level, rib_logtype,		\
		"%s(): " fmt "\n", __func__, ##args)

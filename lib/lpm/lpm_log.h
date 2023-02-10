/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 * Copyright(c) 2020 Arm Limited
 */

extern int lpm_logtype;
#define LPM_LOG(level, fmt, args...)			\
	rte_log(RTE_LOG_ ## level, lpm_logtype,		\
		"%s(): " fmt "\n", __func__, ## args)

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#ifndef __SXE_DPDK_VERSION_H__
#define __SXE_DPDK_VERSION_H__

#include <rte_version.h>

#if (RTE_VERSION >= RTE_VERSION_NUM(19, 0, 0, 0) && RTE_VERSION < RTE_VERSION_NUM(19, 12, 0, 0))
	#define DPDK_19_11_6
#elif (RTE_VERSION >= RTE_VERSION_NUM(20, 0, 0, 0) && RTE_VERSION < RTE_VERSION_NUM(20, 12, 0, 0))
	#define DPDK_20_11_5
#elif (RTE_VERSION >= RTE_VERSION_NUM(21, 0, 0, 0) && RTE_VERSION < RTE_VERSION_NUM(21, 12, 0, 0))
	#define DPDK_21_11_5
#elif (RTE_VERSION >= RTE_VERSION_NUM(22, 0, 0, 0) && RTE_VERSION < RTE_VERSION_NUM(22, 12, 0, 0))
	#define DPDK_22_11_3
#elif (RTE_VERSION >= RTE_VERSION_NUM(23, 0, 0, 0) && RTE_VERSION < RTE_VERSION_NUM(23, 12, 0, 0))
	#define DPDK_23_11_3
#if (RTE_VERSION >= RTE_VERSION_NUM(23, 0, 0, 0) && RTE_VERSION < RTE_VERSION_NUM(23, 8, 0, 0))
	#define DPDK_23_7
#if (RTE_VERSION >= RTE_VERSION_NUM(23, 0, 0, 0) && RTE_VERSION < RTE_VERSION_NUM(23, 4, 0, 0))
	#define DPDK_23_3
#endif
#endif
#elif (RTE_VERSION_NUM(24, 0, 0, 0) <= RTE_VERSION)
	#define DPDK_24_11_1
#endif

#endif

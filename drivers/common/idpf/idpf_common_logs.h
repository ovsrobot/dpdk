/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Intel Corporation
 */

#ifndef _IDPF_COMMON_LOGS_H_
#define _IDPF_COMMON_LOGS_H_

#include <rte_log.h>

extern int idpf_common_logtype;
#define RTE_LOGTYPE_IDPF_COMMON idpf_common_logtype

#define DRV_LOG(level, ...)					\
	RTE_LOG_LINE(level,					\
		IDPF_COMMON,					\
		RTE_FMT("%s(): "				\
			RTE_FMT_HEAD(__VA_ARGS__,),		\
			__func__,				\
			RTE_FMT_TAIL(__VA_ARGS__,)))

#ifdef RTE_LIBRTE_IDPF_DEBUG_RX
#define RX_LOG(...) DRV_LOG(__VA_ARGS__)
#else
#define RX_LOG(...) do {} while (0)
#endif

#ifdef RTE_LIBRTE_IDPF_DEBUG_TX
#define TX_LOG(...) DRV_LOG(__VA_ARGS__)
#else
#define TX_LOG(...) do {} while (0)
#endif

#endif /* _IDPF_COMMON_LOGS_H_ */

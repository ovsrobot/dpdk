/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Intel Corporation
 */

#ifndef _IDPF_LOGS_H_
#define _IDPF_LOGS_H_

#include <rte_log.h>

extern int idpf_logtype_init;
#define RTE_LOGTYPE_IDPF_INIT idpf_logtype_init
extern int idpf_logtype_driver;
#define RTE_LOGTYPE_IDPF_DRIVER idpf_logtype_driver

#define PMD_INIT_LOG(level, ...) \
	RTE_LOG_LINE(level, IDPF_INIT, \
		RTE_FMT("%s(): " \
			RTE_FMT_HEAD(__VA_ARGS__,), \
			__func__, \
			RTE_FMT_TAIL(__VA_ARGS__,)))

#define PMD_DRV_LOG(level, ...) \
	RTE_LOG_LINE(level, IDPF_DRIVER, \
		RTE_FMT("%s(): " \
			RTE_FMT_HEAD(__VA_ARGS__,), \
			__func__, \
			RTE_FMT_TAIL(__VA_ARGS__,)))

#endif /* _IDPF_LOGS_H_ */

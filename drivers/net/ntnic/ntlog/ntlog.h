/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef NTOSS_SYSTEM_NTLOG_H
#define NTOSS_SYSTEM_NTLOG_H

#include <stdarg.h>
#include <stdint.h>
#include <rte_log.h>

extern int nt_log_general;
extern int nt_log_nthw;
extern int nt_log_filter;
extern int nt_log_ntnic;

#define NT_DRIVER_NAME "ntnic"

/* Common log format */
#define NT_LOG_TEMPLATE_COM(level, module, ...) \
	RTE_FMT(NT_DRIVER_NAME " " module ": " level ": " RTE_FMT_HEAD(__VA_ARGS__, ""), \
		RTE_FMT_TAIL(__VA_ARGS__, ""))

/* Extended log format */
#define NT_LOG_TEMPLATE_EXT(level, module, ...) \
	RTE_FMT(NT_DRIVER_NAME " " module ": " level ": [%s: %u] " RTE_FMT_HEAD(__VA_ARGS__, ""), \
		__func__, __LINE__, RTE_FMT_TAIL(__VA_ARGS__, ""))

#define NT_PMD_DRV_GENERAL_LOG(level, module, format, ...) \
	rte_log(RTE_LOG_##level, nt_log_general, \
		NT_LOG_TEMPLATE_##format(#level, #module, __VA_ARGS__))

#define NT_PMD_DRV_NTHW_LOG(level, module, format, ...) \
	rte_log(RTE_LOG_##level, nt_log_nthw, \
		NT_LOG_TEMPLATE_##format(#level, #module, __VA_ARGS__))

#define NT_PMD_DRV_FILTER_LOG(level, module, format, ...) \
	rte_log(RTE_LOG_##level, nt_log_filter, \
		NT_LOG_TEMPLATE_##format(#level, #module, __VA_ARGS__))

#define NT_PMD_DRV_NTNIC_LOG(level, module, format, ...) \
	rte_log(RTE_LOG_##level, nt_log_ntnic, \
		NT_LOG_TEMPLATE_##format(#level, #module, __VA_ARGS__))

#define NT_LOG_ERR(level, module, ...) NT_PMD_DRV_##module##_LOG(ERR, module, COM, __VA_ARGS__)
#define NT_LOG_WRN(level, module, ...) NT_PMD_DRV_##module##_LOG(WARNING, module, COM, __VA_ARGS__)
#define NT_LOG_INF(level, module, ...) NT_PMD_DRV_##module##_LOG(INFO, module, COM, __VA_ARGS__)
#define NT_LOG_DBG(level, module, ...) NT_PMD_DRV_##module##_LOG(DEBUG, module, COM, __VA_ARGS__)

#define NT_LOG_DBGX_ERR(level, module, ...) \
	NT_PMD_DRV_##module##_LOG(ERR, module, EXT, __VA_ARGS__)
#define NT_LOG_DBGX_WRN(level, module, ...) \
	NT_PMD_DRV_##module##_LOG(WARNING, module, EXT, __VA_ARGS__)
#define NT_LOG_DBGX_INF(level, module, ...) \
	NT_PMD_DRV_##module##_LOG(INFO, module, EXT, __VA_ARGS__)
#define NT_LOG_DBGX_DBG(level, module, ...) \
	NT_PMD_DRV_##module##_LOG(DEBUG, module, EXT, __VA_ARGS__)

#define NT_LOG(level, module, ...) NT_LOG_##level(level, module, __VA_ARGS__)

#define NT_LOG_DBGX(level, module, ...) NT_LOG_DBGX_##level(level, module, __VA_ARGS__)

/*
 * nt log helper functions
 * to create a string for NT_LOG usage to output a one-liner log
 * to use when one single function call to NT_LOG is not optimal - that is
 * you do not know the number of parameters at programming time or it is variable
 */
char *ntlog_helper_str_alloc(const char *sinit);
void ntlog_helper_str_add(char *s, const char *format, ...);
void ntlog_helper_str_free(char *s);

#endif	/* NTOSS_SYSTEM_NTLOG_H */

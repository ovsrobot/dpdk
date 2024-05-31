/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef NTOSS_SYSTEM_NTLOG_H
#define NTOSS_SYSTEM_NTLOG_H

#include <stdarg.h>
#include <stdint.h>

#ifndef NT_LOG_MODULE_PREFIX

/* DPDK modules */
#define NT_LOG_MODULE_EAL 0
#define NT_LOG_MODULE_MALLOC 1
#define NT_LOG_MODULE_RING 2
#define NT_LOG_MODULE_MEMPOOL 3
#define NT_LOG_MODULE_TIMER 4
#define NT_LOG_MODULE_PMD 5
#define NT_LOG_MODULE_HASH 6
#define NT_LOG_MODULE_LPM 7
#define NT_LOG_MODULE_KNI 8
#define NT_LOG_MODULE_ACL 9
#define NT_LOG_MODULE_POWER 10
#define NT_LOG_MODULE_METER 11
#define NT_LOG_MODULE_SCHED 12
#define NT_LOG_MODULE_PORT 13
#define NT_LOG_MODULE_TABLE 14
#define NT_LOG_MODULE_PIPELINE 15
#define NT_LOG_MODULE_MBUF 16
#define NT_LOG_MODULE_CRYPTODEV 17
#define NT_LOG_MODULE_EFD 18
#define NT_LOG_MODULE_EVENTDEV 19
#define NT_LOG_MODULE_GSO 20
#define NT_LOG_MODULE_USER1 24
#define NT_LOG_MODULE_USER2 25
#define NT_LOG_MODULE_USER3 26
#define NT_LOG_MODULE_USER4 27
#define NT_LOG_MODULE_USER5 28
#define NT_LOG_MODULE_USER6 29
#define NT_LOG_MODULE_USER7 30
#define NT_LOG_MODULE_USER8 31

/* NT modules */
#define NT_LOG_MODULE_GENERAL 10000	/* Should always be a first (smallest) */
#define NT_LOG_MODULE_NTHW 10001
#define NT_LOG_MODULE_FILTER 10002
#define NT_LOG_MODULE_DRV 10003
#define NT_LOG_MODULE_VDPA 10004
#define NT_LOG_MODULE_FPGA 10005
#define NT_LOG_MODULE_NTCONNECT 10006
#define NT_LOG_MODULE_ETHDEV 10007
#define NT_LOG_MODULE_SENSOR 10008
#define NT_LOG_MODULE_END 10009	/* Mark for the range end of NT_LOG */

#define NT_LOG_MODULE_COUNT (NT_LOG_MODULE_END - NT_LOG_MODULE_GENERAL)
#define NT_LOG_MODULE_INDEX(module) ((module) - (NT_LOG_MODULE_GENERAL))
#define NT_LOG_MODULE_PREFIX(type) NT_LOG_MODULE_##type

#endif

#ifndef NT_LOG_ENABLE
#define NT_LOG_ENABLE 1
#endif

#if defined NT_LOG_ENABLE && NT_LOG_ENABLE > 0
#ifndef NT_LOG_ENABLE_ERR
#define NT_LOG_ENABLE_ERR 1
#endif
#ifndef NT_LOG_ENABLE_WRN
#define NT_LOG_ENABLE_WRN 1
#endif
#ifndef NT_LOG_ENABLE_INF
#define NT_LOG_ENABLE_INF 1
#endif
#ifndef NT_LOG_ENABLE_DBG
#define NT_LOG_ENABLE_DBG 1
#endif
#ifndef NT_LOG_ENABLE_DB1
#define NT_LOG_ENABLE_DB1 0
#endif
#ifndef NT_LOG_ENABLE_DB2
#define NT_LOG_ENABLE_DB2 0
#endif
#endif

#if defined NT_LOG_ENABLE_ERR && NT_LOG_ENABLE_ERR > 0
#define NT_LOG_NT_LOG_ERR(...) nt_log(__VA_ARGS__)
#else
#define NT_LOG_NT_LOG_ERR(...)
#endif

#if defined NT_LOG_ENABLE_WRN && NT_LOG_ENABLE_WRN > 0
#define NT_LOG_NT_LOG_WRN(...) nt_log(__VA_ARGS__)
#else
#define NT_LOG_NT_LOG_WRN(...)
#endif

#if defined NT_LOG_ENABLE_INF && NT_LOG_ENABLE_INF > 0
#define NT_LOG_NT_LOG_INF(...) nt_log(__VA_ARGS__)
#else
#define NT_LOG_NT_LOG_INF(...)
#endif

#if defined NT_LOG_ENABLE_DBG && NT_LOG_ENABLE_DBG > 0
#define NT_LOG_NT_LOG_DBG(...) nt_log(__VA_ARGS__)
#else
#define NT_LOG_NT_LOG_DBG(...)
#endif

#if defined NT_LOG_ENABLE_DB1 && NT_LOG_ENABLE_DB1 > 0
#define NT_LOG_NT_LOG_DB1(...) nt_log(__VA_ARGS__)
#else
#define NT_LOG_NT_LOG_DB1(...)
#endif

#if defined NT_LOG_ENABLE_DB2 && NT_LOG_ENABLE_DB2 > 0
#define NT_LOG_NT_LOG_DB2(...) nt_log(__VA_ARGS__)
#else
#define NT_LOG_NT_LOG_DB2(...)
#endif

#define NT_LOG(level, module, ...)                                                                \
	NT_LOG_NT_LOG_##level(NT_LOG_##level, NT_LOG_MODULE_PREFIX(module),                       \
			      #module ": " #level ": " __VA_ARGS__)

enum nt_log_level {
	NT_LOG_ERR = 0x001,
	NT_LOG_WRN = 0x002,
	NT_LOG_INF = 0x004,
	NT_LOG_DBG = 0x008,
	NT_LOG_DB1 = 0x010,
	NT_LOG_DB2 = 0x020,
};

struct nt_log_impl {
	int (*init)(void);
	int (*log)(enum nt_log_level level, uint32_t module, const char *format, va_list args);
	int (*is_debug)(uint32_t module);
};

int nt_log_init(struct nt_log_impl *impl);

int nt_log(enum nt_log_level level, uint32_t module, const char *format, ...);

/* Returns 1 if RTE_DEBUG, 0 if lower log level, -1 if incorrect module */
int nt_log_is_debug(uint32_t module);

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

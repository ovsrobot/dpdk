/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2025, Wuxi Stars Micro System Technologies Co., Ltd.
 */

#ifndef __SXE2_COMMON_LOG_H__
#define __SXE2_COMMON_LOG_H__

#ifndef RTE_EXEC_ENV_WINDOWS
#include <pthread.h>
#else
#include <windows.h>
#endif

#include "sxe2_type.h"

extern s32 sxe2_common_log;
extern s32 sxe2_log_init;
extern s32 sxe2_log_driver;
extern s32 sxe2_log_rx;
extern s32 sxe2_log_tx;
extern s32 sxe2_log_hw;

#define RTE_LOGTYPE_SXE2_COM  sxe2_common_log
#define RTE_LOGTYPE_SXE2_INIT sxe2_log_init
#define RTE_LOGTYPE_SXE2_DRV  sxe2_log_driver
#define RTE_LOGTYPE_SXE2_RX   sxe2_log_rx
#define RTE_LOGTYPE_SXE2_TX   sxe2_log_tx
#define RTE_LOGTYPE_SXE2_HW   sxe2_log_hw

#define  STIME(log_time) \
	do { \
		time_t tv; \
		struct tm *td; \
		time(&tv); \
		td = localtime(&tv); \
		strftime(log_time, sizeof(log_time), "%Y-%m-%d-%H:%M:%S", td); \
	} while (0)

#define filename_printf(x) (strrchr((x), '/') ? strrchr((x), '/') + 1 : (x))

#ifndef RTE_EXEC_ENV_WINDOWS
#define get_current_thread_id() ((uint64_t)pthread_self())
#else
#define get_current_thread_id() ((uint64_t)GetCurrentThreadId())
#endif

#ifdef SXE2_DPDK_DEBUG

__rte_internal
void
sxe2_common_log_stream_open(void);

__rte_internal
void
sxe2_common_log_stream_close(void);

__rte_internal
void
sxe2_common_log_stream_init(void);

#define SXE2_PMD_LOG(level, log_type, ...) \
	RTE_LOG_LINE_PREFIX(level, log_type, "[%" PRIu64 "]:%s:%u:%s(): ", \
		get_current_thread_id() RTE_LOG_COMMA \
		filename_printf(__FILE__) RTE_LOG_COMMA \
		__LINE__ RTE_LOG_COMMA \
		__func__, __VA_ARGS__)

#define SXE2_PMD_DRV_LOG(level, log_type, adapter, ...) \
	RTE_LOG_LINE_PREFIX(level, log_type, "[%" PRIu64 "]:%s:%u:%s():[port:%u]:", \
		get_current_thread_id() RTE_LOG_COMMA \
		filename_printf(__FILE__) RTE_LOG_COMMA \
		__LINE__ RTE_LOG_COMMA \
		__func__,  RTE_LOG_COMMA \
		adapter->port_id, __VA_ARGS__)


#define PMD_LOG_DEBUG(logtype, fmt, ...) \
	do { \
		sxe2_common_log_stream_open();\
		SXE2_PMD_LOG(DEBUG, SXE2_##logtype, fmt, ##__VA_ARGS__); \
		sxe2_common_log_stream_close();\
	} while (0)

#define PMD_LOG_INFO(logtype, fmt, ...) \
	do { \
		sxe2_common_log_stream_open();\
		SXE2_PMD_LOG(INFO, SXE2_##logtype, fmt, ##__VA_ARGS__); \
		sxe2_common_log_stream_close();\
	} while (0)

#define PMD_LOG_NOTICE(logtype, fmt, ...) \
	do { \
		SXE2_PMD_LOG(NOTICE, SXE2_##logtype, fmt, ##__VA_ARGS__); \
		sxe2_common_log_stream_open();\
		SXE2_PMD_LOG(NOTICE, SXE2_##logtype, fmt, ##__VA_ARGS__); \
		sxe2_common_log_stream_close();\
	} while (0)

#define PMD_LOG_WARN(logtype, fmt, ...) \
	do { \
		SXE2_PMD_LOG(WARNING, SXE2_##logtype, fmt, ##__VA_ARGS__); \
		sxe2_common_log_stream_open();\
		SXE2_PMD_LOG(WARNING, SXE2_##logtype, fmt, ##__VA_ARGS__); \
		sxe2_common_log_stream_close();\
	} while (0)

#define PMD_LOG_ERR(logtype, fmt, ...) \
	do { \
		SXE2_PMD_LOG(ERR, SXE2_##logtype, fmt, ##__VA_ARGS__); \
		sxe2_common_log_stream_open();\
		SXE2_PMD_LOG(ERR, SXE2_##logtype, fmt, ##__VA_ARGS__); \
		sxe2_common_log_stream_close();\
	} while (0)

#define PMD_LOG_CRIT(logtype, fmt, ...) \
	do { \
		SXE2_PMD_LOG(CRIT, SXE2_##logtype, fmt, ##__VA_ARGS__); \
		sxe2_common_log_stream_open();\
		SXE2_PMD_LOG(CRIT, SXE2_##logtype, fmt, ##__VA_ARGS__); \
		sxe2_common_log_stream_close();\
	} while (0)

#define PMD_LOG_ALERT(logtype, fmt, ...) \
	do { \
		SXE2_PMD_LOG(ALERT, SXE2_##logtype, fmt, ##__VA_ARGS__); \
		sxe2_common_log_stream_open();\
		SXE2_PMD_LOG(ALERT, SXE2_##logtype, fmt, ##__VA_ARGS__); \
		sxe2_common_log_stream_close();\
	} while (0)

#define PMD_LOG_EMERG(logtype, fmt, ...) \
	do { \
		SXE2_PMD_LOG(EMERG, SXE2_##logtype, fmt, ##__VA_ARGS__); \
		sxe2_common_log_stream_open();\
		SXE2_PMD_LOG(EMERG, SXE2_##logtype, fmt, ##__VA_ARGS__); \
		sxe2_common_log_stream_close();\
	} while (0)

#define PMD_DEV_LOG_DEBUG(adapter, logtype, fmt, ...) \
		do { \
			sxe2_common_log_stream_open();\
			SXE2_PMD_DRV_LOG(DEBUG, SXE2_##logtype, adapter, fmt, ##__VA_ARGS__); \
			sxe2_common_log_stream_close();\
		} while (0)

#define PMD_DEV_LOG_INFO(adapter, logtype, fmt, ...) \
		do { \
			sxe2_common_log_stream_open();\
			SXE2_PMD_DRV_LOG(INFO, SXE2_##logtype, adapter, fmt, ##__VA_ARGS__); \
			sxe2_common_log_stream_close();\
		} while (0)

#define PMD_DEV_LOG_NOTICE(adapter, logtype, fmt, ...) \
		do { \
			SXE2_PMD_DRV_LOG(NOTICE, SXE2_##logtype, adapter, fmt, ##__VA_ARGS__); \
			sxe2_common_log_stream_open();\
			SXE2_PMD_DRV_LOG(NOTICE, SXE2_##logtype, adapter, fmt, ##__VA_ARGS__); \
			sxe2_common_log_stream_close();\
		} while (0)

#define PMD_DEV_LOG_WARN(adapter, logtype, fmt, ...) \
		do { \
			SXE2_PMD_DRV_LOG(WARNING, SXE2_##logtype, adapter, fmt, ##__VA_ARGS__); \
			sxe2_common_log_stream_open();\
			SXE2_PMD_DRV_LOG(WARNING, SXE2_##logtype, adapter, fmt, ##__VA_ARGS__); \
			sxe2_common_log_stream_close();\
		} while (0)

#define PMD_DEV_LOG_ERR(adapter, logtype, fmt, ...) \
		do { \
			SXE2_PMD_DRV_LOG(ERR, SXE2_##logtype, adapter, fmt, ##__VA_ARGS__); \
			sxe2_common_log_stream_open();\
			SXE2_PMD_DRV_LOG(ERR, SXE2_##logtype, adapter, fmt, ##__VA_ARGS__); \
			sxe2_common_log_stream_close();\
		} while (0)

#define PMD_DEV_LOG_CRIT(adapter, logtype, fmt, ...) \
		do { \
			SXE2_PMD_DRV_LOG(CRIT, SXE2_##logtype, adapter, fmt, ##__VA_ARGS__); \
			sxe2_common_log_stream_open();\
			SXE2_PMD_DRV_LOG(CRIT, SXE2_##logtype, adapter, fmt, ##__VA_ARGS__); \
			sxe2_common_log_stream_close();\
		} while (0)

#define PMD_DEV_LOG_ALERT(adapter, logtype, fmt, ...) \
		do { \
			SXE2_PMD_DRV_LOG(ALERT, SXE2_##logtype, adapter, fmt, ##__VA_ARGS__); \
			sxe2_common_log_stream_open();\
			SXE2_PMD_DRV_LOG(ALERT, SXE2_##logtype, adapter, fmt, ##__VA_ARGS__); \
			sxe2_common_log_stream_close();\
		} while (0)

#define PMD_DEV_LOG_EMERG(adapter, logtype, fmt, ...) \
		do { \
			SXE2_PMD_DRV_LOG(EMERG, SXE2_##logtype, adapter, fmt, ##__VA_ARGS__); \
			sxe2_common_log_stream_open();\
			SXE2_PMD_DRV_LOG(EMERG, SXE2_##logtype, adapter, fmt, ##__VA_ARGS__); \
			sxe2_common_log_stream_close();\
		} while (0)

#else
#define SXE2_PMD_LOG(level, log_type, ...) \
	RTE_LOG_LINE_PREFIX(level, log_type, "%s(): ", \
		__func__, __VA_ARGS__)

#define SXE2_PMD_DRV_LOG(level, log_type, adapter, ...) \
	RTE_LOG_LINE_PREFIX(level, log_type, "%s(): port:%u ", \
		__func__ RTE_LOG_COMMA \
		adapter->dev_port_id, __VA_ARGS__)

#define PMD_LOG_DEBUG(logtype, fmt, ...) \
	SXE2_PMD_LOG(DEBUG, SXE2_##logtype, fmt, ##__VA_ARGS__)

#define PMD_LOG_INFO(logtype, fmt, ...) \
	SXE2_PMD_LOG(INFO, SXE2_##logtype, fmt, ##__VA_ARGS__)

#define PMD_LOG_NOTICE(logtype, fmt, ...) \
	SXE2_PMD_LOG(NOTICE, SXE2_##logtype, fmt, ##__VA_ARGS__)

#define PMD_LOG_WARN(logtype, fmt, ...) \
	SXE2_PMD_LOG(WARNING, SXE2_##logtype, fmt, ##__VA_ARGS__)

#define PMD_LOG_ERR(logtype, fmt, ...) \
	SXE2_PMD_LOG(ERR, SXE2_##logtype, fmt, ##__VA_ARGS__)

#define PMD_LOG_CRIT(logtype, fmt, ...) \
	SXE2_PMD_LOG(CRIT, SXE2_##logtype, fmt, ##__VA_ARGS__)

#define PMD_LOG_ALERT(logtype, fmt, ...) \
	SXE2_PMD_LOG(ALERT, SXE2_##logtype, fmt, ##__VA_ARGS__)

#define PMD_LOG_EMERG(logtype, fmt, ...) \
	SXE2_PMD_LOG(EMERG, SXE2_##logtype, fmt, ##__VA_ARGS__)

#define PMD_DEV_LOG_DEBUG(adapter, logtype, fmt, ...) \
	SXE2_PMD_DRV_LOG(DEBUG, SXE2_##logtype, adapter, fmt, ##__VA_ARGS__)

#define PMD_DEV_LOG_INFO(adapter, logtype, fmt, ...) \
	SXE2_PMD_DRV_LOG(INFO, SXE2_##logtype, adapter, fmt, ##__VA_ARGS__)

#define PMD_DEV_LOG_NOTICE(adapter, logtype, fmt, ...) \
	SXE2_PMD_DRV_LOG(NOTICE, SXE2_##logtype, adapter, fmt, ##__VA_ARGS__)

#define PMD_DEV_LOG_WARN(adapter, logtype, fmt, ...) \
	SXE2_PMD_DRV_LOG(WARNING, SXE2_##logtype, adapter, fmt, ##__VA_ARGS__)

#define PMD_DEV_LOG_ERR(adapter, logtype, fmt, ...) \
	SXE2_PMD_DRV_LOG(ERR, SXE2_##logtype, adapter, fmt, ##__VA_ARGS__)

#define PMD_DEV_LOG_CRIT(adapter, logtype, fmt, ...) \
	SXE2_PMD_DRV_LOG(CRIT, SXE2_##logtype, adapter, fmt, ##__VA_ARGS__)

#define PMD_DEV_LOG_ALERT(adapter, logtype, fmt, ...) \
	SXE2_PMD_DRV_LOG(ALERT, SXE2_##logtype, adapter, fmt, ##__VA_ARGS__)

#define PMD_DEV_LOG_EMERG(adapter, logtype, fmt, ...) \
	SXE2_PMD_DRV_LOG(EMERG, SXE2_##logtype, adapter, fmt, ##__VA_ARGS__)

#endif

#define PMD_INIT_FUNC_TRACE() PMD_LOG_DEBUG(INIT, " >>")

#ifdef SXE2_DPDK_DEBUG

#define LOG_DEBUG(fmt, ...) \
		PMD_LOG_DEBUG(DRV, fmt, ##__VA_ARGS__)

#define LOG_INFO(fmt, ...) \
		PMD_LOG_INFO(DRV, fmt, ##__VA_ARGS__)

#define LOG_WARN(fmt, ...) \
		PMD_LOG_WARN(DRV, fmt, ##__VA_ARGS__)

#define LOG_ERROR(fmt, ...) \
		PMD_LOG_ERR(DRV, fmt, ##__VA_ARGS__)

#define LOG_DEBUG_BDF(dev_name, fmt, ...) \
		PMD_LOG_DEBUG(HW, fmt, ##__VA_ARGS__)

#define LOG_INFO_BDF(dev_name, fmt, ...) \
		PMD_LOG_INFO(HW, fmt, ##__VA_ARGS__)

#define LOG_WARN_BDF(dev_name, fmt, ...) \
		PMD_LOG_WARN(HW, fmt, ##__VA_ARGS__)

#define LOG_ERROR_BDF(dev_name, fmt, ...) \
		PMD_LOG_ERR(HW, fmt, ##__VA_ARGS__)

#else
#define LOG_DEBUG(fmt, ...)
#define LOG_INFO(fmt, ...)
#define LOG_WARN(fmt, ...)
#define LOG_ERROR(fmt, ...)
#define LOG_DEBUG_BDF(dev_name, fmt, ...) \
		PMD_LOG_DEBUG(HW, fmt, ##__VA_ARGS__)

#define LOG_INFO_BDF(dev_name, fmt, ...) \
		PMD_LOG_INFO(HW, fmt, ##__VA_ARGS__)

#define LOG_WARN_BDF(dev_name, fmt, ...) \
		PMD_LOG_WARN(HW, fmt, ##__VA_ARGS__)

#define LOG_ERROR_BDF(dev_name, fmt, ...) \
		PMD_LOG_ERR(HW, fmt, ##__VA_ARGS__)
#endif

#ifdef SXE2_DPDK_DEBUG
#define LOG_DEV_DEBUG(fmt, ...) \
	do { \
		RTE_SET_USED(adapter); \
			LOG_DEBUG_BDF(fmt, ##__VA_ARGS__); \
	} while (0)

#define LOG_DEV_INFO(fmt, ...) \
	do { \
		RTE_SET_USED(adapter); \
		LOG_INFO_BDF(fmt, ##__VA_ARGS__); \
	} while (0)

#define LOG_DEV_WARN(fmt, ...) \
	do { \
		RTE_SET_USED(adapter); \
		LOG_WARN_BDF(fmt, ##__VA_ARGS__); \
	} while (0)

#define LOG_DEV_ERR(fmt, ...) \
	do { \
		RTE_SET_USED(adapter); \
			LOG_ERROR_BDF(fmt, ##__VA_ARGS__); \
	} while (0)

#define LOG_MSG_DEBUG(msglvl, fmt, ...) \
	do { \
		RTE_SET_USED(adapter); \
			LOG_DEBUG_BDF(fmt, ##__VA_ARGS__); \
	} while (0)

#define LOG_MSG_INFO(msglvl, fmt, ...) \
	do { \
		RTE_SET_USED(adapter); \
		LOG_INFO_BDF(fmt, ##__VA_ARGS__); \
	} while (0)

#define LOG_MSG_WARN(msglvl, fmt, ...) \
	do { \
		RTE_SET_USED(adapter); \
		LOG_WARN_BDF(fmt, ##__VA_ARGS__); \
	} while (0)

#define LOG_MSG_ERR(msglvl, fmt, ...) \
	do { \
		RTE_SET_USED(adapter); \
			LOG_ERROR_BDF(fmt, ##__VA_ARGS__); \
	} while (0)

#else

#define LOG_DEV_DEBUG(fmt, ...)         RTE_SET_USED(adapter)
#define LOG_DEV_INFO(fmt, ...)          RTE_SET_USED(adapter)
#define LOG_DEV_WARN(fmt, ...)          RTE_SET_USED(adapter)
#define LOG_DEV_ERR(fmt, ...)           RTE_SET_USED(adapter)
#define LOG_MSG_DEBUG(msglvl, fmt, ...) RTE_SET_USED(adapter)
#define LOG_MSG_INFO(msglvl, fmt, ...)  RTE_SET_USED(adapter)
#define LOG_MSG_WARN(msglvl, fmt, ...)  RTE_SET_USED(adapter)
#define LOG_MSG_ERR(msglvl, fmt, ...)   RTE_SET_USED(adapter)
#endif

#endif /* SXE2_COMMON_LOG_H__ */

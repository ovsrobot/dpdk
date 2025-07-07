/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#ifndef _SXE_LOGS_H_
#define _SXE_LOGS_H_

#include <stdio.h>
#include <sys/time.h>
#include <pthread.h>

#include "sxe_types.h"

#define LOG_FILE_NAME_LEN	 256
#define LOG_FILE_PATH		 "/var/log/"
#define LOG_FILE_PREFIX	   "sxepmd.log"

extern s32 sxe_log_init;
extern s32 sxe_log_rx;
extern s32 sxe_log_tx;
extern s32 sxe_log_drv;
extern s32 sxe_log_hw;

#define RTE_LOGTYPE_sxe_log_init sxe_log_init
#define RTE_LOGTYPE_sxe_log_rx sxe_log_rx
#define RTE_LOGTYPE_sxe_log_tx sxe_log_tx
#define RTE_LOGTYPE_sxe_log_drv sxe_log_drv
#define RTE_LOGTYPE_sxe_log_hw sxe_log_hw

#define INIT sxe_log_init
#define RX   sxe_log_rx
#define TX   sxe_log_tx
#define HW   sxe_log_hw
#define DRV  sxe_log_drv

#define UNUSED(x)	((void)(x))

#define  TIME(log_time) \
	do { \
		struct timeval	tv; \
		struct tm *td; \
		gettimeofday(&tv, NULL); \
		td = localtime(&tv.tv_sec); \
		strftime(log_time, sizeof(log_time), "%Y-%m-%d-%H:%M:%S", td); \
	} while (0)

#define filename_printf(x) (strrchr((x), '/') ? strrchr((x), '/') + 1 : (x))

#ifdef SXE_DPDK_DEBUG
#define PMD_LOG_DEBUG(logtype, ...) \
	do { \
		s8 log_time[40]; \
		TIME(log_time); \
		RTE_LOG_LINE(DEBUG, logtype, \
			"[%s][%s][PRI*64]%s:%d:%s: ",\
			"DEBUG", log_time, pthread_self(), \
			filename_printf(__FILE__), __LINE__, \
			__func__, __VA_ARGS__); \
	} while (0)

#define PMD_LOG_INFO(logtype, ...) \
	do { \
		s8 log_time[40]; \
		TIME(log_time); \
		RTE_LOG_LINE_PREFIX(INFO, logtype, \
			"[%s][%s][PRI*64]%s:%d:%s: ",\
			"INFO", log_time, pthread_self(), \
			filename_printf(__FILE__), __LINE__, \
			__func__, __VA_ARGS__); \
	} while (0)

#define PMD_LOG_NOTICE(logtype, ...) \
	do { \
		s8 log_time[40]; \
		TIME(log_time); \
		RTE_LOG_LINE_PREFIX(NOTICE, logtype, \
			"[%s][%s][PRI*64]%s:%d:%s: ",\
			"NOTICE", log_time, pthread_self(), \
			filename_printf(__FILE__), __LINE__, \
			__func__, __VA_ARGS__); \
	} while (0)

#define PMD_LOG_WARN(logtype, ...) \
	do { \
		s8 log_time[40]; \
		TIME(log_time); \
		RTE_LOG_LINE_PREFIX(WARNING, logtype, \
			"[%s][%s][PRI*64]%s:%d:%s: ",\
			"WARN", log_time, pthread_self(), \
			filename_printf(__FILE__), __LINE__, \
			__func__, __VA_ARGS__); \
	} while (0)

#define PMD_LOG_ERR(logtype, ...) \
	do { \
		s8 log_time[40]; \
		TIME(log_time); \
		RTE_LOG_LINE_PREFIX(ERR, logtype, \
			"[%s][%s][PRI*64]%s:%d:%s: ",\
			"ERR", log_time, pthread_self(), \
			filename_printf(__FILE__), __LINE__, \
			__func__, __VA_ARGS__); \
	} while (0)

#define PMD_LOG_CRIT(logtype, ...) \
	do { \
		s8 log_time[40]; \
		TIME(log_time); \
		RTE_LOG_LINE_PREFIX(CRIT, logtype, \
			"[%s][%s][PRI*64]%s:%d:%s: ",\
			"CRIT", log_time, pthread_self(), \
			filename_printf(__FILE__), __LINE__, \
			__func__, __VA_ARGS__); \
	} while (0)

#define PMD_LOG_ALERT(logtype, ...) \
	do { \
		s8 log_time[40]; \
		TIME(log_time); \
		RTE_LOG_LINE_PREFIX(ALERT, logtype, \
			"[%s][%s][PRI*64]%s:%d:%s: ",\
			"ALERT", log_time, pthread_self(), \
			filename_printf(__FILE__), __LINE__, \
			__func__, __VA_ARGS__); \
	} while (0)

#define PMD_LOG_EMERG(logtype, ...) \
	do { \
		s8 log_time[40]; \
		TIME(log_time); \
		RTE_LOG_LINE_PREFIX(EMERG, logtype, \
			"[%s][%s][PRI*64]%s:%d:%s: ",\
			"EMERG", log_time, pthread_self(), \
			filename_printf(__FILE__), __LINE__, \
			__func__, __VA_ARGS__); \
	} while (0)

#else
#define PMD_LOG_DEBUG(logtype, ...) \
		RTE_LOG_LINE_PREFIX(DEBUG, logtype, "%s(): ",\
			__func__, __VA_ARGS__)

#define PMD_LOG_INFO(logtype, ...) \
		RTE_LOG_LINE_PREFIX(INFO, logtype, "%s(): ",\
			__func__, __VA_ARGS__)

#define PMD_LOG_NOTICE(logtype, ...) \
		RTE_LOG_LINE_PREFIX(NOTICE, logtype, "%s(): ",\
			__func__, __VA_ARGS__)

#define PMD_LOG_WARN(logtype, ...) \
		RTE_LOG_LINE_PREFIX(WARNING, logtype, "%s(): ",\
			__func__, __VA_ARGS__)

#define PMD_LOG_ERR(logtype, ...) \
		RTE_LOG_LINE_PREFIX(ERR, logtype, "%s(): ",\
			__func__, __VA_ARGS__)

#define PMD_LOG_CRIT(logtype, ...) \
		RTE_LOG_LINE_PREFIX(CRIT, logtype, "%s(): ",\
			__func__, __VA_ARGS__)

#define PMD_LOG_ALERT(logtype, ...) \
		RTE_LOG_LINE_PREFIX(ALERT, logtype, "%s(): ",\
			__func__, __VA_ARGS__)

#define PMD_LOG_EMERG(logtype, ...) \
		RTE_LOG_LINE_PREFIX(EMERG, logtype, "%s(): ",\
			__func__, __VA_ARGS__)

#endif

#define PMD_INIT_FUNC_TRACE() PMD_LOG_DEBUG(INIT, " >>")

#ifdef SXE_DPDK_DEBUG
#define LOG_DEBUG(fmt, ...) \
		PMD_LOG_DEBUG(DRV, fmt, ##__VA_ARGS__)

#define LOG_INFO(fmt, ...) \
		PMD_LOG_INFO(DRV, fmt, ##__VA_ARGS__)

#define LOG_WARN(fmt, ...) \
		PMD_LOG_WARN(DRV, fmt, ##__VA_ARGS__)

#define LOG_ERROR(fmt, ...) \
		PMD_LOG_ERR(DRV, fmt, ##__VA_ARGS__)

#define LOG_DEBUG_BDF(fmt, ...) \
		PMD_LOG_DEBUG(HW, "[%s]" fmt, adapter->name, ##__VA_ARGS__)

#define LOG_INFO_BDF(fmt, ...) \
		PMD_LOG_INFO(HW, "[%s]" fmt, adapter->name, ##__VA_ARGS__)

#define LOG_WARN_BDF(fmt, ...) \
		PMD_LOG_WARN(HW, "[%s]" fmt, adapter->name, ##__VA_ARGS__)

#define LOG_ERROR_BDF(fmt, ...) \
		PMD_LOG_ERR(HW, "[%s]" fmt, adapter->name, ##__VA_ARGS__)

#else
#define LOG_DEBUG(fmt, ...) UNUSED(fmt)
#define LOG_INFO(fmt, ...) UNUSED(fmt)
#define LOG_WARN(fmt, ...) UNUSED(fmt)
#define LOG_ERROR(fmt, ...) UNUSED(fmt)
#define LOG_DEBUG_BDF(fmt, ...) UNUSED(adapter)
#define LOG_INFO_BDF(fmt, ...) UNUSED(adapter)
#define LOG_WARN_BDF(fmt, ...) UNUSED(adapter)
#define LOG_ERROR_BDF(fmt, ...) UNUSED(adapter)
#endif

#ifdef SXE_DPDK_DEBUG
#define LOG_DEV_DEBUG(fmt, ...) \
	do { \
		UNUSED(adapter); \
		LOG_DEBUG_BDF(fmt, ##__VA_ARGS__); \
	} while (0)

#define LOG_DEV_INFO(fmt, ...) \
	do { \
		UNUSED(adapter); \
		LOG_INFO_BDF(fmt, ##__VA_ARGS__); \
	} while (0)

#define LOG_DEV_WARN(fmt, ...) \
	do { \
		UNUSED(adapter); \
		LOG_WARN_BDF(fmt, ##__VA_ARGS__); \
	} while (0)

#define LOG_DEV_ERR(fmt, ...) \
	do { \
		UNUSED(adapter); \
		LOG_ERROR_BDF(fmt, ##__VA_ARGS__); \
	} while (0)

#define LOG_MSG_DEBUG(msglvl, fmt, ...) \
	do { \
		UNUSED(adapter); \
		LOG_DEBUG_BDF(fmt, ##__VA_ARGS__); \
	} while (0)

#define LOG_MSG_INFO(msglvl, fmt, ...) \
	do { \
		UNUSED(adapter); \
		LOG_INFO_BDF(fmt, ##__VA_ARGS__); \
	} while (0)

#define LOG_MSG_WARN(msglvl, fmt, ...) \
	do { \
		UNUSED(adapter); \
		LOG_WARN_BDF(fmt, ##__VA_ARGS__); \
	} while (0)

#define LOG_MSG_ERR(msglvl, fmt, ...) \
	do { \
		UNUSED(adapter); \
		LOG_ERROR_BDF(fmt, ##__VA_ARGS__); \
	} while (0)

#else
#define LOG_DEV_DEBUG(fmt, ...) UNUSED(adapter)
#define LOG_DEV_INFO(fmt, ...) UNUSED(adapter)
#define LOG_DEV_WARN(fmt, ...) UNUSED(adapter)
#define LOG_DEV_ERR(fmt, ...) UNUSED(adapter)
#define LOG_MSG_DEBUG(msglvl, fmt, ...) UNUSED(adapter)
#define LOG_MSG_INFO(msglvl, fmt, ...) UNUSED(adapter)
#define LOG_MSG_WARN(msglvl, fmt, ...) UNUSED(adapter)
#define LOG_MSG_ERR(msglvl, fmt, ...) UNUSED(adapter)
#endif

void sxe_log_stream_init(void);

#endif

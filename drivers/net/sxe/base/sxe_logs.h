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


#define PMD_INIT_FUNC_TRACE() PMD_LOG_DEBUG(INIT, " >>")

#define LOG_DEBUG(fmt, ...) UNUSED(fmt)
#define LOG_INFO(fmt, ...) UNUSED(fmt)
#define LOG_WARN(fmt, ...) UNUSED(fmt)
#define LOG_ERROR(fmt, ...) UNUSED(fmt)
#define LOG_DEBUG_BDF(fmt, ...) UNUSED(adapter)
#define LOG_INFO_BDF(fmt, ...) UNUSED(adapter)
#define LOG_WARN_BDF(fmt, ...) UNUSED(adapter)
#define LOG_ERROR_BDF(fmt, ...) UNUSED(adapter)

#define LOG_DEV_DEBUG(fmt, ...) UNUSED(adapter)
#define LOG_DEV_INFO(fmt, ...) UNUSED(adapter)
#define LOG_DEV_WARN(fmt, ...) UNUSED(adapter)
#define LOG_DEV_ERR(fmt, ...) UNUSED(adapter)
#define LOG_MSG_DEBUG(msglvl, fmt, ...) UNUSED(adapter)
#define LOG_MSG_INFO(msglvl, fmt, ...) UNUSED(adapter)
#define LOG_MSG_WARN(msglvl, fmt, ...) UNUSED(adapter)
#define LOG_MSG_ERR(msglvl, fmt, ...) UNUSED(adapter)


void sxe_log_stream_init(void);

#endif

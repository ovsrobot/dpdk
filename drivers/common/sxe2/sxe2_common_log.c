/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2025, Wuxi Stars Micro System Technologies Co., Ltd.
 */

#include <eal_export.h>
#include <string.h>
#include <time.h>
#include <rte_log.h>

#include "sxe2_common_log.h"

#ifdef SXE2_DPDK_DEBUG
#define SXE2_COMMON_LOG_FILE_NAME_LEN     256
#define SXE2_COMMON_LOG_FILE_PATH         "/var/log/"

FILE *g_sxe2_common_log_fp;
s8 g_sxe2_common_log_filename[SXE2_COMMON_LOG_FILE_NAME_LEN] = {0};

RTE_EXPORT_INTERNAL_SYMBOL(sxe2_common_log_stream_init)
void
sxe2_common_log_stream_init(void)
{
	FILE *fp;
	struct tm *td;
	time_t rawtime;
	u8 len;
	s8 stime[40];

	if (g_sxe2_common_log_fp)
		goto l_end;

	memset(g_sxe2_common_log_filename, 0, SXE2_COMMON_LOG_FILE_NAME_LEN);

	len = snprintf(g_sxe2_common_log_filename, SXE2_COMMON_LOG_FILE_NAME_LEN,
			"%ssxe2pmd.log.", SXE2_COMMON_LOG_FILE_PATH);

	time(&rawtime);
	td = localtime(&rawtime);
	strftime(stime, sizeof(stime), "%Y-%m-%d-%H:%M:%S", td);

	snprintf(g_sxe2_common_log_filename + len, SXE2_COMMON_LOG_FILE_NAME_LEN - len,
		"%s", stime);

	fp = fopen(g_sxe2_common_log_filename, "w+");
	if (fp == NULL) {
		RTE_LOG_LINE_PREFIX(ERR, SXE2_COM, "Fail to open log file:%s, errno:%d %s.",
				g_sxe2_common_log_filename RTE_LOG_COMMA errno RTE_LOG_COMMA
				strerror(errno));
		goto l_end;
	}
	g_sxe2_common_log_fp = fp;

l_end:
	return;
}
RTE_EXPORT_INTERNAL_SYMBOL(sxe2_common_log_stream_open)
void
sxe2_common_log_stream_open(void)
{
	rte_openlog_stream(g_sxe2_common_log_fp);
}

RTE_EXPORT_INTERNAL_SYMBOL(sxe2_common_log_stream_close)
void
sxe2_common_log_stream_close(void)
{
	rte_openlog_stream(NULL);
}
#endif

#ifdef SXE2_DPDK_DEBUG
RTE_LOG_REGISTER_SUFFIX(sxe2_common_log, com, DEBUG);
#else
RTE_LOG_REGISTER_SUFFIX(sxe2_common_log, com, NOTICE);
#endif

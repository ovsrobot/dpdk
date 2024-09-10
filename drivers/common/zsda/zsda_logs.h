/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#ifndef _ZSDA_LOGS_H_
#define _ZSDA_LOGS_H_

extern int zsda_gen_logtype;
extern int zsda_dp_logtype;

#define ZSDA_LOG(level, fmt, args...)                                          \
	rte_log(RTE_LOG_##level, (zsda_gen_logtype & 0xff),                    \
		"%s(): [%d] " fmt "\n", __func__, __LINE__, ##args)

#define ZSDA_DP_LOG(level, fmt, args...)                                       \
	rte_log(RTE_LOG_##level, zsda_dp_logtype, "%s(): " fmt "\n", __func__, \
		##args)

#define ZSDA_DP_HEXDUMP_LOG(level, title, buf, len)                            \
	zsda_hexdump_log(RTE_LOG_##level, zsda_dp_logtype, title, buf, len)

/**
 * zsda_hexdump_log - Dump out memory in a special hex dump format.
 *
 * Dump out the message buffer in a special hex dump output format with
 * characters printed for each line of 16 hex values. The message will be sent
 * to the stream used by the rte_log infrastructure.
 */
int zsda_hexdump_log(uint32_t level, uint32_t logtype, const char *title,
		     const void *buf, unsigned int len);

#endif /* _ZSDA_LOGS_H_ */

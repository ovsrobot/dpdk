/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Phytium Technology Co., Ltd.
 */

#ifndef _MACB_LOG_H_
#define _MACB_LOG_H_

/* Current log type. */
extern int macb_logtype;

#define MACB_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, macb_logtype, "%s(): " fmt "\n", \
		__func__, ##args)

#define MACB_INFO(fmt, args...) \
	rte_log(RTE_LOG_INFO, macb_logtype, "MACB: " fmt "\n", \
		##args)

#endif /*_MACB_LOG_H_ */

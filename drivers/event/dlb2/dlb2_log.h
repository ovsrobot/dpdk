/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016-2020 Intel Corporation
 */

#ifndef _DLB2_EVDEV_LOG_H_
#define _DLB2_EVDEV_LOG_H_

extern int eventdev_dlb2_log_level;

/* Dynamic logging */
#define DLB2_LOG_IMPL(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, eventdev_dlb2_log_level, "%s" fmt "\n", \
		__func__, ##args)

#define DLB2_LOG_INFO(fmt, args...) \
	DLB2_LOG_IMPL(INFO, fmt, ## args)

#define DLB2_LOG_ERR(fmt, args...) \
	DLB2_LOG_IMPL(ERR, fmt, ## args)

/* remove debug logs at compile time unless actually debugging */
#define DLB2_LOG_DBG(fmt, args...) \
	rte_log_dp(RTE_LOG_DEBUG, eventdev_dlb2_log_level, fmt, ## args)

#endif /* _DLB2_EVDEV_LOG_H_ */

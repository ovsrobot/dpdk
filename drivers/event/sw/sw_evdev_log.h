/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Intel Corporation
 */

#ifndef _SW_EVDEV_LOG_H_
#define _SW_EVDEV_LOG_H_

extern int eventdev_sw_log_level;
#define RTE_LOGTYPE_EVENTDEV_SW_LOG_LEVEL eventdev_sw_log_level

#define SW_LOG_IMPL(level, fmt, args...) \
	RTE_LOG_LINE(level, EVENTDEV_SW_LOG_LEVEL, "%s" fmt, \
			__func__, ##args)

#define SW_LOG_INFO(fmt, args...) \
	SW_LOG_IMPL(INFO, fmt, ## args)

#define SW_LOG_DBG(fmt, args...) \
	SW_LOG_IMPL(DEBUG, fmt, ## args)

#define SW_LOG_ERR(fmt, args...) \
	SW_LOG_IMPL(ERR, fmt, ## args)

#endif /* _SW_EVDEV_LOG_H_ */

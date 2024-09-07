/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2017 6WIND S.A.
 * Copyright 2017 Mellanox Technologies, Ltd
 */

extern int tap_logtype;
#define RTE_LOGTYPE_TAP tap_logtype

#define TAP_LOG(level, fmt, args...) \
	RTE_LOG_LINE(level, TAP, "%s(): " fmt, \
		__func__, ## args)

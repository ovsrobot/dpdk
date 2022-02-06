/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2017 6WIND S.A.
 * Copyright 2017 Mellanox Technologies, Ltd
 */

#ifndef _TAP_LOG_H_
#define _TAP_LOG_H_

extern int tap_logtype;

#define TAP_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, tap_logtype, "%s(): " fmt "\n", \
		__func__, ## args)

#endif /* _TAP_LOG_H_ */

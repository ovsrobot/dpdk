/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#ifndef	_ACL_LOG_H_
#define	_ACL_LOG_H_

extern int acl_logtype;
#define ACL_LOG(level, fmt, args...)			\
	rte_log(RTE_LOG_ ## level, acl_logtype,	\
		"%s(): " fmt "\n", __func__, ##args)

#endif /* _ACL_LOG_H_ */

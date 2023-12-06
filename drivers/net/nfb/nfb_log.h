/* SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _NFB_STATS_H_
#define _NFB_STATS_H_

extern int nfb_logtype;

#define NFB_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, nfb_logtype, "%s(): " fmt "\n", \
		__func__, ## args)

#endif /* _NFB_STATS_H_ */

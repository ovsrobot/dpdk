/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Corigine, Inc.
 * All rights reserved.
 */

#ifndef _NFP_FLOW_H_
#define _NFP_FLOW_H_

struct nfp_fl_stats {
	uint64_t pkts;
	uint64_t bytes;
};

struct nfp_flow_priv {
	/* flow stats */
	struct nfp_fl_stats *stats; /**< Store stats of flow. */
	rte_spinlock_t stats_lock; /** < Lock the update of 'stats' field. */
};

#endif /* _NFP_FLOW_H_ */

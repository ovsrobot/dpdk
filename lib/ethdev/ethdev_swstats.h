/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) Stephen Hemminger <stephen@networkplumber.org>
 */

#ifndef _RTE_ETHDEV_SWSTATS_H_
#define _RTE_ETHDEV_SWSTATS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_stdatomic.h>

#ifdef RTE_ARCH_64
typedef uint64_t eth_counter_t;
#else
typedef RTE_ATOMIC(uint64_t) eth_counter_t;
#endif

struct rte_eth_qsw_stats {
	eth_counter_t	packets;
	eth_counter_t	bytes;
	eth_counter_t	errors;
	eth_counter_t	multicast;
	eth_counter_t	broadcast;
	/* Size bins in array as RFC 2819, undersized [0], 64 [1], etc */
	eth_counter_t	size_bins[8];
};

__rte_internal
void
rte_eth_qsw_update(struct rte_eth_qsw_stats *stats, const struct rte_mbuf *mbuf);

__rte_internal
void
rte_eth_qsw_error_inc(struct rte_eth_qsw_stats *stats);

__rte_internal
int
rte_eth_qsw_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats);

__rte_internal
int
rte_eth_qsw_stats_reset(struct rte_eth_dev *dev);

__rte_internal
int
rte_eth_qsw_xstats_get_names(struct rte_eth_dev *dev,
				struct rte_eth_xstat_name *xstats_names,
				unsigned int limit);
__rte_internal
int
rte_eth_qsw_xstats_get(struct rte_eth_dev *dev, struct rte_eth_xstat *xstats,
			  unsigned int n);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_ETHDEV_SWSTATS_H_ */

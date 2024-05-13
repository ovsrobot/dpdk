/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) Stephen Hemminger <stephen@networkplumber.org>
 */

#ifndef _RTE_ETHDEV_SWSTATS_H_
#define _RTE_ETHDEV_SWSTATS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_counter.h>

struct rte_eth_counters {
	rte_counter64_t	packets;
	rte_counter64_t	bytes;
	rte_counter64_t	errors;
	rte_counter64_t	multicast;
	rte_counter64_t	broadcast;
	/* Size bins in array as RFC 2819, undersized [0], 64 [1], etc */
	rte_counter64_t	size_bins[8];
};

__rte_internal
void rte_eth_count_packet(struct rte_eth_counters *counters, uint32_t size);

__rte_internal
void rte_eth_count_mbuf(struct rte_eth_counters *counters, const struct rte_mbuf *mbuf);

__rte_internal
void rte_eth_count_error(struct rte_eth_counters *stats);

__rte_internal
int rte_eth_counters_stats_get(const struct rte_eth_dev *dev,
			       size_t tx_offset, size_t rx_offset,
			       struct rte_eth_stats *stats);

__rte_internal
int rte_eth_counters_reset(struct rte_eth_dev *dev,
				size_t tx_offset, size_t rx_offset);

__rte_internal
int rte_eth_counters_xstats_get_names(struct rte_eth_dev *dev,
				      struct rte_eth_xstat_name *xstats_names);
__rte_internal
int rte_eth_counters_xstats_get(struct rte_eth_dev *dev,
				size_t tx_offset, size_t rx_offset,
				struct rte_eth_xstat *xstats, unsigned int n);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_ETHDEV_SWSTATS_H_ */

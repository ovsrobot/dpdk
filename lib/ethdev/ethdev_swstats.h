/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) Stephen Hemminger <stephen@networkplumber.org>
 */

#ifndef _RTE_ETHDEV_SWSTATS_H_
#define _RTE_ETHDEV_SWSTATS_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 *
 * Internal statistics counters for software based devices.
 * Hardware PMD's should use the hardware counters instead.
 *
 * This provides a library for PMD's to keep track of packets and bytes.
 * It is assumed that this will be used per queue and queues are not
 * shared by lcores.
 */
#include <stddef.h>
#include <stdint.h>

#include <rte_compat.h>
#include <rte_counter.h>

struct rte_eth_dev;
struct rte_eth_stats;

/**
 * A structure to be embedded in the device driver per-queue data.
 */
struct rte_eth_counters {
	rte_counter64_t	packets;	/**< Total number of packets. */
	rte_counter64_t	bytes;		/**< Total number of bytes. */
	rte_counter64_t	errors;		/**< Total number of packets with errors. */
};

/**
 * @internal
 * Increment counters for a single packet.
 *
 * @param counters
 *    Pointer to queue structure containing counters.
 * @param packets
 *    Number of packets to count
 * @param bytes
 *    Total size of all packet in bytes.
 */
__rte_internal
static inline void
rte_eth_count_packets(struct rte_eth_counters *counters,
		      uint16_t packets, uint32_t bytes)
{
	rte_counter64_add(&counters->packets, packets);
	rte_counter64_add(&counters->bytes, bytes);
}

/**
 * @internal
 * Increment error counter.
 *
 * @param counters
 *    Pointer to queue structure containing counters.
 */
__rte_internal
static inline void
rte_eth_count_error(struct rte_eth_counters *counters)
{
	rte_counter64_add(&counters->errors, 1);
}

/**
 * @internal
 * Retrieve the general statistics for all queues.
 * @see rte_eth_stats_get.
 *
 * @param dev
 *    Pointer to the Ethernet device structure.
 * @param tx_offset
 *    Offset from the tx_queue structure where stats are located.
 * @param rx_offset
 *    Offset from the rx_queue structure where stats are located.
 * @param stats
 *   A pointer to a structure of type *rte_eth_stats* to be filled
 * @return
 *   Zero if successful. Non-zero otherwise.
 */
__rte_internal
int rte_eth_counters_stats_get(const struct rte_eth_dev *dev,
			       size_t tx_offset, size_t rx_offset,
			       struct rte_eth_stats *stats);

/**
 * @internal
 * Reset the statistics for all queues.
 * @see rte_eth_stats_reset.
 *
 * @param dev
 *    Pointer to the Ethernet device structure.
 * @param tx_offset
 *    Offset from the tx_queue structure where stats are located.
 * @param rx_offset
 *    Offset from the rx_queue structure where stats are located.
 * @return
 *   Zero if successful. Non-zero otherwise.
 */
__rte_internal
int rte_eth_counters_reset(struct rte_eth_dev *dev,
			   size_t tx_offset, size_t rx_offset);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_ETHDEV_SWSTATS_H_ */

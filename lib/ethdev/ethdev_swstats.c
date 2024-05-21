/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) Stephen Hemminger <stephen@networkplumber.org>
 */


#include <rte_config.h>
#include <rte_common.h>
#include <rte_atomic.h>

#include "rte_ethdev.h"
#include "ethdev_driver.h"
#include "ethdev_swstats.h"

int
rte_eth_counters_stats_get(const struct rte_eth_dev *dev,
			   size_t tx_offset, size_t rx_offset,
			   struct rte_eth_stats *stats)
{
	uint64_t packets, bytes, errors;
	unsigned int i;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		const void *txq = dev->data->tx_queues[i];
		const struct rte_eth_counters *counters;

		if (txq == NULL)
			continue;

		counters = (const struct rte_eth_counters *)((const char *)txq + tx_offset);
		packets = rte_counter64_read(&counters->packets);
		bytes = rte_counter64_read(&counters->bytes);
		errors = rte_counter64_read(&counters->errors);

		stats->opackets += packets;
		stats->obytes += bytes;
		stats->oerrors += errors;

		if (i < RTE_ETHDEV_QUEUE_STAT_CNTRS) {
			stats->q_opackets[i] = packets;
			stats->q_obytes[i] = bytes;
		}
	}

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		const void *rxq = dev->data->rx_queues[i];
		const struct rte_eth_counters *counters;

		if (rxq == NULL)
			continue;

		counters = (const struct rte_eth_counters *)((const char *)rxq + rx_offset);
		packets = rte_counter64_read(&counters->packets);
		bytes = rte_counter64_read(&counters->bytes);
		errors = rte_counter64_read(&counters->errors);

		stats->ipackets += packets;
		stats->ibytes += bytes;
		stats->ierrors += errors;

		if (i < RTE_ETHDEV_QUEUE_STAT_CNTRS) {
			stats->q_ipackets[i] = packets;
			stats->q_ibytes[i] = bytes;
		}
	}

	stats->rx_nombuf = dev->data->rx_mbuf_alloc_failed;
	return 0;
}

int
rte_eth_counters_reset(struct rte_eth_dev *dev, size_t tx_offset, size_t rx_offset)
{
	struct rte_eth_counters *counters;
	unsigned int i;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		void *txq  = dev->data->tx_queues[i];

		if (txq == NULL)
			continue;

		counters = (struct rte_eth_counters *)((char *)txq + tx_offset);
		rte_counter64_reset(&counters->packets);
		rte_counter64_reset(&counters->bytes);
		rte_counter64_reset(&counters->errors);
	}

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		void *rxq  = dev->data->rx_queues[i];

		if (rxq == NULL)
			continue;

		counters = (struct rte_eth_counters *)((char *)rxq + rx_offset);
		rte_counter64_reset(&counters->packets);
		rte_counter64_reset(&counters->bytes);
		rte_counter64_reset(&counters->errors);
	}

	return 0;
}

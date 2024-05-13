/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) Stephen Hemminger <stephen@networkplumber.org>
 */

#include <stdbool.h>

#include <rte_common.h>
#include <ethdev_driver.h>

#include "rte_ethdev.h"
#include "ethdev_swstats.h"

static void
eth_counters_reset(struct rte_eth_counters *counters)
{
	unsigned int i;

	rte_counter64_reset(&counters->packets);
	rte_counter64_reset(&counters->bytes);
	rte_counter64_reset(&counters->multicast);
	rte_counter64_reset(&counters->broadcast);

	for (i = 0; i < RTE_DIM(counters->size_bins); i++)
		rte_counter64_reset(&counters->size_bins[i]);
}

void
rte_eth_count_packet(struct rte_eth_counters *counters,  uint32_t sz)
{
	uint32_t bin;

	if (sz == 64) {
		bin = 1;
	} else if (sz > 64 && sz < 1024) {
		/* count zeros, and offset into correct bin */
		bin = (sizeof(sz) * 8) - rte_clz32(sz) - 5;
	} else if (sz < 64) {
		bin = 0;
	} else if (sz < 1519) {
		bin = 6;
	} else {
		bin = 7;
	}

	rte_counter64_add(&counters->packets, 1);
	rte_counter64_add(&counters->bytes, sz);
	rte_counter64_add(&counters->size_bins[bin], 1);
}

void
rte_eth_count_mbuf(struct rte_eth_counters *counters, const struct rte_mbuf *mbuf)
{
	const struct rte_ether_addr *ea;

	rte_eth_count_packet(counters, rte_pktmbuf_pkt_len(mbuf));

	ea = rte_pktmbuf_mtod(mbuf, const struct rte_ether_addr *);
	if (rte_is_multicast_ether_addr(ea)) {
		if (rte_is_broadcast_ether_addr(ea))
			rte_counter64_add(&counters->broadcast, 1);
		else
			rte_counter64_add(&counters->multicast, 1);
	}
}

void
rte_eth_count_error(struct rte_eth_counters *counters)
{
	rte_counter64_add(&counters->errors, 1);
}

int
rte_eth_counters_stats_get(const struct rte_eth_dev *dev,
			   size_t tx_offset, size_t rx_offset,
			   struct rte_eth_stats *stats)
{
	unsigned int i;
	uint64_t packets, bytes, errors;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		const void *txq = dev->data->tx_queues[i];
		const struct rte_eth_counters *counters;

		if (txq == NULL)
			continue;

		counters = (const struct rte_eth_counters *)((const char *)txq + tx_offset);
		packets = rte_counter64_fetch(&counters->packets);
		bytes = rte_counter64_fetch(&counters->bytes);
		errors = rte_counter64_fetch(&counters->errors);

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
		packets = rte_counter64_fetch(&counters->packets);
		bytes = rte_counter64_fetch(&counters->bytes);
		errors = rte_counter64_fetch(&counters->errors);

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
	unsigned int i;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		void *txq  = dev->data->tx_queues[i];
		struct rte_eth_counters *counters;

		if (txq == NULL)
			continue;

		counters = (struct rte_eth_counters *)((char *)txq + tx_offset);
		eth_counters_reset(counters);
	}

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		void *rxq  = dev->data->rx_queues[i];
		struct rte_eth_counters *counters;

		if (rxq == NULL)
			continue;

		counters = (struct rte_eth_counters *)((char *)rxq + rx_offset);
		eth_counters_reset(counters);
	}

	return 0;
}

struct xstats_name_off {
	char name[RTE_ETH_XSTATS_NAME_SIZE];
	size_t offset;
};

/* [rt]x_qX_ is prepended to the name string here */
static const struct xstats_name_off eth_swstats_strings[] = {
	{"good_packets",           offsetof(struct rte_eth_counters, packets)},
	{"good_bytes",             offsetof(struct rte_eth_counters, bytes)},
	{"errors",                 offsetof(struct rte_eth_counters, errors)},
	{"multicast_packets",      offsetof(struct rte_eth_counters, multicast)},
	{"broadcast_packets",      offsetof(struct rte_eth_counters, broadcast)},
	{"undersize_packets",      offsetof(struct rte_eth_counters, size_bins[0])},
	{"size_64_packets",        offsetof(struct rte_eth_counters, size_bins[1])},
	{"size_65_127_packets",    offsetof(struct rte_eth_counters, size_bins[2])},
	{"size_128_255_packets",   offsetof(struct rte_eth_counters, size_bins[3])},
	{"size_256_511_packets",   offsetof(struct rte_eth_counters, size_bins[4])},
	{"size_512_1023_packets",  offsetof(struct rte_eth_counters, size_bins[5])},
	{"size_1024_1518_packets", offsetof(struct rte_eth_counters, size_bins[6])},
	{"size_1519_max_packets",  offsetof(struct rte_eth_counters, size_bins[7])},
};
#define NUM_SWSTATS_XSTATS RTE_DIM(eth_swstats_strings)


int
rte_eth_counters_xstats_get_names(struct rte_eth_dev *dev,
				  struct rte_eth_xstat_name *xstats_names)
{
	unsigned int i, t, count = 0;

	if (xstats_names == NULL)
		return (dev->data->nb_tx_queues + dev->data->nb_rx_queues) * NUM_SWSTATS_XSTATS;

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		const void *rxq = dev->data->rx_queues[i];

		if (rxq == NULL)
			continue;

		for (t = 0; t < NUM_SWSTATS_XSTATS; t++) {
			snprintf(xstats_names[count].name, sizeof(xstats_names[count].name),
				 "rx_q%u_%s", i, eth_swstats_strings[t].name);
			count++;
		}
	}

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		const void *txq = dev->data->tx_queues[i];

		if (txq == NULL)
			continue;

		for (t = 0; t < NUM_SWSTATS_XSTATS; t++) {
			snprintf(xstats_names[count].name, sizeof(xstats_names[count].name),
				 "tx_q%u_%s", i, eth_swstats_strings[t].name);
			count++;
		}
	}
	return count;
}

int
rte_eth_counters_xstats_get(struct rte_eth_dev *dev,
			    size_t tx_offset, size_t rx_offset,
			    struct rte_eth_xstat *xstats, unsigned int n)
{
	unsigned int i, t, count = 0;
	const unsigned int nstats
		= (dev->data->nb_tx_queues + dev->data->nb_rx_queues) * NUM_SWSTATS_XSTATS;

	if (n < nstats)
		return nstats;

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		const void *rxq = dev->data->rx_queues[i];
		const struct rte_eth_counters *counters;

		if (rxq == NULL)
			continue;

		counters = (const struct rte_eth_counters *)((const char *)rxq + rx_offset);
		for (t = 0; t < NUM_SWSTATS_XSTATS; t++) {
			const uint64_t *valuep
				= (const uint64_t *)((const char *)counters
						     + eth_swstats_strings[t].offset);

			xstats[count].value = *valuep;
			xstats[count].id = count;
			++count;
		}
	}

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		const void *txq = dev->data->tx_queues[i];
		const struct rte_eth_counters *counters;

		if (txq == NULL)
			continue;

		counters = (const struct rte_eth_counters *)((const char *)txq + tx_offset);
		for (t = 0; t < NUM_SWSTATS_XSTATS; t++) {
			const uint64_t *valuep
				= (const uint64_t *)((const char *)counters
						     + eth_swstats_strings[t].offset);

			xstats[count].value = *valuep;
			xstats[count].id = count;
			++count;
		}
	}

	return count;
}

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) Stephen Hemminger <stephen@networkplumber.org>
 */

#include <stdbool.h>

#include <rte_common.h>
#include <ethdev_driver.h>

#include "rte_ethdev.h"
#include "ethdev_swstats.h"

/*
 * Handling of 64 bit counters to problems with load/store tearing on 32 bit.
 * Store of aligned 64 bit never gets seperated on 64 bit platform.
 * But on 32 bit need to use atomic.
 */
#ifdef RTE_ARCH_64
typedef uint64_t eth_counter_t;

static inline void
eth_counter_add(eth_counter_t *counter, uint32_t val)
{
	counter += val;
}

static inline uint64_t
eth_counter_read(const eth_counter_t *counter)
{
	return *counter;
}

static inline void
eth_counter_reset(eth_counter_t *counter)
{
	*counter = 0;
}
#else
static inline void
eth_counter_add(eth_counter_t *counter, uint32_t val)
{
	rte_atomic_fetch_add_explicit(counter, val, rte_memory_order_relaxed);
}

static inline uint64_t
eth_counter_read(const eth_counter_t *counter)
{
	return rte_atomic_load_explicit(counter, rte_memory_order_relaxed);
}

static inline void
eth_counter_reset(eth_counter_t *counter)
{
	rte_atomic_store_explicit(counter, 0, rte_memory_order_relaxed);
}

#endif

static void
eth_qsw_reset(struct rte_eth_qsw_stats *qstats)
{
	unsigned int i;

	eth_counter_reset(&qstats->packets);
	eth_counter_reset(&qstats->bytes);
	eth_counter_reset(&qstats->multicast);
	eth_counter_reset(&qstats->broadcast);

	for (i = 0; i < RTE_DIM(qstats->size_bins); i++)
		eth_counter_reset(&qstats->size_bins[i]);
}

void
rte_eth_qsw_update(struct rte_eth_qsw_stats *qstats, const struct rte_mbuf *mbuf)
{
	uint32_t s = mbuf->pkt_len;
	uint32_t bin;
	const struct rte_ether_addr *ea;

	if (s == 64) {
		bin = 1;
	} else if (s > 64 && s < 1024) {
		/* count zeros, and offset into correct bin */
		bin = (sizeof(s) * 8) - rte_clz32(s) - 5;
	} else if (s < 64) {
		bin = 0;
	} else if (s < 1519) {
		bin = 6;
	} else {
		bin = 7;
	}

	eth_counter_add(&qstats->packets, 1);
	eth_counter_add(&qstats->bytes, s);
	eth_counter_add(&qstats->size_bins[bin], 1);

	ea = rte_pktmbuf_mtod(mbuf, const struct rte_ether_addr *);
	if (rte_is_multicast_ether_addr(ea)) {
		if (rte_is_broadcast_ether_addr(ea))
			eth_counter_add(&qstats->broadcast, 1);
		else
			eth_counter_add(&qstats->multicast, 1);
	}
}

void
rte_eth_qsw_error_inc(struct rte_eth_qsw_stats *qstats)
{
	eth_counter_add(&qstats->errors, 1);
}

int
rte_eth_qsw_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats)
{
	unsigned int i;
	uint64_t packets, bytes, errors;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		/* assumes that rte_eth_qsw_stats is at start of the queue structure */
		const struct rte_eth_qsw_stats *qstats = dev->data->tx_queues[i];

		if (qstats == NULL)
			continue;

		packets = eth_counter_read(&qstats->packets);
		bytes = eth_counter_read(&qstats->bytes);
		errors = eth_counter_read(&qstats->errors);

		stats->opackets += packets;
		stats->obytes += bytes;
		stats->oerrors += errors;

		if (i < RTE_ETHDEV_QUEUE_STAT_CNTRS) {
			stats->q_opackets[i] = packets;
			stats->q_obytes[i] = bytes;
		}
	}

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		/* assumes that rte_eth_qsw_stats is at start of the queue structure */
		const struct rte_eth_qsw_stats *qstats = dev->data->rx_queues[i];

		if (qstats == NULL)
			continue;

		packets = eth_counter_read(&qstats->packets);
		bytes = eth_counter_read(&qstats->bytes);
		errors = eth_counter_read(&qstats->errors);

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
rte_eth_qsw_stats_reset(struct rte_eth_dev *dev)
{
	unsigned int i;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		struct rte_eth_qsw_stats *qstats = dev->data->tx_queues[i];

		if (qstats != NULL)
			eth_qsw_reset(qstats);
	}

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		struct rte_eth_qsw_stats *qstats = dev->data->rx_queues[i];

		if (qstats != NULL)
			eth_qsw_reset(qstats);
	}

	return 0;
}

struct xstats_name_off {
	char name[RTE_ETH_XSTATS_NAME_SIZE];
	size_t offset;
};

/* [rt]x_qX_ is prepended to the name string here */
static const struct xstats_name_off eth_swstats_strings[] = {
	{"good_packets",           offsetof(struct rte_eth_qsw_stats, packets)},
	{"good_bytes",             offsetof(struct rte_eth_qsw_stats, bytes)},
	{"errors",                 offsetof(struct rte_eth_qsw_stats, errors)},
	{"multicast_packets",      offsetof(struct rte_eth_qsw_stats, multicast)},
	{"broadcast_packets",      offsetof(struct rte_eth_qsw_stats, broadcast)},
	{"undersize_packets",      offsetof(struct rte_eth_qsw_stats, size_bins[0])},
	{"size_64_packets",        offsetof(struct rte_eth_qsw_stats, size_bins[1])},
	{"size_65_127_packets",    offsetof(struct rte_eth_qsw_stats, size_bins[2])},
	{"size_128_255_packets",   offsetof(struct rte_eth_qsw_stats, size_bins[3])},
	{"size_256_511_packets",   offsetof(struct rte_eth_qsw_stats, size_bins[4])},
	{"size_512_1023_packets",  offsetof(struct rte_eth_qsw_stats, size_bins[5])},
	{"size_1024_1518_packets", offsetof(struct rte_eth_qsw_stats, size_bins[6])},
	{"size_1519_max_packets",  offsetof(struct rte_eth_qsw_stats, size_bins[7])},
};
#define NUM_SWSTATS_XSTATS RTE_DIM(eth_swstats_strings)


int
rte_eth_qsw_xstats_get_names(struct rte_eth_dev *dev,
				struct rte_eth_xstat_name *xstats_names,
				__rte_unused unsigned limit)
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
rte_eth_qsw_xstats_get(struct rte_eth_dev *dev, struct rte_eth_xstat *xstats, unsigned int n)
{
	unsigned int i, t, count = 0;
	const unsigned int nstats
		= (dev->data->nb_tx_queues + dev->data->nb_rx_queues) * NUM_SWSTATS_XSTATS;

	if (n < nstats)
		return nstats;

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		/* assumes that rte_eth_qsw_stats is at start of the queue structure */
		const struct rte_eth_qsw_stats *qstats = dev->data->rx_queues[i];

		if (qstats == NULL)
			continue;

		for (t = 0; t < NUM_SWSTATS_XSTATS; t++) {
			const uint64_t *valuep
				= (const uint64_t *)((const char *)qstats
						     + eth_swstats_strings[t].offset);

			xstats[count].value = *valuep;
			xstats[count].id = count;
			++count;
		}
	}

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		const struct rte_eth_qsw_stats *qstats = dev->data->tx_queues[i];

		if (qstats == NULL)
			continue;

		for (t = 0; t < NUM_SWSTATS_XSTATS; t++) {
			const uint64_t *valuep
				= (const uint64_t *)((const char *)qstats
						     + eth_swstats_strings[t].offset);

			xstats[count].value = *valuep;
			xstats[count].id = count;
			++count;
		}
	}

	return count;
}

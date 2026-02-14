/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Stephen Hemminger
 */

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <rte_common.h>
#include <ethdev_driver.h>
#include <rte_ethdev.h>
#include <rte_ether.h>

#include "rtap.h"

/*
 * Xstats name/offset descriptors, following the virtio PMD pattern.
 *
 * Both xstats_get_names and xstats_get iterate these same tables
 * in the same per-queue order, guaranteeing name[i] matches value[i].
 */
struct rtap_xstats_name_off {
	const char *name;
	unsigned int offset;
};

#define RTAP_RXQ_XSTAT(field) { #field, offsetof(struct rtap_rx_xstats, field) }
#define RTAP_TXQ_XSTAT(field) { #field, offsetof(struct rtap_tx_xstats, field) }

static const struct rtap_xstats_name_off rtap_rxq_xstats[] = {
	RTAP_RXQ_XSTAT(size_bins[0]),
	RTAP_RXQ_XSTAT(size_bins[1]),
	RTAP_RXQ_XSTAT(size_bins[2]),
	RTAP_RXQ_XSTAT(size_bins[3]),
	RTAP_RXQ_XSTAT(size_bins[4]),
	RTAP_RXQ_XSTAT(size_bins[5]),
	RTAP_RXQ_XSTAT(broadcast_packets),
	RTAP_RXQ_XSTAT(multicast_packets),
	RTAP_RXQ_XSTAT(unicast_packets),
	RTAP_RXQ_XSTAT(lro_packets),
	RTAP_RXQ_XSTAT(checksum_good),
	RTAP_RXQ_XSTAT(checksum_none),
	RTAP_RXQ_XSTAT(checksum_bad),
	RTAP_RXQ_XSTAT(mbuf_alloc_failed),
};

static const struct rtap_xstats_name_off rtap_txq_xstats[] = {
	RTAP_TXQ_XSTAT(size_bins[0]),
	RTAP_TXQ_XSTAT(size_bins[1]),
	RTAP_TXQ_XSTAT(size_bins[2]),
	RTAP_TXQ_XSTAT(size_bins[3]),
	RTAP_TXQ_XSTAT(size_bins[4]),
	RTAP_TXQ_XSTAT(size_bins[5]),
	RTAP_TXQ_XSTAT(broadcast_packets),
	RTAP_TXQ_XSTAT(multicast_packets),
	RTAP_TXQ_XSTAT(unicast_packets),
	RTAP_TXQ_XSTAT(tso_packets),
	RTAP_TXQ_XSTAT(checksum_offload),
	RTAP_TXQ_XSTAT(multiseg_packets),
};

/* Display names for size buckets (indexed by array position) */
static const char * const rtap_size_bucket_names[] = {
	"size_64",
	"size_65_to_127",
	"size_128_to_255",
	"size_256_to_511",
	"size_512_to_1023",
	"size_1024_to_1518",
};

/* Size bucket upper bounds for the update helpers */
static const uint16_t rtap_size_bucket_limits[RTAP_NUM_PKT_SIZE_BUCKETS] = {
	64, 127, 255, 511, 1023, 1518,
};

#define RTAP_NUM_RXQ_XSTATS RTE_DIM(rtap_rxq_xstats)
#define RTAP_NUM_TXQ_XSTATS RTE_DIM(rtap_txq_xstats)

static unsigned int
rtap_xstats_count(const struct rte_eth_dev *dev)
{
	return dev->data->nb_rx_queues * RTAP_NUM_RXQ_XSTATS +
	       dev->data->nb_tx_queues * RTAP_NUM_TXQ_XSTATS;
}

/*
 * Build a display name for a per-queue xstat.
 *
 * For size_bins[N] entries, use the human-readable bucket name;
 * for everything else, use the field name directly.
 */
static void
rtap_xstat_name(char *buf, size_t bufsz,
		const char *dir, unsigned int q,
		const struct rtap_xstats_name_off *desc)
{
	/* Check if this is a size_bins entry */
	for (unsigned int i = 0; i < RTAP_NUM_PKT_SIZE_BUCKETS; i++) {
		char binref[32];

		snprintf(binref, sizeof(binref), "size_bins[%u]", i);
		if (strcmp(desc->name, binref) == 0) {
			snprintf(buf, bufsz, "%s_q%u_%s_packets",
				 dir, q, rtap_size_bucket_names[i]);
			return;
		}
	}

	snprintf(buf, bufsz, "%s_q%u_%s", dir, q, desc->name);
}

int
rtap_xstats_get_names(struct rte_eth_dev *dev,
		      struct rte_eth_xstat_name *xstats_names,
		      unsigned int limit)
{
	unsigned int nb_rx = dev->data->nb_rx_queues;
	unsigned int nb_tx = dev->data->nb_tx_queues;
	unsigned int count = rtap_xstats_count(dev);
	unsigned int idx = 0;

	if (xstats_names == NULL)
		return count;

	/* Rx queue stats: all stats for queue 0, then all for queue 1, ... */
	for (unsigned int q = 0; q < nb_rx; q++) {
		for (unsigned int i = 0; i < RTAP_NUM_RXQ_XSTATS; i++) {
			if (idx >= limit)
				goto out;

			rtap_xstat_name(xstats_names[idx].name,
					sizeof(xstats_names[idx].name),
					"rx", q, &rtap_rxq_xstats[i]);
			idx++;
		}
	}

	/* Tx queue stats: all stats for queue 0, then all for queue 1, ... */
	for (unsigned int q = 0; q < nb_tx; q++) {
		for (unsigned int i = 0; i < RTAP_NUM_TXQ_XSTATS; i++) {
			if (idx >= limit)
				goto out;

			rtap_xstat_name(xstats_names[idx].name,
					sizeof(xstats_names[idx].name),
					"tx", q, &rtap_txq_xstats[i]);
			idx++;
		}
	}

out:
	return count;
}

int
rtap_xstats_get(struct rte_eth_dev *dev, struct rte_eth_xstat *xstats,
		unsigned int n)
{
	unsigned int nb_rx = dev->data->nb_rx_queues;
	unsigned int nb_tx = dev->data->nb_tx_queues;
	unsigned int count = rtap_xstats_count(dev);
	unsigned int idx = 0;

	if (n < count)
		return count;

	/* Collect Rx queue xstats — same per-queue order as names */
	for (unsigned int q = 0; q < nb_rx; q++) {
		struct rtap_rx_queue *rxq = dev->data->rx_queues[q];

		for (unsigned int i = 0; i < RTAP_NUM_RXQ_XSTATS; i++) {
			xstats[idx].id = idx;
			if (rxq == NULL)
				xstats[idx].value = 0;
			else
				xstats[idx].value =
					*(uint64_t *)((char *)&rxq->xstats +
						       rtap_rxq_xstats[i].offset);
			idx++;
		}
	}

	/* Collect Tx queue xstats — same per-queue order as names */
	for (unsigned int q = 0; q < nb_tx; q++) {
		struct rtap_tx_queue *txq = dev->data->tx_queues[q];

		for (unsigned int i = 0; i < RTAP_NUM_TXQ_XSTATS; i++) {
			xstats[idx].id = idx;
			if (txq == NULL)
				xstats[idx].value = 0;
			else
				xstats[idx].value =
					*(uint64_t *)((char *)&txq->xstats +
						       rtap_txq_xstats[i].offset);
			idx++;
		}
	}

	return idx;
}

int
rtap_xstats_reset(struct rte_eth_dev *dev)
{
	for (unsigned int q = 0; q < dev->data->nb_rx_queues; q++) {
		struct rtap_rx_queue *rxq = dev->data->rx_queues[q];
		if (rxq != NULL)
			memset(&rxq->xstats, 0, sizeof(rxq->xstats));
	}

	for (unsigned int q = 0; q < dev->data->nb_tx_queues; q++) {
		struct rtap_tx_queue *txq = dev->data->tx_queues[q];
		if (txq != NULL)
			memset(&txq->xstats, 0, sizeof(txq->xstats));
	}

	return 0;
}

/* Helper to update Rx xstats — called from rx_burst */
void
rtap_rx_xstats_update(struct rtap_rx_queue *rxq, struct rte_mbuf *mb)
{
	struct rtap_rx_xstats *xs = &rxq->xstats;
	uint16_t pkt_len = mb->pkt_len;
	struct rte_ether_hdr *eth_hdr;

	/* Update size bucket */
	for (unsigned int i = 0; i < RTAP_NUM_PKT_SIZE_BUCKETS; i++) {
		if (pkt_len <= rtap_size_bucket_limits[i]) {
			xs->size_bins[i]++;
			break;
		}
	}

	/* Update packet type counters */
	eth_hdr = rte_pktmbuf_mtod(mb, struct rte_ether_hdr *);
	if (rte_is_broadcast_ether_addr(&eth_hdr->dst_addr))
		xs->broadcast_packets++;
	else if (rte_is_multicast_ether_addr(&eth_hdr->dst_addr))
		xs->multicast_packets++;
	else
		xs->unicast_packets++;

	/* Update offload-related counters */
	if (mb->ol_flags & RTE_MBUF_F_RX_LRO)
		xs->lro_packets++;

	if (mb->ol_flags & RTE_MBUF_F_RX_L4_CKSUM_GOOD)
		xs->checksum_good++;
	else if (mb->ol_flags & RTE_MBUF_F_RX_L4_CKSUM_NONE)
		xs->checksum_none++;
	else if (mb->ol_flags & RTE_MBUF_F_RX_L4_CKSUM_BAD)
		xs->checksum_bad++;
}

/* Helper to update Tx xstats — called from tx_burst */
void
rtap_tx_xstats_update(struct rtap_tx_queue *txq, struct rte_mbuf *mb)
{
	struct rtap_tx_xstats *xs = &txq->xstats;
	uint16_t pkt_len = mb->pkt_len;
	struct rte_ether_hdr *eth_hdr;

	/* Update size bucket */
	for (unsigned int i = 0; i < RTAP_NUM_PKT_SIZE_BUCKETS; i++) {
		if (pkt_len <= rtap_size_bucket_limits[i]) {
			xs->size_bins[i]++;
			break;
		}
	}

	/* Update packet type counters */
	eth_hdr = rte_pktmbuf_mtod(mb, struct rte_ether_hdr *);
	if (rte_is_broadcast_ether_addr(&eth_hdr->dst_addr))
		xs->broadcast_packets++;
	else if (rte_is_multicast_ether_addr(&eth_hdr->dst_addr))
		xs->multicast_packets++;
	else
		xs->unicast_packets++;

	/* Update offload-related counters */
	if (mb->ol_flags & RTE_MBUF_F_TX_TCP_SEG)
		xs->tso_packets++;

	if ((mb->ol_flags & RTE_MBUF_F_TX_L4_MASK) != 0)
		xs->checksum_offload++;

	if (mb->nb_segs > 1)
		xs->multiseg_packets++;
}

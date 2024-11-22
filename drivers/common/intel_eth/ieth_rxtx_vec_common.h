/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Intel Corporation
 */

#ifndef IETH_RXTX_VEC_COMMON_H_
#define IETH_RXTX_VEC_COMMON_H_

#include <stdint.h>
#include <unistd.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include "ieth_rxtx.h"

#define IETH_RX_BURST 32

static inline uint16_t
ieth_rx_reassemble_packets(struct rte_mbuf **rx_bufs,
			  uint16_t nb_bufs, uint8_t *split_flags,
			  struct rte_mbuf **pkt_first_seg,
			  struct rte_mbuf **pkt_last_seg,
			  const uint8_t crc_len)
{
	struct rte_mbuf *pkts[IETH_RX_BURST] = {0}; /*finished pkts*/
	struct rte_mbuf *start = *pkt_first_seg;
	struct rte_mbuf *end = *pkt_last_seg;
	unsigned int pkt_idx, buf_idx;

	for (buf_idx = 0, pkt_idx = 0; buf_idx < nb_bufs; buf_idx++) {
		if (end) {
			/* processing a split packet */
			end->next = rx_bufs[buf_idx];
			rx_bufs[buf_idx]->data_len += crc_len;

			start->nb_segs++;
			start->pkt_len += rx_bufs[buf_idx]->data_len;
			end = end->next;

			if (!split_flags[buf_idx]) {
				/* it's the last packet of the set */
				start->hash = end->hash;
				start->vlan_tci = end->vlan_tci;
				start->ol_flags = end->ol_flags;
				/* we need to strip crc for the whole packet */
				start->pkt_len -= crc_len;
				if (end->data_len > crc_len)
					end->data_len -= crc_len;
				else {
					/* free up last mbuf */
					struct rte_mbuf *secondlast = start;

					start->nb_segs--;
					while (secondlast->next != end)
						secondlast = secondlast->next;
					secondlast->data_len -= (crc_len - end->data_len);
					secondlast->next = NULL;
					rte_pktmbuf_free_seg(end);
				}
				pkts[pkt_idx++] = start;
				start = NULL;
				end = NULL;
			}
		} else{
			/* not processing a split packet */
			if (!split_flags[buf_idx]) {
				/* not a split packet, save and skip */
				pkts[pkt_idx++] = rx_bufs[buf_idx];
				continue;
			}
			start = rx_bufs[buf_idx];
			end = start;
			rx_bufs[buf_idx]->data_len += crc_len;
			rx_bufs[buf_idx]->pkt_len += crc_len;
		}
	}

	/* save the partial packet for next time */
	*pkt_first_seg = start;
	*pkt_last_seg = end;
	memcpy(rx_bufs, pkts, pkt_idx * (sizeof(*pkts)));
	return pkt_idx;
}

static __rte_always_inline void
ieth_tx_backlog_entry(struct ieth_tx_entry *txep, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	for (uint16_t i = 0; i < (int)nb_pkts; ++i)
		txep[i].mbuf = tx_pkts[i];
}

#define IETH_VPMD_TX_MAX_FREE_BUF 64

typedef int (*ieth_desc_done_fn)(struct ieth_tx_queue *txq, uint16_t idx);

static __rte_always_inline int
ieth_tx_free_bufs(struct ieth_tx_queue *txq, ieth_desc_done_fn desc_done)
{
	struct ieth_tx_entry *txep;
	uint32_t n;
	uint32_t i;
	int nb_free = 0;
	struct rte_mbuf *m, *free[IETH_VPMD_TX_MAX_FREE_BUF];

	/* check DD bits on threshold descriptor */
	if (!desc_done(txq, txq->tx_next_dd))
		return 0;

	n = txq->tx_rs_thresh;

	 /* first buffer to free from S/W ring is at index
	  * tx_next_dd - (tx_rs_thresh-1)
	  */
	txep = &txq->sw_ring[txq->tx_next_dd - (n - 1)];

	if (txq->offloads & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) {
		for (i = 0; i < n; i++) {
			free[i] = txep[i].mbuf;
			/* no need to reset txep[i].mbuf in vector path */
		}
		rte_mempool_put_bulk(free[0]->pool, (void **)free, n);
		goto done;
	}

	m = rte_pktmbuf_prefree_seg(txep[0].mbuf);
	if (likely(m != NULL)) {
		free[0] = m;
		nb_free = 1;
		for (i = 1; i < n; i++) {
			m = rte_pktmbuf_prefree_seg(txep[i].mbuf);
			if (likely(m != NULL)) {
				if (likely(m->pool == free[0]->pool)) {
					free[nb_free++] = m;
				} else {
					rte_mempool_put_bulk(free[0]->pool,
							     (void *)free,
							     nb_free);
					free[0] = m;
					nb_free = 1;
				}
			}
		}
		rte_mempool_put_bulk(free[0]->pool, (void **)free, nb_free);
	} else {
		for (i = 1; i < n; i++) {
			m = rte_pktmbuf_prefree_seg(txep[i].mbuf);
			if (m != NULL)
				rte_mempool_put(m->pool, m);
		}
	}

done:
	/* buffers were freed, update counters */
	txq->nb_tx_free = (uint16_t)(txq->nb_tx_free + txq->tx_rs_thresh);
	txq->tx_next_dd = (uint16_t)(txq->tx_next_dd + txq->tx_rs_thresh);
	if (txq->tx_next_dd >= txq->nb_tx_desc)
		txq->tx_next_dd = (uint16_t)(txq->tx_rs_thresh - 1);

	return txq->tx_rs_thresh;
}

static __rte_always_inline int
ieth_tx_free_bufs_vector(struct ieth_tx_queue *txq, ieth_desc_done_fn desc_done, bool ctx_descs)
{
	int nb_free = 0;
	struct rte_mbuf *free[IETH_VPMD_TX_MAX_FREE_BUF];
	struct rte_mbuf *m;

	/* check DD bits on threshold descriptor */
	if (!desc_done(txq, txq->tx_next_dd))
		return 0;

	const uint32_t n = txq->tx_rs_thresh >> ctx_descs;

	/* first buffer to free from S/W ring is at index
	 * tx_next_dd - (tx_rs_thresh - 1)
	 */
	struct ieth_vec_tx_entry *txep = txq->sw_ring_v;
	txep += (txq->tx_next_dd >> ctx_descs) - (n - 1);

	if (txq->offloads & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE && (n & 31) == 0) {
		struct rte_mempool *mp = txep[0].mbuf->pool;
		void **cache_objs;
		struct rte_mempool_cache *cache = rte_mempool_default_cache(mp,
				rte_lcore_id());

		if (!cache || cache->len == 0)
			goto normal;

		cache_objs = &cache->objs[cache->len];

		if (n > RTE_MEMPOOL_CACHE_MAX_SIZE) {
			rte_mempool_ops_enqueue_bulk(mp, (void *)txep, n);
			goto done;
		}

		/* The cache follows the following algorithm
		 *   1. Add the objects to the cache
		 *   2. Anything greater than the cache min value (if it
		 *   crosses the cache flush threshold) is flushed to the ring.
		 */
		/* Add elements back into the cache */
		uint32_t copied = 0;
		/* n is multiple of 32 */
		while (copied < n) {
			memcpy(&cache_objs[copied], &txep[copied], 32 * sizeof(void *));
			copied += 32;
		}
		cache->len += n;

		if (cache->len >= cache->flushthresh) {
			rte_mempool_ops_enqueue_bulk(mp, &cache->objs[cache->size],
				 cache->len - cache->size);
			cache->len = cache->size;
		}
		goto done;
	}

normal:
	m = rte_pktmbuf_prefree_seg(txep[0].mbuf);
	if (likely(m)) {
		free[0] = m;
		nb_free = 1;
		for (uint32_t i = 1; i < n; i++) {
			m = rte_pktmbuf_prefree_seg(txep[i].mbuf);
			if (likely(m)) {
				if (likely(m->pool == free[0]->pool)) {
					free[nb_free++] = m;
				} else {
					rte_mempool_put_bulk(free[0]->pool, (void *)free, nb_free);
					free[0] = m;
					nb_free = 1;
				}
			}
		}
		rte_mempool_put_bulk(free[0]->pool, (void **)free, nb_free);
	} else {
		for (uint32_t i = 1; i < n; i++) {
			m = rte_pktmbuf_prefree_seg(txep[i].mbuf);
			if (m)
				rte_mempool_put(m->pool, m);
		}
	}

done:
	/* buffers were freed, update counters */
	txq->nb_tx_free = (uint16_t)(txq->nb_tx_free + txq->tx_rs_thresh);
	txq->tx_next_dd = (uint16_t)(txq->tx_next_dd + txq->tx_rs_thresh);
	if (txq->tx_next_dd >= txq->nb_tx_desc)
		txq->tx_next_dd = (uint16_t)(txq->tx_rs_thresh - 1);

	return txq->tx_rs_thresh;
}

#endif /* IETH_RXTX_VEC_COMMON_H_ */

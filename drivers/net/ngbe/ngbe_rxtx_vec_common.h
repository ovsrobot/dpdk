/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2015-2024 Beijing WangXun Technology Co., Ltd.
 * Copyright(c) 2010-2015 Intel Corporation
 */

#ifndef _NGBE_RXTX_VEC_COMMON_H_
#define _NGBE_RXTX_VEC_COMMON_H_
#include <stdint.h>

#include "ngbe_ethdev.h"
#include "ngbe_rxtx.h"

#define NGBE_RXD_PTID_SHIFT 9

#define RTE_NGBE_RXQ_REARM_THRESH      32
#define RTE_NGBE_MAX_RX_BURST          RTE_NGBE_RXQ_REARM_THRESH

static inline uint16_t
reassemble_packets(struct ngbe_rx_queue *rxq, struct rte_mbuf **rx_bufs,
		   uint16_t nb_bufs, uint8_t *split_flags)
{
	struct rte_mbuf *pkts[nb_bufs]; /*finished pkts*/
	struct rte_mbuf *start = rxq->pkt_first_seg;
	struct rte_mbuf *end =  rxq->pkt_last_seg;
	unsigned int pkt_idx, buf_idx;

	for (buf_idx = 0, pkt_idx = 0; buf_idx < nb_bufs; buf_idx++) {
		if (end != NULL) {
			/* processing a split packet */
			end->next = rx_bufs[buf_idx];
			rx_bufs[buf_idx]->data_len += rxq->crc_len;

			start->nb_segs++;
			start->pkt_len += rx_bufs[buf_idx]->data_len;
			end = end->next;

			if (!split_flags[buf_idx]) {
				/* it's the last packet of the set */
				start->hash = end->hash;
				start->ol_flags = end->ol_flags;
				/* we need to strip crc for the whole packet */
				start->pkt_len -= rxq->crc_len;
				if (end->data_len > rxq->crc_len) {
					end->data_len -= rxq->crc_len;
				} else {
					/* free up last mbuf */
					struct rte_mbuf *secondlast = start;

					start->nb_segs--;
					while (secondlast->next != end)
						secondlast = secondlast->next;
					secondlast->data_len -= (rxq->crc_len -
							end->data_len);
					secondlast->next = NULL;
					rte_pktmbuf_free_seg(end);
				}
				pkts[pkt_idx++] = start;
				start = NULL;
				end = NULL;
			}
		} else {
			/* not processing a split packet */
			if (!split_flags[buf_idx]) {
				/* not a split packet, save and skip */
				pkts[pkt_idx++] = rx_bufs[buf_idx];
				continue;
			}
			start = rx_bufs[buf_idx];
			end = start;
			rx_bufs[buf_idx]->data_len += rxq->crc_len;
			rx_bufs[buf_idx]->pkt_len += rxq->crc_len;
		}
	}

	/* save the partial packet for next time */
	rxq->pkt_first_seg = start;
	rxq->pkt_last_seg = end;
	memcpy(rx_bufs, pkts, pkt_idx * (sizeof(*pkts)));
	return pkt_idx;
}

static __rte_always_inline int
ngbe_tx_free_bufs(struct ngbe_tx_queue *txq)
{
	struct ngbe_tx_entry_v *txep;
	uint32_t status;
	uint32_t n;
	uint32_t i;
	int nb_free = 0;
	struct rte_mbuf *m, *free[RTE_NGBE_TX_MAX_FREE_BUF_SZ];

	/* check DD bit on threshold descriptor */
	status = txq->tx_ring[txq->tx_next_dd].dw3;
	if (!(status & NGBE_TXD_DD)) {
		if (txq->nb_tx_free >> 1 < txq->tx_free_thresh)
			ngbe_set32_masked(txq->tdc_reg_addr,
				NGBE_TXCFG_FLUSH, NGBE_TXCFG_FLUSH);
		return 0;
	}

	n = txq->tx_free_thresh;

	/*
	 * first buffer to free from S/W ring is at index
	 * tx_next_dd - (tx_rs_thresh-1)
	 */
	txep = &txq->sw_ring_v[txq->tx_next_dd - (n - 1)];
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
							(void *)free, nb_free);
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

	/* buffers were freed, update counters */
	txq->nb_tx_free = (uint16_t)(txq->nb_tx_free + txq->tx_free_thresh);
	txq->tx_next_dd = (uint16_t)(txq->tx_next_dd + txq->tx_free_thresh);
	if (txq->tx_next_dd >= txq->nb_tx_desc)
		txq->tx_next_dd = (uint16_t)(txq->tx_free_thresh - 1);

	return txq->tx_free_thresh;
}

static __rte_always_inline void
tx_backlog_entry(struct ngbe_tx_entry_v *txep,
		 struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	int i;

	for (i = 0; i < (int)nb_pkts; ++i)
		txep[i].mbuf = tx_pkts[i];
}

static inline void
_ngbe_tx_queue_release_mbufs_vec(struct ngbe_tx_queue *txq)
{
	unsigned int i;
	struct ngbe_tx_entry_v *txe;
	const uint16_t max_desc = (uint16_t)(txq->nb_tx_desc - 1);

	if (txq->sw_ring == NULL || txq->nb_tx_free == max_desc)
		return;

	/* release the used mbufs in sw_ring */
	for (i = txq->tx_next_dd - (txq->tx_free_thresh - 1);
	     i != txq->tx_tail;
	     i = (i + 1) % txq->nb_tx_desc) {
		txe = &txq->sw_ring_v[i];
		rte_pktmbuf_free_seg(txe->mbuf);
	}
	txq->nb_tx_free = max_desc;

	/* reset tx_entry */
	for (i = 0; i < txq->nb_tx_desc; i++) {
		txe = &txq->sw_ring_v[i];
		txe->mbuf = NULL;
	}
}

static inline void
_ngbe_rx_queue_release_mbufs_vec(struct ngbe_rx_queue *rxq)
{
	unsigned int i;

	if (rxq->sw_ring == NULL || rxq->rxrearm_nb >= rxq->nb_rx_desc)
		return;

	/* free all mbufs that are valid in the ring */
	if (rxq->rxrearm_nb == 0) {
		for (i = 0; i < rxq->nb_rx_desc; i++) {
			if (rxq->sw_ring[i].mbuf != NULL)
				rte_pktmbuf_free_seg(rxq->sw_ring[i].mbuf);
		}
	} else {
		for (i = rxq->rx_tail;
		     i != rxq->rxrearm_start;
		     i = (i + 1) % rxq->nb_rx_desc) {
			if (rxq->sw_ring[i].mbuf != NULL)
				rte_pktmbuf_free_seg(rxq->sw_ring[i].mbuf);
		}
	}

	rxq->rxrearm_nb = rxq->nb_rx_desc;

	/* set all entries to NULL */
	memset(rxq->sw_ring, 0, sizeof(rxq->sw_ring[0]) * rxq->nb_rx_desc);
}

static inline void
_ngbe_tx_free_swring_vec(struct ngbe_tx_queue *txq)
{
	if (txq == NULL)
		return;

	if (txq->sw_ring != NULL) {
		rte_free(txq->sw_ring_v - 1);
		txq->sw_ring_v = NULL;
	}
}

static inline void
_ngbe_reset_tx_queue_vec(struct ngbe_tx_queue *txq)
{
	static const struct ngbe_tx_desc zeroed_desc = {0};
	struct ngbe_tx_entry_v *txe = txq->sw_ring_v;
	uint16_t i;

	/* Zero out HW ring memory */
	for (i = 0; i < txq->nb_tx_desc; i++)
		txq->tx_ring[i] = zeroed_desc;

	/* Initialize SW ring entries */
	for (i = 0; i < txq->nb_tx_desc; i++) {
		volatile struct ngbe_tx_desc *txd = &txq->tx_ring[i];

		txd->dw3 = NGBE_TXD_DD;
		txe[i].mbuf = NULL;
	}

	txq->tx_next_dd = (uint16_t)(txq->tx_free_thresh - 1);

	txq->tx_tail = 0;
	/*
	 * Always allow 1 descriptor to be un-allocated to avoid
	 * a H/W race condition
	 */
	txq->last_desc_cleaned = (uint16_t)(txq->nb_tx_desc - 1);
	txq->nb_tx_free = (uint16_t)(txq->nb_tx_desc - 1);
	txq->ctx_curr = 0;
	memset((void *)&txq->ctx_cache, 0,
		NGBE_CTX_NUM * sizeof(struct ngbe_ctx_info));
}

static inline int
ngbe_rxq_vec_setup_default(struct ngbe_rx_queue *rxq)
{
	uintptr_t p;
	struct rte_mbuf mb_def = { .buf_addr = 0 }; /* zeroed mbuf */

	mb_def.nb_segs = 1;
	mb_def.data_off = RTE_PKTMBUF_HEADROOM;
	mb_def.port = rxq->port_id;
	rte_mbuf_refcnt_set(&mb_def, 1);

	/* prevent compiler reordering: rearm_data covers previous fields */
	rte_compiler_barrier();
	p = (uintptr_t)&mb_def.rearm_data;
	rxq->mbuf_initializer = *(uint64_t *)p;
	return 0;
}

static inline int
ngbe_txq_vec_setup_default(struct ngbe_tx_queue *txq,
			    const struct ngbe_txq_ops *txq_ops)
{
	if (txq->sw_ring_v == NULL)
		return -1;

	/* leave the first one for overflow */
	txq->sw_ring_v = txq->sw_ring_v + 1;
	txq->ops = txq_ops;

	return 0;
}

static inline int
ngbe_rx_vec_dev_conf_condition_check_default(struct rte_eth_dev *dev)
{
	RTE_SET_USED(dev);
#ifndef RTE_LIBRTE_IEEE1588

	return 0;
#else
	return -1;
#endif
}
#endif

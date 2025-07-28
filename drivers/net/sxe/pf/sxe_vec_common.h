/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */
#ifndef __SXE_VEC_COMMON_H__
#define __SXE_VEC_COMMON_H__

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SIMD
#include <stdint.h>
#include <rte_mempool.h>
#include <ethdev_driver.h>
#include <dev_driver.h>
#include <rte_malloc.h>
#include "sxe.h"
#include "sxe_queue.h"
#include "sxe_rx.h"

#define RTE_SXE_MAX_TX_FREE_BUF_SZ	64
#define SXE_TXD_STAT_DD				0x00000001

static __rte_always_inline s32
sxe_tx_bufs_vec_free(struct sxe_tx_queue *txq)
{
	struct sxe_tx_buffer_vec *txep;
	u32 status;
	u32 n;
	u32 i;
	s32 ret;
	s32 nb_free = 0;
	struct rte_mbuf *m, *free[RTE_SXE_MAX_TX_FREE_BUF_SZ];

	status = txq->desc_ring[txq->next_dd].wb.status;
	if (!(status & SXE_TXD_STAT_DD)) {
		ret = 0;
		goto out;
	}

	n = txq->rs_thresh;

	txep = &txq->buffer_ring_vec[txq->next_dd - (n - 1)];
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

	txq->desc_free_num = (u16)(txq->desc_free_num + txq->rs_thresh);
	txq->next_dd = (u16)(txq->next_dd + txq->rs_thresh);
	if (txq->next_dd >= txq->ring_depth)
		txq->next_dd = (u16)(txq->rs_thresh - 1);

	ret = txq->rs_thresh;
out:
	return ret;
}

static inline u16
sxe_packets_reassemble(sxe_rx_queue_s *rxq, struct rte_mbuf **rx_bufs,
			u16 bufs_num, u8 *split_flags)
{
	struct rte_mbuf **pkts = (struct rte_mbuf **)malloc(bufs_num * sizeof(struct rte_mbuf *));
	if (pkts == NULL) {
		perror("pkts malloc failed");
		exit(EXIT_FAILURE);
	}
	struct rte_mbuf *start = rxq->pkt_first_seg;
	struct rte_mbuf *end = rxq->pkt_last_seg;
	u32 pkt_idx, buf_idx;

	for (buf_idx = 0, pkt_idx = 0; buf_idx < bufs_num; buf_idx++) {
		if (end != NULL) {
			end->next = rx_bufs[buf_idx];
			rx_bufs[buf_idx]->data_len += rxq->crc_len;

			start->nb_segs++;
			start->pkt_len += rx_bufs[buf_idx]->data_len;
			end = end->next;

			if (!split_flags[buf_idx]) {
				start->hash = end->hash;
				start->ol_flags = end->ol_flags;
				start->pkt_len -= rxq->crc_len;
				if (end->data_len > rxq->crc_len) {
					end->data_len -= rxq->crc_len;
				} else {
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
			if (!split_flags[buf_idx]) {
				pkts[pkt_idx++] = rx_bufs[buf_idx];
				continue;
			}
			start = rx_bufs[buf_idx];
			end = rx_bufs[buf_idx];
			rx_bufs[buf_idx]->data_len += rxq->crc_len;
			rx_bufs[buf_idx]->pkt_len += rxq->crc_len;
		}
	}

	rxq->pkt_first_seg = start;
	rxq->pkt_last_seg = end;
	memcpy(rx_bufs, pkts, pkt_idx * (sizeof(*pkts)));

	free(pkts);
	return pkt_idx;
}

static inline void
sxe_rx_vec_mbufs_release(sxe_rx_queue_s *rxq)
{
	u16 i;

	if (rxq->buffer_ring == NULL || rxq->realloc_num >= rxq->ring_depth)
		return;

	if (rxq->realloc_num == 0) {
		for (i = 0; i < rxq->ring_depth; i++) {
			if (rxq->buffer_ring[i].mbuf != NULL)
				rte_pktmbuf_free_seg(rxq->buffer_ring[i].mbuf);
		}
	} else {
		for (i = rxq->processing_idx;
			 i != rxq->realloc_start;
			 i = (i + 1) % rxq->ring_depth) {
			if (rxq->buffer_ring[i].mbuf != NULL)
				rte_pktmbuf_free_seg(rxq->buffer_ring[i].mbuf);
		}
	}

	rxq->realloc_num = rxq->ring_depth;

	memset(rxq->buffer_ring, 0, sizeof(rxq->buffer_ring[0]) * rxq->ring_depth);
}

static inline s32
sxe_default_rxq_vec_setup(sxe_rx_queue_s *rxq)
{
	uintptr_t p;
	struct rte_mbuf mbuf = { .buf_addr = 0 };

	mbuf.nb_segs = 1;
	mbuf.data_off = RTE_PKTMBUF_HEADROOM;
	mbuf.port = rxq->port_id;
	rte_mbuf_refcnt_set(&mbuf, 1);

	rte_compiler_barrier();
	p = (uintptr_t)&mbuf.rearm_data;
	rxq->mbuf_init_value = *(u64 *)p;

	return 0;
}

static inline s32
sxe_default_rx_vec_condition_check(struct rte_eth_dev *dev)
{
	s32 ret = 0;

#ifndef RTE_LIBRTE_IEEE1588
	struct rte_eth_fdir_conf *fnav_conf = SXE_DEV_FNAV_CONF(dev);
	if (fnav_conf->mode != RTE_FDIR_MODE_NONE)
		ret = -1;
#else
	RTE_SET_USED(dev);
	ret = -1;
#endif

	return ret;
}

static __rte_always_inline void
sxe_vec_mbuf_fill(struct sxe_tx_buffer_vec *buffer_ring,
		 struct rte_mbuf **tx_pkts, u16 pkts_num)
{
	s32 i;

	for (i = 0; i < pkts_num; ++i)
		buffer_ring[i].mbuf = tx_pkts[i];
}

static inline void
sxe_tx_queue_vec_init(sxe_tx_queue_s *txq)
{
	u16 i;
	volatile sxe_tx_data_desc_u *txd;
	static const sxe_tx_data_desc_u zeroed_desc = { {0} };
	struct sxe_tx_buffer_vec *tx_buffer = txq->buffer_ring_vec;

	for (i = 0; i < txq->ring_depth; i++)
		txq->desc_ring[i] = zeroed_desc;

	for (i = 0; i < txq->ring_depth; i++) {
		txd = &txq->desc_ring[i];
		txd->wb.status = SXE_TX_DESC_STAT_DD;
		tx_buffer[i].mbuf = NULL;
	}

	txq->ctx_curr	  = 0;
	txq->desc_used_num = 0;
	txq->desc_free_num = txq->ring_depth - 1;
	txq->next_to_use   = 0;
	txq->next_to_clean = txq->ring_depth - 1;
	txq->next_dd	   = txq->rs_thresh  - 1;
	txq->next_rs	   = txq->rs_thresh  - 1;
	memset((void *)&txq->ctx_cache, 0,
			SXE_CTXT_DESC_NUM * sizeof(struct sxe_ctxt_info));
}

static inline void
sxe_tx_mbufs_vec_release(sxe_tx_queue_s *txq)
{
	u16 i;
	struct sxe_tx_buffer_vec *tx_buffer;
	const u16 max_desc = (u16)(txq->ring_depth - 1);

	if (txq->buffer_ring_vec == NULL || txq->desc_free_num == max_desc)
		return;

	for (i = txq->next_dd - (txq->rs_thresh - 1);
		 i != txq->next_to_use;
		 i = (i + 1) % txq->ring_depth) {
		tx_buffer = &txq->buffer_ring_vec[i];
		rte_pktmbuf_free_seg(tx_buffer->mbuf);
	}
	txq->desc_free_num = max_desc;

	for (i = 0; i < txq->ring_depth; i++) {
		tx_buffer = &txq->buffer_ring_vec[i];
		tx_buffer->mbuf = NULL;
	}
}

static inline void
sxe_tx_buffer_ring_vec_free(sxe_tx_queue_s *txq)
{
	if (txq == NULL)
		return;

	if (txq->buffer_ring_vec != NULL) {
		rte_free(txq->buffer_ring_vec - 1);
		txq->buffer_ring_vec = NULL;
	}
}

static inline s32
sxe_default_txq_vec_setup(sxe_tx_queue_s *txq,
				const struct sxe_txq_ops *txq_ops)
{
	s32 ret = 0;

	if (txq->buffer_ring_vec == NULL) {
		ret = -1;
		goto l_out;
	}

	txq->buffer_ring_vec = txq->buffer_ring_vec + 1;
	txq->ops = txq_ops;

l_out:
	return ret;
}

static inline int
sxe_tx_done_cleanup_vec(sxe_tx_queue_s *txq, u32 free_cnt)
{
	UNUSED(txq);
	UNUSED(free_cnt);

	return -ENOTSUP;
}

s32 sxe_txq_vec_setup(sxe_tx_queue_s *txq);

s32 sxe_rx_vec_condition_check(struct rte_eth_dev *dev);

s32 sxe_rxq_vec_setup(sxe_rx_queue_s *rxq);

void sxe_rx_queue_vec_mbufs_release(sxe_rx_queue_s *rxq);

u16 sxe_scattered_pkts_vec_recv(void *rx_queue, struct rte_mbuf **rx_pkts, u16 pkts_num);

u16 sxe_pkts_vec_recv(void *rx_queue, struct rte_mbuf **rx_pkts, u16 pkts_num);

u16
__sxe_pkts_vector_xmit(void *tx_queue, struct rte_mbuf **tx_pkts,
			   u16 pkts_num);

#endif
#endif

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2025, Wuxi Stars Micro System Technologies Co., Ltd.
 */

#include "sxe2_txrx_vec.h"
#include "sxe2_txrx_vec_common.h"
#include "sxe2_queue.h"
#include "sxe2_ethdev.h"
#include "sxe2_common_log.h"
#include "sxe2_errno.h"

s32 __rte_cold sxe2_rx_vec_support_check(struct rte_eth_dev *dev, u32 *vec_flags)
{
	struct sxe2_rx_queue *rxq;
	s32 ret = SXE2_SUCCESS;
	u16 i;
	*vec_flags = SXE2_RX_MODE_VEC_SIMPLE;
	for (i = 0; i < dev->data->nb_rx_queues; ++i) {
		rxq = (struct sxe2_rx_queue *)dev->data->rx_queues[i];
		if (rxq == NULL) {
			ret = SXE2_ERR_INVAL;
			goto l_end;
		}
		if (!rte_is_power_of_2(rxq->ring_depth)) {
			ret = SXE2_ERR_NOTSUP;
			goto l_end;
		}
		if (rxq->rx_free_thresh < SXE2_RX_PKTS_BURST_BATCH_NUM_VEC &&
			 (rxq->ring_depth % rxq->rx_free_thresh) != 0) {
			ret = SXE2_ERR_NOTSUP;
			goto l_end;
		}
		if ((rxq->offloads & SXE2_RX_VEC_NO_SUPPORT_OFFLOAD) != 0) {
			ret = SXE2_ERR_NOTSUP;
			goto l_end;
		}
		if ((rxq->offloads & SXE2_RX_VEC_SUPPORT_OFFLOAD) != 0)
			*vec_flags = SXE2_RX_MODE_VEC_OFFLOAD;
	}
l_end:
	return ret;
}

bool __rte_cold sxe2_rx_offload_en_check(struct rte_eth_dev *dev, u64 offload)
{
	struct sxe2_rx_queue *rxq;
	bool en = false;
	u16 i;
	for (i = 0; i < dev->data->nb_rx_queues; ++i) {
		rxq = (struct sxe2_rx_queue *)dev->data->rx_queues[i];
		if (rxq == NULL)
			continue;
		if ((rxq->offloads & offload) != 0) {
			en = true;
			goto l_end;
		}
	}
l_end:
	return en;
}

static inline void sxe2_rx_queue_mbufs_release_vec(struct sxe2_rx_queue *rxq)
{
	const u16 mask = rxq->ring_depth - 1;
	u16 i;
	if (unlikely(!rxq->buffer_ring)) {
		PMD_LOG_DEBUG(RX, "Rx queue release mbufs vec, buffer_ring if NULL."
				"port_id:%u queue_id:%u", rxq->port_id, rxq->queue_id);
		return;
	}
	if (rxq->realloc_num >= rxq->ring_depth)
		return;
	if (rxq->realloc_num == 0) {
		for (i = 0; i < rxq->ring_depth; ++i) {
			if (rxq->buffer_ring[i]) {
				rte_pktmbuf_free_seg(rxq->buffer_ring[i]);
				rxq->buffer_ring[i] = NULL;
			}
		}
	} else {
		for (i = rxq->processing_idx;
				i != rxq->realloc_start;
				i = (i + 1) & mask) {
			if (rxq->buffer_ring[i]) {
				rte_pktmbuf_free_seg(rxq->buffer_ring[i]);
				rxq->buffer_ring[i] = NULL;
			}
		}
	}
	rxq->realloc_num = rxq->ring_depth;
	memset(rxq->buffer_ring, 0, rxq->ring_depth * sizeof(rxq->buffer_ring[0]));
}

static inline void sxe2_rx_queue_vec_init(struct sxe2_rx_queue *rxq)
{
	uintptr_t data;
	struct rte_mbuf mbuf_def;
	mbuf_def.buf_addr = 0;
	mbuf_def.nb_segs = 1;
	mbuf_def.data_off = RTE_PKTMBUF_HEADROOM;
	mbuf_def.port = rxq->port_id;
	rte_mbuf_refcnt_set(&mbuf_def, 1);
	rte_compiler_barrier();
	data = (uintptr_t)&mbuf_def.rearm_data;
	rxq->mbuf_init_value = *(u64 *)data;
}

s32 __rte_cold sxe2_rx_queues_vec_prepare(struct rte_eth_dev *dev)
{
	struct sxe2_rx_queue *rxq = NULL;
	s32 ret = SXE2_SUCCESS;
	u16 i;
	for (i = 0; i < dev->data->nb_rx_queues; ++i) {
		rxq = (struct sxe2_rx_queue *)dev->data->rx_queues[i];
		if (rxq == NULL) {
			PMD_LOG_INFO(RX, "Failed to prepare rx queue, rxq[%d] is NULL", i);
			continue;
		}
		rxq->ops.mbufs_release = sxe2_rx_queue_mbufs_release_vec;
		sxe2_rx_queue_vec_init(rxq);
	}
	return ret;
}

s32 __rte_cold sxe2_tx_vec_support_check(struct rte_eth_dev *dev, u32 *vec_flags)
{
	struct sxe2_tx_queue *txq;
	s32 ret = SXE2_SUCCESS;
	u32 i;
	*vec_flags = SXE2_TX_MODE_VEC_SIMPLE;
	for (i = 0; i < dev->data->nb_tx_queues; ++i) {
		txq = (struct sxe2_tx_queue *)dev->data->tx_queues[i];
		if (txq == NULL) {
			ret = SXE2_ERR_INVAL;
			goto l_end;
		}
		if (txq->rs_thresh < SXE2_TX_RS_THRESH_MIN_VEC ||
			 txq->rs_thresh > SXE2_TX_FREE_BUFFER_SIZE_MAX_VEC) {
			ret = SXE2_ERR_NOTSUP;
			goto l_end;
		}
		if ((txq->offloads & SXE2_TX_VEC_NO_SUPPORT_OFFLOAD) != 0) {
			ret = SXE2_ERR_NOTSUP;
			goto l_end;
		}
		if ((txq->offloads & SXE2_TX_VEC_SUPPORT_OFFLOAD) != 0)
			*vec_flags = SXE2_TX_MODE_VEC_OFFLOAD;
	}
l_end:
	return ret;
}

static void sxe2_tx_queue_mbufs_release_vec(struct sxe2_tx_queue *txq)
{
	struct sxe2_tx_buffer *buffer;
	u16 i;
	if (unlikely(txq == NULL || txq->buffer_ring == NULL)) {
		PMD_LOG_ERR(TX, "Tx release mbufs vec, invalid params.");
		goto l_end;
	}
	i = txq->next_dd - (txq->rs_thresh - 1);
	buffer = txq->buffer_ring;
	if (txq->next_use < i) {
		for ( ; i < txq->ring_depth; ++i) {
			rte_pktmbuf_free_seg(buffer[i].mbuf);
			buffer[i].mbuf = NULL;
		}
		i = 0;
	}
	for (; i < txq->next_use; ++i) {
		rte_pktmbuf_free_seg(buffer[i].mbuf);
		buffer[i].mbuf = NULL;
	}
l_end:
	return;
}

s32 __rte_cold sxe2_tx_queues_vec_prepare(struct rte_eth_dev *dev)
{
	struct sxe2_tx_queue *txq = NULL;
	s32 ret = SXE2_SUCCESS;
	u16 i;
	for (i = 0; i < dev->data->nb_tx_queues; ++i) {
		txq = dev->data->tx_queues[i];
		if (txq == NULL) {
			PMD_LOG_INFO(TX, "Failed to prepare tx queue, txq[%d] is NULL", i);
			continue;
		}
		txq->ops.mbufs_release = sxe2_tx_queue_mbufs_release_vec;
	}
	return ret;
}

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#include <rte_ethdev.h>
#include <rte_malloc.h>
#include "sxe_compat_version.h"
#include <ethdev_driver.h>
#include <bus_pci_driver.h>

#include "sxe_rx.h"
#include "sxe_tx.h"
#include "sxe_logs.h"
#include "sxe_regs.h"
#include "sxe.h"
#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SIMD
#include "sxe_vec_common.h"
#include <rte_vect.h>
#endif
#include "sxe_queue_common.h"
#include "sxe_queue.h"

static void sxe_tx_queues_clear(struct rte_eth_dev *dev)
{
	u16 i;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		struct sxe_tx_queue *txq = dev->data->tx_queues[i];

		if (txq != NULL && txq->ops != NULL) {
			txq->ops->mbufs_release(txq);
			txq->ops->init(txq);
		}
	}
}

static void sxe_rx_queues_clear(struct rte_eth_dev *dev, bool rx_batch_alloc_allowed)
{
	u16 i;

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		struct sxe_rx_queue *rxq = dev->data->rx_queues[i];

		if (rxq != NULL) {
			sxe_rx_queue_mbufs_free(rxq);
			sxe_rx_queue_init(rx_batch_alloc_allowed, rxq);
		}
	}
}

s32 __rte_cold __sxe_rx_queue_setup(struct rx_setup *rx_setup, bool is_vf)
{
	struct rte_eth_dev *dev = rx_setup->dev;
	const struct rte_eth_rxconf *rx_conf = rx_setup->rx_conf;
	u16 queue_idx = rx_setup->queue_idx;
	u32 socket_id = rx_setup->socket_id;
	u16 desc_num = rx_setup->desc_num;
	struct rte_mempool *mp = rx_setup->mp;
	const struct rte_memzone *rx_mz;
	struct sxe_rx_queue *rxq;
	u16 len;
	u64 offloads;
	s32 ret = 0;
#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SIMD
	struct sxe_adapter *pf_adapter = dev->data->dev_private;
	struct sxevf_adapter *vf_adapter = dev->data->dev_private;
#endif

	PMD_INIT_FUNC_TRACE();

	offloads = rx_conf->offloads | dev->data->dev_conf.rxmode.offloads;

	if (desc_num % SXE_RX_DESC_RING_ALIGN != 0 ||
			desc_num > SXE_MAX_RING_DESC ||
			desc_num < SXE_MIN_RING_DESC) {
		PMD_LOG_ERR(INIT, "desc_num %u error", desc_num);
		ret = -EINVAL;
		goto l_end;
	}

	if (dev->data->rx_queues[queue_idx] != NULL) {
		sxe_rx_queue_free(dev->data->rx_queues[queue_idx]);
		dev->data->rx_queues[queue_idx] = NULL;
	}

	rxq = rte_zmalloc_socket("ethdev RX queue", sizeof(struct sxe_rx_queue),
				 RTE_CACHE_LINE_SIZE, socket_id);
	if (rxq == NULL) {
		PMD_LOG_ERR(INIT, "rxq malloc mem failed");
		ret = -ENOMEM;
		goto l_end;
	}

	rxq->mb_pool = mp;
	rxq->ring_depth = desc_num;
	rxq->batch_alloc_size = rx_conf->rx_free_thresh;
	rxq->queue_id = queue_idx;
	rxq->reg_idx = (u16)((RTE_ETH_DEV_SRIOV(dev).active == 0) ?
		queue_idx : RTE_ETH_DEV_SRIOV(dev).def_pool_q_idx + queue_idx);
	rxq->port_id = dev->data->port_id;
	if (dev->data->dev_conf.rxmode.offloads & RTE_ETH_RX_OFFLOAD_KEEP_CRC)
		rxq->crc_len = RTE_ETHER_CRC_LEN;
	else
		rxq->crc_len = 0;

	rxq->drop_en = rx_conf->rx_drop_en;
	rxq->deferred_start = rx_conf->rx_deferred_start;
	rxq->offloads = offloads;

	rxq->pkt_type_mask = SXE_PACKET_TYPE_MASK;

	rx_mz = rte_eth_dma_zone_reserve(dev, "rx_ring", queue_idx,
					SXE_RX_RING_SIZE, SXE_ALIGN, socket_id);
	if (rx_mz == NULL) {
		PMD_LOG_ERR(INIT, "rxq malloc desc mem failed");
		sxe_rx_queue_free(rxq);
		ret = -ENOMEM;
		goto l_end;
	}

	rxq->mz = rx_mz;

	memset(rx_mz->addr, 0, SXE_RX_RING_SIZE);

	if (is_vf)
		rxq->rdt_reg_addr = (volatile u32 *)(rx_setup->reg_base_addr +
			SXE_VFRDT(rxq->reg_idx));
	else
		rxq->rdt_reg_addr = (volatile u32 *)(rx_setup->reg_base_addr +
			SXE_RDT(rxq->reg_idx));

	rxq->base_addr = rx_mz->iova;

	rxq->desc_ring = (union sxe_rx_data_desc *)rx_mz->addr;

	if (!sxe_check_is_rx_batch_alloc_support(rxq)) {
		PMD_LOG_DEBUG(INIT, "queue[%d] doesn't support rx batch alloc "
				"- canceling the feature for the whole port[%d]",
				rxq->queue_id, rxq->port_id);
		*rx_setup->rx_batch_alloc_allowed = false;
	}

	len = desc_num;
	if (*rx_setup->rx_batch_alloc_allowed)
		len += RTE_PMD_SXE_MAX_RX_BURST;

	rxq->buffer_ring = rte_zmalloc_socket("rxq->sw_ring",
					  sizeof(struct sxe_rx_buffer) * len,
					  RTE_CACHE_LINE_SIZE, socket_id);
	if (!rxq->buffer_ring) {
		PMD_LOG_ERR(INIT, "rxq malloc buffer mem failed");
		sxe_rx_queue_free(rxq);
		ret = -ENOMEM;
		goto l_end;
	}

	rxq->sc_buffer_ring =
		rte_zmalloc_socket("rxq->sw_sc_ring",
				   sizeof(struct sxe_rx_buffer) * len,
				   RTE_CACHE_LINE_SIZE, socket_id);
	if (!rxq->sc_buffer_ring) {
		PMD_LOG_ERR(INIT, "rxq malloc sc buffer mem failed");
		sxe_rx_queue_free(rxq);
		ret = -ENOMEM;
		goto l_end;
	}

	PMD_LOG_DEBUG(INIT, "buffer_ring=%p sc_buffer_ring=%p desc_ring=%p "
				"dma_addr=0x%" SXE_PRIX64,
			 rxq->buffer_ring, rxq->sc_buffer_ring, rxq->desc_ring,
			 rxq->base_addr);

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SIMD
	if (!rte_is_power_of_2(desc_num)) {
		PMD_LOG_DEBUG(INIT, "queue[%d] doesn't meet Vector Rx "
					"preconditions - canceling the feature for "
					"the whole port[%d]",
				 rxq->queue_id, rxq->port_id);
		if (is_vf)
			vf_adapter->rx_vec_allowed = false;
		else
			pf_adapter->rx_vec_allowed = false;

	} else {
		sxe_rxq_vec_setup(rxq);
	}
#endif

	dev->data->rx_queues[queue_idx] = rxq;

	sxe_rx_queue_init(*rx_setup->rx_batch_alloc_allowed, rxq);

l_end:
	return ret;
}

int __rte_cold __sxe_tx_queue_setup(struct tx_setup *tx_setup, bool is_vf)
{
	s32 ret;
	struct rte_eth_dev *dev = tx_setup->dev;
	const struct rte_eth_txconf *tx_conf = tx_setup->tx_conf;
	u16 tx_queue_id = tx_setup->queue_idx;
	u32 socket_id = tx_setup->socket_id;
	u16 ring_depth = tx_setup->desc_num;
	struct sxe_tx_queue *txq;
	u16 rs_thresh, free_thresh;

	PMD_INIT_FUNC_TRACE();

	ret = sxe_txq_arg_validate(dev, ring_depth, &rs_thresh,
					&free_thresh, tx_conf);
	if (ret) {
		PMD_LOG_ERR(INIT, "tx queue[%d] arg validate failed", tx_queue_id);
		goto l_end;
	} else {
		PMD_LOG_INFO(INIT, "tx queue[%d] ring_depth=%d, "
				"rs_thresh=%d, free_thresh=%d", tx_queue_id,
				ring_depth, rs_thresh, free_thresh);
	}

	txq = sxe_tx_queue_alloc(dev, tx_queue_id, ring_depth, socket_id);
	if (!txq) {
		PMD_LOG_ERR(INIT, "tx queue[%d] resource alloc failed", tx_queue_id);
		ret = -ENOMEM;
		goto l_end;
	}

	txq->ops		= sxe_tx_default_ops_get();
	txq->ring_depth		= ring_depth;
	txq->queue_idx		= tx_queue_id;
	txq->port_id		= dev->data->port_id;
	txq->pthresh		= tx_conf->tx_thresh.pthresh;
	txq->hthresh		= tx_conf->tx_thresh.hthresh;
	txq->wthresh		= tx_conf->tx_thresh.wthresh;
	txq->rs_thresh		= rs_thresh;
	txq->free_thresh	= free_thresh;
	txq->tx_deferred_start	= tx_conf->tx_deferred_start;
	txq->reg_idx		= (u16)((RTE_ETH_DEV_SRIOV(dev).active == 0) ?
		tx_queue_id : RTE_ETH_DEV_SRIOV(dev).def_pool_q_idx + tx_queue_id);
	txq->offloads		= tx_conf->offloads | dev->data->dev_conf.txmode.offloads;

	if (is_vf)
		txq->tdt_reg_addr = (volatile u32 *)(tx_setup->reg_base_addr +
						     SXE_VFTDT(txq->reg_idx));
	else
		txq->tdt_reg_addr = (u32 *)(tx_setup->reg_base_addr +
					    SXE_TDT(txq->reg_idx));

	PMD_LOG_INFO(INIT, "buffer_ring=%p desc_ring=%p dma_addr=0x%" SXE_PRIX64,
			 txq->buffer_ring, txq->desc_ring, (u64)txq->base_addr);
	sxe_tx_function_set(dev, txq);

	txq->ops->init(txq);

	dev->data->tx_queues[tx_queue_id] = txq;

l_end:
	return ret;
}

void __sxe_rx_queue_info_get(struct rte_eth_dev *dev, u16 queue_id,
					struct rte_eth_rxq_info *qinfo)
{
	struct sxe_rx_queue *rxq;

	rxq = dev->data->rx_queues[queue_id];

	qinfo->mp = rxq->mb_pool;
	qinfo->scattered_rx = dev->data->scattered_rx;
	qinfo->nb_desc = rxq->ring_depth;

	qinfo->conf.rx_free_thresh = rxq->batch_alloc_size;
	qinfo->conf.rx_drop_en = rxq->drop_en;
	qinfo->conf.rx_deferred_start = rxq->deferred_start;
	qinfo->conf.offloads = rxq->offloads;
}

void __sxe_recycle_rxq_info_get(struct rte_eth_dev *dev, u16 queue_id,
		struct rte_eth_recycle_rxq_info *q_info)
{
	struct sxe_rx_queue *rxq;
#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SIMD
	struct sxe_adapter *adapter = dev->data->dev_private;
#endif

	rxq = dev->data->rx_queues[queue_id];

	q_info->mbuf_ring = (void *)rxq->buffer_ring;
	q_info->mp = rxq->mb_pool;
	q_info->mbuf_ring_size = rxq->ring_depth;
	q_info->receive_tail = &rxq->processing_idx;
#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SIMD
	if (adapter->rx_vec_allowed) {
#if defined(RTE_ARCH_X86) || defined(RTE_ARCH_ARM)
		q_info->refill_requirement = rxq->realloc_num;
		q_info->refill_head = &rxq->realloc_start;
#endif
	} else {
		q_info->refill_requirement = rxq->batch_alloc_size;
		q_info->refill_head = &rxq->batch_alloc_trigger;
	}
#else
	q_info->refill_requirement = rxq->batch_alloc_size;
	q_info->refill_head = &rxq->batch_alloc_trigger;
#endif
	return;
}

void __sxe_tx_queue_info_get(struct rte_eth_dev *dev, u16 queue_id,
		struct rte_eth_txq_info *q_info)
{
	struct sxe_tx_queue *txq;

	txq = dev->data->tx_queues[queue_id];

	q_info->nb_desc = txq->ring_depth;
	q_info->conf.tx_thresh.pthresh = txq->pthresh;
	q_info->conf.tx_thresh.hthresh = txq->hthresh;
	q_info->conf.tx_thresh.wthresh = txq->wthresh;
	q_info->conf.tx_free_thresh = txq->free_thresh;
	q_info->conf.tx_rs_thresh = txq->rs_thresh;
	q_info->conf.offloads = txq->offloads;
	q_info->conf.tx_deferred_start = txq->tx_deferred_start;
}

s32 __sxe_tx_done_cleanup(void *tx_queue, u32 free_cnt)
{
	int ret;
	struct sxe_tx_queue *txq = (struct sxe_tx_queue *)tx_queue;
	if (txq->offloads == 0 &&
		txq->rs_thresh >= RTE_PMD_SXE_MAX_TX_BURST) {
#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SIMD
		if (txq->rs_thresh <= RTE_SXE_MAX_TX_FREE_BUF_SZ &&
			(rte_eal_process_type() != RTE_PROC_PRIMARY ||
			txq->buffer_ring_vec != NULL)) {
			ret = sxe_tx_done_cleanup_vec(txq, free_cnt);
		} else {
			ret = sxe_tx_done_cleanup_simple(txq, free_cnt);
		}
#else
		ret = sxe_tx_done_cleanup_simple(txq, free_cnt);
#endif

	} else {
		ret = sxe_tx_done_cleanup_full(txq, free_cnt);
	}

	return ret;
}

s32 __rte_cold __sxe_rx_queue_mbufs_alloc(struct sxe_rx_queue *rxq)
{
	struct sxe_rx_buffer *buf_ring = rxq->buffer_ring;
	s32 ret = 0;
	u64 dma_addr;
	u16 i;

	for (i = 0; i < rxq->ring_depth; i++) {
		volatile union sxe_rx_data_desc *desc;
		struct rte_mbuf *mbuf = rte_mbuf_raw_alloc(rxq->mb_pool);

		if (mbuf == NULL) {
			PMD_LOG_ERR(DRV, "rx mbuf alloc failed queue_id=%u",
					(u16)rxq->queue_id);
			ret = -ENOMEM;
			goto l_end;
		}

		mbuf->data_off = RTE_PKTMBUF_HEADROOM;
		mbuf->port = rxq->port_id;

		dma_addr =
			rte_cpu_to_le_64(rte_mbuf_data_iova_default(mbuf));
		desc = &rxq->desc_ring[i];
		desc->read.hdr_addr = 0;
		desc->read.pkt_addr = dma_addr;
		buf_ring[i].mbuf = mbuf;
	}

l_end:
	return ret;
}

void __rte_cold __sxe_rx_queue_free(struct sxe_rx_queue *rxq)
{
	if (rxq != NULL) {
		sxe_rx_queue_mbufs_free(rxq);
		rte_free(rxq->buffer_ring);
		rte_free(rxq->sc_buffer_ring);
		rte_memzone_free(rxq->mz);
		rte_free(rxq);
	}
}

void __rte_cold __sxe_tx_queue_free(struct sxe_tx_queue *txq)
{
	if (txq != NULL && txq->ops != NULL) {
		txq->ops->mbufs_release(txq);
		txq->ops->buffer_ring_free(txq);
		rte_memzone_free(txq->mz);
		rte_free(txq);
	}
}

void __rte_cold __sxe_txrx_queues_clear(struct rte_eth_dev *dev, bool rx_batch_alloc_allowed)
{
	PMD_INIT_FUNC_TRACE();

	sxe_tx_queues_clear(dev);

	sxe_rx_queues_clear(dev, rx_batch_alloc_allowed);
}

void __sxe_queues_free(struct rte_eth_dev *dev)
{
	unsigned int i;

	PMD_INIT_FUNC_TRACE();

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		__sxe_rx_queue_free(dev->data->rx_queues[i]);
		dev->data->rx_queues[i] = NULL;
	}
	dev->data->nb_rx_queues = 0;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		__sxe_tx_queue_free(dev->data->tx_queues[i]);
		dev->data->tx_queues[i] = NULL;
	}
	dev->data->nb_tx_queues = 0;
}

void __sxe_secondary_proc_init(struct rte_eth_dev *eth_dev,
	bool rx_batch_alloc_allowed, bool *rx_vec_allowed)
{
	struct sxe_tx_queue *txq;
	if (eth_dev->data->tx_queues) {
		txq = eth_dev->data->tx_queues[eth_dev->data->nb_tx_queues - 1];
		sxe_tx_function_set(eth_dev, txq);
	} else {
		PMD_LOG_NOTICE(INIT, "No TX queues configured yet. "
				 "Using default TX function.");
	}

	sxe_rx_function_set(eth_dev, rx_batch_alloc_allowed, rx_vec_allowed);
}

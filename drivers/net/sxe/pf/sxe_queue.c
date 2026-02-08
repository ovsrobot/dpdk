/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */
#include <ethdev_driver.h>
#include <dev_driver.h>
#include "sxe_ethdev.h"
#include "rte_malloc.h"
#include "sxe.h"
#include "sxe_hw.h"
#include "sxe_logs.h"
#include "sxe_queue.h"
#include "sxe_offload.h"
#include "sxe_queue_common.h"
#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SIMD
#include "sxe_vec_common.h"
#endif
#include "sxe_compat_version.h"

#define SXE_RXQ_SCAN_INTERVAL   4

#ifndef DEFAULT_TX_RS_THRESH
#define DEFAULT_TX_RS_THRESH   32
#endif

#ifndef DEFAULT_TX_FREE_THRESH
#define DEFAULT_TX_FREE_THRESH 32
#endif

#define RTE_SXE_WAIT_100_US	100

#define SXE_MMW_SIZE_DEFAULT		0x4
#define SXE_MMW_SIZE_JUMBO_FRAME	0x14
#define SXE_MAX_JUMBO_FRAME_SIZE	0x2600

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SRIOV
static s32 sxe_vf_rss_rxq_num_validate(struct rte_eth_dev *dev, u16 rxq_num)
{
	s32 ret = 0;
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(dev);

	switch (rxq_num) {
	case SXE_1_RING_PER_POOL:
	case SXE_2_RING_PER_POOL:
		RTE_ETH_DEV_SRIOV(dev).active = RTE_ETH_64_POOLS;
		break;
	case SXE_4_RING_PER_POOL:
		RTE_ETH_DEV_SRIOV(dev).active = RTE_ETH_32_POOLS;
		break;
	default:
		ret = -EINVAL;
		goto l_end;
	}

	RTE_ETH_DEV_SRIOV(dev).nb_q_per_pool =
		SXE_HW_TXRX_RING_NUM_MAX / RTE_ETH_DEV_SRIOV(dev).active;
	RTE_ETH_DEV_SRIOV(dev).def_pool_q_idx =
		pci_dev->max_vfs * RTE_ETH_DEV_SRIOV(dev).nb_q_per_pool;

	PMD_LOG_INFO(INIT, "enable sriov, vfs num:%u, %u pool mode, %u queue pre pool "
				"vm total queue num are %u",
				pci_dev->max_vfs,
				RTE_ETH_DEV_SRIOV(dev).active,
				RTE_ETH_DEV_SRIOV(dev).nb_q_per_pool,
				RTE_ETH_DEV_SRIOV(dev).def_pool_q_idx);
l_end:
	return ret;
}

s32 sxe_sriov_mq_mode_check(struct rte_eth_dev *dev)
{
	s32 ret = 0;
	struct rte_eth_conf *dev_conf = &dev->data->dev_conf;
	u16 rx_q_num = dev->data->nb_rx_queues;
	u16 tx_q_num = dev->data->nb_tx_queues;

	switch (dev_conf->rxmode.mq_mode) {
	case RTE_ETH_MQ_RX_VMDQ_DCB:
		PMD_LOG_INFO(INIT, "RTE_ETH_MQ_RX_VMDQ_DCB mode supported in sriov");
		break;

	case RTE_ETH_MQ_RX_VMDQ_DCB_RSS:
		PMD_LOG_ERR(INIT, "RTE_ETH_MQ_RX_VMDQ_DCB_RSS mode unsupported in sriov");
		ret = -EINVAL;
		goto l_end;

	case RTE_ETH_MQ_RX_RSS:
	case RTE_ETH_MQ_RX_VMDQ_RSS:
		dev->data->dev_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_VMDQ_RSS;
		if ((rx_q_num <= RTE_ETH_DEV_SRIOV(dev).nb_q_per_pool) &&
				sxe_vf_rss_rxq_num_validate(dev, rx_q_num)) {
			PMD_LOG_ERR(INIT, "sriov is active, invalid queue number[%d], "
				" for vmdq rss, allowed value are 1, 2 or 4",
					rx_q_num);
			ret = -EINVAL;
			goto l_end;
		}
		break;

	case RTE_ETH_MQ_RX_VMDQ_ONLY:
	case RTE_ETH_MQ_RX_NONE:
		dev->data->dev_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_VMDQ_ONLY;
		break;

	default:
		PMD_LOG_ERR(INIT, "sriov is active, wrong mq_mode rx %d",
				dev_conf->rxmode.mq_mode);
		ret = -EINVAL;
		goto l_end;
	}

	switch (dev_conf->txmode.mq_mode) {
	case RTE_ETH_MQ_TX_VMDQ_DCB:
		PMD_LOG_INFO(INIT, "RTE_ETH_MQ_TX_VMDQ_DCB mode supported in sriov");
		break;

	case RTE_ETH_MQ_TX_DCB:
		PMD_LOG_ERR(INIT, "RTE_ETH_MQ_TX_DCB mode unsupported in sriov");
		ret = -EINVAL;
		goto l_end;

	default:
		dev->data->dev_conf.txmode.mq_mode = RTE_ETH_MQ_TX_VMDQ_ONLY;
		break;
	}

	if ((rx_q_num > RTE_ETH_DEV_SRIOV(dev).nb_q_per_pool) ||
		(tx_q_num > RTE_ETH_DEV_SRIOV(dev).nb_q_per_pool)) {
		PMD_LOG_ERR(INIT, "SRIOV is active,"
				" rx_q_num=%d tx_q_num=%d queue number"
				" must be less than or equal to %d.",
				rx_q_num, tx_q_num,
				RTE_ETH_DEV_SRIOV(dev).nb_q_per_pool);
		ret = -EINVAL;
		goto l_end;
	}

	PMD_LOG_INFO(INIT, "sriov enable, rx_mq_mode=%d, tx_mq_mode=%d, "
			"rx_q_mun=%d, tx_q_num=%d, q_pre_pool=%d",
			dev_conf->rxmode.mq_mode, dev_conf->txmode.mq_mode,
			rx_q_num, tx_q_num, RTE_ETH_DEV_SRIOV(dev).nb_q_per_pool);

l_end:
	return ret;
}

#endif

static inline s32 sxe_non_sriov_mq_mode_check(struct rte_eth_dev *dev)
{
	s32 ret = -EINVAL;
	struct rte_eth_conf *dev_conf = &dev->data->dev_conf;
	u16 rx_q_num = dev->data->nb_rx_queues;
	u16 tx_q_num = dev->data->nb_tx_queues;

	switch (dev_conf->rxmode.mq_mode) {
	case RTE_ETH_MQ_RX_VMDQ_DCB_RSS:
		PMD_LOG_ERR(INIT, "VMDQ+DCB+RSS mq_mode is not supported");
		goto l_end;
	case RTE_ETH_MQ_RX_VMDQ_DCB:
		if (rx_q_num != SXE_HW_TXRX_RING_NUM_MAX) {
			PMD_LOG_ERR(INIT, "VMDQ+DCB selected, nb_rx_q != %d",
					SXE_HW_TXRX_RING_NUM_MAX);
			goto l_end;
		}

		if (!(dev_conf->rx_adv_conf.vmdq_dcb_conf.nb_queue_pools ==
			RTE_ETH_16_POOLS ||
			dev_conf->rx_adv_conf.vmdq_dcb_conf.nb_queue_pools ==
			RTE_ETH_32_POOLS)) {
			PMD_LOG_ERR(INIT, "VMDQ+DCB selected,"
					" nb_queue_pools must be %d or %d",
					RTE_ETH_16_POOLS, RTE_ETH_32_POOLS);
			goto l_end;
		}
		break;
	case RTE_ETH_MQ_RX_DCB:
		if (!(dev_conf->rx_adv_conf.dcb_rx_conf.nb_tcs == RTE_ETH_4_TCS ||
			dev_conf->rx_adv_conf.dcb_rx_conf.nb_tcs == RTE_ETH_8_TCS)) {
			PMD_LOG_ERR(INIT, "DCB selected, nb_tcs != %d"
					" and nb_tcs != %d",
					RTE_ETH_4_TCS, RTE_ETH_8_TCS);
			goto l_end;
		}
		break;
	default:
		PMD_LOG_INFO(INIT, "%d rx mq_mode supported",
					dev_conf->rxmode.mq_mode);
		break;
	}

	switch (dev_conf->txmode.mq_mode) {
	case RTE_ETH_MQ_TX_NONE:
		if (tx_q_num > SXE_HW_TX_NONE_MODE_Q_NUM) {
			PMD_LOG_ERR(INIT, "Neither VT nor DCB are enabled, "
					"nb_tx_q > %d.",
					SXE_HW_TX_NONE_MODE_Q_NUM);
			goto l_end;
		}
		break;
	case RTE_ETH_MQ_TX_VMDQ_DCB:
		if (tx_q_num != SXE_HW_TXRX_RING_NUM_MAX) {
			PMD_LOG_ERR(INIT, "VMDQ+DCB selected, nb_tx_q != %d",
					SXE_HW_TXRX_RING_NUM_MAX);
			goto l_end;
		}

		if (!(dev_conf->tx_adv_conf.vmdq_dcb_tx_conf.nb_queue_pools ==
			RTE_ETH_16_POOLS ||
			dev_conf->tx_adv_conf.vmdq_dcb_tx_conf.nb_queue_pools ==
			RTE_ETH_32_POOLS)) {
			PMD_LOG_ERR(INIT, "VMDQ+DCB selected,"
					" nb_queue_pools must be %d or %d",
					RTE_ETH_16_POOLS, RTE_ETH_32_POOLS);
			goto l_end;
		}
		break;
	case RTE_ETH_MQ_TX_DCB:
		if (!(dev_conf->tx_adv_conf.dcb_tx_conf.nb_tcs == RTE_ETH_4_TCS ||
			dev_conf->tx_adv_conf.dcb_tx_conf.nb_tcs == RTE_ETH_8_TCS)) {
			PMD_LOG_ERR(INIT, "DCB selected, nb_tcs != %d"
					" and nb_tcs != %d",
					RTE_ETH_4_TCS, RTE_ETH_8_TCS);
			goto l_end;
		}
		break;
	default:
		PMD_LOG_INFO(INIT, "%d tx mq_mode supported",
					dev_conf->txmode.mq_mode);
		break;
	}

	ret = 0;

	PMD_LOG_INFO(INIT, "sriov disable, rx_mq_mode=%d, tx_mq_mode=%d, "
		"rx_q_mun=%d, tx_q_num=%d",
		dev_conf->rxmode.mq_mode, dev_conf->txmode.mq_mode,
		rx_q_num, tx_q_num);

l_end:
	return ret;
}

s32 sxe_mq_mode_check(struct rte_eth_dev *dev)
{
	s32 ret = 0;

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SRIOV
	if (RTE_ETH_DEV_SRIOV(dev).active) {
		ret = sxe_sriov_mq_mode_check(dev);
#else
	if (RTE_ETH_DEV_SRIOV(dev).active) {
		ret = -ENOTSUP;
		PMD_LOG_ERR(INIT, "sriov not supported");
#endif
	} else {
		ret = sxe_non_sriov_mq_mode_check(dev);
	}

	return ret;
}

void sxe_tx_queue_info_get(struct rte_eth_dev *dev, u16 queue_id,
		struct rte_eth_txq_info *q_info)
{
	__sxe_tx_queue_info_get(dev, queue_id, q_info);
}

void sxe_recycle_rxq_info_get(struct rte_eth_dev *dev, u16 queue_id,
		struct rte_eth_recycle_rxq_info *q_info)
{
	__sxe_recycle_rxq_info_get(dev, queue_id, q_info);
}

s32 __rte_cold sxe_txq_arg_validate(struct rte_eth_dev *dev, u16 ring_depth,
				u16 *rs_thresh, u16 *free_thresh,
				const struct rte_eth_txconf *tx_conf)
{
	s32 ret = -EINVAL;

	if (ring_depth % SXE_TX_DESC_RING_ALIGN != 0 ||
		ring_depth > SXE_MAX_RING_DESC ||
		ring_depth < SXE_MIN_RING_DESC) {
		goto l_end;
	}

	*free_thresh = (u16)((tx_conf->tx_free_thresh) ?
			tx_conf->tx_free_thresh : DEFAULT_TX_FREE_THRESH);
	*rs_thresh = (DEFAULT_TX_RS_THRESH + *free_thresh > ring_depth) ?
			ring_depth - *free_thresh : DEFAULT_TX_RS_THRESH;

	if (tx_conf->tx_rs_thresh > 0)
		*rs_thresh = tx_conf->tx_rs_thresh;

	if (*rs_thresh + *free_thresh > ring_depth) {
		PMD_LOG_ERR(INIT, "tx_rs_thresh + tx_free_thresh must not "
				 "exceed nb_desc. (tx_rs_thresh=%u "
				 "tx_free_thresh=%u nb_desc=%u port = %d)",
				 *rs_thresh, *free_thresh,
				 ring_depth, dev->data->port_id);
		goto l_end;
	}

	if (*rs_thresh >= (ring_depth - 2)) {
		PMD_LOG_ERR(INIT, "tx_rs_thresh must be less than the number "
				"of TX descriptors minus 2. (tx_rs_thresh=%u "
				"port=%d)",
				*rs_thresh, dev->data->port_id);
		goto l_end;
	}

	if (*rs_thresh > DEFAULT_TX_RS_THRESH) {
		PMD_LOG_ERR(INIT, "tx_rs_thresh must be less or equal than %u. "
			"(tx_rs_thresh=%u port=%d)",
			DEFAULT_TX_RS_THRESH, *rs_thresh,
			dev->data->port_id);
		goto l_end;
	}

	if (*free_thresh >= (ring_depth - 3)) {
		PMD_LOG_ERR(INIT, "tx_rs_thresh must be less than the "
				 "tx_free_thresh must be less than the number of "
				 "TX descriptors minus 3. (tx_free_thresh=%u "
				 "port=%d)",
				 *free_thresh, dev->data->port_id);
		goto l_end;
	}

	if (*rs_thresh > *free_thresh) {
		PMD_LOG_ERR(INIT, "tx_rs_thresh must be less than or equal to "
				 "tx_free_thresh. (tx_free_thresh=%u "
				 "tx_rs_thresh=%u port=%d)",
				 *free_thresh, *rs_thresh, dev->data->port_id);
		goto l_end;
	}

	if ((ring_depth % *rs_thresh) != 0) {
		PMD_LOG_ERR(INIT, "tx_rs_thresh must be a divisor of the "
				 "number of TX descriptors. (tx_rs_thresh=%u "
				 "port=%d, ring_depth=%d)",
				 *rs_thresh, dev->data->port_id, ring_depth);
		goto l_end;
	}

	if ((*rs_thresh > 1) && tx_conf->tx_thresh.wthresh != 0) {
		PMD_LOG_ERR(INIT, "TX WTHRESH must be set to 0 if "
				 "tx_rs_thresh is greater than 1. "
				 "(tx_rs_thresh=%u port=%d)",
				 *rs_thresh, dev->data->port_id);
		goto l_end;
	}

	ret = 0;

l_end:
	return ret;
}

static void __rte_cold sxe_tx_buffer_ring_free(sxe_tx_queue_s *txq)
{
	if (txq != NULL && txq->buffer_ring != NULL)
		rte_free(txq->buffer_ring);
}

static void __rte_cold sxe_tx_queue_mbufs_release(sxe_tx_queue_s *txq)
{
	u32 i;

	if (txq->buffer_ring != NULL) {
		for (i = 0; i < txq->ring_depth; i++) {
			if (txq->buffer_ring[i].mbuf != NULL) {
				rte_pktmbuf_free_seg(txq->buffer_ring[i].mbuf);
				txq->buffer_ring[i].mbuf = NULL;
			}
		}
	}
}

void __rte_cold sxe_tx_queue_free(sxe_tx_queue_s *txq)
{
	__sxe_tx_queue_free(txq);
}

void __rte_cold sxe_tx_queue_release(struct rte_eth_dev *dev,
					u16 queue_idx)
{
	sxe_tx_queue_free(dev->data->tx_queues[queue_idx]);
}

static void __rte_cold sxe_tx_queue_init(sxe_tx_queue_s *txq)
{
	u16 prev, i;
	volatile sxe_tx_data_desc_u *txd;
	static const sxe_tx_data_desc_u zeroed_desc = { {0} };
	struct sxe_tx_buffer *tx_buffer = txq->buffer_ring;

	for (i = 0; i < txq->ring_depth; i++)
		txq->desc_ring[i] = zeroed_desc;

	prev = txq->ring_depth - 1;
	for (i = 0; i < txq->ring_depth; i++) {
		txd = &txq->desc_ring[i];
		txd->wb.status = rte_cpu_to_le_32(SXE_TX_DESC_STAT_DD);
		tx_buffer[i].mbuf	   = NULL;
		tx_buffer[i].last_id	= i;
		tx_buffer[prev].next_id = i;
		prev = i;
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

sxe_tx_queue_s * __rte_cold sxe_tx_queue_alloc(struct rte_eth_dev *dev,
					u16 queue_idx,
					u16 ring_depth,
					u32 socket_id)
{
	sxe_tx_queue_s *txq;
	const struct rte_memzone *tz;

	if (dev->data->tx_queues[queue_idx] != NULL) {
		sxe_tx_queue_free(dev->data->tx_queues[queue_idx]);
		dev->data->tx_queues[queue_idx] = NULL;
	}

	txq = rte_zmalloc_socket("tx queue", sizeof(sxe_tx_queue_s),
				 RTE_CACHE_LINE_SIZE, socket_id);
	if (txq == NULL) {
		PMD_LOG_ERR(INIT, "tx queue[%d] alloc failed", queue_idx);
		goto l_end;
	}

	tz = rte_eth_dma_zone_reserve(dev, "tx_desc_ring", queue_idx,
			sizeof(sxe_tx_data_desc_u) * SXE_MAX_RING_DESC,
			SXE_ALIGN, socket_id);
	if (tz == NULL) {
		PMD_LOG_ERR(INIT, "tx desc ring alloc failed, queue_id=%d", queue_idx);
		rte_free(txq);
		txq = NULL;
		goto l_end;
	}

	txq->buffer_ring = rte_zmalloc_socket("tx_buffer_ring",
				sizeof(struct sxe_tx_buffer) * ring_depth,
				RTE_CACHE_LINE_SIZE, socket_id);
	if (txq->buffer_ring == NULL) {
		PMD_LOG_ERR(INIT, "tx buffer alloc failed, queue_id=%d", queue_idx);
		rte_memzone_free(tz);
		rte_free(txq);
		txq = NULL;
		goto l_end;
	}

	txq->mz = tz;
	txq->base_addr = tz->iova;
	txq->desc_ring = (sxe_tx_data_desc_u *)tz->addr;

l_end:
	return txq;
}

s32 __rte_cold sxe_tx_queue_start(struct rte_eth_dev *dev, u16 queue_id)
{
	sxe_tx_queue_s *txq = dev->data->tx_queues[queue_id];
	struct sxe_hw *hw = (&((struct sxe_adapter *)(dev->data->dev_private))->hw);

	PMD_INIT_FUNC_TRACE();

	sxe_hw_tx_ring_head_init(hw, txq->reg_idx);
	sxe_hw_tx_ring_tail_init(hw, txq->reg_idx);
	sxe_hw_tx_ring_switch(hw, txq->reg_idx, true);

	dev->data->tx_queue_state[queue_id] = RTE_ETH_QUEUE_STATE_STARTED;

	return 0;
}

s32 __rte_cold sxe_tx_queue_stop(struct rte_eth_dev *dev, u16 queue_id)
{
	s32 poll_ms = RTE_SXE_REGISTER_POLL_WAIT_10_MS;
	u32 head, tail;
	sxe_tx_queue_s *txq = dev->data->tx_queues[queue_id];
	struct sxe_hw *hw = (&((struct sxe_adapter *)(dev->data->dev_private))->hw);

	PMD_INIT_FUNC_TRACE();

	do {
		rte_delay_us(RTE_SXE_WAIT_100_US);
		sxe_hw_tx_ring_info_get(hw, txq->reg_idx, &head, &tail);

	} while (--poll_ms && (head != tail));

	if (!poll_ms) {
		PMD_LOG_ERR(INIT, "Tx Queue %d is not empty when stopping.",
				queue_id);
	}

	sxe_hw_tx_ring_switch(hw, txq->reg_idx, false);

	if (txq->ops != NULL) {
		txq->ops->mbufs_release(txq);
		txq->ops->init(txq);
	}
	dev->data->tx_queue_state[queue_id] = RTE_ETH_QUEUE_STATE_STOPPED;
	return 0;
}

void sxe_rx_queue_info_get(struct rte_eth_dev *dev, u16 queue_id,
	struct rte_eth_rxq_info *qinfo)
{
	__sxe_rx_queue_info_get(dev, queue_id, qinfo);
}

s32 __rte_cold sxe_rx_queue_mbufs_alloc(struct sxe_rx_queue *rxq)
{
	return __sxe_rx_queue_mbufs_alloc(rxq);
}

s32 __rte_cold sxe_rx_queue_start(struct rte_eth_dev *dev,
						u16 queue_id)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw	  *hw = &adapter->hw;
	struct sxe_rx_queue *rxq;
	u16 reg_idx;
	s32 ret;

	PMD_INIT_FUNC_TRACE();

	rxq = dev->data->rx_queues[queue_id];
	reg_idx = rxq->reg_idx;

	ret = sxe_rx_queue_mbufs_alloc(rxq);
	if (ret) {
		PMD_LOG_ERR(INIT, "could not alloc mbuf for queue:%d",
				 queue_id);
		goto l_end;
	}

	sxe_hw_rx_ring_switch(hw, reg_idx, true);

	sxe_hw_rx_queue_desc_reg_configure(hw, reg_idx, 0, rxq->ring_depth - 1);
	dev->data->rx_queue_state[queue_id] = RTE_ETH_QUEUE_STATE_STARTED;

l_end:
	return ret;
}

static void __rte_cold sxe_rx_queue_sc_mbufs_free(struct rte_mbuf *mbuf)
{
	u16 i;
	u16 num_segs = mbuf->nb_segs;
	struct rte_mbuf *next_seg;

	for (i = 0; i < num_segs; i++) {
		next_seg = mbuf->next;
		rte_pktmbuf_free_seg(mbuf);
		mbuf = next_seg;
	}
}

void __rte_cold sxe_rx_queue_mbufs_free(struct sxe_rx_queue *rxq)
{
	u16 i;

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SIMD
	if (rxq->is_using_sse) {
		sxe_rx_queue_vec_mbufs_release(rxq);
		return;
	}
#endif

	if (rxq->buffer_ring != NULL) {
		for (i = 0; i < rxq->ring_depth; i++) {
			if (rxq->buffer_ring[i].mbuf != NULL) {
				rte_pktmbuf_free_seg(rxq->buffer_ring[i].mbuf);
				rxq->buffer_ring[i].mbuf = NULL;
			}
		}
		if (rxq->completed_pkts_num) {
			for (i = 0; i < rxq->completed_pkts_num; ++i) {
				struct rte_mbuf *mbuf;

				mbuf = rxq->completed_ring[rxq->next_ret_pkg + i];
				rte_pktmbuf_free_seg(mbuf);
			}
			rxq->completed_pkts_num = 0;
		}
	}

	if (rxq->sc_buffer_ring) {
		for (i = 0; i < rxq->ring_depth; i++) {
			if (rxq->sc_buffer_ring[i].mbuf) {
				sxe_rx_queue_sc_mbufs_free(rxq->sc_buffer_ring[i].mbuf);
				rxq->sc_buffer_ring[i].mbuf = NULL;
			}
		}
	}
}

void __rte_cold sxe_rx_queue_init(bool rx_batch_alloc_allowed,
						struct sxe_rx_queue *rxq)
{
	static const sxe_rx_data_desc_u zeroed_desc = { {0} };
	u16 i;
	u16 len = rxq->ring_depth;

	if (rx_batch_alloc_allowed)
		len += RTE_PMD_SXE_MAX_RX_BURST;

	for (i = 0; i < len; i++)
		rxq->desc_ring[i] = zeroed_desc;

	memset(&rxq->fake_mbuf, 0, sizeof(rxq->fake_mbuf));
	for (i = rxq->ring_depth; i < len; ++i)
		rxq->buffer_ring[i].mbuf = &rxq->fake_mbuf;

	rxq->completed_pkts_num = 0;
	rxq->next_ret_pkg = 0;
	rxq->batch_alloc_trigger = rxq->batch_alloc_size - 1;
	rxq->processing_idx = 0;
	rxq->hold_num = 0;

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SIMD
	if (rxq->pkt_first_seg != NULL)
		rte_pktmbuf_free(rxq->pkt_first_seg);

	rxq->pkt_first_seg = NULL;
	rxq->pkt_last_seg = NULL;

#if defined(RTE_ARCH_X86)
	rxq->realloc_start = 0;
	rxq->realloc_num = 0;
#endif
#endif
}

void __rte_cold sxe_rx_queue_free(struct sxe_rx_queue *rxq)
{
	__sxe_rx_queue_free(rxq);
}

void __rte_cold sxe_rx_queue_release(struct rte_eth_dev *dev,
					u16 queue_idx)
{
	sxe_rx_queue_free(dev->data->rx_queues[queue_idx]);
}

s32 __rte_cold sxe_rx_queue_stop(struct rte_eth_dev *dev, u16 queue_id)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw	 *hw = &adapter->hw;
	struct sxe_rx_queue *rxq;
	u16 reg_idx;

	PMD_INIT_FUNC_TRACE();

	rxq = dev->data->rx_queues[queue_id];
	reg_idx = rxq->reg_idx;

	sxe_hw_rx_ring_switch(hw, reg_idx, false);

	rte_delay_us(RTE_SXE_WAIT_100_US);

	sxe_rx_queue_mbufs_free(rxq);
	sxe_rx_queue_init(adapter->rx_batch_alloc_allowed, rxq);
	dev->data->rx_queue_state[queue_id] = RTE_ETH_QUEUE_STATE_STOPPED;

	return 0;
}

int sxe_rx_queue_count(void *rx_queue)
{
	volatile sxe_rx_data_desc_u *desc;
	struct sxe_rx_queue *rxq;
	u32 count = 0;

	rxq = rx_queue;

	desc = &rxq->desc_ring[rxq->processing_idx];

	while ((count < rxq->ring_depth) &&
		(desc->wb.upper.status_error &
			rte_cpu_to_le_32(SXE_RXDADV_STAT_DD))) {
		count += SXE_RXQ_SCAN_INTERVAL;
		desc  += SXE_RXQ_SCAN_INTERVAL;
		if (rxq->processing_idx + count >= rxq->ring_depth) {
			desc = &(rxq->desc_ring[rxq->processing_idx +
				count - rxq->ring_depth]);
		}
	}

	return count;
}

void __rte_cold sxe_txrx_queues_clear(struct rte_eth_dev *dev, bool rx_batch_alloc_allowed)
{
	__sxe_txrx_queues_clear(dev, rx_batch_alloc_allowed);
}

void sxe_queues_free(struct rte_eth_dev *dev)
{
	__sxe_queues_free(dev);
}

const struct sxe_txq_ops sxe_def_txq_ops = {
	.init			 = sxe_tx_queue_init,
	.mbufs_release	= sxe_tx_queue_mbufs_release,
	.buffer_ring_free = sxe_tx_buffer_ring_free,
};

const struct sxe_txq_ops *sxe_tx_default_ops_get(void)
{
	return &sxe_def_txq_ops;
}

void sxe_multi_queue_tx_configure(struct rte_eth_dev *dev)
{
	struct sxe_hw *hw = (&((struct sxe_adapter *)(dev->data->dev_private))->hw);
	u16 pools_num = RTE_ETH_DEV_SRIOV(dev).active;
	bool sriov_active = !!pools_num;
	bool vmdq_active = (dev->data->dev_conf.txmode.mq_mode ==
				RTE_ETH_MQ_TX_VMDQ_ONLY);

	sxe_hw_tx_multi_queue_configure(hw, vmdq_active, sriov_active, pools_num);
}


s32 sxe_queue_rate_limit_set(struct rte_eth_dev *dev,
					u16 queue_idx, u32 tx_rate)
{
	int ret = 0;
	u32 rf_dec, rf_int, bcnrc_val;
	u16 link_speed = dev->data->dev_link.link_speed;
	struct sxe_adapter *adapter = (struct sxe_adapter *)(dev->data->dev_private);
	struct sxe_hw *hw = &adapter->hw;

	if (queue_idx >= SXE_HW_TXRX_RING_NUM_MAX) {
		ret = -EINVAL;
		goto l_end;
	}

	if (tx_rate != 0) {
		rf_int = (u32)link_speed / (u32)tx_rate;
		rf_dec = (u32)link_speed % (u32)tx_rate;
		rf_dec = (rf_dec << SXE_RTTBCNRC_RF_INT_SHIFT) / tx_rate;

		bcnrc_val = SXE_RTTBCNRC_RS_ENA;
		bcnrc_val |= ((rf_int << SXE_RTTBCNRC_RF_INT_SHIFT) &
				SXE_RTTBCNRC_RF_INT_MASK);
		bcnrc_val |= (rf_dec & SXE_RTTBCNRC_RF_DEC_MASK);
	} else {
		bcnrc_val = 0;
	}

	if (dev->data->mtu + SXE_ETH_OVERHEAD >= SXE_MAX_JUMBO_FRAME_SIZE) {
		sxe_hw_dcb_max_mem_window_set(hw,
						SXE_MMW_SIZE_JUMBO_FRAME);
	} else {
		sxe_hw_dcb_max_mem_window_set(hw, SXE_MMW_SIZE_DEFAULT);
	}

	sxe_hw_dcb_tx_ring_rate_factor_set(hw, queue_idx, bcnrc_val);

l_end:
	return ret;
}

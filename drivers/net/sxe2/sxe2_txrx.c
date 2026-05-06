/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2025, Wuxi Stars Micro System Technologies Co., Ltd.
 */

#include <rte_common.h>
#include <rte_net.h>
#include <rte_vect.h>
#include <rte_malloc.h>
#include <rte_memzone.h>
#include <ethdev_driver.h>
#include <unistd.h>
#include "sxe2_txrx.h"
#include "sxe2_txrx_common.h"
#include "sxe2_txrx_vec.h"
#include "sxe2_txrx_poll.h"
#include "sxe2_ethdev.h"
#include "sxe2_common_log.h"
#include "sxe2_errno.h"
#include "sxe2_osal.h"
#include "sxe2_cmd_chnl.h"
#if defined(RTE_ARCH_ARM64)
#include <rte_cpuflags.h>
#endif
s32 __rte_cold
sxe2_tx_simple_batch_support_check(struct rte_eth_dev *dev,
		u32 *batch_flags)
{
	struct sxe2_tx_queue *txq;
	s32 ret = SXE2_SUCCESS;
	u16 i;
	for (i = 0; i < dev->data->nb_tx_queues; ++i) {
		txq = (struct sxe2_tx_queue *)dev->data->tx_queues[i];
		if (txq == NULL) {
			ret = SXE2_ERR_INVAL;
			goto l_end;
		}
		if (txq->offloads != (txq->offloads & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) ||
		     txq->rs_thresh < SXE2_TX_PKTS_BURST_BATCH_NUM) {
			ret = SXE2_ERR_NOTSUP;
			goto l_end;
		}
	}
	*batch_flags = SXE2_TX_MODE_SIMPLE_BATCH;
l_end:
	return ret;
}
static s32 sxe2_tx_desciptor_status(void *tx_queue, u16 offset)
{
	struct sxe2_tx_queue *txq = (struct sxe2_tx_queue *)tx_queue;
	s32 ret;
	u16 desc_idx;
	if (unlikely(offset >= txq->ring_depth)) {
		ret = SXE2_ERR_INVAL;
		goto l_end;
	}
	desc_idx = txq->next_use + offset;
	desc_idx = DIV_ROUND_UP(desc_idx, txq->rs_thresh) * (txq->rs_thresh);
	if (desc_idx >= txq->ring_depth) {
		desc_idx -= txq->ring_depth;
		if (desc_idx >= txq->ring_depth)
			desc_idx -= txq->ring_depth;
	}
	if (desc_idx == 0)
		desc_idx = txq->rs_thresh - 1;
	else
		desc_idx -= 1;
	if (rte_cpu_to_le_64(SXE2_TX_DESC_DTYPE_DESC_DONE) ==
		(txq->desc_ring[desc_idx].wb.dd &
		rte_cpu_to_le_64(SXE2_TX_DESC_DTYPE_DESC_MASK)))
		ret = RTE_ETH_TX_DESC_DONE;
	else
		ret = RTE_ETH_TX_DESC_FULL;
l_end:
	return ret;
}

static inline s32 sxe2_tx_mbuf_empty_check(struct rte_mbuf *mbuf)
{
	struct rte_mbuf *m_seg = mbuf;
	while (m_seg != NULL) {
		if (m_seg->data_len == 0)
			return SXE2_ERR_INVAL;
		m_seg = m_seg->next;
	}
	return SXE2_SUCCESS;
}

u16 sxe2_tx_pkts_prepare(__rte_unused void *tx_queue,
		struct rte_mbuf **tx_pkts, u16 nb_pkts)
{
	struct sxe2_tx_queue *txq = tx_queue;
	struct rte_mbuf *mbuf;
	u64 ol_flags = 0;
	s32 ret = SXE2_SUCCESS;
	s32 i = 0;
	for (i = 0; i < nb_pkts; i++) {
		mbuf = tx_pkts[i];
		if (!mbuf)
			continue;
		ol_flags = mbuf->ol_flags;
		if (!(ol_flags & (RTE_MBUF_F_TX_TCP_SEG | RTE_MBUF_F_TX_UDP_SEG))) {
			if (mbuf->nb_segs > SXE2_TX_MTU_SEG_MAX ||
					mbuf->pkt_len > SXE2_FRAME_SIZE_MAX) {
				rte_errno = -SXE2_ERR_INVAL;
				goto l_end;
			}
		} else if ((mbuf->tso_segsz < SXE2_MIN_TSO_MSS) ||
			(mbuf->tso_segsz > SXE2_MAX_TSO_MSS) ||
			(mbuf->nb_segs   > txq->ring_depth) ||
			(mbuf->pkt_len > SXE2_TX_TSO_PKTLEN_MAX)) {
			rte_errno = -SXE2_ERR_INVAL;
			goto l_end;
		}
		if (mbuf->pkt_len < SXE2_TX_MIN_PKT_LEN) {
			rte_errno = -SXE2_ERR_INVAL;
			goto l_end;
		}
#ifdef RTE_ETHDEV_DEBUG_TX
		ret = rte_validate_tx_offload(mbuf);
		if (ret != SXE2_SUCCESS) {
			rte_errno = -ret;
			goto l_end;
		}
#endif
		ret = rte_net_intel_cksum_prepare(mbuf);
		if (ret != SXE2_SUCCESS) {
			rte_errno = -ret;
			goto l_end;
		}
		ret = sxe2_tx_mbuf_empty_check(mbuf);
		if (ret != SXE2_SUCCESS) {
			rte_errno = -ret;
			goto l_end;
		}
	}
l_end:
	return i;
}

void sxe2_tx_mode_func_set(struct rte_eth_dev *dev)
{
	struct sxe2_adapter *adapter = SXE2_DEV_PRIVATE_TO_ADAPTER(dev);
	u32 tx_mode_flags = 0;
	s32 ret;
	u32 vec_flags;
	u32 batch_flags;
	RTE_SET_USED(vec_flags);
	PMD_INIT_FUNC_TRACE();
	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		ret = sxe2_tx_vec_support_check(dev, &vec_flags);
		if (ret == SXE2_SUCCESS &&
				(rte_vect_get_max_simd_bitwidth() >= RTE_VECT_SIMD_128)) {
#ifdef RTE_ARCH_X86
			if ((rte_vect_get_max_simd_bitwidth() >= RTE_VECT_SIMD_512) &&
					(rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX512F) == 1) &&
					(rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX512BW) == 1)) {
#ifdef CC_AVX512_SUPPORT
				tx_mode_flags |= (vec_flags | SXE2_TX_MODE_VEC_AVX512);
#else
				PMD_LOG_INFO(TX, "AVX512 is not supported in build env.");
#endif
			}
			if ((0 == (tx_mode_flags & SXE2_TX_MODE_VEC_SET_MASK)) &&
					((rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX2) == 1) ||
					(rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX512F) == 1)) &&
					(rte_vect_get_max_simd_bitwidth() >= RTE_VECT_SIMD_256)) {
				tx_mode_flags |= (vec_flags | SXE2_TX_MODE_VEC_AVX2);
			}
			if ((0 == (tx_mode_flags & SXE2_TX_MODE_VEC_SET_MASK)))
				tx_mode_flags |= (vec_flags | SXE2_TX_MODE_VEC_SSE);
#endif
			if (tx_mode_flags & SXE2_TX_MODE_VEC_SET_MASK) {
				ret = sxe2_tx_queues_vec_prepare(dev);
				if (ret != SXE2_SUCCESS)
					tx_mode_flags &= (~SXE2_TX_MODE_VEC_SET_MASK);
			}
		}
		ret = sxe2_tx_simple_batch_support_check(dev, &batch_flags);
		if (ret == SXE2_SUCCESS && batch_flags == SXE2_TX_MODE_SIMPLE_BATCH)
			tx_mode_flags |= SXE2_TX_MODE_SIMPLE_BATCH;
	}
	if (tx_mode_flags & SXE2_TX_MODE_VEC_SET_MASK) {
		dev->tx_pkt_prepare = NULL;
#ifdef RTE_ARCH_X86
		if (tx_mode_flags & SXE2_TX_MODE_VEC_OFFLOAD) {
			dev->tx_pkt_prepare = sxe2_tx_pkts_prepare;
			dev->tx_pkt_burst = sxe2_tx_pkts_vec_sse;
		} else {
			dev->tx_pkt_burst = sxe2_tx_pkts_vec_sse_simple;
		}
#endif
	} else {
		if (tx_mode_flags & SXE2_TX_MODE_SIMPLE_BATCH) {
			dev->tx_pkt_prepare = NULL;
			dev->tx_pkt_burst = sxe2_tx_pkts_simple;
		} else {
			dev->tx_pkt_prepare = sxe2_tx_pkts_prepare;
			dev->tx_pkt_burst = sxe2_tx_pkts;
		}
	}
	adapter->q_ctxt.tx_mode_flags = tx_mode_flags;
	PMD_LOG_DEBUG(TX, "Tx mode flags:0x%016x port_id:%u.",
				tx_mode_flags, dev->data->port_id);
}

static const struct {
	eth_tx_burst_t tx_burst;
	const char *info;
} sxe2_tx_burst_infos[] = {
	{ sxe2_tx_pkts,   "Scalar" },
#ifdef RTE_ARCH_X86
	{ sxe2_tx_pkts_vec_sse,        "Vector SSE" },
	{ sxe2_tx_pkts_vec_sse_simple, "Vector SSE Simple" },
#endif
};

s32 sxe2_tx_burst_mode_get(struct rte_eth_dev *dev,
		__rte_unused uint16_t queue_id, struct rte_eth_burst_mode *mode)
{
	eth_tx_burst_t pkt_burst = dev->tx_pkt_burst;
	s32 ret = SXE2_ERR_INVAL;
	u32 i;
	u32 size;
	size = RTE_DIM(sxe2_tx_burst_infos);
	for (i = 0; i < size; ++i) {
		if (pkt_burst == sxe2_tx_burst_infos[i].tx_burst) {
			snprintf(mode->info, sizeof(mode->info), "%s",
					sxe2_tx_burst_infos[i].info);
			ret = SXE2_SUCCESS;
			break;
		}
	}
	return ret;
}

static s32 sxe2_rx_desciptor_status(void *rx_queue, u16 offset)
{
	struct sxe2_rx_queue *rxq = (struct sxe2_rx_queue *)rx_queue;
	volatile union sxe2_rx_desc *desc;
	s32 ret;
	if (unlikely(offset >= rxq->ring_depth)) {
		ret = SXE2_ERR_INVAL;
		goto l_end;
	}
	if (offset >= rxq->ring_depth - rxq->hold_num) {
		ret = RTE_ETH_RX_DESC_UNAVAIL;
		goto l_end;
	}
	if (rxq->processing_idx + offset >= rxq->ring_depth)
		desc = &rxq->desc_ring[rxq->processing_idx + offset - rxq->ring_depth];
	else
		desc = &rxq->desc_ring[rxq->processing_idx + offset];
	if (rte_le_to_cpu_64(desc->wb.status_err_ptype_len) & SXE2_RX_DESC_STATUS_DD_MASK)
		ret = RTE_ETH_RX_DESC_DONE;
	else
		ret = RTE_ETH_RX_DESC_AVAIL;
l_end:
	PMD_LOG_DEBUG(RX, "Rx queue desc[%u] status:%d queue_id:%u port_id:%u",
				offset, ret, rxq->queue_id, rxq->port_id);
	return ret;
}

static s32 sxe2_rx_queue_count(void *rx_queue)
{
	struct sxe2_rx_queue *rxq = (struct sxe2_rx_queue *)rx_queue;
	volatile union sxe2_rx_desc *desc;
	u16 done_num = 0;
	desc = &rxq->desc_ring[rxq->processing_idx];
	while ((done_num < rxq->ring_depth) &&
		(rte_le_to_cpu_64(desc->wb.status_err_ptype_len) &
		SXE2_RX_DESC_STATUS_DD_MASK)) {
		done_num += SXE2_RX_QUEUE_CHECK_INTERVAL_NUM;
		if (rxq->processing_idx + done_num >= rxq->ring_depth)
			desc = &rxq->desc_ring[rxq->processing_idx + done_num - rxq->ring_depth];
		else
			desc += SXE2_RX_QUEUE_CHECK_INTERVAL_NUM;
	}
	PMD_LOG_DEBUG(RX, "Rx queue done desc count:%u queue_id:%u port_id:%u",
				done_num, rxq->queue_id, rxq->port_id);
	return done_num;
}

void sxe2_rx_mode_func_set(struct rte_eth_dev *dev)
{
	struct sxe2_adapter *adapter = SXE2_DEV_PRIVATE_TO_ADAPTER(dev);
	u32 rx_mode_flags = 0;
	s32 ret;
	u32 vec_flags;

	PMD_INIT_FUNC_TRACE();
	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		ret = sxe2_rx_vec_support_check(dev, &vec_flags);
		if (ret == SXE2_SUCCESS &&
			 rte_vect_get_max_simd_bitwidth() >= RTE_VECT_SIMD_128) {
#ifdef RTE_ARCH_X86
			if (((rx_mode_flags & SXE2_RX_MODE_VEC_SET_MASK) == 0) &&
				((rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX2) == 1) ||
				(rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX512F) == 1)) &&
				(rte_vect_get_max_simd_bitwidth() >= RTE_VECT_SIMD_256)) {
				rx_mode_flags |= (vec_flags | SXE2_RX_MODE_VEC_AVX2);
			}
			if (((rx_mode_flags & SXE2_RX_MODE_VEC_SET_MASK) == 0) &&
				rte_vect_get_max_simd_bitwidth() >= RTE_VECT_SIMD_128) {
				rx_mode_flags |= (vec_flags | SXE2_RX_MODE_VEC_SSE);
			}
#endif
			if ((rx_mode_flags & SXE2_RX_MODE_VEC_SET_MASK) != 0) {
				ret = sxe2_rx_queues_vec_prepare(dev);
				if (ret != SXE2_SUCCESS)
					rx_mode_flags &= (~SXE2_RX_MODE_VEC_SET_MASK);
			}
		}
	}
#ifdef RTE_ARCH_X86
	if (rx_mode_flags & SXE2_RX_MODE_VEC_SET_MASK)
		dev->rx_pkt_burst = sxe2_rx_pkts_scattered_vec_sse_offload;
#endif
	if (sxe2_rx_offload_en_check(dev, RTE_ETH_RX_OFFLOAD_BUFFER_SPLIT))
		dev->rx_pkt_burst = sxe2_rx_pkts_scattered_split;
	else
		dev->rx_pkt_burst = sxe2_rx_pkts_scattered;
	goto l_end;
l_end:
	PMD_LOG_DEBUG(RX, "Rx mode flags:0x%016x port_id:%u.",
				rx_mode_flags, dev->data->port_id);
	adapter->q_ctxt.rx_mode_flags = rx_mode_flags;
}

static const struct {
	eth_rx_burst_t rx_burst;
	const char *info;
} sxe2_rx_burst_infos[] = {
	{ sxe2_rx_pkts_scattered,          "Scalar Scattered" },
	{ sxe2_rx_pkts_scattered_split,          "Scalar Scattered split" },
#ifdef RTE_ARCH_X86
	{ sxe2_rx_pkts_scattered_vec_sse_offload,      "Vector SSE Scattered" },
#endif
};

s32 sxe2_rx_burst_mode_get(struct rte_eth_dev *dev,
			__rte_unused u16 queue_id, struct rte_eth_burst_mode *mode)
{
	eth_rx_burst_t pkt_burst = dev->rx_pkt_burst;
	s32 ret = SXE2_ERR_INVAL;
	u32 i, size;
	size = RTE_DIM(sxe2_rx_burst_infos);
	for (i = 0; i < size; ++i) {
		if (pkt_burst == sxe2_rx_burst_infos[i].rx_burst) {
			snprintf(mode->info, sizeof(mode->info), "%s",
				 sxe2_rx_burst_infos[i].info);
			ret = SXE2_SUCCESS;
			break;
		}
	}
	return ret;
}

void sxe2_set_common_function(struct rte_eth_dev *dev)
{
	PMD_INIT_FUNC_TRACE();
	dev->rx_queue_count = sxe2_rx_queue_count;
	dev->rx_descriptor_status = sxe2_rx_desciptor_status;
	dev->rx_pkt_burst = sxe2_rx_pkts_scattered;
	dev->tx_descriptor_status = sxe2_tx_desciptor_status;
	dev->tx_pkt_prepare = sxe2_tx_pkts_prepare;
	dev->tx_pkt_burst = sxe2_tx_pkts;
}

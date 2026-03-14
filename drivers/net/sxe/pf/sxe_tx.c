/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */
#include <ethdev_driver.h>
#include <dev_driver.h>
#include <rte_net.h>
#include "sxe.h"
#include "sxe_tx.h"
#include "sxe_hw.h"
#include "sxe_logs.h"
#include "sxe_queue_common.h"
#include "sxe_tx_common.h"
#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SIMD
#include "sxe_vec_common.h"
#include <rte_vect.h>
#endif
#include "sxe_compat_version.h"

#define SXE_TX_DESC_NO_WB 1

#define SXE_TX_OFFLOAD_NOTSUP_MASK (RTE_MBUF_F_TX_OFFLOAD_MASK ^ SXE_TX_OFFLOAD_MASK)
#define RTE_SXE_MAX_TX_FREE_BUF_SZ 64
#define SXE_TXD_IDX_SHIFT	4
#define SXE_TX_MIN_PKT_LEN	14

void __rte_cold sxe_tx_function_set(struct rte_eth_dev *dev,
					sxe_tx_queue_s *txq)
{
	/* Offload off and signle simple tx code path < 32 use simple tx code path */
	if (txq->offloads == 0 &&
		txq->rs_thresh >= RTE_PMD_SXE_MAX_TX_BURST) {
		dev->tx_pkt_prepare = NULL;
#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SIMD
		if (txq->rs_thresh <= RTE_SXE_MAX_TX_FREE_BUF_SZ &&
			(rte_eal_process_type() != RTE_PROC_PRIMARY ||
			sxe_txq_vec_setup(txq) == 0)) {

#if defined(RTE_ARCH_X86) || defined(RTE_ARCH_ARM)
			dev->recycle_tx_mbufs_reuse = sxe_recycle_tx_mbufs_reuse_vec;
#endif
			dev->tx_pkt_burst   = sxe_pkts_vector_xmit;
			PMD_LOG_INFO(INIT, "using vector tx code path");
		} else {
			dev->tx_pkt_burst   = sxe_pkts_simple_xmit;
			PMD_LOG_INFO(INIT, "using simple tx code path");
		}
#else
		dev->tx_pkt_burst	= sxe_pkts_simple_xmit;
		PMD_LOG_INFO(INIT, "using simple tx code path");
#endif

	} else {
		dev->tx_pkt_burst   = sxe_pkts_xmit_with_offload;
		dev->tx_pkt_prepare = sxe_prep_pkts;

		PMD_LOG_INFO(INIT, "using full-featured tx code path");
		PMD_LOG_INFO(INIT, " - offloads = 0x%" SXE_PRIX64,
					(unsigned long)txq->offloads);
		PMD_LOG_INFO(INIT, " - tx_rs_thresh = %d "
				   "[RTE_PMD_SXE_MAX_TX_BURST=%d]",
				txq->rs_thresh,
				RTE_PMD_SXE_MAX_TX_BURST);
	}
}

int __rte_cold sxe_tx_queue_setup(struct rte_eth_dev *dev,
				u16 tx_queue_id,
				u16 ring_depth,
				u32 socket_id,
				const struct rte_eth_txconf *tx_conf)
{
	s32 ret;
	struct sxe_hw *hw = (&((struct sxe_adapter *)(dev->data->dev_private))->hw);
	struct tx_setup tx_setup;

	tx_setup.dev = dev;
	tx_setup.desc_num = ring_depth;
	tx_setup.queue_idx = tx_queue_id;
	tx_setup.socket_id = socket_id;
	tx_setup.reg_base_addr = hw->reg_base_addr;
	tx_setup.tx_conf = tx_conf;

	ret = __sxe_tx_queue_setup(&tx_setup, false);

	return ret;
}

static void __rte_cold sxe_tx_start(struct rte_eth_dev *dev)
{
	u32 i;
	sxe_tx_queue_s *txq;
	struct sxe_hw *hw = (&((struct sxe_adapter *)(dev->data->dev_private))->hw);

	PMD_INIT_FUNC_TRACE();

	sxe_hw_tx_enable(hw);

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		txq = dev->data->tx_queues[i];
		sxe_hw_tx_desc_thresh_set(hw, txq->reg_idx,
				txq->wthresh, txq->hthresh, txq->pthresh);
		if (!txq->tx_deferred_start)
			sxe_tx_queue_start(dev, i);
	}
}

static void sxe_tx_buf_configure(struct sxe_hw *hw)
{
	sxe_hw_tx_pkt_buf_switch(hw, false);

	sxe_hw_tx_pkt_buf_size_configure(hw, 0);

	sxe_hw_tx_pkt_buf_thresh_configure(hw, 0, false);

	sxe_hw_tx_pkt_buf_switch(hw, true);

	sxe_hw_mac_pad_enable(hw);
}

void __rte_cold sxe_tx_configure(struct rte_eth_dev *dev)
{
	u16 i;
	u64 queue_dma_addr;
	u32 ring_size;
	sxe_tx_queue_s *txq;
	struct sxe_hw *hw = (&((struct sxe_adapter *)(dev->data->dev_private))->hw);

	PMD_INIT_FUNC_TRACE();

	sxe_multi_queue_tx_configure(dev);

	sxe_tx_buf_configure(hw);

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		txq = dev->data->tx_queues[i];
		queue_dma_addr = txq->base_addr;
		ring_size = txq->ring_depth * sizeof(sxe_tx_data_desc_u);

		sxe_hw_tx_ring_desc_configure(hw, ring_size, queue_dma_addr,
						txq->reg_idx);
	}

	sxe_tx_start(dev);
}

static inline void sxe_single_desc_fill(volatile sxe_tx_data_desc_u *desc,
				struct rte_mbuf **pkts)
{
	u32 pkt_len;
	u64 buf_dma_addr;

	buf_dma_addr = rte_mbuf_data_iova(*pkts);
	pkt_len = (*pkts)->data_len;

	desc->read.buffer_addr = rte_cpu_to_le_64(buf_dma_addr);
	desc->read.cmd_type_len =
			rte_cpu_to_le_32((u32)SXE_TX_DESC_FLAGS | pkt_len);
	desc->read.olinfo_status =
			rte_cpu_to_le_32(pkt_len << SXE_TX_DESC_PAYLEN_SHIFT);
	rte_sxe_prefetch(&(*pkts)->pool);
}

#define TX4_PER_LOOP 4
#define TX4_PER_LOOP_MASK (TX4_PER_LOOP - 1)

static inline void sxe_four_desc_fill(volatile sxe_tx_data_desc_u *desc,
			struct rte_mbuf **pkts)
{
	s32 i;
	u64 buf_dma_addr;
	u32 pkt_len;

	for (i = 0; i < TX4_PER_LOOP; ++i, ++desc, ++pkts) {
		buf_dma_addr = rte_mbuf_data_iova(*pkts);
		pkt_len = (*pkts)->data_len;

		desc->read.buffer_addr = rte_cpu_to_le_64(buf_dma_addr);

		desc->read.cmd_type_len =
			rte_cpu_to_le_32((u32)SXE_TX_DESC_FLAGS | pkt_len);

		desc->read.olinfo_status =
			rte_cpu_to_le_32(pkt_len << SXE_TX_DESC_PAYLEN_SHIFT);

		rte_sxe_prefetch(&(*pkts)->pool);
	}
}

static inline void sxe_tx_ring_fill(sxe_tx_queue_s *txq,
				struct rte_mbuf **pkts, u16 pkts_num)
{
	u32 i, j, mainpart, leftover;
	volatile sxe_tx_data_desc_u *desc =
					&txq->desc_ring[txq->next_to_use];
	struct sxe_tx_buffer *buffer = &txq->buffer_ring[txq->next_to_use];

	mainpart = (pkts_num & ((u32)(~TX4_PER_LOOP_MASK)));
	leftover = (pkts_num & ((u32)(TX4_PER_LOOP_MASK)));

	for (i = 0; i < mainpart; i += TX4_PER_LOOP) {
		for (j = 0; j < TX4_PER_LOOP; ++j)
			(buffer + i + j)->mbuf = *(pkts + i + j);
		sxe_four_desc_fill(desc + i, pkts + i);
	}

	if (unlikely(leftover > 0)) {
		for (i = 0; i < leftover; ++i) {
			(buffer + mainpart + i)->mbuf = *(pkts + mainpart + i);
			sxe_single_desc_fill(desc + mainpart + i,
						pkts + mainpart + i);
		}
	}
}

s32 sxe_tx_bufs_free(sxe_tx_queue_s *txq)
{
	s32 ret = 0;
	u32 status;
	s32 i, mbuf_free_num = 0;
	struct sxe_tx_buffer *buffer;
	struct rte_mbuf *mbuf, *free_mbuf[RTE_SXE_MAX_TX_FREE_BUF_SZ];

	status = txq->desc_ring[txq->next_dd].wb.status;
	if (!(status & rte_cpu_to_le_32(SXE_TX_DESC_STAT_DD))) {
		ret = 0;
		goto l_end;
	}

	buffer = &txq->buffer_ring[txq->next_dd - txq->rs_thresh - 1];

	for (i = 0; i < txq->rs_thresh; ++i, ++buffer) {
		mbuf = rte_pktmbuf_prefree_seg(buffer->mbuf);
		buffer->mbuf = NULL;

		if (unlikely(mbuf == NULL))
			continue;

		if (mbuf_free_num >= RTE_SXE_MAX_TX_FREE_BUF_SZ ||
			(mbuf_free_num > 0 && mbuf->pool != free_mbuf[0]->pool)) {
			rte_mempool_put_bulk(free_mbuf[0]->pool,
						 (void **)free_mbuf, mbuf_free_num);
			mbuf_free_num = 0;
		}

		free_mbuf[mbuf_free_num++] = mbuf;
	}

	if (mbuf_free_num > 0) {
		rte_mempool_put_bulk(free_mbuf[0]->pool,
					(void **)free_mbuf, mbuf_free_num);
	}

	txq->next_dd	   += txq->rs_thresh;
	txq->desc_free_num += txq->rs_thresh;
	if (txq->next_dd >= txq->ring_depth)
		txq->next_dd = txq->rs_thresh - 1;

	ret = txq->rs_thresh;

l_end:
	return ret;
}

static inline u16 sxe_pkts_xmit(void *tx_queue,
			struct rte_mbuf **tx_pkts, u16 xmit_pkts_num)
{
	u16 n = 0;
	sxe_tx_queue_s *txq = (sxe_tx_queue_s *)tx_queue;
	volatile sxe_tx_data_desc_u *desc_ring = txq->desc_ring;

	if (txq->desc_free_num < txq->free_thresh)
		sxe_tx_bufs_free(txq);

	xmit_pkts_num = (u16)RTE_MIN(txq->desc_free_num, xmit_pkts_num);
	if (unlikely(xmit_pkts_num == 0)) {
		LOG_DEBUG("simple xmit: not enough free desc, "
			"free_desc=%u, need_xmit_pkts=%u",
			txq->desc_free_num, xmit_pkts_num);
		goto l_end;
	}

	txq->desc_free_num -= xmit_pkts_num;

	if ((txq->next_to_use + xmit_pkts_num) > txq->ring_depth) {
		n = txq->ring_depth - txq->next_to_use;

		sxe_tx_ring_fill(txq, tx_pkts, n);

		desc_ring[txq->next_rs].read.cmd_type_len |=
			rte_cpu_to_le_32(SXE_TX_DESC_RS_MASK);
		txq->next_rs = (u16)(txq->rs_thresh - 1);

		txq->next_to_use = 0;
	}

	sxe_tx_ring_fill(txq, tx_pkts + n, (u16)(xmit_pkts_num - n));
	txq->next_to_use = (u16)(txq->next_to_use + (xmit_pkts_num - n));

	if (txq->next_to_use > txq->next_rs) {
		desc_ring[txq->next_rs].read.cmd_type_len |=
			rte_cpu_to_le_32(SXE_TX_DESC_RS_MASK);
		txq->next_rs = (u16)(txq->next_rs + txq->rs_thresh);
		if (txq->next_rs >= txq->ring_depth)
			txq->next_rs = (u16)(txq->rs_thresh - 1);
	}

	if (txq->next_to_use >= txq->ring_depth)
		txq->next_to_use = 0;

	rte_wmb();
	rte_write32_wc_relaxed((rte_cpu_to_le_32(txq->next_to_use)),
							txq->tdt_reg_addr);

l_end:
	return xmit_pkts_num;
}

u16 sxe_pkts_simple_xmit(void *tx_queue, struct rte_mbuf **tx_pkts, u16 pkts_num)
{
	sxe_tx_queue_s *queue = tx_queue;
	u16 ret, xmit_pkts_num, need_xmit_pkts;
	UNUSED(queue);

	if (likely(pkts_num <= RTE_PMD_SXE_MAX_TX_BURST)) {
		xmit_pkts_num = sxe_pkts_xmit(tx_queue, tx_pkts, pkts_num);
		goto l_end;
	}

	/* When pkts_num > 32, it needs to besent in a loop */
	xmit_pkts_num = 0;
	while (pkts_num) {
		need_xmit_pkts = (u16)RTE_MIN(pkts_num, RTE_PMD_SXE_MAX_TX_BURST);

		/* Signle transmit */
		ret = sxe_pkts_xmit(tx_queue, &tx_pkts[xmit_pkts_num],
							need_xmit_pkts);

		pkts_num	  -= ret;
		xmit_pkts_num += ret;

		/* Don't have enough desc */
		if (ret < need_xmit_pkts)
			break;
	}

	LOG_DEBUG("simple xmit:port_id=%u, queue_id=%u, "
		"remain_pkts_num=%d, xmit_pkts_num=%d",
		queue->port_id, queue->port_id,
		pkts_num, xmit_pkts_num);

l_end:
	return xmit_pkts_num;
}

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SIMD
#if defined(RTE_ARCH_X86) || defined(RTE_ARCH_ARM)
u16 sxe_recycle_tx_mbufs_reuse_vec(void *tx_queue,
	struct rte_eth_recycle_rxq_info *recycle_rxq_info)
{
	sxe_tx_queue_s *txq = tx_queue;
	struct sxe_tx_buffer *txep;
	struct rte_mbuf **rxep;
	int i, n;
	u32 status;
	u16 nb_recycle_mbufs;
	u16 avail = 0;
	u16 mbuf_ring_size = recycle_rxq_info->mbuf_ring_size;
	u16 mask = recycle_rxq_info->mbuf_ring_size - 1;
	u16 refill_requirement = recycle_rxq_info->refill_requirement;
	u16 refill_head = *recycle_rxq_info->refill_head;
	u16 receive_tail = *recycle_rxq_info->receive_tail;

	avail = (mbuf_ring_size - (refill_head - receive_tail)) & mask;

	if (txq->desc_free_num > txq->free_thresh || avail <= txq->rs_thresh)
		return 0;

	status = txq->desc_ring[txq->next_dd].wb.status;
	if (!(status & SXE_TX_DESC_STAT_DD))
		return 0;

	n = txq->rs_thresh;
	nb_recycle_mbufs = n;

	if ((refill_requirement && refill_requirement != n) ||
		(!refill_requirement && (refill_head + n > mbuf_ring_size)))
		return 0;

	txep = &txq->buffer_ring[txq->next_dd - (n - 1)];
	rxep = recycle_rxq_info->mbuf_ring;
	rxep += refill_head;

	if (txq->offloads & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) {
		if (unlikely(recycle_rxq_info->mp != txep[0].mbuf->pool))
			return 0;

		for (i = 0; i < n; i++)
			rxep[i] = txep[i].mbuf;
	} else {
		for (i = 0; i < n; i++) {
			rxep[i] = rte_pktmbuf_prefree_seg(txep[i].mbuf);

			if (unlikely(rxep[i] == NULL || recycle_rxq_info->mp != txep[i].mbuf->pool))
				nb_recycle_mbufs = 0;
		}
		if (nb_recycle_mbufs == 0) {
			for (i = 0; i < n; i++) {
				if (rxep[i] != NULL)
					rte_mempool_put(rxep[i]->pool, rxep[i]);
			}
		}
	}

	txq->desc_free_num = (u16)(txq->desc_free_num + txq->rs_thresh);
	txq->next_dd = (u16)(txq->next_dd + txq->rs_thresh);
	if (txq->next_dd >= txq->ring_depth)
		txq->next_dd = (u16)(txq->rs_thresh - 1);

	return nb_recycle_mbufs;
}
#endif

u16 sxe_pkts_vector_xmit(void *tx_queue, struct rte_mbuf **tx_pkts,
			   u16 pkts_num)
{
	u16 xmit_pkts_num = 0;
	sxe_tx_queue_s *queue = (sxe_tx_queue_s *)tx_queue;

	while (pkts_num) {
		u16 ret, need_xmit_pkts;

		need_xmit_pkts = (u16)RTE_MIN(pkts_num, queue->rs_thresh);
		ret = __sxe_pkts_vector_xmit(tx_queue, &tx_pkts[xmit_pkts_num],
				need_xmit_pkts);

		xmit_pkts_num += ret;
		pkts_num -= ret;
		if (ret < need_xmit_pkts)
			break;
	}

	return xmit_pkts_num;
}
#endif

u16 sxe_prep_pkts(void *tx_queue, struct rte_mbuf **tx_pkts, u16 pkts_num)
{
	s32 i, ret;
	u64 ol_flags;
	struct rte_mbuf *mbuf;
	sxe_tx_queue_s *txq = (sxe_tx_queue_s *)tx_queue;

	/* Check if the pkts is legal */
	for (i = 0; i < pkts_num; i++) {
		mbuf = tx_pkts[i];
		ol_flags = mbuf->ol_flags;

		if (mbuf->nb_segs > SXE_TX_MAX_SEG - txq->wthresh) {
			rte_errno = EINVAL;
			goto l_end;
		}

		/* Check offload */
		if (ol_flags & SXE_TX_OFFLOAD_NOTSUP_MASK) {
			rte_errno = ENOTSUP;
			goto l_end;
		}

		if (mbuf->pkt_len < SXE_TX_MIN_PKT_LEN) {
			rte_errno = EINVAL;
			goto l_end;
		}

#ifdef RTE_ETHDEV_DEBUG_TX
		ret = rte_validate_tx_offload(mbuf);
		if (ret != 0) {
			rte_errno = -ret;
			goto l_end;
		}
#endif
		ret = rte_net_intel_cksum_prepare(mbuf);
		if (ret != 0) {
			rte_errno = -ret;
			goto l_end;
		}
	}

l_end:
	return i;
}

static inline bool sxe_cache_ctxt_desc_match(sxe_tx_queue_s *txq,
				struct rte_mbuf *pkt,
				u64 flags,
				union sxe_tx_offload *ol_info)
{
	bool ret;

	ol_info->l2_len	   = pkt->l2_len;
	ol_info->l3_len	   = pkt->l3_len;
	ol_info->l4_len	   = pkt->l4_len;
	ol_info->vlan_tci	 = pkt->vlan_tci;
	ol_info->tso_segsz	= pkt->tso_segsz;
	ol_info->outer_l2_len = pkt->outer_l2_len;
	ol_info->outer_l3_len = pkt->outer_l3_len;

	if (likely(txq->ctx_cache[txq->ctx_curr].flags == flags &&
		   (txq->ctx_cache[txq->ctx_curr].tx_offload.data[0] ==
			(txq->ctx_cache[txq->ctx_curr].tx_offload_mask.data[0]
			 & ol_info->data[0])) &&
		   (txq->ctx_cache[txq->ctx_curr].tx_offload.data[1] ==
			(txq->ctx_cache[txq->ctx_curr].tx_offload_mask.data[1]
			 & ol_info->data[1])))) {
		ret = false;
		goto l_end;
	}

	txq->ctx_curr ^= 1;

	if (likely(txq->ctx_cache[txq->ctx_curr].flags == flags &&
		   (txq->ctx_cache[txq->ctx_curr].tx_offload.data[0] ==
			(txq->ctx_cache[txq->ctx_curr].tx_offload_mask.data[0]
			 & ol_info->data[0])) &&
		   (txq->ctx_cache[txq->ctx_curr].tx_offload.data[1] ==
			(txq->ctx_cache[txq->ctx_curr].tx_offload_mask.data[1]
			 & ol_info->data[1])))) {
		ret = false;
		goto l_end;
	}

	ret = true;

l_end:
	return ret;
}

static inline void sxe_ctxt_desc_fill(sxe_tx_queue_s *txq,
			volatile struct sxe_tx_context_desc *ctx_txd,
			u64 ol_flags,
			union sxe_tx_offload tx_offload,
			__rte_unused u64 *mdata)
{
	u32 type_tucmd_mlhl;
	u32 mss_l4len_idx = 0;
	u32 ctx_idx;
	u32 vlan_macip_lens;
	union sxe_tx_offload tx_offload_mask;
	u32 seqnum_seed = 0;

	ctx_idx = txq->ctx_curr;
	tx_offload_mask.data[0] = 0;
	tx_offload_mask.data[1] = 0;
	type_tucmd_mlhl = 0;


	mss_l4len_idx |= (ctx_idx << SXE_TXD_IDX_SHIFT);

	if (ol_flags & RTE_MBUF_F_TX_VLAN)
		tx_offload_mask.vlan_tci |= ~0;

	if (ol_flags & RTE_MBUF_F_TX_TCP_SEG) {
		if (ol_flags & RTE_MBUF_F_TX_IP_CKSUM) {
			type_tucmd_mlhl = SXE_TX_CTXTD_TUCMD_IPV4 |
				SXE_TX_CTXTD_TUCMD_L4T_TCP |
				SXE_TX_CTXTD_DTYP_CTXT;
		} else {
			type_tucmd_mlhl = SXE_TX_CTXTD_TUCMD_IPV6 |
				SXE_TX_CTXTD_TUCMD_L4T_TCP |
				SXE_TX_CTXTD_DTYP_CTXT;
		}
		mss_l4len_idx |= tx_offload.tso_segsz << SXE_TX_CTXTD_MSS_SHIFT;
		mss_l4len_idx |= tx_offload.l4_len << SXE_TX_CTXTD_L4LEN_SHIFT;

		tx_offload_mask.l2_len |= ~0;
		tx_offload_mask.l3_len |= ~0;
		tx_offload_mask.l4_len |= ~0;
		tx_offload_mask.tso_segsz |= ~0;

	} else {
		if (ol_flags & RTE_MBUF_F_TX_IP_CKSUM) {
			type_tucmd_mlhl = SXE_TX_CTXTD_TUCMD_IPV4;
			tx_offload_mask.l2_len |= ~0;
			tx_offload_mask.l3_len |= ~0;
		}

		switch (ol_flags & RTE_MBUF_F_TX_L4_MASK) {
		case RTE_MBUF_F_TX_UDP_CKSUM:
			type_tucmd_mlhl |= SXE_TX_CTXTD_TUCMD_L4T_UDP |
				SXE_TX_CTXTD_DTYP_CTXT;
			mss_l4len_idx |= sizeof(struct rte_udp_hdr)
				<< SXE_TX_CTXTD_L4LEN_SHIFT;
			tx_offload_mask.l2_len |= ~0;
			tx_offload_mask.l3_len |= ~0;
			break;
		case RTE_MBUF_F_TX_TCP_CKSUM:
			type_tucmd_mlhl |= SXE_TX_CTXTD_TUCMD_L4T_TCP |
				SXE_TX_CTXTD_DTYP_CTXT;
			mss_l4len_idx |= sizeof(struct rte_tcp_hdr)
				<< SXE_TX_CTXTD_L4LEN_SHIFT;
			tx_offload_mask.l2_len |= ~0;
			tx_offload_mask.l3_len |= ~0;
			break;
		case RTE_MBUF_F_TX_SCTP_CKSUM:
			type_tucmd_mlhl |= SXE_TX_CTXTD_TUCMD_L4T_SCTP |
				SXE_TX_CTXTD_DTYP_CTXT;
			mss_l4len_idx |= sizeof(struct rte_sctp_hdr)
				<< SXE_TX_CTXTD_L4LEN_SHIFT;
			tx_offload_mask.l2_len |= ~0;
			tx_offload_mask.l3_len |= ~0;
			break;
		default:
			type_tucmd_mlhl |= SXE_TX_CTXTD_TUCMD_L4T_RSV |
				SXE_TX_CTXTD_DTYP_CTXT;
			break;
		}
	}

	vlan_macip_lens = tx_offload.l3_len;
	vlan_macip_lens |= ((u32)tx_offload.vlan_tci << SXE_TX_CTXTD_VLAN_SHIFT);

	if (ol_flags & RTE_MBUF_F_TX_OUTER_IP_CKSUM) {
		tx_offload_mask.outer_l2_len |= ~0;
		tx_offload_mask.outer_l3_len |= ~0;
		tx_offload_mask.l2_len |= ~0;
		seqnum_seed |= tx_offload.outer_l3_len
				   << SXE_TX_CTXTD_OUTER_IPLEN_SHIFT;
		seqnum_seed |= tx_offload.l2_len
				   << SXE_TX_CTXTD_TUNNEL_LEN_SHIFT;
		vlan_macip_lens |= (tx_offload.outer_l2_len <<
					SXE_TX_CTXTD_MACLEN_SHIFT);
	} else {
		vlan_macip_lens |= (tx_offload.l2_len <<
						SXE_TX_CTXTD_MACLEN_SHIFT);
	}

	txq->ctx_cache[ctx_idx].flags = ol_flags;
	txq->ctx_cache[ctx_idx].tx_offload.data[0]  =
		tx_offload_mask.data[0] & tx_offload.data[0];
	txq->ctx_cache[ctx_idx].tx_offload.data[1]  =
		tx_offload_mask.data[1] & tx_offload.data[1];
	txq->ctx_cache[ctx_idx].tx_offload_mask	= tx_offload_mask;

	ctx_txd->type_tucmd_mlhl = rte_cpu_to_le_32(type_tucmd_mlhl);
	ctx_txd->vlan_macip_lens = rte_cpu_to_le_32(vlan_macip_lens);
	ctx_txd->mss_l4len_idx   = rte_cpu_to_le_32(mss_l4len_idx);
	ctx_txd->seqnum_seed	 = seqnum_seed;
}

static inline u32 sxe_tx_desc_csum_info_setup(u64 ol_flags)
{
	u32 desc_csum = 0;

	if ((ol_flags & RTE_MBUF_F_TX_L4_MASK) != RTE_MBUF_F_TX_L4_NO_CKSUM)
		desc_csum |= SXE_TXD_POPTS_TXSM;

	if (ol_flags & RTE_MBUF_F_TX_IP_CKSUM)
		desc_csum |= SXE_TXD_POPTS_IXSM;

	if (ol_flags & RTE_MBUF_F_TX_TCP_SEG)
		desc_csum |= SXE_TXD_POPTS_TXSM;

	return desc_csum;
}

static inline u32 sxe_tx_desc_cmdtype_setup(u64 ol_flags)
{
	u32 cmdtype = 0;

	if (ol_flags & RTE_MBUF_F_TX_VLAN)
		cmdtype |= SXE_TX_DESC_VLE;

	if (ol_flags & RTE_MBUF_F_TX_TCP_SEG)
		cmdtype |= SXE_TXD_DCMD_TSE;

	if (ol_flags & RTE_MBUF_F_TX_OUTER_IP_CKSUM)
		cmdtype |= (1 << SXE_TX_OUTERIPCS_SHIFT);

#ifdef SXE_DPDK_MACSEC
	if (ol_flags & RTE_MBUF_F_TX_MACSEC)
		cmdtype |= SXE_TXD_MAC_LINKSEC;
#endif

	return cmdtype;
}

static inline s32 sxe_xmit_cleanup(sxe_tx_queue_s *txq)
{
	s32 ret = 0;
	u32 wb_status;
	u16 ntc = txq->next_to_clean;
	u16 ring_depth = txq->ring_depth;
	u16 desc_to_clean_to, nb_tx_to_clean;
	struct sxe_tx_buffer *buffer_ring = txq->buffer_ring;
	volatile sxe_tx_data_desc_u *desc_ring = txq->desc_ring;

	PMD_INIT_FUNC_TRACE();

	desc_to_clean_to = (u16)(ntc + txq->rs_thresh);

	if (desc_to_clean_to >= ring_depth)
		desc_to_clean_to = (u16)(desc_to_clean_to - ring_depth);

	desc_to_clean_to = buffer_ring[desc_to_clean_to].last_id;

	wb_status = desc_ring[desc_to_clean_to].wb.status;
	if (!(wb_status & rte_cpu_to_le_32(SXE_TX_DESC_STAT_DD))) {
		LOG_DEBUG("TX descriptor %4u is not done"
				"(port=%d queue=%d)",
				desc_to_clean_to,
				txq->port_id, txq->queue_idx);

		ret = -SXE_TX_DESC_NO_WB;
		goto l_end;
	}

	if (ntc > desc_to_clean_to) {
		nb_tx_to_clean = (u16)((ring_depth - ntc) +
						desc_to_clean_to);
	} else {
		nb_tx_to_clean = (u16)(desc_to_clean_to - ntc);
	}

	LOG_DEBUG("Cleaning %4u TX descriptors: %4u to %4u "
			"(port=%d queue=%d)",
			nb_tx_to_clean, ntc, desc_to_clean_to,
			txq->port_id, txq->queue_idx);

	desc_ring[desc_to_clean_to].wb.status = 0;

	txq->next_to_clean = desc_to_clean_to;

	txq->desc_free_num = (u16)(txq->desc_free_num + nb_tx_to_clean);

l_end:
	return ret;
}

static inline s32 sxe_tx_pkt_desc_clean(sxe_tx_queue_s *txq,
			u32 need_desc_num)
{
	s32 ret = 0;

	LOG_DEBUG("Not enough free TX descriptors "
			"need_desc_num=%4u nb_free=%4u "
			"(port=%d queue=%d)",
			need_desc_num, txq->desc_free_num,
			txq->port_id, txq->queue_idx);

	ret = sxe_xmit_cleanup(txq);
	if (ret)
		goto l_end;

	if (unlikely(need_desc_num > txq->rs_thresh)) {
		LOG_DEBUG("The number of descriptors needed to "
			"transmit the packet exceeds the "
			"RS bit threshold. This will impact "
			"performance."
			"need_desc_num=%4u nb_free=%4u "
			"rs_thresh=%4u. "
			"(port=%d queue=%d)",
			need_desc_num, txq->desc_free_num,
			txq->rs_thresh,
			txq->port_id, txq->queue_idx);

		/* Clean up enought desc */
		while (need_desc_num > txq->desc_free_num) {
			ret = sxe_xmit_cleanup(txq);
			if (ret)
				goto l_end;
		}
	}

l_end:
	return ret;
}

u16 __sxe_pkts_xmit_with_offload(void *tx_queue, struct rte_mbuf **tx_pkts, u16 pkts_num)
{
	s32 ret;
	u64 ol_req;
	bool new_ctx;
	u64 buf_dma_addr;
	struct rte_mbuf *pkt;
	struct rte_mbuf *m_seg;
	union sxe_tx_offload ol_info;
	sxe_tx_queue_s  *txq = tx_queue;
	u32 pkt_len, cmd_type_len, olinfo_status;
	u16 need_desc_num, last_desc_idx, xmit_num, ntu, seg_len;
	volatile sxe_tx_data_desc_u *tail_desc = NULL;
	volatile sxe_tx_data_desc_u *desc_ring, *desc;
	struct sxe_tx_buffer *buffer_ring, *buffer, *next_buffer;

	ol_info.data[SXE_CTXT_DESC_0] = 0;
	ol_info.data[SXE_CTXT_DESC_1] = 0;
	ntu		 = txq->next_to_use;
	desc_ring   = txq->desc_ring;
	buffer_ring = txq->buffer_ring;
	buffer	  = &buffer_ring[ntu];

	if (txq->desc_free_num < txq->free_thresh)
		sxe_xmit_cleanup(txq);

	/* Refresh cache, pre fetch data to cache */
	rte_sxe_prefetch(&buffer->mbuf->pool);

	for (xmit_num = 0; xmit_num < pkts_num; xmit_num++) {
		new_ctx = false;
		pkt = *tx_pkts++;
		pkt_len = pkt->pkt_len;

		ol_req = pkt->ol_flags & SXE_TX_OFFLOAD_MASK;
		if (ol_req)
			new_ctx = sxe_cache_ctxt_desc_match(txq, pkt, ol_req, &ol_info);

		need_desc_num = (u16)(pkt->nb_segs + new_ctx);

		if (tail_desc != NULL &&
			need_desc_num + txq->desc_used_num >= txq->rs_thresh) {
			tail_desc->read.cmd_type_len |=
				rte_cpu_to_le_32(SXE_TX_DESC_RS_MASK);
		}

		last_desc_idx = (u16)(ntu + need_desc_num - 1);

		if (last_desc_idx >= txq->ring_depth)
			last_desc_idx = (u16)(last_desc_idx - txq->ring_depth);

		LOG_DEBUG("port_id=%u queue_id=%u pktlen=%u"
			   " next_to_ues=%u last_desc_idx=%u",
			   (unsigned int)txq->port_id,
			   (unsigned int)txq->queue_idx,
			   (unsigned int)pkt_len,
			   (unsigned int)ntu,
			   (unsigned int)last_desc_idx);

		if (need_desc_num > txq->desc_free_num) {
			ret = sxe_tx_pkt_desc_clean(txq, need_desc_num);
			if (ret) {
				if (xmit_num == 0)
					goto l_end;

				goto l_end_of_tx;
			}
		}

		cmd_type_len = SXE_TX_DESC_TYPE_DATA | SXE_TX_DESC_IFCS;
#ifdef RTE_LIBRTE_IEEE1588
		if (pkt->ol_flags & RTE_MBUF_F_TX_IEEE1588_TMST)
			cmd_type_len |= SXE_TXD_MAC_1588;
#endif

		olinfo_status = 0;
		if (ol_req) {
			if (pkt->ol_flags & RTE_MBUF_F_TX_TCP_SEG) {
				pkt_len -= (ol_info.l2_len +
					ol_info.l3_len + ol_info.l4_len);
			}

			if (new_ctx) {
				volatile struct sxe_tx_context_desc *ctx_desc;

				ctx_desc = (volatile struct
					sxe_tx_context_desc *) &desc_ring[ntu];

				next_buffer = &buffer_ring[buffer->next_id];
				rte_prefetch0(&next_buffer->mbuf->pool);

				if (buffer->mbuf != NULL) {
					rte_pktmbuf_free_seg(buffer->mbuf);
					buffer->mbuf = NULL;
				}

				sxe_ctxt_desc_fill(txq, ctx_desc, ol_req,
						ol_info, NULL);

				buffer->last_id = last_desc_idx;
				ntu = buffer->next_id;
				buffer = next_buffer;
			}

			LOG_DEBUG("tx need offload, port_id=%u "
			"queue_id=%u pktlen=%u, ctxt_id=%u",
			   (unsigned int)txq->port_id,
			   (unsigned int)txq->queue_idx,
			   (unsigned int)pkt_len,
			   (unsigned int)txq->ctx_curr);

			cmd_type_len  |= sxe_tx_desc_cmdtype_setup(pkt->ol_flags);
			olinfo_status |= sxe_tx_desc_csum_info_setup(pkt->ol_flags);
			olinfo_status |= txq->ctx_curr << SXE_TXD_IDX_SHIFT;
		}
		olinfo_status |= (pkt_len << SXE_TX_DESC_PAYLEN_SHIFT);

		m_seg = pkt;
		do {
			desc = &desc_ring[ntu];
			next_buffer = &buffer_ring[buffer->next_id];

			rte_prefetch0(&next_buffer->mbuf->pool);
			if (buffer->mbuf != NULL)
				rte_pktmbuf_free_seg(buffer->mbuf);

			buffer->mbuf = m_seg;

			seg_len = m_seg->data_len;

			buf_dma_addr = rte_mbuf_data_iova(m_seg);
			desc->read.buffer_addr =
				rte_cpu_to_le_64(buf_dma_addr);
			desc->read.cmd_type_len =
				rte_cpu_to_le_32(cmd_type_len | seg_len);
			desc->read.olinfo_status =
				rte_cpu_to_le_32(olinfo_status);
			buffer->last_id = last_desc_idx;
			ntu = buffer->next_id;
			buffer = next_buffer;
			m_seg = m_seg->next;
		} while (m_seg != NULL);

		cmd_type_len |= SXE_TX_DESC_EOP_MASK;
		txq->desc_used_num += need_desc_num;
		txq->desc_free_num -= need_desc_num;

		if (txq->desc_used_num >= txq->rs_thresh) {
			LOG_DEBUG("Setting RS bit on TXD id="
					"%4u (port=%d queue=%d)",
					last_desc_idx, txq->port_id, txq->queue_idx);

			cmd_type_len |= SXE_TX_DESC_RS_MASK;

			txq->desc_used_num = 0;
			tail_desc = NULL;
		} else {
			tail_desc = desc;
		}

		desc->read.cmd_type_len |= rte_cpu_to_le_32(cmd_type_len);
	}

l_end_of_tx:
	if (tail_desc != NULL)
		tail_desc->read.cmd_type_len |= rte_cpu_to_le_32(SXE_TX_DESC_RS_MASK);

	rte_wmb();

	LOG_DEBUG("port_id=%u queue_idx=%u next_to_use=%u xmit_num=%u",
		   (unsigned int)txq->port_id, (unsigned int)txq->queue_idx,
		   (unsigned int)ntu, (unsigned int)xmit_num);

	rte_write32_wc_relaxed(ntu, txq->tdt_reg_addr);

	txq->next_to_use = ntu;

l_end:
	return xmit_num;
}

u16 sxe_pkts_xmit_with_offload(void *tx_queue, struct rte_mbuf **tx_pkts, u16 pkts_num)
{
	return __sxe_pkts_xmit_with_offload(tx_queue, tx_pkts, pkts_num);
}

u32 sxe_tx_done_cleanup_full(sxe_tx_queue_s *txq, u32 free_cnt)
{
	u32 pkt_cnt;
	u16 i, ntu, tx_id;
	u16 nb_tx_free_last;
	u16 nb_tx_to_clean;
	struct sxe_tx_buffer *buffer_ring = txq->buffer_ring;

	ntu	= txq->next_to_use;
	tx_id  = buffer_ring[ntu].next_id;

	if (txq->desc_free_num == 0 && sxe_xmit_cleanup(txq)) {
		pkt_cnt = 0;
		goto l_end;
	}

	nb_tx_to_clean  = txq->desc_free_num;
	nb_tx_free_last = txq->desc_free_num;

	if (!free_cnt)
		free_cnt = txq->ring_depth;

	for (pkt_cnt = 0; pkt_cnt < free_cnt; ) {
		for (i = 0; i < (nb_tx_to_clean && pkt_cnt < free_cnt &&
			tx_id != ntu); i++) {
			if (buffer_ring[tx_id].mbuf != NULL) {
				rte_pktmbuf_free_seg(buffer_ring[tx_id].mbuf);
				buffer_ring[tx_id].mbuf = NULL;

				pkt_cnt += (buffer_ring[tx_id].last_id == tx_id);
			}

			tx_id = buffer_ring[tx_id].next_id;
		}

		if (txq->rs_thresh > txq->ring_depth - txq->desc_free_num ||
				tx_id == ntu) {
			break;
		}

		if (pkt_cnt < free_cnt) {
			if (sxe_xmit_cleanup(txq))
				break;

			nb_tx_to_clean = txq->desc_free_num - nb_tx_free_last;
			nb_tx_free_last = txq->desc_free_num;
		}
	}

l_end:
	return pkt_cnt;
}

int sxe_tx_done_cleanup_simple(sxe_tx_queue_s *txq, u32 free_cnt)
{
	int i, n, cnt;

	if (free_cnt == 0 || free_cnt > txq->ring_depth)
		free_cnt = txq->ring_depth;

	cnt = free_cnt - free_cnt % txq->rs_thresh;

	for (i = 0; i < cnt; i += n) {
		if (txq->ring_depth - txq->desc_free_num < txq->rs_thresh)
			break;

		n = sxe_tx_bufs_free(txq);
		if (n == 0)
			break;
	}

	return i;
}

int sxe_tx_done_cleanup(void *tx_queue, u32 free_cnt)
{
	s32 ret;

	ret = __sxe_tx_done_cleanup(tx_queue, free_cnt);
	if (ret)
		PMD_LOG_ERR(INIT, "tx cleanup fail.(err:%d)", ret);

	return ret;
}

int sxe_tx_descriptor_status(void *tx_queue, u16 offset)
{
	return __sxe_tx_descriptor_status(tx_queue, offset);
}

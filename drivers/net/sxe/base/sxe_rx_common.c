/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_mbuf.h>
#include <ethdev_driver.h>
#include <rte_prefetch.h>
#include <rte_malloc.h>

#include "sxe.h"
#include "sxe_rx.h"
#include "sxe_logs.h"
#include "sxe_hw.h"
#include "sxe_queue_common.h"
#include "sxe_vf.h"
#include "sxe_errno.h"
#include "sxe_irq.h"
#include "sxe_rx_common.h"
#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SIMD
#include "sxe_vec_common.h"
#include "rte_vect.h"
#endif

static inline void sxe_rx_resource_prefetch(u16 next_idx,
				struct sxe_rx_buffer *buf_ring,
				volatile union sxe_rx_data_desc *desc_ring)
{
	rte_sxe_prefetch(buf_ring[next_idx].mbuf);

	if ((next_idx & 0x3) == 0) {
		rte_sxe_prefetch(&desc_ring[next_idx]);
		rte_sxe_prefetch(&buf_ring[next_idx]);
	}

}

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SIMD
#if defined(RTE_ARCH_X86) || defined(RTE_ARCH_ARM)
static void sxe_recycle_rx_descriptors_refill_vec(void *rx_queue, u16 nb_mbufs)
{
	struct sxe_rx_queue *rxq = rx_queue;
	struct sxe_rx_buffer *rxep;
	volatile union sxe_rx_data_desc *rxdp;
	u16 rx_id;
	u64 paddr;
	u64 dma_addr;
	u16 i;

	rxdp = rxq->desc_ring + rxq->realloc_start;
	rxep = &rxq->buffer_ring[rxq->realloc_start];

	for (i = 0; i < nb_mbufs; i++) {
		paddr = (rxep[i].mbuf)->buf_iova + RTE_PKTMBUF_HEADROOM;
		dma_addr = rte_cpu_to_le_64(paddr);
		rxdp[i].read.hdr_addr = 0;
		rxdp[i].read.pkt_addr = dma_addr;
	}

	rxq->realloc_start += nb_mbufs;
	if (rxq->realloc_start >= rxq->ring_depth)
		rxq->realloc_start = 0;

	rxq->realloc_num -= nb_mbufs;

	rx_id = (u16)((rxq->realloc_start == 0) ?
					(rxq->ring_depth - 1) : (rxq->realloc_start - 1));

	SXE_PCI_REG_WC_WRITE_RELAXED(rxq->rdt_reg_addr, rx_id);
}
#endif
#endif

void __rte_cold __sxe_rx_function_set(struct rte_eth_dev *dev,
	bool rx_batch_alloc_allowed, bool *rx_vec_allowed)
{
#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SIMD
	u16  i, is_using_sse;

	if (sxe_rx_vec_condition_check(dev) ||
		!rx_batch_alloc_allowed
		) {
		PMD_LOG_DEBUG(INIT, "Port[%d] doesn't meet Vector Rx "
					"preconditions", dev->data->port_id);
		*rx_vec_allowed = false;
	}
#else
	UNUSED(rx_vec_allowed);
#endif

	if (dev->data->lro) {
		if (rx_batch_alloc_allowed) {
			PMD_LOG_DEBUG(INIT, "LRO is requested. Using a bulk "
					   "allocation version");
			dev->rx_pkt_burst = sxe_batch_alloc_lro_pkts_recv;
		} else {
			PMD_LOG_DEBUG(INIT, "LRO is requested. Using a single "
					   "allocation version");
			dev->rx_pkt_burst = sxe_single_alloc_lro_pkts_recv;
		}
	} else if (dev->data->scattered_rx) {
#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SIMD
		if (*rx_vec_allowed) {
			PMD_LOG_DEBUG(INIT, "Using Vector Scattered Rx "
						"callback (port=%d).",
					 dev->data->port_id);

#if defined(RTE_ARCH_X86) || defined(RTE_ARCH_ARM)
			dev->recycle_rx_descriptors_refill = sxe_recycle_rx_descriptors_refill_vec;

#endif
			dev->rx_pkt_burst = sxe_scattered_pkts_vec_recv;

#endif

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SIMD

		} else if (rx_batch_alloc_allowed) {
#else
		if (rx_batch_alloc_allowed) {
#endif

			PMD_LOG_DEBUG(INIT, "Using a Scattered with bulk "
					   "allocation callback (port=%d).",
					 dev->data->port_id);

			dev->rx_pkt_burst = sxe_batch_alloc_lro_pkts_recv;
		} else {
			PMD_LOG_DEBUG(INIT, "Using Regular (non-vector, "
						"single allocation) "
						"Scattered Rx callback "
						"(port=%d).",
					 dev->data->port_id);

			dev->rx_pkt_burst = sxe_single_alloc_lro_pkts_recv;
		}
	}
	#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SIMD
	else if (*rx_vec_allowed) {
		PMD_LOG_DEBUG(INIT, "Vector rx enabled, please make sure RX "
					"burst size no less than %d (port=%d).",
				 SXE_DESCS_PER_LOOP,
				 dev->data->port_id);

#if defined(RTE_ARCH_X86) || defined(RTE_ARCH_ARM)
		dev->recycle_rx_descriptors_refill = sxe_recycle_rx_descriptors_refill_vec;

#endif
		dev->rx_pkt_burst = sxe_pkts_vec_recv;
	}
#endif
	else if (rx_batch_alloc_allowed) {
		PMD_LOG_DEBUG(INIT, "Rx Burst Bulk Alloc Preconditions are "
					"satisfied. Rx Burst Bulk Alloc function "
					"will be used on port=%d.",
				dev->data->port_id);

		dev->rx_pkt_burst = sxe_batch_alloc_pkts_recv;
	} else {
		PMD_LOG_DEBUG(INIT, "Rx Burst Bulk Alloc Preconditions are not "
				"satisfied, or Scattered Rx is requested "
				"(port=%d).",
				dev->data->port_id);

		dev->rx_pkt_burst = sxe_pkts_recv;
	}

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SIMD
	is_using_sse =
		(dev->rx_pkt_burst == sxe_scattered_pkts_vec_recv ||
		dev->rx_pkt_burst == sxe_pkts_vec_recv);

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		struct sxe_rx_queue *rxq = dev->data->rx_queues[i];

		rxq->is_using_sse = is_using_sse;
	}
#endif

}

s32 __sxe_rx_descriptor_status(void *rx_queue, u16 offset)
{
	int ret = RTE_ETH_RX_DESC_AVAIL;
	struct sxe_rx_queue *rxq = rx_queue;
	volatile u32 *status;
	u32 hold_num, desc;

	if (unlikely(offset >= rxq->ring_depth)) {
		LOG_DEBUG("rx queue[%u] get desc status err,"
			"offset=%u >= ring_depth=%u",
			rxq->queue_id, offset, rxq->ring_depth);
		ret = -EINVAL;
		goto l_end;
	}

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SIMD
#if defined(RTE_ARCH_X86)
	if (rxq->is_using_sse)
		hold_num = rxq->realloc_num;
	else
#endif
#endif
		hold_num = rxq->hold_num;
	if (offset >= rxq->ring_depth - hold_num) {
		ret = RTE_ETH_RX_DESC_UNAVAIL;
		goto l_end;
	}

	desc = rxq->processing_idx + offset;
	if (desc >= rxq->ring_depth)
		desc -= rxq->ring_depth;

	status = &rxq->desc_ring[desc].wb.upper.status_error;
	if (*status & rte_cpu_to_le_32(SXE_RXDADV_STAT_DD))
		ret =  RTE_ETH_RX_DESC_DONE;

l_end:
	LOG_DEBUG("rx queue[%u] get desc status=%d", rxq->queue_id, ret);
	return ret;
}

u16 __sxe_pkts_recv(void *rx_queue, struct rte_mbuf **rx_pkts,
		u16 pkts_num)
{
	struct sxe_rx_queue *rxq = (struct sxe_rx_queue *)rx_queue;
	volatile union sxe_rx_data_desc *desc_ring = rxq->desc_ring;
	volatile union sxe_rx_data_desc *cur_desc;
	struct sxe_rx_buffer *buff_ring = rxq->buffer_ring;
	struct sxe_rx_buffer *cur_buf;
	struct rte_mbuf *cur_mb;
	struct rte_mbuf *new_mb;
	union sxe_rx_data_desc rxd;
	u16 processing_idx = rxq->processing_idx;
	u64 dma_addr;
	u32 staterr;
	u32 pkt_info;
	u16 done_num = 0;
	u16 hold_num = 0;
	u16 pkt_len;

	while (done_num < pkts_num) {
		cur_desc = &desc_ring[processing_idx];
		staterr = cur_desc->wb.upper.status_error;
		if (!(staterr & rte_cpu_to_le_32(SXE_RXDADV_STAT_DD)))
			break;

		rxd = *cur_desc;

		LOG_DEBUG("port_id=%u queue_id=%u processing_idx=%u "
			   "staterr=0x%08x pkt_len=%u",
			   (unsigned int)rxq->port_id, (unsigned int)rxq->queue_id,
			   (unsigned int)processing_idx, (unsigned int)staterr,
			   (unsigned int)rte_le_to_cpu_16(rxd.wb.upper.length));

		new_mb = rte_mbuf_raw_alloc(rxq->mb_pool);
		if (new_mb == NULL) {
			LOG_ERROR("RX mbuf alloc failed port_id=%u "
				   "queue_id=%u", (unsigned int)rxq->port_id,
				   (unsigned int)rxq->queue_id);
			rte_eth_devices[rxq->port_id].data->rx_mbuf_alloc_failed++;
			break;
		}

		hold_num++;
		cur_buf = &buff_ring[processing_idx];
		processing_idx++;
		if (processing_idx == rxq->ring_depth)
			processing_idx = 0;

		sxe_rx_resource_prefetch(processing_idx, buff_ring, desc_ring);

		cur_mb = cur_buf->mbuf;
		cur_buf->mbuf = new_mb;
		dma_addr =
			rte_cpu_to_le_64(rte_mbuf_data_iova_default(new_mb));
		cur_desc->read.hdr_addr = 0;
		cur_desc->read.pkt_addr = dma_addr;

		cur_mb->data_off = RTE_PKTMBUF_HEADROOM;
		rte_packet_prefetch((char *)cur_mb->buf_addr + cur_mb->data_off);
		cur_mb->nb_segs = 1;
		cur_mb->next = NULL;
		pkt_len = (u16)(rte_le_to_cpu_16(rxd.wb.upper.length) -
						rxq->crc_len);
		cur_mb->pkt_len = pkt_len;
		cur_mb->data_len = pkt_len;

		pkt_info = rte_le_to_cpu_32(rxd.wb.lower.lo_dword.data);

		sxe_rx_mbuf_common_header_fill(rxq, cur_mb, rxd, pkt_info, staterr);

		rx_pkts[done_num++] = cur_mb;
	}

	rxq->processing_idx = processing_idx;

	hold_num = (u16)(hold_num + rxq->hold_num);
	if (hold_num > rxq->batch_alloc_size) {
		LOG_DEBUG("port_id=%u queue_id=%u rx_tail=%u "
			   "num_hold=%u num_done=%u",
			   (unsigned int)rxq->port_id, (unsigned int)rxq->queue_id,
			   (unsigned int)processing_idx, (unsigned int)hold_num,
			   (unsigned int)done_num);
		processing_idx = (u16)((processing_idx == 0) ?
				(rxq->ring_depth - 1) : (processing_idx - 1));
		SXE_PCI_REG_WC_WRITE(rxq->rdt_reg_addr, processing_idx);
		hold_num = 0;
	}

	rxq->hold_num = hold_num;
	return done_num;
}

const u32 *__sxe_dev_supported_ptypes_get(struct rte_eth_dev *dev, size_t *no_of_elements)
{
	const u32 *ptypes = NULL;
	static const u32 ptypes_arr[] = {
		RTE_PTYPE_L2_ETHER,
		RTE_PTYPE_L3_IPV4,
		RTE_PTYPE_L3_IPV4_EXT,
		RTE_PTYPE_L3_IPV6,
		RTE_PTYPE_L3_IPV6_EXT,
		RTE_PTYPE_L4_SCTP,
		RTE_PTYPE_L4_TCP,
		RTE_PTYPE_L4_UDP,
		RTE_PTYPE_TUNNEL_IP,
		RTE_PTYPE_INNER_L3_IPV6,
		RTE_PTYPE_INNER_L3_IPV6_EXT,
		RTE_PTYPE_INNER_L4_TCP,
		RTE_PTYPE_INNER_L4_UDP,
		RTE_PTYPE_UNKNOWN
	};

	if (dev->rx_pkt_burst == sxe_pkts_recv ||
		dev->rx_pkt_burst == sxe_batch_alloc_pkts_recv ||
		dev->rx_pkt_burst == sxe_single_alloc_lro_pkts_recv ||
		dev->rx_pkt_burst == sxe_batch_alloc_lro_pkts_recv) {
		*no_of_elements = RTE_DIM(ptypes_arr);
		ptypes = ptypes_arr;
		goto l_end;
	}

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SIMD
#if defined(RTE_ARCH_X86)
	if (dev->rx_pkt_burst == sxe_pkts_vec_recv ||
		dev->rx_pkt_burst == sxe_scattered_pkts_vec_recv) {
		*no_of_elements = RTE_DIM(ptypes_arr);
		ptypes = ptypes_arr;
	}

#endif
#endif

l_end:
	return ptypes;
}

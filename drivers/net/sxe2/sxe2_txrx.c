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
#include "sxe2_osal.h"
#include "sxe2_cmd_chnl.h"
#if defined(RTE_ARCH_ARM64)
#include <rte_cpuflags.h>
#endif

int32_t __rte_cold
sxe2_tx_simple_batch_support_check(struct rte_eth_dev *dev,
		uint32_t *batch_flags)
{
	struct sxe2_tx_queue *txq;
	int32_t ret = 0;
	uint16_t i;

	for (i = 0; i < dev->data->nb_tx_queues; ++i) {
		txq = (struct sxe2_tx_queue *)dev->data->tx_queues[i];
		if (txq == NULL) {
			ret = -EINVAL;
			goto l_end;
		}
		if (txq->offloads != (txq->offloads & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) ||
		     txq->rs_thresh < SXE2_TX_PKTS_BURST_BATCH_NUM) {
			ret = -ENOTSUP;
			goto l_end;
		}
	}
	*batch_flags = SXE2_TX_MODE_SIMPLE_BATCH;
l_end:
	return ret;
}

static int32_t sxe2_tx_descriptor_status(void *tx_queue, uint16_t offset)
{
	struct sxe2_tx_queue *txq = (struct sxe2_tx_queue *)tx_queue;
	int32_t ret;
	uint16_t desc_idx;

	if (unlikely(offset >= txq->ring_depth)) {
		ret = -EINVAL;
		goto l_end;
	}
	desc_idx = txq->next_use + offset;
	desc_idx = SXE2_DIV_ROUND_UP(desc_idx, txq->rs_thresh) * (txq->rs_thresh);
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

static inline int32_t sxe2_tx_mbuf_empty_check(struct rte_mbuf *mbuf)
{
	struct rte_mbuf *m_seg = mbuf;
	while (m_seg != NULL) {
		if (m_seg->data_len == 0)
			return -EINVAL;
		m_seg = m_seg->next;
	}

	return 0;
}

uint16_t sxe2_tx_pkts_prepare(void *tx_queue,
		struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	struct sxe2_tx_queue *txq = tx_queue;
	struct rte_mbuf *mbuf;
	uint64_t ol_flags = 0;
	int32_t ret = 0;
	int32_t i = 0;

	for (i = 0; i < nb_pkts; i++) {
		mbuf = tx_pkts[i];
		if (!mbuf)
			continue;
		ol_flags = mbuf->ol_flags;
		if (!(ol_flags & (RTE_MBUF_F_TX_TCP_SEG | RTE_MBUF_F_TX_UDP_SEG))) {
			if (mbuf->nb_segs > SXE2_TX_MTU_SEG_MAX ||
					mbuf->pkt_len > SXE2_FRAME_SIZE_MAX) {
				rte_errno = -EINVAL;
				goto l_end;
			}
		} else if ((mbuf->tso_segsz < SXE2_MIN_TSO_MSS) ||
			(mbuf->tso_segsz > SXE2_MAX_TSO_MSS) ||
			(mbuf->nb_segs   > txq->ring_depth) ||
			(mbuf->pkt_len > SXE2_TX_TSO_PKTLEN_MAX)) {
			rte_errno = -EINVAL;
			goto l_end;
		}
		if (mbuf->pkt_len < SXE2_TX_MIN_PKT_LEN) {
			rte_errno = -EINVAL;
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
		ret = sxe2_tx_mbuf_empty_check(mbuf);
		if (ret != 0) {
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
	uint32_t tx_mode_flags;
	int32_t ret;
	uint32_t vec_flags = 0;
	uint32_t batch_flags = 0;

	PMD_INIT_FUNC_TRACE();
	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		tx_mode_flags = 0;
		ret = sxe2_tx_vec_support_check(dev, &vec_flags);
		if (ret == 0 &&
		    rte_vect_get_max_simd_bitwidth() >= RTE_VECT_SIMD_128) {
			tx_mode_flags = vec_flags;
#ifdef RTE_ARCH_X86
			if ((rte_vect_get_max_simd_bitwidth() >= RTE_VECT_SIMD_512) &&
			    (rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX512F) == 1) &&
			    (rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX512BW) == 1)) {
#ifdef CC_AVX512_SUPPORT
				tx_mode_flags |= SXE2_TX_MODE_VEC_AVX512;
#else
				PMD_LOG_INFO(TX, "AVX512 is not supported in build env.");
#endif
			}
			if (((tx_mode_flags & SXE2_TX_MODE_VEC_SET_MASK) == 0) &&
			    ((rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX2) == 1) ||
			    (rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX512F) == 1)) &&
			    (rte_vect_get_max_simd_bitwidth() >= RTE_VECT_SIMD_256))
				tx_mode_flags |= SXE2_TX_MODE_VEC_AVX2;

			if ((0 == (tx_mode_flags & SXE2_TX_MODE_VEC_SET_MASK)))
				tx_mode_flags |=  SXE2_TX_MODE_VEC_SSE;
#elif defined(RTE_ARCH_ARM64)
			if (rte_cpu_get_flag_enabled(RTE_CPUFLAG_NEON) == 1)
				tx_mode_flags |= (vec_flags | SXE2_TX_MODE_VEC_NEON);
#endif
			if (tx_mode_flags & SXE2_TX_MODE_VEC_SET_MASK) {
				ret = sxe2_tx_queues_vec_prepare(dev);
				if (ret != 0)
					tx_mode_flags &= ~SXE2_TX_MODE_VEC_SET_MASK;
			}
		}
		ret = sxe2_tx_simple_batch_support_check(dev, &batch_flags);
		if (ret == 0 && batch_flags == SXE2_TX_MODE_SIMPLE_BATCH)
			tx_mode_flags |= SXE2_TX_MODE_SIMPLE_BATCH;

		adapter->q_ctxt.tx_mode_flags = tx_mode_flags;
	} else {
		tx_mode_flags = adapter->q_ctxt.tx_mode_flags;
	}

	if (tx_mode_flags & SXE2_TX_MODE_VEC_SET_MASK) {
		dev->tx_pkt_prepare = NULL;
#ifdef RTE_ARCH_X86
		if (tx_mode_flags & SXE2_TX_MODE_VEC_AVX512) {
#ifdef CC_AVX512_SUPPORT
			if (tx_mode_flags & SXE2_TX_MODE_VEC_OFFLOAD) {
				dev->tx_pkt_prepare = sxe2_tx_pkts_prepare;
				dev->tx_pkt_burst = sxe2_tx_pkts_vec_avx512;
			} else {
				dev->tx_pkt_burst = sxe2_tx_pkts_vec_avx512_simple;
			}
#endif
		} else if (tx_mode_flags & SXE2_TX_MODE_VEC_AVX2) {
			if (tx_mode_flags & SXE2_TX_MODE_VEC_OFFLOAD) {
				dev->tx_pkt_prepare = sxe2_tx_pkts_prepare;
				dev->tx_pkt_burst = sxe2_tx_pkts_vec_avx2;
			} else {
				dev->tx_pkt_burst = sxe2_tx_pkts_vec_avx2_simple;
			}
		} else {
			if (tx_mode_flags & SXE2_TX_MODE_VEC_OFFLOAD) {
				dev->tx_pkt_prepare = sxe2_tx_pkts_prepare;
				dev->tx_pkt_burst = sxe2_tx_pkts_vec_sse;
			} else {
				dev->tx_pkt_burst = sxe2_tx_pkts_vec_sse_simple;
			}
		}
#elif defined(RTE_ARCH_ARM64)
		if (tx_mode_flags & SXE2_TX_MODE_VEC_NEON) {
			dev->tx_pkt_prepare = sxe2_tx_pkts_prepare;
			dev->tx_pkt_burst = sxe2_tx_pkts_vec_neon;
		} else {
			dev->tx_pkt_burst = sxe2_tx_pkts_vec_neon_simple;
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
}

static const struct {
	eth_tx_burst_t tx_burst;
	const char *info;
} sxe2_tx_burst_infos[] = {
	{ sxe2_tx_pkts,   "Scalar" },
#ifdef RTE_ARCH_X86
#ifdef CC_AVX512_SUPPORT
	{ sxe2_tx_pkts_vec_avx512,
	      "Vector AVX512" },
	{ sxe2_tx_pkts_vec_avx512_simple,
	      "Vector AVX512 Simple" },
#endif
	{ sxe2_tx_pkts_vec_avx2,
	      "Vector AVX2" },
	{ sxe2_tx_pkts_vec_avx2_simple,
	      "Vector AVX2 Simple" },
	{ sxe2_tx_pkts_vec_sse,
	      "Vector SSE" },
	{ sxe2_tx_pkts_vec_sse_simple,
	      "Vector SSE Simple" },
#endif
#ifdef RTE_ARCH_ARM64
	{ sxe2_tx_pkts_vec_neon,
	  "Vector NEON" },
	{ sxe2_tx_pkts_vec_neon_simple,
	  "Vector NEON Simple" },
#endif
};

int32_t sxe2_tx_burst_mode_get(struct rte_eth_dev *dev,
		__rte_unused uint16_t queue_id, struct rte_eth_burst_mode *mode)
{
	eth_tx_burst_t pkt_burst = dev->tx_pkt_burst;
	int32_t ret = -EINVAL;
	uint32_t i;
	uint32_t size;

	size = RTE_DIM(sxe2_tx_burst_infos);
	for (i = 0; i < size; ++i) {
		if (pkt_burst == sxe2_tx_burst_infos[i].tx_burst) {
			snprintf(mode->info, sizeof(mode->info), "%s",
					sxe2_tx_burst_infos[i].info);
			ret = 0;
			break;
		}
	}
	return ret;
}

static int32_t sxe2_rx_descriptor_status(void *rx_queue, uint16_t offset)
{
	struct sxe2_rx_queue *rxq = (struct sxe2_rx_queue *)rx_queue;
	volatile union sxe2_rx_desc *desc;
	int32_t ret;

	if (unlikely(offset >= rxq->ring_depth)) {
		ret = -EINVAL;
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

static int32_t sxe2_rx_queue_count(void *rx_queue)
{
	struct sxe2_rx_queue *rxq = (struct sxe2_rx_queue *)rx_queue;
	volatile union sxe2_rx_desc *desc;
	uint16_t done_num = 0;

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
	uint32_t rx_mode_flags = 0;
	int32_t ret;
	uint32_t vec_flags = 0;
	PMD_INIT_FUNC_TRACE();

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		ret = sxe2_rx_vec_support_check(dev, &vec_flags);
		if (ret == 0 &&
		    rte_vect_get_max_simd_bitwidth() >= RTE_VECT_SIMD_128) {
			rx_mode_flags = vec_flags;
#ifdef RTE_ARCH_X86
			if ((rte_vect_get_max_simd_bitwidth() >= RTE_VECT_SIMD_512) &&
				(rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX512F) == 1) &&
				(rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX512BW) == 1)) {
#ifdef CC_AVX512_SUPPORT
				rx_mode_flags |= SXE2_RX_MODE_VEC_AVX512;
#else
				PMD_LOG_INFO(RX, "AVX512 support detected but not enabled");
#endif
			}
			if (((rx_mode_flags & SXE2_RX_MODE_VEC_SET_MASK) == 0) &&
				((rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX2) == 1) ||
				(rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX512F) == 1)) &&
				(rte_vect_get_max_simd_bitwidth() >= RTE_VECT_SIMD_256))
				rx_mode_flags |= SXE2_RX_MODE_VEC_AVX2;

			if (((rx_mode_flags & SXE2_RX_MODE_VEC_SET_MASK) == 0) &&
				rte_vect_get_max_simd_bitwidth() >= RTE_VECT_SIMD_128)
				rx_mode_flags |= SXE2_RX_MODE_VEC_SSE;

#elif defined(RTE_ARCH_ARM64)
			if (rte_cpu_get_flag_enabled(RTE_CPUFLAG_NEON) == 1) {
				rx_mode_flags |= (vec_flags | SXE2_RX_MODE_VEC_NEON);
			}
#endif
			if ((rx_mode_flags & SXE2_RX_MODE_VEC_SET_MASK) != 0) {
				ret = sxe2_rx_queues_vec_prepare(dev);
				if (ret != 0)
					rx_mode_flags &= ~SXE2_RX_MODE_VEC_SET_MASK;
			}
		}
		adapter->q_ctxt.rx_mode_flags = rx_mode_flags;
	} else {
		rx_mode_flags = adapter->q_ctxt.rx_mode_flags;
	}

#ifdef RTE_ARCH_X86
	if (rx_mode_flags & SXE2_RX_MODE_VEC_SET_MASK) {
		if (rx_mode_flags & SXE2_RX_MODE_VEC_AVX512) {
#ifdef CC_AVX512_SUPPORT
			if (rx_mode_flags & SXE2_RX_MODE_VEC_OFFLOAD)
				dev->rx_pkt_burst = sxe2_rx_pkts_scattered_vec_avx512_offload;
			else
				dev->rx_pkt_burst = sxe2_rx_pkts_scattered_vec_avx512;
#endif
		} else if (rx_mode_flags & SXE2_RX_MODE_VEC_AVX2) {
			if (rx_mode_flags & SXE2_RX_MODE_VEC_OFFLOAD)
				dev->rx_pkt_burst = sxe2_rx_pkts_scattered_vec_avx2_offload;
			else
				dev->rx_pkt_burst = sxe2_rx_pkts_scattered_vec_avx2;
		} else {
			dev->rx_pkt_burst = sxe2_rx_pkts_scattered_vec_sse_offload;
		}
		return;
	}
#elif defined(RTE_ARCH_ARM64)
	if (rx_mode_flags & SXE2_RX_MODE_VEC_SET_MASK) {
		if (rx_mode_flags & SXE2_RX_MODE_VEC_OFFLOAD)
			dev->rx_pkt_burst = sxe2_rx_pkts_scattered_vec_neon_offload;
		else
			dev->rx_pkt_burst = sxe2_rx_pkts_scattered_vec_neon;
		return;
	}
#endif
	if (sxe2_rx_offload_en_check(dev, RTE_ETH_RX_OFFLOAD_BUFFER_SPLIT))
		dev->rx_pkt_burst = sxe2_rx_pkts_scattered_split;
	else
		dev->rx_pkt_burst = sxe2_rx_pkts_scattered;
}

static const struct {
	eth_rx_burst_t rx_burst;
	const char *info;
} sxe2_rx_burst_infos[] = {
	{ sxe2_rx_pkts_scattered,
	      "Scalar Scattered" },
	{ sxe2_rx_pkts_scattered_split,
	      "Scalar Scattered split" },
#ifdef RTE_ARCH_X86
#ifdef CC_AVX512_SUPPORT
	{ sxe2_rx_pkts_scattered_vec_avx512,
	      "Vector AVX512 Scattered" },
	{ sxe2_rx_pkts_scattered_vec_avx512_offload,
	      "Offload Vector AVX512 Scattered" },
#endif
	{ sxe2_rx_pkts_scattered_vec_avx2,
	      "Vector AVX2 Scattered" },
	{ sxe2_rx_pkts_scattered_vec_avx2_offload,
	      "Offload Vector AVX2 Scattered" },
	{ sxe2_rx_pkts_scattered_vec_sse_offload,
	      "Vector SSE Scattered" },
#endif
#ifdef RTE_ARCH_ARM64
	{ sxe2_rx_pkts_scattered_vec_neon,
	  "Vector NEON Scattered" },
	{ sxe2_rx_pkts_scattered_vec_neon_offload,
	  "Offload Vector NEON Scattered" },
#endif
};

int32_t sxe2_rx_burst_mode_get(struct rte_eth_dev *dev,
			       __rte_unused uint16_t queue_id,
			       struct rte_eth_burst_mode *mode)
{
	eth_rx_burst_t pkt_burst = dev->rx_pkt_burst;
	int32_t ret = -EINVAL;
	uint32_t i, size;

	size = RTE_DIM(sxe2_rx_burst_infos);
	for (i = 0; i < size; ++i) {
		if (pkt_burst == sxe2_rx_burst_infos[i].rx_burst) {
			snprintf(mode->info, sizeof(mode->info), "%s",
				 sxe2_rx_burst_infos[i].info);
			ret = 0;
			break;
		}
	}
	return ret;
}

void sxe2_set_common_function(struct rte_eth_dev *dev)
{
	PMD_INIT_FUNC_TRACE();
	dev->rx_queue_count = sxe2_rx_queue_count;
	dev->rx_descriptor_status = sxe2_rx_descriptor_status;

	dev->tx_descriptor_status = sxe2_tx_descriptor_status;
	dev->tx_pkt_prepare = sxe2_tx_pkts_prepare;
}

static void sxe2_init_ptype_list(uint32_t *ptype)
{
	/* ptype[0] reserved */
	ptype[1] = RTE_PTYPE_L2_ETHER;
	ptype[2] = RTE_PTYPE_L2_ETHER_TIMESYNC;
	/* ptype[3] - ptype[5] reserved */
	ptype[6] = RTE_PTYPE_L2_ETHER_LLDP;
	/* ECP */
	ptype[7] = RTE_PTYPE_UNKNOWN;
	/* ptype[8] - ptype[9] reserved */
	/* EAPol */
	ptype[10] = RTE_PTYPE_UNKNOWN;
	ptype[11] = RTE_PTYPE_L2_ETHER_ARP;
	/* ptype[12] - ptype[21] reserved */

	/* Non tunneled IPv4 */
	ptype[22] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_L4_FRAG;
	ptype[23] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_L4_NONFRAG;
	ptype[24] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_L4_UDP;
	/* ptype[25] reserved */
	ptype[26] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_L4_TCP;
	ptype[27] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_L4_SCTP;
	ptype[28] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_L4_ICMP;

	/* IPv4 --> IPv4 */
	ptype[29] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_IP |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_FRAG;
	ptype[30] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_IP |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[31] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_IP |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_UDP;
	/* ptype[32] reserved */
	ptype[33] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_IP |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_TCP;
	ptype[34] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_IP |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_SCTP;
	ptype[35] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_IP |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_ICMP;

	/* IPv4 --> IPv6 */
	ptype[36] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_IP |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_FRAG;
	ptype[37] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_IP |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[38] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_IP |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_UDP;
	/* ptype[39] reserved */
	ptype[40] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_IP |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_TCP;
	ptype[41] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_IP |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_SCTP;
	ptype[42] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_IP |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_ICMP;

	/* IPv4 --> GRE/GENEVE/VXLAN */
	ptype[43] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT;

	/* IPv4 --> GRE/GENEVE/VXLAN --> IPv4 */
	ptype[44] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_FRAG;
	ptype[45] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[46] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_UDP;
	/* ptype[47] reserved */
	ptype[48] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_TCP;
	ptype[49] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_SCTP;
	ptype[50] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_ICMP;

	/* IPv4 --> GRE/GENEVE/VXLAN --> IPv6 */
	ptype[51] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_FRAG;
	ptype[52] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[53] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_UDP;
	/* ptype[54] reserved */
	ptype[55] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_TCP;
	ptype[56] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_SCTP;
	ptype[57] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_ICMP;

	/* IPv4 --> GRE/GENEVE/VXLAN --> MAC */
	ptype[58] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER;

	/* IPv4 --> GRE/GENEVE/VXLAN --> MAC --> IPv4 */
	ptype[59] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_FRAG;
	ptype[60] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[61] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_UDP;
	/* ptype[62] reserved */
	ptype[63] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_TCP;
	ptype[64] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_SCTP;
	ptype[65] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_ICMP;

	/* IPv4 --> GRE/GENEVE/VXLAN --> MAC --> IPv6 */
	ptype[66] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_FRAG;
	ptype[67] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[68] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_UDP;
	/* ptype[69] reserved */
	ptype[70] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_TCP;
	ptype[71] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_SCTP;
	ptype[72] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_ICMP;
	/* IPv4 --> GRE/GENEVE/VXLAN --> MAC/VLAN */
	ptype[73] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN;
	/* IPv4 --> GRE/GENEVE/VXLAN --> MAC/VLAN --> IPv4 */
	ptype[74] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_FRAG;
	ptype[75] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[76] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_INNER_L4_UDP;
	/* ptype[77] reserved */
	ptype[78] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_INNER_L4_TCP;
	ptype[79] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_INNER_L4_SCTP;
	ptype[80] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_INNER_L4_ICMP;
	/* IPv4 --> GRE/GENEVE/VXLAN --> MAC/VLAN --> IPv6 */
	ptype[81] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN | RTE_PTYPE_INNER_L4_FRAG;
	ptype[82] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[83] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN | RTE_PTYPE_INNER_L4_UDP;
	/* ptype[64] reserved */
	ptype[85] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN | RTE_PTYPE_INNER_L4_TCP;
	ptype[86] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN | RTE_PTYPE_INNER_L4_SCTP;
	ptype[87] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN | RTE_PTYPE_INNER_L4_ICMP;
	/* Non tunneled IPv6 */
	ptype[88] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_L4_FRAG;
	ptype[89] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_L4_NONFRAG;
	ptype[90] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_L4_UDP;
	/* ptype[91] reserved */
	ptype[92] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_L4_TCP;
	ptype[93] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_L4_SCTP;
	ptype[94] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_L4_ICMP;

	/* IPv6 --> IPv4 */
	ptype[95] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_IP |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_FRAG;
	ptype[96] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_IP |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[97] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_IP |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_UDP;
	/* ptype[98] reserved */
	ptype[99] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_IP |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_TCP;
	ptype[100] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_IP |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_SCTP;
	ptype[101] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_IP |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_ICMP;

	/* IPv6 --> IPv6 */
	ptype[102] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_IP |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_FRAG;
	ptype[103] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_IP |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[104] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_IP |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_UDP;
	/* ptype[105] reserved */
	ptype[106] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_IP |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_TCP;
	ptype[107] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_IP |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_SCTP;
	ptype[108] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_IP |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_ICMP;

	/* IPv6 --> GRE/GENEVE/VXLAN */
	ptype[109] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT;

	/* IPv6 --> GRE/GENEVE/VXLAN --> IPv4 */
	ptype[110] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_FRAG;
	ptype[111] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[112] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_UDP;
	/* ptype[113] reserved */
	ptype[114] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_TCP;
	ptype[115] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_SCTP;
	ptype[116] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_ICMP;

	/* IPv6 --> GRE/GENEVE/VXLAN --> IPv6 */
	ptype[117] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_FRAG;
	ptype[118] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[119] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_UDP;
	/* ptype[120] reserved */
	ptype[121] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_TCP;
	ptype[122] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_SCTP;
	ptype[123] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_ICMP;

	/* IPv6 --> GRE/GENEVE/VXLAN --> MAC */
	ptype[124] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER;

	/* IPv6 --> GRE/GENEVE/VXLAN --> MAC --> IPv4 */
	ptype[125] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_FRAG;
	ptype[126] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[127] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_UDP;
	/* ptype[128] reserved */
	ptype[129] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_TCP;
	ptype[130] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_SCTP;
	ptype[131] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_ICMP;

	/* IPv6 --> GRE/GENEVE/VXLAN --> MAC --> IPv6 */
	ptype[132] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_FRAG;
	ptype[133] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[134] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_UDP;
	/* ptype[135] reserved */
	ptype[136] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_TCP;
	ptype[137] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_SCTP;
	ptype[138] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_ICMP;

	/* IPv6 --> GRE/GENEVE/VXLAN --> MAC/VLAN */
	ptype[139] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN;

	/* IPv6 --> GRE/GENEVE/VXLAN --> MAC/VLAN --> IPv4 */
	ptype[140] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_FRAG;
	ptype[141] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[142] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_INNER_L4_UDP;
	/* ptype[143] reserved */
	ptype[144] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_INNER_L4_TCP;
	ptype[145] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_INNER_L4_SCTP;
	ptype[146] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_INNER_L4_ICMP;

	/* IPv6 --> GRE/GENEVE/VXLAN --> MAC/VLAN --> IPv6 */
	ptype[147] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_FRAG;
	ptype[148] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[149] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN | RTE_PTYPE_INNER_L4_UDP;
	/* ptype[150] reserved */
	ptype[151] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN | RTE_PTYPE_INNER_L4_TCP;
	ptype[152] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN | RTE_PTYPE_INNER_L4_SCTP;
	ptype[153] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN | RTE_PTYPE_INNER_L4_ICMP;
	/* ptype[154] - ptype[159] reserved */
	/* IPSec */
	ptype[160] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_ESP;
	ptype[161] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_ESP;
	/* AH */
	ptype[162] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_L4_NONFRAG;
	ptype[163] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_NONFRAG;
	/* NAT-T-ESP */
	ptype[164] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_ESP;
	ptype[165] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_ESP;
	/* SDN-ESP */
	ptype[166] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_ESP;
	ptype[167] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_ESP;
	/* ptype[168] - ptype[271] reserved */
	/* IPV4 --> VRRP */
	ptype[272] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_L4_NONFRAG;
	/* IPV4 --> OSPF */
	ptype[273] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_L4_NONFRAG;
	/* IPV6 --> VRRP */
	ptype[274] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_NONFRAG;
	/* IPV6 --> VRRP */
	ptype[275] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_NONFRAG;
	/* ATAoE */
	ptype[276] = RTE_PTYPE_UNKNOWN;
	/* Control */
	ptype[278] = RTE_PTYPE_UNKNOWN;
	/* ptype[279] - ptype[324] reserved */
	/* GTP */
	ptype[325] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_GTPC;
	ptype[326] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_GTPC;
	ptype[327] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_GTPC;
	ptype[328] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_GTPC;
	ptype[329] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_GTPU;
	ptype[330] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_GTPU;
	ptype[331] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_GTPU |
		RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_FRAG;
	ptype[332] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_GTPU |
		RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[333] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_GTPU |
		RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[334] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_GTPU |
		RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_TCP;
	ptype[335] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_GTPU |
		RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_ICMP;
	ptype[336] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_GTPU |
		RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_FRAG;
	ptype[337] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_GTPU |
		RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[338] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_GTPU |
		RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[339] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_GTPU |
		RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_TCP;
	ptype[340] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_GTPU |
		RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_ICMP;
	ptype[341] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_GTPU |
		RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_FRAG;
	ptype[342] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_GTPU |
		RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[343] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_GTPU |
		RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[344] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_GTPU |
		RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_TCP;
	ptype[345] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_GTPU |
		RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_ICMP;
	ptype[346] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_GTPU |
		RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_FRAG;
	ptype[347] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_GTPU |
		RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[348] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_GTPU |
		RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[349] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_GTPU |
		RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_TCP;
	ptype[350] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_GTPU |
		RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_ICMP;
	/* PFCP */
	ptype[351] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_L4_UDP;
	ptype[352] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_L4_UDP;
	ptype[353] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_L4_UDP;
	ptype[354] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_L4_UDP;
	/* ptype[355] - ptype[359] reserved */
	/* L2TPv3 */
	ptype[360] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_L2TP;
	ptype[361] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_L2TP;
	/* ptype[362] - ptype[370] reserved */
	/* eCPRI */
	ptype[371] = RTE_PTYPE_UNKNOWN;
	ptype[381] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_L4_UDP;
	ptype[391] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_UDP;
	ptype[396] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	/* MAC, IPv6, UDP, TUN, MAC, IPv4, IGMP */
	ptype[397] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	/* MAC, IPv4, UDP, TUN, MAC, IPv4, EIGRP */
	ptype[398] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	/* MAC, IPv6, UDP, TUN, MAC, IPv4, EIGRP */
	ptype[399] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	/* MAC, IPv4, UDP, TUN, MAC, IPv4, PIM */
	ptype[400] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	/* MAC, IPv6, UDP, TUN, MAC, IPv4, PIM */
	ptype[401] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	/* MAC, IPv4, UDP, TUN, MAC, IPv6, IGMP */
	ptype[402] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	/* MAC, IPv6, UDP, TUN, MAC, IPv6, IGMP */
	ptype[403] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	/* MAC, IPv4, UDP, TUN, MAC, IPv6, EIGRP */
	ptype[404] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	/* MAC, IPv6, UDP, TUN, MAC, IPv6, EIGRP */
	ptype[405] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	/* MAC, IPv4, UDP, TUN, MAC, IPv6, PIM */
	ptype[406] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	/* MAC, IPv6, UDP, TUN, MAC, IPv6, PIM */
	ptype[407] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	/* MAC, IPv4, UDP, TUN, MAC, IPv4, VRRP */
	ptype[408] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	/* MAC, IPv6, UDP, TUN, MAC, IPv4, VRRP */
	ptype[409] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	/* MAC, IPv4, UDP, TUN, MAC, IPv6, VRRP */
	ptype[410] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	/* MAC, IPv6, UDP, TUN, MAC, IPv6, VRRP */
	ptype[411] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	/* MAC, IPv4, UDP, TUN, MAC, IPv4, OSPF */
	ptype[412] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	/* MAC, IPv6, UDP, TUN, MAC, IPv4, OSPF */
	ptype[413] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	/* MAC, IPv4, UDP, TUN, MAC, IPv6, OSPF */
	ptype[414] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	/* MAC, IPv6, UDP, TUN, MAC, IPv6, OSPF */
	ptype[415] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	/* MAC, IPv4, UDP, TUN, MAC, IPv4, L2_TP_V3 */
	ptype[416] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	/* MAC, IPv6, UDP, TUN, MAC, IPv4, L2_TP_V3 */
	ptype[417] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	/* MAC, IPv4, UDP, TUN, MAC, IPv6, L2_TP_V3 */
	ptype[418] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	/* MAC, IPv6, UDP, TUN, MAC, IPv6, L2_TP_V3 */
	ptype[419] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	/* MAC, IPv4, UDP, TUN, MAC, IPv4, AH */
	ptype[420] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	/* MAC, IPv6, UDP, TUN, MAC, IPv4, AH */
	ptype[421] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	/* MAC, IPv4, UDP, TUN, MAC, IPv6, AH */
	ptype[422] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	/* MAC, IPv6, UDP, TUN, MAC, IPv6, AH */
	ptype[423] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	/* MAC, IPv4, UDP, TUN, MAC, IPv4, ESP */
	ptype[424] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	/* MAC, IPv6, UDP, TUN, MAC, IPv4, ESP */
	ptype[425] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	/* MAC, IPv4, UDP, TUN, MAC, IPv6, ESP */
	ptype[426] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	/* MAC, IPv6, UDP, TUN, MAC, IPv6, ESP */
	ptype[427] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	/* TP-TUN GTPU */
	ptype[450] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[451] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[452] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[453] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[454] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[455] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[456] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[457] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[458] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[459] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[460] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[461] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[462] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[463] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[464] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[465] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[466] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[467] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[468] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[469] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[470] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[471] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[472] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[473] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[474] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[475] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[476] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[477] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[478] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[479] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[480] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[481] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[482] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[483] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[484] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[485] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[486] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[487] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[488] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[489] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[490] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[491] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[492] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[493] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[494] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[495] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[496] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	ptype[497] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_INNER_L4_UDP;
	/* ptype[498] - ptype[767] reserved */
	/* L2(NETWORK CPU) */
	/* ISIS */
	ptype[768] = RTE_PTYPE_UNKNOWN;
	/* SDF */
	ptype[769] = RTE_PTYPE_UNKNOWN;
	/* PPoE_NEGO */
	ptype[770] = RTE_PTYPE_L2_ETHER_PPPOE;
	/* PPoE_PROTOCOL */
	ptype[771] = RTE_PTYPE_L2_ETHER_PPPOE;
	ptype[772] = RTE_PTYPE_L2_ETHER_PPPOE;
	/* LACP */
	ptype[773] = RTE_PTYPE_UNKNOWN;
	/* ptype[774] - ptype[775] reserved */
	/* IPv4 L3(NETWORK CPU) */
	ptype[776] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_L4_IGMP;
	/* EIGRP */
	ptype[777] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_L4_NONFRAG;
	/* PIM */
	ptype[778] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_L4_NONFRAG;
	ptype[779] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_L2TP;
	ptype[780] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_L2TP;
	ptype[781] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_L2TP;
	/* ptype[782] - ptype[783] reserved */
	/* IPv6 L3(NETWORK CPU) */
	ptype[784] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_IGMP;
	/* EIGRP */
	ptype[785] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_NONFRAG;
	/* PIM */
	ptype[786] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_NONFRAG;
	ptype[787] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_L2TP;
	ptype[788] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_L2TP;
	ptype[789] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_L2TP;
	/* ptype[790] - ptype[791] reserved */
	/* IPv4 L4(NETWORK CPU) */
	ptype[792] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_L4_TCP;
	ptype[793] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_L4_TCP;
	ptype[794] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_L4_UDP;
	ptype[795] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_L4_UDP;
	ptype[796] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_L4_UDP;
	ptype[797] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
		RTE_PTYPE_L4_UDP;
	ptype[798] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_L4_UDP;
	ptype[799] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_L4_UDP;
	ptype[800] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_L4_UDP;
	ptype[801] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_L4_UDP;
	/* ptype[802] - ptype[807] reserved */
	/* IPv6 L4(NETWORK CPU) */
	ptype[808] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_TCP;
	ptype[809] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_TCP;
	ptype[810] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_UDP;
	ptype[811] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_UDP;
	ptype[812] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
		RTE_PTYPE_L4_UDP;
	ptype[813] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_UDP;
	ptype[814] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_UDP;
	ptype[815] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_UDP;
	ptype[816] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_UDP;
	ptype[817] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_UDP;
	/* ptype[818] - ptype[819] reserved */
	/* IPv6 -> MAC */
	ptype[820] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_NONFRAG;
	/* IPv6 -> MAC -> IPv4*/
	ptype[821] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_NONFRAG;
	ptype[822] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_NONFRAG;
	ptype[823] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_NONFRAG;
	ptype[824] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_NONFRAG;
	ptype[825] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_NONFRAG;
	ptype[826] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_NONFRAG;
	/* IPv6 -> MAC -> IPv4*/
	ptype[827] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_NONFRAG;
	ptype[828] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_NONFRAG;
	ptype[829] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_NONFRAG;
	ptype[830] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_NONFRAG;
	ptype[831] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_NONFRAG;
	ptype[832] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_NONFRAG;
	/* ptype[833] - ptype[834] reserved */
	/* IPv6 -> MAC/VLAN */
	ptype[835] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_NONFRAG;
	/* IPv6 -> MAC/VLAN -> IPv4 */
	ptype[836] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_NONFRAG;
	ptype[837] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_NONFRAG;
	ptype[838] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_NONFRAG;
	ptype[839] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_NONFRAG;
	ptype[840] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_NONFRAG;
	ptype[841] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_NONFRAG;
	/* IPv6 -> MAC/VLAN -> IPv6 */
	ptype[842] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_NONFRAG;
	ptype[843] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_NONFRAG;
	ptype[844] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_NONFRAG;
	ptype[845] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_NONFRAG;
	ptype[846] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_NONFRAG;
	ptype[847] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_L4_NONFRAG;

	/* IPv6 -> UDP -> VXLAN/GENEVE -> PAY */
	ptype[878] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT;

	/* IPv6 -> UDP -> VXLAN/GENEVE -> IPv4 */
	ptype[877] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_FRAG;
	ptype[876] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[879] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_UDP;
	ptype[880] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_TCP;
	ptype[875] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_SCTP;
	ptype[874] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_ICMP;

	/* IPv6 -> UDP -> VXLAN/GENEVE -> IPv6 */
	ptype[871] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_FRAG;
	ptype[870] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[872] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_UDP;
	ptype[873] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_TCP;
	ptype[869] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_SCTP;
	ptype[868] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_ICMP;

	/* IPv4 -> UDP -> VXLAN/GENEVE -> PAY */
	ptype[891] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT;
	/* IPv4 -> UDP -> VXLAN/GENEVE -> IPv4 */
	ptype[890] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_FRAG;
	ptype[889] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[892] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_UDP;
	ptype[893] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_TCP;
	ptype[888] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_SCTP;
	ptype[887] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_ICMP;
	/* IPv4 -> UDP -> VXLAN/GENEVE -> IPv6 */
	ptype[884] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_FRAG;
	ptype[883] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[885] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_UDP;
	ptype[886] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_TCP;
	ptype[882] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_SCTP;
	ptype[881] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_ICMP;

	/* IPv6 -> UDP -> GRE -> PAY */
	ptype[904] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT;
	/* IPv6 -> UDP -> GRE -> IPv4 */
	ptype[903] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_FRAG;
	ptype[902] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[905] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_UDP;
	ptype[906] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_TCP;
	ptype[901] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_SCTP;
	ptype[900] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_ICMP;
	/* IPv6 -> UDP -> GRE -> IPv6 */
	ptype[897] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_FRAG;
	ptype[896] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[898] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_UDP;
	ptype[899] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_TCP;
	ptype[895] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_SCTP;
	ptype[894] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_ICMP;

	/* IPv4 -> UDP -> GRE -> PAY */
	ptype[917] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT;
	/* IPv4 -> UDP -> GRE -> IPv4 */
	ptype[916] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_FRAG;
	ptype[915] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[918] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_UDP;
	ptype[919] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_TCP;
	ptype[914] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_SCTP;
	ptype[913] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_ICMP;
	/* IPv4 -> UDP -> GRE -> IPv6 */
	ptype[910] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_FRAG;
	ptype[909] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[911] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_UDP;
	ptype[912] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_TCP;
	ptype[908] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_SCTP;
	ptype[907] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_ICMP;

	/* IPv6 -> UDP -> VXLAN/GENEVE -> MACVLAN -> PAY */
	ptype[930] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN;

	/* IPv6 -> UDP -> VXLAN/GENEVE -> MACVLAN -> IPv4 */
	ptype[929] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_FRAG;
	ptype[928] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[931] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_UDP;
	ptype[932] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_TCP;
	ptype[927] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_SCTP;
	ptype[926] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_ICMP;

	/* IPv6 -> UDP -> VXLAN/GENEVE -> MACVLAN -> IPv6 */
	ptype[923] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_FRAG;
	ptype[922] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[924] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_UDP;
	ptype[925] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_TCP;
	ptype[921] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_SCTP;
	ptype[920] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_ICMP;

	/* IPv4 -> UDP -> VXLAN/GENEVE -> MACVLAN -> PAY */
	ptype[943] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN;
	/* IPv4 -> UDP -> VXLAN/GENEVE -> MACVLAN -> IPv4 */
	ptype[942] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_FRAG;
	ptype[941] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[944] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_UDP;
	ptype[945] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_TCP;
	ptype[940] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_SCTP;
	ptype[939] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_ICMP;
	/* IPv4 -> UDP -> VXLAN/GENEVE -> MACVLAN -> IPv6 */
	ptype[936] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_FRAG;
	ptype[935] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[937] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_UDP;
	ptype[938] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_TCP;
	ptype[934] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_SCTP;
	ptype[933] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_ICMP;

	/* IPv6 > UDP -> GRE -> MACVLAN -> PAY */
	ptype[956] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN;
	/* IPv6 -> UDP -> GRE -> MACVLAN -> IPv4 */
	ptype[955] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_FRAG;
	ptype[954] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[957] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_UDP;
	ptype[958] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_TCP;
	ptype[953] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_SCTP;
	ptype[952] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_ICMP;
	/* IPv6 -> UDP -> GRE -> MACVLAN -> IPv6 */
	ptype[949] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_FRAG;
	ptype[948] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[950] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_UDP;
	ptype[951] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_TCP;
	ptype[947] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_SCTP;
	ptype[946] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_ICMP;

	/* IPv4 -> UDP -> GRE -> MACVLAN -> PAY */
	ptype[969] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN;
	/* IPv4 -> UDP -> GRE -> MACVLAN -> IPv4 */
	ptype[968] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_FRAG;
	ptype[967] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[970] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_UDP;
	ptype[971] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_TCP;
	ptype[966] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_SCTP;
	ptype[965] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_ICMP;
	/* IPv4 -> UDP -> GRE -> MACVLAN -> IPv6 */
	ptype[962] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_FRAG;
	ptype[961] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[963] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_UDP;
	ptype[964] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_TCP;
	ptype[960] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_SCTP;
	ptype[959] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER_VLAN |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_ICMP;

	/* IPv6 -> UDP -> VXLAN/GENEVE -> MAC -> PAY */
	ptype[982] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER;

	/* IPv6 -> UDP -> VXLAN/GENEVE -> MAC -> IPv4 */
	ptype[981] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_FRAG;
	ptype[980] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[983] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_UDP;
	ptype[984] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_TCP;
	ptype[979] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_SCTP;
	ptype[978] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_ICMP;

	/* IPv6 -> UDP -> VXLAN/GENEVE -> MAC -> IPv6 */
	ptype[975] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_FRAG;
	ptype[974] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[976] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_UDP;
	ptype[977] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_TCP;
	ptype[973] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_SCTP;
	ptype[972] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				 RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_INNER_L4_ICMP;

	/* IPv4 -> UDP -> VXLAN/GENEVE -> MAC -> PAY */
	ptype[995] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER;
	/* IPv4 -> UDP -> VXLAN/GENEVE -> MAC -> IPv4 */
	ptype[994] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_FRAG;
	ptype[993] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[996] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_UDP;
	ptype[997] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_TCP;
	ptype[992] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_SCTP;
	ptype[991] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_ICMP;
	/* IPv4 -> UDP -> VXLAN/GENEVE -> MAC -> IPv6 */
	ptype[988] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_FRAG;
	ptype[987] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[989] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_UDP;
	ptype[990] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_TCP;
	ptype[986] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_SCTP;
	ptype[985] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_ICMP;

	/* IPv6 > UDP -> GRE -> MAC -> PAY */
	ptype[1008] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER;
	/* IPv6 -> UDP -> GRE -> MAC -> IPv4 */
	ptype[1007] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_FRAG;
	ptype[1006] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[1009] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_UDP;
	ptype[1010] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_TCP;
	ptype[1005] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_SCTP;
	ptype[1004] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_ICMP;
	/* IPv6 -> UDP -> GRE -> MAC -> IPv6 */
	ptype[1001] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_FRAG;
	ptype[1000] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[1002] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_UDP;
	ptype[1003] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_TCP;
	ptype[999] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_SCTP;
	ptype[998] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_ICMP;

	/* IPv4 -> UDP -> GRE -> MAC -> PAY */
	ptype[1021] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				 RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER;
	/* IPv4 -> UDP -> GRE -> MAC -> IPv4 */
	ptype[1020] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_FRAG;
	ptype[1019] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[1022] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_UDP;
	ptype[1023] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_TCP;
	ptype[1018] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_SCTP;
	ptype[1017] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_ICMP;
	/* IPv4 -> UDP -> GRE -> MAC -> IPv6 */
	ptype[1014] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_FRAG;
	ptype[1013] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_NONFRAG;
	ptype[1015] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_UDP;
	ptype[1016] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_TCP;
	ptype[1012] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_SCTP;
	ptype[1011] = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
				RTE_PTYPE_TUNNEL_GRENAT | RTE_PTYPE_INNER_L2_ETHER |
				RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				RTE_PTYPE_INNER_L4_ICMP;
}

void sxe2_init_ptype_tbl(struct rte_eth_dev *dev)
{
	struct sxe2_adapter *adapter = SXE2_DEV_PRIVATE_TO_ADAPTER(dev);
	uint32_t *ptype = adapter->ptype_tbl;

	PMD_INIT_FUNC_TRACE();
	sxe2_init_ptype_list(ptype);
}

const uint32_t *
sxe2_dev_supported_ptypes_get(struct rte_eth_dev *dev, size_t *no_of_elements)
{
	const uint32_t *ret = NULL;

	static const uint32_t ptypes[] = {
		RTE_PTYPE_L2_ETHER,
		RTE_PTYPE_L2_ETHER_TIMESYNC,
		RTE_PTYPE_L2_ETHER_LLDP,
		RTE_PTYPE_L2_ETHER_ARP,
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN,
		RTE_PTYPE_L3_IPV6_EXT_UNKNOWN,
		RTE_PTYPE_L4_FRAG,
		RTE_PTYPE_L4_ICMP,
		RTE_PTYPE_L4_NONFRAG,
		RTE_PTYPE_L4_SCTP,
		RTE_PTYPE_L4_TCP,
		RTE_PTYPE_L4_UDP,
		RTE_PTYPE_TUNNEL_GRENAT,
		RTE_PTYPE_TUNNEL_IP,
		RTE_PTYPE_INNER_L2_ETHER,
		RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN,
		RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN,
		RTE_PTYPE_INNER_L4_FRAG,
		RTE_PTYPE_INNER_L4_ICMP,
		RTE_PTYPE_INNER_L4_NONFRAG,
		RTE_PTYPE_INNER_L4_SCTP,
		RTE_PTYPE_INNER_L4_TCP,
		RTE_PTYPE_INNER_L4_UDP,
		RTE_PTYPE_UNKNOWN
	};

	if (dev->rx_pkt_burst != NULL) {
		*no_of_elements = RTE_DIM(ptypes);
		ret = ptypes;
	} else {
		ret = NULL;
	}

	return ret;
}

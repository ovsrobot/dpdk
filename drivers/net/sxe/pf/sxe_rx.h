/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#ifndef __SXE_DPDK_RX_H__
#define __SXE_DPDK_RX_H__

#include "sxe_types.h"
#include "sxe_queue.h"
#include "sxe_hw.h"
#include "sxe_compat_version.h"
#include "sxe_logs.h"

#define SXE_RXDADV_ERR_CKSUM_BIT  30
#define SXE_RXDADV_ERR_CKSUM_MSK  3

#define SXE_PACKET_TYPE_MAX			   0X80
#define SXE_PACKET_TYPE_TN_MAX			0X100
#define SXE_PACKET_TYPE_MASK			  0X7F
#define SXE_RXD_STAT_TMST				 0x10000

#define SXE_DESCS_PER_LOOP 4

#define SXE_PCI_REG_WC_WRITE(reg, value)			\
	rte_write32_wc((rte_cpu_to_le_32(value)), reg)
#define SXE_PCI_REG_WC_WRITE_RELAXED(reg, value)		\
	rte_write32_wc_relaxed((rte_cpu_to_le_32(value)), reg)

#define SXE_RX_RING_SIZE ((SXE_MAX_RING_DESC + RTE_PMD_SXE_MAX_RX_BURST) * \
			sizeof(sxe_rx_data_desc_u))

extern const u32 sxe_ptype_table[SXE_PACKET_TYPE_MAX];
extern const u32 sxe_ptype_table_tn[SXE_PACKET_TYPE_TN_MAX];

static inline u64 sxe_rx_desc_status_to_pkt_flags(u32 rx_status,
							u64 vlan_flags)
{
	u64 pkt_flags;

	pkt_flags = (rx_status & SXE_RXD_STAT_VP) ?  vlan_flags : 0;

#ifdef RTE_LIBRTE_IEEE1588
	if (rx_status & SXE_RXD_STAT_TMST)
		pkt_flags = pkt_flags | RTE_MBUF_F_RX_IEEE1588_TMST;
#endif
	return pkt_flags;
}

static inline u64 sxe_rx_desc_error_to_pkt_flags(u32 rx_status)
{
	u64 pkt_flags;

	static u64 error_to_pkt_flags_map[4] = {
		RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_GOOD,
		RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_BAD,
		RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_GOOD,
		RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_BAD
	};

	pkt_flags = error_to_pkt_flags_map[(rx_status >>
		SXE_RXDADV_ERR_CKSUM_BIT) & SXE_RXDADV_ERR_CKSUM_MSK];

	if ((rx_status & SXE_RXD_STAT_OUTERIPCS) &&
		(rx_status & SXE_RXDADV_ERR_OUTERIPER)) {
		pkt_flags |= RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD;
	}

	return pkt_flags;
}

static inline u64 sxe_rx_desc_pkt_info_to_pkt_flags(u16 pkt_info)
{
	u64 flags = 0;

	static alignas(RTE_CACHE_LINE_SIZE) u64 ip_rss_types_map[16] = {
		0, RTE_MBUF_F_RX_RSS_HASH, RTE_MBUF_F_RX_RSS_HASH, RTE_MBUF_F_RX_RSS_HASH,
		0, RTE_MBUF_F_RX_RSS_HASH, 0, RTE_MBUF_F_RX_RSS_HASH,
		RTE_MBUF_F_RX_RSS_HASH, 0, 0, 0,
		0, 0, 0,  RTE_MBUF_F_RX_FDIR,
	};

#ifdef RTE_LIBRTE_IEEE1588
		static u64 ip_pkt_etqf_map[8] = {
			0, 0, 0, RTE_MBUF_F_RX_IEEE1588_PTP,
			0, 0, 0, 0,
		};

		if (likely(pkt_info & SXE_RXDADV_PKTTYPE_ETQF)) {
			flags = ip_pkt_etqf_map[(pkt_info >> 4) & 0X07] |
				ip_rss_types_map[pkt_info & 0XF];
		} else {
			flags = ip_rss_types_map[pkt_info & 0XF];
		}
#else
		flags = ip_rss_types_map[pkt_info & 0XF];
#endif
	return flags;
}

static inline u32 sxe_rxd_pkt_info_to_pkt_type(u32 pkt_info,
							u16 ptype_mask)
{
	if (unlikely(pkt_info & SXE_RXDADV_PKTTYPE_ETQF))
		return RTE_PTYPE_UNKNOWN;

	pkt_info = (pkt_info >> SXE_RXDADV_PKTTYPE_ETQF_SHIFT) & ptype_mask;

	pkt_info &= SXE_PACKET_TYPE_MASK;

	return sxe_ptype_table[pkt_info];
}

static inline u32 sxe_lro_count(sxe_rx_data_desc_u *rx)
{
	return (rte_le_to_cpu_32(rx->wb.lower.lo_dword.data) &
		SXE_RXDADV_LROCNT_MASK) >> SXE_RXDADV_LROCNT_SHIFT;
}

static inline bool __rte_cold
	sxe_check_is_rx_batch_alloc_support(sxe_rx_queue_s *rxq)
{
	bool support = true;

	if (!(rxq->batch_alloc_size >= RTE_PMD_SXE_MAX_RX_BURST)) {
		PMD_LOG_DEBUG(INIT, "rx burst batch alloc check: "
				 "rxq->batch_alloc_size=%d, "
				 "RTE_PMD_SXE_MAX_RX_BURST=%d",
				 rxq->batch_alloc_size, RTE_PMD_SXE_MAX_RX_BURST);
		support = false;
	} else if (!(rxq->batch_alloc_size < rxq->ring_depth)) {
		PMD_LOG_DEBUG(INIT, "rx burst batch alloc check: "
				 "rxq->batch_alloc_size=%d, "
				 "rxq->ring_depth=%d",
				 rxq->batch_alloc_size, rxq->ring_depth);
		support = false;
	} else if (!((rxq->ring_depth % rxq->batch_alloc_size) == 0)) {
		PMD_LOG_DEBUG(INIT, "rx burst batch alloc preconditions: "
				 "rxq->nb_rx_desc=%d, "
				 "rxq->batch_alloc_size=%d",
				 rxq->ring_depth, rxq->batch_alloc_size);
		support = false;
	}

	return support;
}

s32 sxe_rx_configure(struct rte_eth_dev *dev);

void sxe_rx_function_set(struct rte_eth_dev *dev,
		bool rx_batch_alloc_allowed, bool *rx_vec_allowed);

s32 sxe_rx_descriptor_status(void *rx_queue, u16 offset);

u16 sxe_pkts_recv(void *rx_queue, struct rte_mbuf **rx_pkts, u16 num_pkts);

s32 sxe_rx_queue_setup(struct rte_eth_dev *dev,
			 u16 queue_idx, u16 num_desc,
			 unsigned int socket_id,
			 const struct rte_eth_rxconf *rx_conf,
			 struct rte_mempool *mp);

s32 sxe_rx_features_configure(struct rte_eth_dev *dev);

const u32 *sxe_dev_supported_ptypes_get(struct rte_eth_dev *dev, size_t *no_of_elements);

s32
sxe_monitor_addr_get(void *rx_queue, struct rte_power_monitor_cond *pmc);

void sxe_rx_mbuf_common_header_fill(sxe_rx_queue_s *rxq,
					struct rte_mbuf *mbuf,
					volatile sxe_rx_data_desc_u desc,
					u32 pkt_info, u32 staterr);

u16 sxe_batch_alloc_lro_pkts_recv(void *rx_queue,
					struct rte_mbuf **rx_pkts,
					u16 pkts_num);

u16 sxe_single_alloc_lro_pkts_recv(void *rx_queue,
					struct rte_mbuf **rx_pkts,
					u16 pkts_num);

u16 sxe_batch_alloc_pkts_recv(void *rx_queue,
					struct rte_mbuf **rx_pkts,
					u16 pkts_num);

void sxe_vmdq_rx_mode_get(u32 rx_mask, u32 *orig_val);

#endif

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SIMD
#include <stdint.h>
#include <ethdev_driver.h>
#include <rte_malloc.h>

#include <rte_vect.h>
#include "sxe_vec_common.h"

#define RTE_SXE_DESCS_PER_LOOP			4
#define SXE_PACKET_TYPE_MASK_TUNNEL		0xFF
#define SXE_PACKET_TYPE_SHIFT			0x04
#define SXE_RXDADV_ERR_TCPE				0x40000000
#define SXE_VPMD_DESC_EOP_MASK			0x02020202
#define SXE_UINT8_BIT					(CHAR_BIT * sizeof(u8))

static inline void
sxe_rxq_rearm(struct sxe_rx_queue *rxq)
{
	s32 i;
	u16 rx_id;
	volatile union sxe_rx_data_desc *rxdp;
	struct sxe_rx_buffer *rxep = &rxq->buffer_ring[rxq->realloc_start];
	struct rte_mbuf *mb0, *mb1;
	uint64x2_t dma_addr0, dma_addr1;
	uint64x2_t zero = vdupq_n_u64(0);
	u64 paddr;
	uint8x8_t p;

	rxdp = rxq->desc_ring + rxq->realloc_start;

	if (unlikely(rte_mempool_get_bulk(rxq->mb_pool,
					  (void *)rxep,
					  RTE_PMD_SXE_MAX_RX_BURST) < 0)) {
		if (rxq->realloc_num + RTE_PMD_SXE_MAX_RX_BURST >=
			rxq->ring_depth) {
			for (i = 0; i < RTE_SXE_DESCS_PER_LOOP; i++) {
				rxep[i].mbuf = &rxq->fake_mbuf;
				vst1q_u64(RTE_CAST_PTR(u64 *, &rxdp[i].read),
					  zero);
			}
		}
		rte_eth_devices[rxq->port_id].data->rx_mbuf_alloc_failed +=
			RTE_PMD_SXE_MAX_RX_BURST;
		return;
	}

	p = vld1_u8((u8 *)&rxq->mbuf_init_value);

	for (i = 0; i < RTE_PMD_SXE_MAX_RX_BURST; i += 2, rxep += 2) {
		mb0 = rxep[0].mbuf;
		mb1 = rxep[1].mbuf;

		vst1_u8((u8 *)&mb0->rearm_data, p);
		paddr = mb0->buf_iova + RTE_PKTMBUF_HEADROOM;
		dma_addr0 = vsetq_lane_u64(paddr, zero, 0);

		vst1q_u64(RTE_CAST_PTR(u64 *, &rxdp++->read), dma_addr0);

		vst1_u8((u8 *)&mb1->rearm_data, p);
		paddr = mb1->buf_iova + RTE_PKTMBUF_HEADROOM;
		dma_addr1 = vsetq_lane_u64(paddr, zero, 0);
		vst1q_u64(RTE_CAST_PTR(u64 *, &rxdp++->read), dma_addr1);
	}

	rxq->realloc_start += RTE_PMD_SXE_MAX_RX_BURST;
	if (rxq->realloc_start >= rxq->ring_depth)
		rxq->realloc_start = 0;

	rxq->realloc_num -= RTE_PMD_SXE_MAX_RX_BURST;

	rx_id = (u16)((rxq->realloc_start == 0) ?
				(rxq->ring_depth - 1) : (rxq->realloc_start - 1));

	sxe_write_addr(rx_id, rxq->rdt_reg_addr);
}

static inline void
sxe_desc_to_olflags_v(uint8x16x2_t sterr_tmp1, uint8x16x2_t sterr_tmp2,
		  uint8x16_t staterr, u8 vlan_flags, u16 udp_p_flag,
		  struct rte_mbuf **rx_pkts)
{
	u16 udp_p_flag_hi;
	uint8x16_t ptype, udp_csum_skip;
	uint32x4_t temp_udp_csum_skip = {0, 0, 0, 0};
	uint8x16_t vtag_lo, vtag_hi, vtag;
	uint8x16_t temp_csum;
	uint32x4_t csum = {0, 0, 0, 0};

	union {
		u16 e[4];
		u64 word;
	} vol;

	const uint8x16_t rsstype_msk = {
			0x0F, 0x0F, 0x0F, 0x0F,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00};

	const uint8x16_t rss_flags = {
			0, RTE_MBUF_F_RX_RSS_HASH, RTE_MBUF_F_RX_RSS_HASH, RTE_MBUF_F_RX_RSS_HASH,
			0, RTE_MBUF_F_RX_RSS_HASH, 0, RTE_MBUF_F_RX_RSS_HASH,
			RTE_MBUF_F_RX_RSS_HASH, 0, 0, 0,
			0, 0, 0, RTE_MBUF_F_RX_FDIR};

	const uint8x16_t vlan_csum_msk = {
			SXE_RXD_STAT_VP, SXE_RXD_STAT_VP,
			SXE_RXD_STAT_VP, SXE_RXD_STAT_VP,
			0, 0, 0, 0,
			0, 0, 0, 0,
			(SXE_RXDADV_ERR_TCPE | SXE_RXDADV_ERR_IPE) >> 24,
			(SXE_RXDADV_ERR_TCPE | SXE_RXDADV_ERR_IPE) >> 24,
			(SXE_RXDADV_ERR_TCPE | SXE_RXDADV_ERR_IPE) >> 24,
			(SXE_RXDADV_ERR_TCPE | SXE_RXDADV_ERR_IPE) >> 24};

	const uint8x16_t vlan_csum_map_lo = {
			RTE_MBUF_F_RX_IP_CKSUM_GOOD,
			RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_BAD,
			RTE_MBUF_F_RX_IP_CKSUM_BAD,
			RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_BAD,
			0, 0, 0, 0,
			vlan_flags | RTE_MBUF_F_RX_IP_CKSUM_GOOD,
			vlan_flags | RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_BAD,
			vlan_flags | RTE_MBUF_F_RX_IP_CKSUM_BAD,
			vlan_flags | RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_BAD,
			0, 0, 0, 0};

	const uint8x16_t vlan_csum_map_hi = {
			RTE_MBUF_F_RX_L4_CKSUM_GOOD >> sizeof(u8), 0,
			RTE_MBUF_F_RX_L4_CKSUM_GOOD >> sizeof(u8), 0,
			0, 0, 0, 0,
			RTE_MBUF_F_RX_L4_CKSUM_GOOD >> sizeof(u8), 0,
			RTE_MBUF_F_RX_L4_CKSUM_GOOD >> sizeof(u8), 0,
			0, 0, 0, 0};

	udp_p_flag_hi = udp_p_flag >> 8;

	const uint8x16_t udp_hdr_p_msk = {
			0, 0, 0, 0,
			udp_p_flag_hi, udp_p_flag_hi, udp_p_flag_hi, udp_p_flag_hi,
			0, 0, 0, 0,
			0, 0, 0, 0};

	const uint8x16_t udp_csum_bad_shuf = {
			0xFF, ~(u8)RTE_MBUF_F_RX_L4_CKSUM_BAD, 0, 0,
			0, 0, 0, 0,
			0, 0, 0, 0,
			0, 0, 0, 0};

	ptype = vzipq_u8(sterr_tmp1.val[0], sterr_tmp2.val[0]).val[0];

	udp_csum_skip = vandq_u8(ptype, udp_hdr_p_msk);

	temp_udp_csum_skip = vcopyq_laneq_u32(temp_udp_csum_skip, 0,
				vreinterpretq_u32_u8(udp_csum_skip), 1);

	ptype = vandq_u8(ptype, rsstype_msk);
	ptype = vqtbl1q_u8(rss_flags, ptype);

	vtag = vandq_u8(staterr, vlan_csum_msk);

	temp_csum = vshrq_n_u8(vtag, 6);

	csum = vsetq_lane_u32(vgetq_lane_u32(vreinterpretq_u32_u8(temp_csum), 3), csum, 0);
	vtag = vorrq_u8(vreinterpretq_u8_u32(csum), vtag);

	vtag_hi = vqtbl1q_u8(vlan_csum_map_hi, vtag);
	vtag_hi = vshrq_n_u8(vtag_hi, 7);

	vtag_lo = vqtbl1q_u8(vlan_csum_map_lo, vtag);
	vtag_lo = vorrq_u8(ptype, vtag_lo);

	udp_csum_skip = vshrq_n_u8(vreinterpretq_u8_u32(temp_udp_csum_skip), 1);
	udp_csum_skip = vqtbl1q_u8(udp_csum_bad_shuf, udp_csum_skip);
	vtag_lo = vandq_u8(vtag_lo, udp_csum_skip);

	vtag = vzipq_u8(vtag_lo, vtag_hi).val[0];
	vol.word = vgetq_lane_u64(vreinterpretq_u64_u8(vtag), 0);

	rx_pkts[0]->ol_flags = vol.e[0];
	rx_pkts[1]->ol_flags = vol.e[1];
	rx_pkts[2]->ol_flags = vol.e[2];
	rx_pkts[3]->ol_flags = vol.e[3];
}

static inline u32
sxe_get_packet_type(u32 pkt_info,
		u32 etqf_check,
		u32 tunnel_check)
{
	u32 rte;

	if (etqf_check) {
		rte = RTE_PTYPE_UNKNOWN;
		goto out;
	}

	if (tunnel_check) {
		pkt_info &= SXE_PACKET_TYPE_MASK_TUNNEL;
		rte = sxe_ptype_table_tn[pkt_info];
		goto out;
	}

	pkt_info &= SXE_PACKET_TYPE_MASK;
	rte = sxe_ptype_table[pkt_info];

out:
	return rte;
}

static inline void
sxe_desc_to_ptype_v(uint64x2_t descs[4], u16 pkt_type_mask,
		struct rte_mbuf **rx_pkts)
{
	uint32x4_t etqf_check, tunnel_check;
	uint32x4_t etqf_mask = vdupq_n_u32(0x8000);
	uint32x4_t tunnel_mask = vdupq_n_u32(0x10000);
	uint32x4_t ptype_mask = vdupq_n_u32((u32)pkt_type_mask);
	uint32x4_t ptype0 = vzipq_u32(vreinterpretq_u32_u64(descs[0]),
				vreinterpretq_u32_u64(descs[2])).val[0];
	uint32x4_t ptype1 = vzipq_u32(vreinterpretq_u32_u64(descs[1]),
				vreinterpretq_u32_u64(descs[3])).val[0];

	ptype0 = vzipq_u32(ptype0, ptype1).val[0];

	etqf_check = vandq_u32(ptype0, etqf_mask);
	tunnel_check = vandq_u32(ptype0, tunnel_mask);

	ptype0 = vandq_u32(vshrq_n_u32(ptype0, SXE_PACKET_TYPE_SHIFT),
			ptype_mask);

	rx_pkts[0]->packet_type =
		sxe_get_packet_type(vgetq_lane_u32(ptype0, 0),
				vgetq_lane_u32(etqf_check, 0),
				vgetq_lane_u32(tunnel_check, 0));
	rx_pkts[1]->packet_type =
		sxe_get_packet_type(vgetq_lane_u32(ptype0, 1),
				vgetq_lane_u32(etqf_check, 1),
				vgetq_lane_u32(tunnel_check, 1));
	rx_pkts[2]->packet_type =
		sxe_get_packet_type(vgetq_lane_u32(ptype0, 2),
				vgetq_lane_u32(etqf_check, 2),
				vgetq_lane_u32(tunnel_check, 2));
	rx_pkts[3]->packet_type =
		sxe_get_packet_type(vgetq_lane_u32(ptype0, 3),
				vgetq_lane_u32(etqf_check, 3),
				vgetq_lane_u32(tunnel_check, 3));
}

static inline u16
sxe_recv_raw_pkts_vec(struct sxe_rx_queue *rxq, struct rte_mbuf **rx_pkts,
		   u16 nb_pkts, u8 *split_packet)
{
	volatile union sxe_rx_data_desc *rxdp;
	struct sxe_rx_buffer *sw_ring;
	u16 nb_pkts_recd;
	s32 pos;
	u16 rte;
	uint8x16_t shuf_msk = {
		0xFF, 0xFF,
		0xFF, 0xFF,
		12, 13,
		0xFF, 0xFF,
		12, 13,
		14, 15,
		4, 5, 6, 7
		};
	uint16x8_t crc_adjust = {0, 0, rxq->crc_len, 0,
				 rxq->crc_len, 0, 0, 0};

	nb_pkts = RTE_ALIGN_FLOOR(nb_pkts, RTE_SXE_DESCS_PER_LOOP);

	rxdp = rxq->desc_ring + rxq->processing_idx;

	rte_prefetch_non_temporal(rxdp);

	if (rxq->realloc_num > RTE_PMD_SXE_MAX_RX_BURST)
		sxe_rxq_rearm(rxq);

	if (!(rxdp->wb.upper.status_error &
				rte_cpu_to_le_32(SXE_RXDADV_STAT_DD))) {
		rte = 0;
		goto out;
	}

	sw_ring = &rxq->buffer_ring[rxq->processing_idx];

	RTE_BUILD_BUG_ON((RTE_MBUF_F_RX_VLAN | RTE_MBUF_F_RX_VLAN_STRIPPED) > UINT8_MAX);

	u16 udp_p_flag = SXE_RXDADV_PKTTYPE_UDP;
	u8 vlan_flags = rxq->vlan_flags & UINT8_MAX;

	for (pos = 0, nb_pkts_recd = 0; pos < nb_pkts;
			pos += RTE_SXE_DESCS_PER_LOOP,
			rxdp += RTE_SXE_DESCS_PER_LOOP) {
		uint64x2_t descs[RTE_SXE_DESCS_PER_LOOP];
		uint8x16_t pkt_mb1, pkt_mb2, pkt_mb3, pkt_mb4;
		uint8x16x2_t sterr_tmp1, sterr_tmp2;
		uint64x2_t mbp1, mbp2;
		uint8x16_t staterr;
		uint16x8_t tmp;
		u32 stat;

		mbp1 = vld1q_u64((u64 *)&sw_ring[pos]);

		vst1q_u64((u64 *)&rx_pkts[pos], mbp1);

		mbp2 = vld1q_u64((u64 *)&sw_ring[pos + 2]);

		descs[0] =  vld1q_u64(RTE_CAST_PTR(u64 *, (rxdp)));
		descs[1] =  vld1q_u64(RTE_CAST_PTR(u64 *, (rxdp + 1)));
		descs[2] =  vld1q_u64(RTE_CAST_PTR(u64 *, (rxdp + 2)));
		descs[3] =  vld1q_u64(RTE_CAST_PTR(u64 *, (rxdp + 3)));

		vst1q_u64((u64 *)&rx_pkts[pos + 2], mbp2);

		if (split_packet) {
			rte_mbuf_prefetch_part2(rx_pkts[pos]);
			rte_mbuf_prefetch_part2(rx_pkts[pos + 1]);
			rte_mbuf_prefetch_part2(rx_pkts[pos + 2]);
			rte_mbuf_prefetch_part2(rx_pkts[pos + 3]);
		}

		pkt_mb4 = vqtbl1q_u8(vreinterpretq_u8_u64(descs[3]), shuf_msk);
		pkt_mb3 = vqtbl1q_u8(vreinterpretq_u8_u64(descs[2]), shuf_msk);

		pkt_mb2 = vqtbl1q_u8(vreinterpretq_u8_u64(descs[1]), shuf_msk);
		pkt_mb1 = vqtbl1q_u8(vreinterpretq_u8_u64(descs[0]), shuf_msk);

		sterr_tmp2 = vzipq_u8(vreinterpretq_u8_u64(descs[1]),
					  vreinterpretq_u8_u64(descs[3]));
		sterr_tmp1 = vzipq_u8(vreinterpretq_u8_u64(descs[0]),
					  vreinterpretq_u8_u64(descs[2]));

		staterr = vzipq_u8(sterr_tmp1.val[1], sterr_tmp2.val[1]).val[0];

		sxe_desc_to_olflags_v(sterr_tmp1, sterr_tmp2, staterr, vlan_flags,
				  udp_p_flag, &rx_pkts[pos]);

		tmp = vsubq_u16(vreinterpretq_u16_u8(pkt_mb4), crc_adjust);
		pkt_mb4 = vreinterpretq_u8_u16(tmp);
		tmp = vsubq_u16(vreinterpretq_u16_u8(pkt_mb3), crc_adjust);
		pkt_mb3 = vreinterpretq_u8_u16(tmp);

		vst1q_u8((void *)&rx_pkts[pos + 3]->rx_descriptor_fields1,
			 pkt_mb4);
		vst1q_u8((void *)&rx_pkts[pos + 2]->rx_descriptor_fields1,
			 pkt_mb3);

		tmp = vsubq_u16(vreinterpretq_u16_u8(pkt_mb2), crc_adjust);
		pkt_mb2 = vreinterpretq_u8_u16(tmp);
		tmp = vsubq_u16(vreinterpretq_u16_u8(pkt_mb1), crc_adjust);
		pkt_mb1 = vreinterpretq_u8_u16(tmp);

		if (split_packet) {
			stat = vgetq_lane_u32(vreinterpretq_u32_u8(staterr), 0);
			*(s32 *)split_packet = ~stat & SXE_VPMD_DESC_EOP_MASK;

			split_packet += RTE_SXE_DESCS_PER_LOOP;
		}

		staterr = vshlq_n_u8(staterr, SXE_UINT8_BIT - 1);
		staterr = vreinterpretq_u8_s8
				(vshrq_n_s8(vreinterpretq_s8_u8(staterr),
					SXE_UINT8_BIT - 1));
		stat = ~vgetq_lane_u32(vreinterpretq_u32_u8(staterr), 0);

		rte_prefetch_non_temporal(rxdp + RTE_SXE_DESCS_PER_LOOP);

		vst1q_u8((u8 *)&rx_pkts[pos + 1]->rx_descriptor_fields1,
			 pkt_mb2);
		vst1q_u8((u8 *)&rx_pkts[pos]->rx_descriptor_fields1,
			 pkt_mb1);

		sxe_desc_to_ptype_v(descs, rxq->pkt_type_mask, &rx_pkts[pos]);

		if (unlikely(stat == 0)) {
			nb_pkts_recd += RTE_SXE_DESCS_PER_LOOP;
		} else {
			nb_pkts_recd += rte_ctz32(stat) / SXE_UINT8_BIT;
			break;
		}
	}

	rxq->processing_idx = (u16)(rxq->processing_idx + nb_pkts_recd);
	rxq->processing_idx = (u16)(rxq->processing_idx & (rxq->ring_depth - 1));
	rxq->realloc_num = (u16)(rxq->realloc_num + nb_pkts_recd);

	rte = nb_pkts_recd;

out:
	return rte;
}

u16 sxe_pkts_vec_recv(void *rx_queue, struct rte_mbuf **rx_pkts, u16 nb_pkts)
{
	return sxe_recv_raw_pkts_vec(rx_queue, rx_pkts, nb_pkts, NULL);
}

static u16 sxe_recv_scattered_burst_vec(void *rx_queue,
			struct rte_mbuf **rx_pkts, u16 nb_pkts)
{
	u32 i = 0;
	struct sxe_rx_queue *rxq = rx_queue;
	u8 split_flags[RTE_PMD_SXE_MAX_RX_BURST] = {0};

	u16 nb_bufs = sxe_recv_raw_pkts_vec(rxq, rx_pkts, nb_pkts,
			split_flags);
	if (nb_bufs == 0)
		goto l_out;

	const u64 *split_fl64 = (u64 *)split_flags;
	if (rxq->pkt_first_seg == NULL &&
			split_fl64[0] == 0 && split_fl64[1] == 0 &&
			split_fl64[2] == 0 && split_fl64[3] == 0)
		goto l_out;

	if (rxq->pkt_first_seg == NULL) {
		while (i < nb_bufs && !split_flags[i])
			i++;
		if (i == nb_bufs)
			goto l_out;
		rxq->pkt_first_seg = rx_pkts[i];
	}

	nb_bufs = i + sxe_packets_reassemble(rxq, &rx_pkts[i], nb_bufs - i,
		&split_flags[i]);

l_out:
	return nb_bufs;
}

u16
sxe_scattered_pkts_vec_recv(void *rx_queue, struct rte_mbuf **rx_pkts,
				  u16 nb_pkts)
{
	u16 retval = 0;

	while (nb_pkts > RTE_PMD_SXE_MAX_RX_BURST) {
		u16 burst;

		burst = sxe_recv_scattered_burst_vec(rx_queue,
							   rx_pkts + retval,
							   RTE_PMD_SXE_MAX_RX_BURST);
		retval += burst;
		nb_pkts -= burst;
		if (burst < RTE_PMD_SXE_MAX_RX_BURST)
			goto l_out;
	}

	retval += sxe_recv_scattered_burst_vec(rx_queue,
						rx_pkts + retval,
						nb_pkts);
l_out:
	return retval;
}

static inline void
sxe_single_vec_desc_fill(volatile union sxe_tx_data_desc *txdp,
		struct rte_mbuf *pkt, u64 flags)
{
	uint64x2_t descriptor = {
			pkt->buf_iova + pkt->data_off,
			(u64)pkt->pkt_len << 46 | flags | pkt->data_len};

	vst1q_u64(RTE_CAST_PTR(u64 *, &txdp->read), descriptor);
}

static inline void
sxe_vec_desc_fill(volatile union sxe_tx_data_desc *txdp,
		struct rte_mbuf **pkt, u16 nb_pkts,  u64 flags)
{
	s32 i;

	for (i = 0; i < nb_pkts; ++i, ++txdp, ++pkt)
		sxe_single_vec_desc_fill(txdp, *pkt, flags);
}

u16 __sxe_pkts_vector_xmit(void *tx_queue, struct rte_mbuf **tx_pkts,
			   u16 nb_pkts)
{
	struct sxe_tx_queue *txq = (struct sxe_tx_queue *)tx_queue;
	volatile union sxe_tx_data_desc *txdp;
	struct sxe_tx_buffer_vec *txep;
	u16 n, nb_commit, tx_id;
	u64 flags = SXE_TX_DESC_FLAGS;
	u64 rs = SXE_TX_DESC_RS_MASK | SXE_TX_DESC_FLAGS;
	s32 i;

	nb_pkts = RTE_MIN(nb_pkts, txq->rs_thresh);

	if (txq->desc_free_num < txq->free_thresh)
		sxe_tx_bufs_vec_free(txq);

	nb_pkts = (u16)RTE_MIN(txq->desc_free_num, nb_pkts);
	nb_commit = nb_pkts;
	if (unlikely(nb_pkts == 0))
		goto l_out;

	tx_id = txq->next_to_use;
	txdp = &txq->desc_ring[tx_id];
	txep = &txq->buffer_ring_vec[tx_id];

	txq->desc_free_num = (u16)(txq->desc_free_num - nb_pkts);

	n = (u16)(txq->ring_depth - tx_id);
	if (nb_commit >= n) {
		sxe_vec_mbuf_fill(txep, tx_pkts, n);

		for (i = 0; i < n - 1; ++i, ++tx_pkts, ++txdp)
			sxe_single_vec_desc_fill(txdp, *tx_pkts, flags);

		sxe_single_vec_desc_fill(txdp, *tx_pkts++, rs);

		nb_commit = (u16)(nb_commit - n);

		tx_id = 0;
		txq->next_rs = (u16)(txq->rs_thresh - 1);

		txdp = &txq->desc_ring[tx_id];
		txep = &txq->buffer_ring_vec[tx_id];
	}

	sxe_vec_mbuf_fill(txep, tx_pkts, nb_commit);
	sxe_vec_desc_fill(txdp, tx_pkts, nb_commit, flags);

	tx_id = (u16)(tx_id + nb_commit);
	if (tx_id > txq->next_rs) {
		txq->desc_ring[txq->next_rs].read.cmd_type_len |=
			rte_cpu_to_le_32(SXE_TX_DESC_RS_MASK);
		txq->next_rs = (u16)(txq->next_rs +
			txq->rs_thresh);
	}

	txq->next_to_use = tx_id;

	sxe_write_addr(txq->next_to_use, txq->tdt_reg_addr);

l_out:
	return nb_pkts;
}

static void __rte_cold
sxe_tx_queue_release_mbufs_vec(struct sxe_tx_queue *txq)
{
	sxe_tx_mbufs_vec_release(txq);
}

void __rte_cold
sxe_rx_queue_vec_mbufs_release(struct sxe_rx_queue *rxq)
{
	sxe_rx_vec_mbufs_release(rxq);
}

static void __rte_cold
sxe_tx_free_swring(struct sxe_tx_queue *txq)
{
	sxe_tx_buffer_ring_vec_free(txq);
}

static void __rte_cold
sxe_reset_tx_queue(struct sxe_tx_queue *txq)
{
	sxe_tx_queue_vec_init(txq);
}

static const struct sxe_txq_ops vec_txq_ops = {
	.init = sxe_reset_tx_queue,
	.mbufs_release = sxe_tx_queue_release_mbufs_vec,
	.buffer_ring_free = sxe_tx_free_swring,
};

s32 __rte_cold
sxe_rxq_vec_setup(struct sxe_rx_queue *rxq)
{
	return sxe_default_rxq_vec_setup(rxq);
}

s32 __rte_cold
sxe_txq_vec_setup(struct sxe_tx_queue *txq)
{
	return sxe_default_txq_vec_setup(txq, &vec_txq_ops);
}

s32 __rte_cold
sxe_rx_vec_condition_check(struct rte_eth_dev *dev)
{
	struct rte_eth_rxmode *rxmode = &dev->data->dev_conf.rxmode;

	if (rxmode->offloads & DEV_RX_OFFLOAD_CHECKSUM)
		return -1;

	return sxe_default_rx_vec_condition_check(dev);
}

#endif

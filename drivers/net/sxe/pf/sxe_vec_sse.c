/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SIMD
#include <stdint.h>
#include <ethdev_driver.h>
#include <rte_malloc.h>
#include <rte_vect.h>

#include "sxe_vec_common.h"
#include "sxe_compat_version.h"

#pragma GCC diagnostic ignored "-Wcast-qual"

#define SXE_MAX_TX_FREE_BUF_SZ 64

static inline void
sxe_rxq_realloc(sxe_rx_queue_s *rx_queue)
{
	s32 i;
	u16 rx_index;
	volatile union sxe_rx_data_desc *desc_ring;
	sxe_rx_buffer_s *buf_ring =
			&rx_queue->buffer_ring[rx_queue->realloc_start];
	struct rte_mbuf *mbuf_0, *mbuf_1;
	__m128i head_room = _mm_set_epi64x(RTE_PKTMBUF_HEADROOM,
			RTE_PKTMBUF_HEADROOM);
	__m128i dma_addr0, dma_addr1;

	const __m128i addr_mask = _mm_set_epi64x(0, UINT64_MAX);

	desc_ring = rx_queue->desc_ring + rx_queue->realloc_start;

	if (rte_mempool_get_bulk(rx_queue->mb_pool,
				 (void *)buf_ring,
				 RTE_PMD_SXE_MAX_RX_BURST) < 0) {
		if (rx_queue->realloc_num + RTE_PMD_SXE_MAX_RX_BURST >=
			rx_queue->ring_depth) {
			dma_addr0 = _mm_setzero_si128();
			for (i = 0; i < SXE_DESCS_PER_LOOP; i++) {
				buf_ring[i].mbuf = &rx_queue->fake_mbuf;
				_mm_store_si128((__m128i *)&desc_ring[i].read,
						dma_addr0);
			}
		}
		rte_eth_devices[rx_queue->port_id].data->rx_mbuf_alloc_failed +=
			RTE_PMD_SXE_MAX_RX_BURST;
		return;
	}

	for (i = 0; i < RTE_PMD_SXE_MAX_RX_BURST; i += 2, buf_ring += 2) {
		__m128i vaddr0, vaddr1;

		mbuf_0 = buf_ring[0].mbuf;
		mbuf_1 = buf_ring[1].mbuf;

		RTE_BUILD_BUG_ON(offsetof(struct rte_mbuf, buf_iova) !=
				offsetof(struct rte_mbuf, buf_addr) + 8);

		vaddr0 = _mm_loadu_si128((__m128i *)&mbuf_0->buf_addr);
		vaddr1 = _mm_loadu_si128((__m128i *)&mbuf_1->buf_addr);

		dma_addr0 = _mm_unpackhi_epi64(vaddr0, vaddr0);
		dma_addr1 = _mm_unpackhi_epi64(vaddr1, vaddr1);

		dma_addr0 = _mm_add_epi64(dma_addr0, head_room);
		dma_addr1 = _mm_add_epi64(dma_addr1, head_room);

		dma_addr0 = _mm_and_si128(dma_addr0, addr_mask);
		dma_addr1 = _mm_and_si128(dma_addr1, addr_mask);

		_mm_store_si128((__m128i *)&desc_ring++->read, dma_addr0);
		_mm_store_si128((__m128i *)&desc_ring++->read, dma_addr1);
	}

	rx_queue->realloc_start += RTE_PMD_SXE_MAX_RX_BURST;
	if (rx_queue->realloc_start >= rx_queue->ring_depth)
		rx_queue->realloc_start = 0;

	rx_queue->realloc_num -= RTE_PMD_SXE_MAX_RX_BURST;

	rx_index = (u16)((rx_queue->realloc_start == 0) ?
			(rx_queue->ring_depth - 1) : (rx_queue->realloc_start - 1));

	SXE_PCI_REG_WC_WRITE_RELAXED(rx_queue->rdt_reg_addr, rx_index);
}

static inline void
sxe_desc_to_olflags(__m128i descs[4], __m128i mbuf_init, u8 vlan_flags,
			u16 udp_p_flag, struct rte_mbuf **rx_pkts)
{
	__m128i ptype0, ptype1, vtype0, vtype1, csum, udp_csum_skip;
	__m128i rearm0, rearm1, rearm2, rearm3;

	const __m128i rsstype_mask = _mm_set_epi16
			(0x0000, 0x0000, 0x0000, 0x0000,
			0x000F, 0x000F, 0x000F, 0x000F);

	const __m128i ol_flags_mask = _mm_set_epi16
			(0x0000, 0x0000, 0x0000, 0x0000,
			0x00FF, 0x00FF, 0x00FF, 0x00FF);

	const __m128i rss_flags = _mm_set_epi8(RTE_MBUF_F_RX_FDIR, 0, 0, 0,
			0, 0, 0, RTE_MBUF_F_RX_RSS_HASH,
			RTE_MBUF_F_RX_RSS_HASH, 0, RTE_MBUF_F_RX_RSS_HASH, 0,
			RTE_MBUF_F_RX_RSS_HASH, RTE_MBUF_F_RX_RSS_HASH, RTE_MBUF_F_RX_RSS_HASH, 0);

	const __m128i vlan_csum_mask = _mm_set_epi16
		((SXE_RXDADV_ERR_L4E | SXE_RXDADV_ERR_IPE) >> 16,
		(SXE_RXDADV_ERR_L4E | SXE_RXDADV_ERR_IPE) >> 16,
		(SXE_RXDADV_ERR_L4E | SXE_RXDADV_ERR_IPE) >> 16,
		(SXE_RXDADV_ERR_L4E | SXE_RXDADV_ERR_IPE) >> 16,
		SXE_RXD_STAT_VP, SXE_RXD_STAT_VP,
		SXE_RXD_STAT_VP, SXE_RXD_STAT_VP);

	const __m128i vlan_csum_map_low = _mm_set_epi8
		(0, 0, 0, 0,
		vlan_flags | RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_BAD,
		vlan_flags | RTE_MBUF_F_RX_IP_CKSUM_BAD,
		vlan_flags | RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_BAD,
		vlan_flags | RTE_MBUF_F_RX_IP_CKSUM_GOOD,
		0, 0, 0, 0,
		RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_BAD,
		RTE_MBUF_F_RX_IP_CKSUM_BAD,
		RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_BAD,
		RTE_MBUF_F_RX_IP_CKSUM_GOOD);

	const __m128i vlan_csum_map_high = _mm_set_epi8
		(0, 0, 0, 0,
		0, RTE_MBUF_F_RX_L4_CKSUM_GOOD >> sizeof(u8), 0,
		RTE_MBUF_F_RX_L4_CKSUM_GOOD >> sizeof(u8),
		0, 0, 0, 0,
		0, RTE_MBUF_F_RX_L4_CKSUM_GOOD >> sizeof(u8), 0,
		RTE_MBUF_F_RX_L4_CKSUM_GOOD >> sizeof(u8));

	const __m128i udp_hdr_p_msk = _mm_set_epi16
		(0, 0, 0, 0,
		 udp_p_flag, udp_p_flag, udp_p_flag, udp_p_flag);

	const __m128i udp_csum_bad_shuf = _mm_set_epi8
		(0, 0, 0, 0, 0, 0, 0, 0,
		 0, 0, 0, 0, 0, 0, ~(u8)RTE_MBUF_F_RX_L4_CKSUM_BAD, 0xFF);

	ptype0 = _mm_unpacklo_epi16(descs[0], descs[1]);
	ptype1 = _mm_unpacklo_epi16(descs[2], descs[3]);

	vtype0 = _mm_unpackhi_epi16(descs[0], descs[1]);
	vtype1 = _mm_unpackhi_epi16(descs[2], descs[3]);

	ptype0 = _mm_unpacklo_epi32(ptype0, ptype1);

	udp_csum_skip = _mm_and_si128(ptype0, udp_hdr_p_msk);

	ptype0 = _mm_and_si128(ptype0, rsstype_mask);

	ptype0 = _mm_shuffle_epi8(rss_flags, ptype0);

	vtype1 = _mm_unpacklo_epi32(vtype0, vtype1);
	vtype1 = _mm_and_si128(vtype1, vlan_csum_mask);

	csum = _mm_srli_epi16(vtype1, 14);

	csum = _mm_srli_si128(csum, 8);
	vtype1 = _mm_or_si128(csum, vtype1);

	vtype0 = _mm_shuffle_epi8(vlan_csum_map_high, vtype1);
	vtype0 = _mm_slli_epi16(vtype0, sizeof(u8));

	vtype1 = _mm_shuffle_epi8(vlan_csum_map_low, vtype1);
	vtype1 = _mm_and_si128(vtype1, ol_flags_mask);
	vtype1 = _mm_or_si128(vtype0, vtype1);

	vtype1 = _mm_or_si128(ptype0, vtype1);

	udp_csum_skip = _mm_srli_epi16(udp_csum_skip, 9);
	udp_csum_skip = _mm_shuffle_epi8(udp_csum_bad_shuf, udp_csum_skip);
	vtype1 = _mm_and_si128(vtype1, udp_csum_skip);

	rearm0 = _mm_blend_epi16(mbuf_init, _mm_slli_si128(vtype1, 8), 0x10);
	rearm1 = _mm_blend_epi16(mbuf_init, _mm_slli_si128(vtype1, 6), 0x10);
	rearm2 = _mm_blend_epi16(mbuf_init, _mm_slli_si128(vtype1, 4), 0x10);
	rearm3 = _mm_blend_epi16(mbuf_init, _mm_slli_si128(vtype1, 2), 0x10);

	RTE_BUILD_BUG_ON(offsetof(struct rte_mbuf, ol_flags) !=
			offsetof(struct rte_mbuf, rearm_data) + 8);
	RTE_BUILD_BUG_ON(offsetof(struct rte_mbuf, rearm_data) !=
			RTE_ALIGN(offsetof(struct rte_mbuf, rearm_data), 16));

	_mm_store_si128((__m128i *)&rx_pkts[0]->rearm_data, rearm0);
	_mm_store_si128((__m128i *)&rx_pkts[1]->rearm_data, rearm1);
	_mm_store_si128((__m128i *)&rx_pkts[2]->rearm_data, rearm2);
	_mm_store_si128((__m128i *)&rx_pkts[3]->rearm_data, rearm3);
}

static inline u32 sxe_packet_type_get(int index,
					u32 pkt_info,
					u32 etqf_check)
{
	if (etqf_check & (0x02 << (index * SXE_DESCS_PER_LOOP)))
		return RTE_PTYPE_UNKNOWN;

	pkt_info &= SXE_PACKET_TYPE_MASK;
	return sxe_ptype_table[pkt_info];
}

static inline void
sxe_desc_to_ptype_vec(__m128i descs[4], u16 pkt_type_mask,
		struct rte_mbuf **rx_pkts)
{
	__m128i etqf_mask = _mm_set_epi64x(0x800000008000LL, 0x800000008000LL);
	__m128i ptype_mask = _mm_set_epi32(pkt_type_mask,
			pkt_type_mask, pkt_type_mask, pkt_type_mask);

	u32 etqf_check, pkt_info;

	__m128i ptype0 = _mm_unpacklo_epi32(descs[0], descs[2]);
	__m128i ptype1 = _mm_unpacklo_epi32(descs[1], descs[3]);

	ptype0 = _mm_unpacklo_epi32(ptype0, ptype1);

	etqf_check = _mm_movemask_epi8(_mm_and_si128(ptype0, etqf_mask));

	ptype0 = _mm_and_si128(_mm_srli_epi32(ptype0, SXE_RXDADV_PKTTYPE_ETQF_SHIFT),
				   ptype_mask);


	pkt_info = _mm_extract_epi32(ptype0, 0);
	rx_pkts[0]->packet_type =
		sxe_packet_type_get(0, pkt_info, etqf_check);
	pkt_info = _mm_extract_epi32(ptype0, 1);
	rx_pkts[1]->packet_type =
		sxe_packet_type_get(1, pkt_info, etqf_check);
	pkt_info = _mm_extract_epi32(ptype0, 2);
	rx_pkts[2]->packet_type =
		sxe_packet_type_get(2, pkt_info, etqf_check);
	pkt_info = _mm_extract_epi32(ptype0, 3);
	rx_pkts[3]->packet_type =
		sxe_packet_type_get(3, pkt_info, etqf_check);
}

static inline u16
sxe_raw_pkts_vec_recv(sxe_rx_queue_s *rx_queue, struct rte_mbuf **rx_pkts,
		u16 pkts_num, u8 *split_packet)
{
	volatile union sxe_rx_data_desc *desc_ring;
	sxe_rx_buffer_s *buffer_ring;
	u16 pkts_recd_num;
	s32 pos;
	u64 var;
	__m128i shuf_msk;
	__m128i crc_adjust = _mm_set_epi16
				(0, 0, 0,
				-rx_queue->crc_len,
				0,
				-rx_queue->crc_len,
				0, 0
			);

	RTE_BUILD_BUG_ON(offsetof(struct rte_mbuf, pkt_len) !=
			offsetof(struct rte_mbuf, rx_descriptor_fields1) + 4);
	RTE_BUILD_BUG_ON(offsetof(struct rte_mbuf, data_len) !=
			offsetof(struct rte_mbuf, rx_descriptor_fields1) + 8);
	__m128i dd_check, eop_check;
	__m128i mbuf_init;
	u8 vlan_flags;
	u16 udp_p_flag = 0;

	pkts_num = RTE_MIN(pkts_num, RTE_PMD_SXE_MAX_RX_BURST);

	pkts_num = RTE_ALIGN_FLOOR(pkts_num, SXE_DESCS_PER_LOOP);

	desc_ring = rx_queue->desc_ring + rx_queue->processing_idx;

	rte_prefetch0(desc_ring);

	if (rx_queue->realloc_num > RTE_PMD_SXE_MAX_RX_BURST)
		sxe_rxq_realloc(rx_queue);

	if (!(desc_ring->wb.upper.status_error &
				rte_cpu_to_le_32(SXE_RXDADV_STAT_DD))) {
		pkts_recd_num = 0;
		goto l_out;
	}

	udp_p_flag = SXE_RXDADV_PKTTYPE_UDP;

	dd_check = _mm_set_epi64x(0x0000000100000001LL, 0x0000000100000001LL);

	eop_check = _mm_set_epi64x(0x0000000200000002LL, 0x0000000200000002LL);

	shuf_msk = _mm_set_epi8
		(7, 6, 5, 4,
		15, 14,
		13, 12,
		0xFF, 0xFF,
		13, 12,
		0xFF, 0xFF,
		0xFF, 0xFF
		);

	RTE_BUILD_BUG_ON(offsetof(struct rte_mbuf, pkt_len) !=
			offsetof(struct rte_mbuf, rx_descriptor_fields1) + 4);
	RTE_BUILD_BUG_ON(offsetof(struct rte_mbuf, data_len) !=
			offsetof(struct rte_mbuf, rx_descriptor_fields1) + 8);
	RTE_BUILD_BUG_ON(offsetof(struct rte_mbuf, vlan_tci) !=
			offsetof(struct rte_mbuf, rx_descriptor_fields1) + 10);
	RTE_BUILD_BUG_ON(offsetof(struct rte_mbuf, hash) !=
			offsetof(struct rte_mbuf, rx_descriptor_fields1) + 12);

	mbuf_init = _mm_set_epi64x(0, rx_queue->mbuf_init_value);

	buffer_ring = &rx_queue->buffer_ring[rx_queue->processing_idx];

	RTE_BUILD_BUG_ON((RTE_MBUF_F_RX_VLAN | RTE_MBUF_F_RX_VLAN_STRIPPED) > UINT8_MAX);
	vlan_flags = rx_queue->vlan_flags & UINT8_MAX;

	for (pos = 0, pkts_recd_num = 0; pos < pkts_num;
			pos += SXE_DESCS_PER_LOOP,
			desc_ring += SXE_DESCS_PER_LOOP) {
		__m128i descs[SXE_DESCS_PER_LOOP];
		__m128i pkt_mb1, pkt_mb2, pkt_mb3, pkt_mb4;
		__m128i zero, staterr, state_err1, state_err2;
		__m128i mbp1;
#if defined(RTE_ARCH_X86_64)
		__m128i mbp2;
#endif

		mbp1 = _mm_loadu_si128((__m128i *)&buffer_ring[pos]);

		descs[3] = _mm_loadu_si128((__m128i *)(desc_ring + 3));
		rte_compiler_barrier();

		_mm_storeu_si128((__m128i *)&rx_pkts[pos], mbp1);

#if defined(RTE_ARCH_X86_64)
		mbp2 = _mm_loadu_si128((__m128i *)&buffer_ring[pos + 2]);
#endif

		descs[2] = _mm_loadu_si128((__m128i *)(desc_ring + 2));
		rte_compiler_barrier();
		descs[1] = _mm_loadu_si128((__m128i *)(desc_ring + 1));
		rte_compiler_barrier();
		descs[0] = _mm_loadu_si128((__m128i *)(desc_ring));

#if defined(RTE_ARCH_X86_64)
		_mm_storeu_si128((__m128i *)&rx_pkts[pos + 2], mbp2);
#endif

		if (split_packet) {
			rte_mbuf_prefetch_part2(rx_pkts[pos]);
			rte_mbuf_prefetch_part2(rx_pkts[pos + 1]);
			rte_mbuf_prefetch_part2(rx_pkts[pos + 2]);
			rte_mbuf_prefetch_part2(rx_pkts[pos + 3]);
		}

		rte_compiler_barrier();

		pkt_mb4 = _mm_shuffle_epi8(descs[3], shuf_msk);
		pkt_mb3 = _mm_shuffle_epi8(descs[2], shuf_msk);
		pkt_mb2 = _mm_shuffle_epi8(descs[1], shuf_msk);
		pkt_mb1 = _mm_shuffle_epi8(descs[0], shuf_msk);

		state_err2 = _mm_unpackhi_epi32(descs[3], descs[2]);
		state_err1 = _mm_unpackhi_epi32(descs[1], descs[0]);

		sxe_desc_to_olflags(descs, mbuf_init, vlan_flags, udp_p_flag,
					&rx_pkts[pos]);

		pkt_mb4 = _mm_add_epi16(pkt_mb4, crc_adjust);
		pkt_mb3 = _mm_add_epi16(pkt_mb3, crc_adjust);

		zero = _mm_xor_si128(dd_check, dd_check);

		staterr = _mm_unpacklo_epi32(state_err1, state_err2);

		_mm_storeu_si128((void *)&rx_pkts[pos + 3]->rx_descriptor_fields1,
				pkt_mb4);
		_mm_storeu_si128((void *)&rx_pkts[pos + 2]->rx_descriptor_fields1,
				pkt_mb3);

		pkt_mb2 = _mm_add_epi16(pkt_mb2, crc_adjust);
		pkt_mb1 = _mm_add_epi16(pkt_mb1, crc_adjust);

		if (split_packet) {
			__m128i eop_shuf_mask = _mm_set_epi8
				(0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF,
				0x04, 0x0C, 0x00, 0x08
				);

			__m128i eop_bits = _mm_andnot_si128(staterr, eop_check);
			eop_bits = _mm_shuffle_epi8(eop_bits, eop_shuf_mask);
			*(int *)split_packet = _mm_cvtsi128_si32(eop_bits);
			split_packet += SXE_DESCS_PER_LOOP;
		}

		staterr = _mm_and_si128(staterr, dd_check);

		staterr = _mm_packs_epi32(staterr, zero);

		_mm_storeu_si128((void *)&rx_pkts[pos + 1]->rx_descriptor_fields1,
				pkt_mb2);
		_mm_storeu_si128((void *)&rx_pkts[pos]->rx_descriptor_fields1,
				pkt_mb1);

		sxe_desc_to_ptype_vec(descs, rx_queue->pkt_type_mask, &rx_pkts[pos]);
		var = rte_popcount64(_mm_cvtsi128_si64(staterr));
		pkts_recd_num += var;
		if (likely(var != SXE_DESCS_PER_LOOP))
			break;
	}

	rx_queue->processing_idx = (u16)(rx_queue->processing_idx + pkts_recd_num);
	rx_queue->processing_idx = (u16)(rx_queue->processing_idx & (rx_queue->ring_depth - 1));
	rx_queue->realloc_num = (u16)(rx_queue->realloc_num + pkts_recd_num);

l_out:
	return pkts_recd_num;
}

u16
sxe_pkts_vec_recv(void *rx_queue, struct rte_mbuf **rx_pkts, u16 pkts_num)
{
	return sxe_raw_pkts_vec_recv(rx_queue, rx_pkts, pkts_num, NULL);
}

static u16
sxe_scattered_burst_vec_recv(void *rx_queue, struct rte_mbuf **rx_pkts,
				u16 pkts_num)
{
	u16 i = 0;
	u16 bufs_num;
	sxe_rx_queue_s *rxq = rx_queue;
	u8 split_flags[RTE_PMD_SXE_MAX_RX_BURST] = {0};

	bufs_num = sxe_raw_pkts_vec_recv(rxq, rx_pkts, pkts_num,
			split_flags);
	if (bufs_num == 0)
		goto l_out;

	const u64 *split_flag_64 = (u64 *)split_flags;
	if (rxq->pkt_first_seg == NULL &&
		split_flag_64[0] == 0 && split_flag_64[1] == 0 &&
		split_flag_64[2] == 0 && split_flag_64[3] == 0)
		goto l_out;

	if (rxq->pkt_first_seg == NULL) {
		while (i < bufs_num && !split_flags[i])
			i++;
		if (i == bufs_num)
			goto l_out;
		rxq->pkt_first_seg = rx_pkts[i];
	}

	bufs_num = i + sxe_packets_reassemble(rxq, &rx_pkts[i], bufs_num - i,
		&split_flags[i]);

l_out:
	return bufs_num;
}

u16
sxe_scattered_pkts_vec_recv(void *rx_queue, struct rte_mbuf **rx_pkts,
				  u16 pkts_num)
{
	u16 ret = 0;

	while (pkts_num > RTE_PMD_SXE_MAX_RX_BURST) {
		u16 burst;

		burst = sxe_scattered_burst_vec_recv(rx_queue,
						rx_pkts + ret,
						RTE_PMD_SXE_MAX_RX_BURST);
		ret += burst;
		pkts_num -= burst;
		if (burst < RTE_PMD_SXE_MAX_RX_BURST)
			goto l_out;
	}

	ret += sxe_scattered_burst_vec_recv(rx_queue,
					rx_pkts + ret,
					pkts_num);
l_out:
	return ret;
}

void __rte_cold
sxe_rx_queue_vec_mbufs_release(sxe_rx_queue_s *rx_queue)
{
	sxe_rx_vec_mbufs_release(rx_queue);
}

s32 __rte_cold
sxe_rxq_vec_setup(sxe_rx_queue_s *rx_queue)
{
	return sxe_default_rxq_vec_setup(rx_queue);
}

s32 __rte_cold
sxe_rx_vec_condition_check(struct rte_eth_dev *dev)
{
	return sxe_default_rx_vec_condition_check(dev);
}

static inline void
sxe_single_vec_desc_fill(volatile sxe_tx_data_desc_u *desc_ring,
		struct rte_mbuf *pkts, u64 flags)
{
	__m128i descriptor = _mm_set_epi64x((u64)pkts->pkt_len << 46 |
			flags | pkts->data_len,
			pkts->buf_iova + pkts->data_off);
	_mm_store_si128((__m128i *)&desc_ring->read, descriptor);
}

static inline void
sxe_vec_desc_fill(volatile sxe_tx_data_desc_u *desc_ring,
		struct rte_mbuf **pkts, u16 pkts_num, u64 flags)
{
	s32 i;

	for (i = 0; i < pkts_num; ++i, ++desc_ring, ++pkts)
		sxe_single_vec_desc_fill(desc_ring, *pkts, flags);
}

u16
__sxe_pkts_vector_xmit(void *tx_queue, struct rte_mbuf **tx_pkts,
			   u16 pkts_num)
{
	sxe_tx_queue_s *txq = (sxe_tx_queue_s *)tx_queue;
	volatile sxe_tx_data_desc_u *desc_ring;
	struct sxe_tx_buffer_vec *buffer_ring;
	u16 n, commit_num, ntu, xmit_pkts_num;
	u64 flags = SXE_TX_DESC_FLAGS;
	u64 rs_flags = SXE_TX_DESC_RS_MASK | SXE_TX_DESC_FLAGS;
	s32 i;

	if (txq->desc_free_num < txq->free_thresh)
		sxe_tx_bufs_vec_free(txq);

	xmit_pkts_num = RTE_MIN(pkts_num, txq->rs_thresh);
	xmit_pkts_num = (u16)RTE_MIN(txq->desc_free_num, xmit_pkts_num);

	commit_num = xmit_pkts_num;
	if (unlikely(commit_num == 0))
		goto l_out;

	ntu = txq->next_to_use;
	desc_ring = &txq->desc_ring[ntu];
	buffer_ring = &txq->buffer_ring_vec[ntu];

	txq->desc_free_num = (u16)(txq->desc_free_num - xmit_pkts_num);

	n = (u16)(txq->ring_depth - ntu);
	if (commit_num >= n) {
		sxe_vec_mbuf_fill(buffer_ring, tx_pkts, n);

		for (i = 0; i < n - 1; ++i, ++tx_pkts, ++desc_ring)
			sxe_single_vec_desc_fill(desc_ring, *tx_pkts, flags);

		sxe_single_vec_desc_fill(desc_ring, *tx_pkts++, rs_flags);

		commit_num = (u16)(commit_num - n);

		ntu = 0;
		txq->next_rs = (u16)(txq->rs_thresh - 1);

		desc_ring = &txq->desc_ring[ntu];
		buffer_ring = &txq->buffer_ring_vec[ntu];
	}

	sxe_vec_mbuf_fill(buffer_ring, tx_pkts, commit_num);

	sxe_vec_desc_fill(desc_ring, tx_pkts, commit_num, flags);

	ntu = (u16)(ntu + commit_num);
	if (ntu > txq->next_rs) {
		txq->desc_ring[txq->next_rs].read.cmd_type_len |=
			rte_cpu_to_le_32(SXE_TX_DESC_RS_MASK);
		txq->next_rs = (u16)(txq->next_rs +
			txq->rs_thresh);
	}

	txq->next_to_use = ntu;
	rte_wmb();
	rte_write32_wc_relaxed((rte_cpu_to_le_32(txq->next_to_use)),
							txq->tdt_reg_addr);

l_out:
	return xmit_pkts_num;
}

static void __rte_cold
sxe_tx_queue_init(sxe_tx_queue_s *tx_queue)
{
	sxe_tx_queue_vec_init(tx_queue);
}

static void __rte_cold
sxe_tx_queue_mbufs_release(sxe_tx_queue_s *tx_queue)
{
	sxe_tx_mbufs_vec_release(tx_queue);
}

static void __rte_cold
sxe_tx_buffer_ring_free(sxe_tx_queue_s *tx_queue)
{
	sxe_tx_buffer_ring_vec_free(tx_queue);
}

static const struct sxe_txq_ops txq_vec_ops = {
	.init			 = sxe_tx_queue_init,
	.mbufs_release	= sxe_tx_queue_mbufs_release,
	.buffer_ring_free = sxe_tx_buffer_ring_free,
};

s32 __rte_cold
sxe_txq_vec_setup(sxe_tx_queue_s *tx_queue)
{
	return sxe_default_txq_vec_setup(tx_queue, &txq_vec_ops);
}

#endif

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2014-2021 Netronome Systems, Inc.
 * All rights reserved.
 *
 * Small portions derived from code Copyright(c) 2010-2015 Intel Corporation.
 */

/*
 * vim:shiftwidth=8:noexpandtab
 *
 * @file dpdk/pmd/nfp_rxtx.c
 *
 * Netronome vNIC DPDK Poll-Mode Driver: Rx/Tx functions
 */

#include <ethdev_driver.h>
#include <ethdev_pci.h>

#include "nfp_common.h"
#include "nfp_ctrl.h"
#include "nfp_rxtx.h"
#include "nfp_logs.h"
#include "nfd3/nfp_nfd3.h"
#include "nfdk/nfp_nfdk.h"
#include "nfpcore/nfp_mip.h"
#include "nfpcore/nfp_rtsym.h"

static int
nfp_net_rx_fill_freelist(struct nfp_net_rxq *rxq)
{
	struct nfp_net_rx_buff *rxe = rxq->rxbufs;
	uint64_t dma_addr;
	unsigned int i;

	PMD_RX_LOG(DEBUG, "Fill Rx Freelist for %u descriptors",
		   rxq->rx_count);

	for (i = 0; i < rxq->rx_count; i++) {
		struct nfp_net_rx_desc *rxd;
		struct rte_mbuf *mbuf = rte_pktmbuf_alloc(rxq->mem_pool);

		if (mbuf == NULL) {
			PMD_DRV_LOG(ERR, "RX mbuf alloc failed queue_id=%u",
				(unsigned int)rxq->qidx);
			return -ENOMEM;
		}

		dma_addr = rte_cpu_to_le_64(RTE_MBUF_DMA_ADDR_DEFAULT(mbuf));

		rxd = &rxq->rxds[i];
		rxd->fld.dd = 0;
		rxd->fld.dma_addr_hi = (dma_addr >> 32) & 0xffff;
		rxd->fld.dma_addr_lo = dma_addr & 0xffffffff;
		rxe[i].mbuf = mbuf;
		PMD_RX_LOG(DEBUG, "[%d]: %" PRIx64, i, dma_addr);
	}

	/* Make sure all writes are flushed before telling the hardware */
	rte_wmb();

	/* Not advertising the whole ring as the firmware gets confused if so */
	PMD_RX_LOG(DEBUG, "Increment FL write pointer in %u",
		   rxq->rx_count - 1);

	nfp_qcp_ptr_add(rxq->qcp_fl, NFP_QCP_WRITE_PTR, rxq->rx_count - 1);

	return 0;
}

int
nfp_net_rx_freelist_setup(struct rte_eth_dev *dev)
{
	int i;

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		if (nfp_net_rx_fill_freelist(dev->data->rx_queues[i]) < 0)
			return -1;
	}
	return 0;
}

uint32_t
nfp_net_rx_queue_count(void *rx_queue)
{
	struct nfp_net_rxq *rxq;
	struct nfp_net_rx_desc *rxds;
	uint32_t idx;
	uint32_t count;

	rxq = rx_queue;

	idx = rxq->rd_p;

	count = 0;

	/*
	 * Other PMDs are just checking the DD bit in intervals of 4
	 * descriptors and counting all four if the first has the DD
	 * bit on. Of course, this is not accurate but can be good for
	 * performance. But ideally that should be done in descriptors
	 * chunks belonging to the same cache line
	 */

	while (count < rxq->rx_count) {
		rxds = &rxq->rxds[idx];
		if ((rxds->rxd.meta_len_dd & PCIE_DESC_RX_DD) == 0)
			break;

		count++;
		idx++;

		/* Wrapping? */
		if ((idx) == rxq->rx_count)
			idx = 0;
	}

	return count;
}

/* nfp_net_parse_chained_meta() - Parse the chained metadata from packet */
static bool
nfp_net_parse_chained_meta(uint8_t *meta_base,
		rte_be32_t meta_header,
		struct nfp_meta_parsed *meta)
{
	uint8_t *meta_offset;
	uint32_t meta_info;
	uint32_t vlan_info;

	meta_info = rte_be_to_cpu_32(meta_header);
	meta_offset = meta_base + 4;

	for (; meta_info != 0; meta_info >>= NFP_NET_META_FIELD_SIZE, meta_offset += 4) {
		switch (meta_info & NFP_NET_META_FIELD_MASK) {
		case NFP_NET_META_HASH:
			/* Next field type is about the hash type */
			meta_info >>= NFP_NET_META_FIELD_SIZE;
			/* Hash value is in the data field */
			meta->hash = rte_be_to_cpu_32(*(rte_be32_t *)meta_offset);
			meta->hash_type = meta_info & NFP_NET_META_FIELD_MASK;
			break;
		case NFP_NET_META_VLAN:
			vlan_info = rte_be_to_cpu_32(*(rte_be32_t *)meta_offset);
			meta->vlan[meta->vlan_layer].offload =
					vlan_info >> NFP_NET_META_VLAN_OFFLOAD;
			meta->vlan[meta->vlan_layer].tci =
					vlan_info & NFP_NET_META_VLAN_MASK;
			meta->vlan[meta->vlan_layer].tpid = NFP_NET_META_TPID(vlan_info);
			++meta->vlan_layer;
			break;
		default:
			/* Unsupported metadata can be a performance issue */
			return false;
		}
	}

	return true;
}

/*
 * nfp_net_parse_meta_hash() - Set mbuf hash data based on the metadata info
 *
 * The RSS hash and hash-type are prepended to the packet data.
 * Extract and decode it and set the mbuf fields.
 */
static void
nfp_net_parse_meta_hash(const struct nfp_meta_parsed *meta,
		struct nfp_net_rxq *rxq,
		struct rte_mbuf *mbuf)
{
	struct nfp_net_hw *hw = rxq->hw;

	if ((hw->ctrl & NFP_NET_CFG_CTRL_RSS_ANY) == 0)
		return;

	mbuf->hash.rss = meta->hash;
	mbuf->ol_flags |= RTE_MBUF_F_RX_RSS_HASH;

	switch (meta->hash_type) {
	case NFP_NET_RSS_IPV4:
		mbuf->packet_type |= RTE_PTYPE_INNER_L3_IPV4;
		break;
	case NFP_NET_RSS_IPV6:
		mbuf->packet_type |= RTE_PTYPE_INNER_L3_IPV6;
		break;
	case NFP_NET_RSS_IPV6_EX:
		mbuf->packet_type |= RTE_PTYPE_INNER_L3_IPV6_EXT;
		break;
	case NFP_NET_RSS_IPV4_TCP:
		mbuf->packet_type |= RTE_PTYPE_INNER_L3_IPV6_EXT;
		break;
	case NFP_NET_RSS_IPV6_TCP:
		mbuf->packet_type |= RTE_PTYPE_INNER_L3_IPV6_EXT;
		break;
	case NFP_NET_RSS_IPV4_UDP:
		mbuf->packet_type |= RTE_PTYPE_INNER_L3_IPV6_EXT;
		break;
	case NFP_NET_RSS_IPV6_UDP:
		mbuf->packet_type |= RTE_PTYPE_INNER_L3_IPV6_EXT;
		break;
	default:
		mbuf->packet_type |= RTE_PTYPE_INNER_L4_MASK;
	}
}

/*
 * nfp_net_parse_single_meta() - Parse the single metadata
 *
 * The RSS hash and hash-type are prepended to the packet data.
 * Get it from metadata area.
 */
static inline void
nfp_net_parse_single_meta(uint8_t *meta_base,
		rte_be32_t meta_header,
		struct nfp_meta_parsed *meta)
{
	meta->hash_type = rte_be_to_cpu_32(meta_header);
	meta->hash = rte_be_to_cpu_32(*(rte_be32_t *)(meta_base + 4));
}

/*
 * nfp_net_parse_meta_vlan() - Set mbuf vlan_strip data based on metadata info
 *
 * The VLAN info TPID and TCI are prepended to the packet data.
 * Extract and decode it and set the mbuf fields.
 */
static void
nfp_net_parse_meta_vlan(const struct nfp_meta_parsed *meta,
		struct nfp_net_rx_desc *rxd,
		struct nfp_net_rxq *rxq,
		struct rte_mbuf *mb)
{
	struct nfp_net_hw *hw = rxq->hw;

	/* Skip if hardware don't support setting vlan. */
	if ((hw->ctrl & (NFP_NET_CFG_CTRL_RXVLAN | NFP_NET_CFG_CTRL_RXVLAN_V2)) == 0)
		return;

	/*
	 * The nic support the two way to send the VLAN info,
	 * 1. According the metadata to send the VLAN info when NFP_NET_CFG_CTRL_RXVLAN_V2
	 * is set
	 * 2. According the descriptor to sned the VLAN info when NFP_NET_CFG_CTRL_RXVLAN
	 * is set
	 *
	 * If the nic doesn't send the VLAN info, it is not necessary
	 * to do anything.
	 */
	if ((hw->ctrl & NFP_NET_CFG_CTRL_RXVLAN_V2) != 0) {
		if (meta->vlan_layer >= 1 && meta->vlan[0].offload != 0) {
			mb->vlan_tci = rte_cpu_to_le_32(meta->vlan[0].tci);
			mb->ol_flags |= RTE_MBUF_F_RX_VLAN | RTE_MBUF_F_RX_VLAN_STRIPPED;
		}
	} else if ((hw->ctrl & NFP_NET_CFG_CTRL_RXVLAN) != 0) {
		if ((rxd->rxd.flags & PCIE_DESC_RX_VLAN) != 0) {
			mb->vlan_tci = rte_cpu_to_le_32(rxd->rxd.vlan);
			mb->ol_flags |= RTE_MBUF_F_RX_VLAN | RTE_MBUF_F_RX_VLAN_STRIPPED;
		}
	}
}

/*
 * nfp_net_parse_meta_qinq() - Set mbuf qinq_strip data based on metadata info
 *
 * The out VLAN tci are prepended to the packet data.
 * Extract and decode it and set the mbuf fields.
 *
 * If both RTE_MBUF_F_RX_VLAN and NFP_NET_CFG_CTRL_RXQINQ are set, the 2 VLANs
 *   have been stripped by the hardware and their TCIs are saved in
 *   mbuf->vlan_tci (inner) and mbuf->vlan_tci_outer (outer).
 * If NFP_NET_CFG_CTRL_RXQINQ is set and RTE_MBUF_F_RX_VLAN is unset, only the
 *   outer VLAN is removed from packet data, but both tci are saved in
 *   mbuf->vlan_tci (inner) and mbuf->vlan_tci_outer (outer).
 *
 * qinq set & vlan set : meta->vlan_layer>=2, meta->vlan[0].offload=1, meta->vlan[1].offload=1
 * qinq set & vlan not set: meta->vlan_layer>=2, meta->vlan[1].offload=1,meta->vlan[0].offload=0
 * qinq not set & vlan set: meta->vlan_layer=1, meta->vlan[0].offload=1
 * qinq not set & vlan not set: meta->vlan_layer=0
 */
static void
nfp_net_parse_meta_qinq(const struct nfp_meta_parsed *meta,
		struct nfp_net_rxq *rxq,
		struct rte_mbuf *mb)
{
	struct nfp_net_hw *hw = rxq->hw;

	if ((hw->ctrl & NFP_NET_CFG_CTRL_RXQINQ) == 0 ||
			(hw->cap & NFP_NET_CFG_CTRL_RXQINQ) == 0)
		return;

	if (meta->vlan_layer < NFP_META_MAX_VLANS)
		return;

	if (meta->vlan[0].offload == 0)
		mb->vlan_tci = rte_cpu_to_le_16(meta->vlan[0].tci);
	mb->vlan_tci_outer = rte_cpu_to_le_16(meta->vlan[1].tci);
	PMD_RX_LOG(DEBUG, "Received outer vlan is %u inter vlan is %u",
			mb->vlan_tci_outer, mb->vlan_tci);
	mb->ol_flags |= RTE_MBUF_F_RX_QINQ | RTE_MBUF_F_RX_QINQ_STRIPPED;
}

/* nfp_net_parse_meta() - Parse the metadata from packet */
static void
nfp_net_parse_meta(struct nfp_net_rx_desc *rxds,
		struct nfp_net_rxq *rxq,
		struct nfp_net_hw *hw,
		struct rte_mbuf *mb)
{
	uint8_t *meta_base;
	rte_be32_t meta_header;
	struct nfp_meta_parsed meta = {};

	if (unlikely(NFP_DESC_META_LEN(rxds) == 0))
		return;

	meta_base = rte_pktmbuf_mtod(mb, uint8_t *);
	meta_base -= NFP_DESC_META_LEN(rxds);
	meta_header = *(rte_be32_t *)meta_base;

	switch (hw->meta_format) {
	case NFP_NET_METAFORMAT_CHAINED:
		if (nfp_net_parse_chained_meta(meta_base, meta_header, &meta)) {
			nfp_net_parse_meta_hash(&meta, rxq, mb);
			nfp_net_parse_meta_vlan(&meta, rxds, rxq, mb);
			nfp_net_parse_meta_qinq(&meta, rxq, mb);
		} else {
			PMD_RX_LOG(DEBUG, "RX chained metadata format is wrong!");
		}
		break;
	case NFP_NET_METAFORMAT_SINGLE:
		if ((rxds->rxd.flags & PCIE_DESC_RX_RSS) != 0) {
			nfp_net_parse_single_meta(meta_base, meta_header, &meta);
			nfp_net_parse_meta_hash(&meta, rxq, mb);
		}
		break;
	default:
		PMD_RX_LOG(DEBUG, "RX metadata do not exist.");
	}
}

/*
 * RX path design:
 *
 * There are some decisions to take:
 * 1) How to check DD RX descriptors bit
 * 2) How and when to allocate new mbufs
 *
 * Current implementation checks just one single DD bit each loop. As each
 * descriptor is 8 bytes, it is likely a good idea to check descriptors in
 * a single cache line instead. Tests with this change have not shown any
 * performance improvement but it requires further investigation. For example,
 * depending on which descriptor is next, the number of descriptors could be
 * less than 8 for just checking those in the same cache line. This implies
 * extra work which could be counterproductive by itself. Indeed, last firmware
 * changes are just doing this: writing several descriptors with the DD bit
 * for saving PCIe bandwidth and DMA operations from the NFP.
 *
 * Mbuf allocation is done when a new packet is received. Then the descriptor
 * is automatically linked with the new mbuf and the old one is given to the
 * user. The main drawback with this design is mbuf allocation is heavier than
 * using bulk allocations allowed by DPDK with rte_mempool_get_bulk. From the
 * cache point of view it does not seem allocating the mbuf early on as we are
 * doing now have any benefit at all. Again, tests with this change have not
 * shown any improvement. Also, rte_mempool_get_bulk returns all or nothing
 * so looking at the implications of this type of allocation should be studied
 * deeply
 */

uint16_t
nfp_net_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	struct nfp_net_rxq *rxq;
	struct nfp_net_rx_desc *rxds;
	struct nfp_net_rx_buff *rxb;
	struct nfp_net_hw *hw;
	struct rte_mbuf *mb;
	struct rte_mbuf *new_mb;
	uint16_t nb_hold;
	uint64_t dma_addr;
	uint16_t avail;

	avail = 0;
	rxq = rx_queue;
	if (unlikely(rxq == NULL)) {
		/*
		 * DPDK just checks the queue is lower than max queues
		 * enabled. But the queue needs to be configured
		 */
		PMD_RX_LOG(ERR, "RX Bad queue");
		return avail;
	}

	hw = rxq->hw;
	nb_hold = 0;

	while (avail < nb_pkts) {
		rxb = &rxq->rxbufs[rxq->rd_p];
		if (unlikely(rxb == NULL)) {
			PMD_RX_LOG(ERR, "rxb does not exist!");
			break;
		}

		rxds = &rxq->rxds[rxq->rd_p];
		if ((rxds->rxd.meta_len_dd & PCIE_DESC_RX_DD) == 0)
			break;

		/*
		 * Memory barrier to ensure that we won't do other
		 * reads before the DD bit.
		 */
		rte_rmb();

		/*
		 * We got a packet. Let's alloc a new mbuf for refilling the
		 * free descriptor ring as soon as possible
		 */
		new_mb = rte_pktmbuf_alloc(rxq->mem_pool);
		if (unlikely(new_mb == NULL)) {
			PMD_RX_LOG(DEBUG,
			"RX mbuf alloc failed port_id=%u queue_id=%u",
				rxq->port_id, (unsigned int)rxq->qidx);
			nfp_net_mbuf_alloc_failed(rxq);
			break;
		}

		/*
		 * Grab the mbuf and refill the descriptor with the
		 * previously allocated mbuf
		 */
		mb = rxb->mbuf;
		rxb->mbuf = new_mb;

		PMD_RX_LOG(DEBUG, "Packet len: %u, mbuf_size: %u",
			   rxds->rxd.data_len, rxq->mbuf_size);

		/* Size of this segment */
		mb->data_len = rxds->rxd.data_len - NFP_DESC_META_LEN(rxds);
		/* Size of the whole packet. We just support 1 segment */
		mb->pkt_len = rxds->rxd.data_len - NFP_DESC_META_LEN(rxds);

		if (unlikely((mb->data_len + hw->rx_offset) >
			     rxq->mbuf_size)) {
			/*
			 * This should not happen and the user has the
			 * responsibility of avoiding it. But we have
			 * to give some info about the error
			 */
			PMD_RX_LOG(ERR,
				"mbuf overflow likely due to the RX offset.\n"
				"\t\tYour mbuf size should have extra space for"
				" RX offset=%u bytes.\n"
				"\t\tCurrently you just have %u bytes available"
				" but the received packet is %u bytes long",
				hw->rx_offset,
				rxq->mbuf_size - hw->rx_offset,
				mb->data_len);
			rte_pktmbuf_free(mb);
			break;
		}

		/* Filling the received mbuf with packet info */
		if (hw->rx_offset)
			mb->data_off = RTE_PKTMBUF_HEADROOM + hw->rx_offset;
		else
			mb->data_off = RTE_PKTMBUF_HEADROOM +
				       NFP_DESC_META_LEN(rxds);

		/* No scatter mode supported */
		mb->nb_segs = 1;
		mb->next = NULL;
		mb->port = rxq->port_id;

		nfp_net_parse_meta(rxds, rxq, hw, mb);

		/* Checking the checksum flag */
		nfp_net_rx_cksum(rxq, rxds, mb);

		/* Adding the mbuf to the mbuf array passed by the app */
		rx_pkts[avail++] = mb;

		/* Now resetting and updating the descriptor */
		rxds->vals[0] = 0;
		rxds->vals[1] = 0;
		dma_addr = rte_cpu_to_le_64(RTE_MBUF_DMA_ADDR_DEFAULT(new_mb));
		rxds->fld.dd = 0;
		rxds->fld.dma_addr_hi = (dma_addr >> 32) & 0xffff;
		rxds->fld.dma_addr_lo = dma_addr & 0xffffffff;
		nb_hold++;

		rxq->rd_p++;
		if (unlikely(rxq->rd_p == rxq->rx_count)) /* wrapping?*/
			rxq->rd_p = 0;
	}

	if (nb_hold == 0)
		return nb_hold;

	PMD_RX_LOG(DEBUG, "RX  port_id=%u queue_id=%u, %d packets received",
		   rxq->port_id, (unsigned int)rxq->qidx, nb_hold);

	nb_hold += rxq->nb_rx_hold;

	/*
	 * FL descriptors needs to be written before incrementing the
	 * FL queue WR pointer
	 */
	rte_wmb();
	if (nb_hold > rxq->rx_free_thresh) {
		PMD_RX_LOG(DEBUG, "port=%u queue=%u nb_hold=%u avail=%u",
			   rxq->port_id, (unsigned int)rxq->qidx,
			   (unsigned int)nb_hold, (unsigned int)avail);
		nfp_qcp_ptr_add(rxq->qcp_fl, NFP_QCP_WRITE_PTR, nb_hold);
		nb_hold = 0;
	}
	rxq->nb_rx_hold = nb_hold;

	return avail;
}

static void
nfp_net_rx_queue_release_mbufs(struct nfp_net_rxq *rxq)
{
	unsigned int i;

	if (rxq->rxbufs == NULL)
		return;

	for (i = 0; i < rxq->rx_count; i++) {
		if (rxq->rxbufs[i].mbuf) {
			rte_pktmbuf_free_seg(rxq->rxbufs[i].mbuf);
			rxq->rxbufs[i].mbuf = NULL;
		}
	}
}

void
nfp_net_rx_queue_release(struct rte_eth_dev *dev, uint16_t queue_idx)
{
	struct nfp_net_rxq *rxq = dev->data->rx_queues[queue_idx];

	if (rxq) {
		nfp_net_rx_queue_release_mbufs(rxq);
		rte_eth_dma_zone_free(dev, "rx_ring", queue_idx);
		rte_free(rxq->rxbufs);
		rte_free(rxq);
	}
}

void
nfp_net_reset_rx_queue(struct nfp_net_rxq *rxq)
{
	nfp_net_rx_queue_release_mbufs(rxq);
	rxq->rd_p = 0;
	rxq->nb_rx_hold = 0;
}

int
nfp_net_rx_queue_setup(struct rte_eth_dev *dev,
		       uint16_t queue_idx, uint16_t nb_desc,
		       unsigned int socket_id,
		       const struct rte_eth_rxconf *rx_conf,
		       struct rte_mempool *mp)
{
	int ret;
	uint16_t min_rx_desc;
	uint16_t max_rx_desc;
	const struct rte_memzone *tz;
	struct nfp_net_rxq *rxq;
	struct nfp_net_hw *hw;
	uint32_t rx_desc_sz;

	hw = NFP_NET_DEV_PRIVATE_TO_HW(dev->data->dev_private);

	PMD_INIT_FUNC_TRACE();

	ret = nfp_net_rx_desc_limits(hw, &min_rx_desc, &max_rx_desc);
	if (ret != 0)
		return ret;

	/* Validating number of descriptors */
	rx_desc_sz = nb_desc * sizeof(struct nfp_net_rx_desc);
	if (rx_desc_sz % NFP_ALIGN_RING_DESC != 0 ||
	    nb_desc > max_rx_desc || nb_desc < min_rx_desc) {
		PMD_DRV_LOG(ERR, "Wrong nb_desc value");
		return -EINVAL;
	}

	/*
	 * Free memory prior to re-allocation if needed. This is the case after
	 * calling nfp_net_stop
	 */
	if (dev->data->rx_queues[queue_idx]) {
		nfp_net_rx_queue_release(dev, queue_idx);
		dev->data->rx_queues[queue_idx] = NULL;
	}

	/* Allocating rx queue data structure */
	rxq = rte_zmalloc_socket("ethdev RX queue", sizeof(struct nfp_net_rxq),
				 RTE_CACHE_LINE_SIZE, socket_id);
	if (rxq == NULL)
		return -ENOMEM;

	dev->data->rx_queues[queue_idx] = rxq;

	/* Hw queues mapping based on firmware configuration */
	rxq->qidx = queue_idx;
	rxq->fl_qcidx = queue_idx * hw->stride_rx;
	rxq->rx_qcidx = rxq->fl_qcidx + (hw->stride_rx - 1);
	rxq->qcp_fl = hw->rx_bar + NFP_QCP_QUEUE_OFF(rxq->fl_qcidx);
	rxq->qcp_rx = hw->rx_bar + NFP_QCP_QUEUE_OFF(rxq->rx_qcidx);

	/*
	 * Tracking mbuf size for detecting a potential mbuf overflow due to
	 * RX offset
	 */
	rxq->mem_pool = mp;
	rxq->mbuf_size = rxq->mem_pool->elt_size;
	rxq->mbuf_size -= (sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM);
	hw->flbufsz = rxq->mbuf_size;

	rxq->rx_count = nb_desc;
	rxq->port_id = dev->data->port_id;
	rxq->rx_free_thresh = rx_conf->rx_free_thresh;
	rxq->drop_en = rx_conf->rx_drop_en;

	/*
	 * Allocate RX ring hardware descriptors. A memzone large enough to
	 * handle the maximum ring size is allocated in order to allow for
	 * resizing in later calls to the queue setup function.
	 */
	tz = rte_eth_dma_zone_reserve(dev, "rx_ring", queue_idx,
				   sizeof(struct nfp_net_rx_desc) *
				   max_rx_desc, NFP_MEMZONE_ALIGN,
				   socket_id);

	if (tz == NULL) {
		PMD_DRV_LOG(ERR, "Error allocating rx dma");
		nfp_net_rx_queue_release(dev, queue_idx);
		dev->data->rx_queues[queue_idx] = NULL;
		return -ENOMEM;
	}

	/* Saving physical and virtual addresses for the RX ring */
	rxq->dma = (uint64_t)tz->iova;
	rxq->rxds = (struct nfp_net_rx_desc *)tz->addr;

	/* mbuf pointers array for referencing mbufs linked to RX descriptors */
	rxq->rxbufs = rte_zmalloc_socket("rxq->rxbufs",
					 sizeof(*rxq->rxbufs) * nb_desc,
					 RTE_CACHE_LINE_SIZE, socket_id);
	if (rxq->rxbufs == NULL) {
		nfp_net_rx_queue_release(dev, queue_idx);
		dev->data->rx_queues[queue_idx] = NULL;
		return -ENOMEM;
	}

	PMD_RX_LOG(DEBUG, "rxbufs=%p hw_ring=%p dma_addr=0x%" PRIx64,
		   rxq->rxbufs, rxq->rxds, (unsigned long)rxq->dma);

	nfp_net_reset_rx_queue(rxq);

	rxq->hw = hw;

	/*
	 * Telling the HW about the physical address of the RX ring and number
	 * of descriptors in log2 format
	 */
	nn_cfg_writeq(hw, NFP_NET_CFG_RXR_ADDR(queue_idx), rxq->dma);
	nn_cfg_writeb(hw, NFP_NET_CFG_RXR_SZ(queue_idx), rte_log2_u32(nb_desc));

	return 0;
}

/*
 * nfp_net_tx_free_bufs - Check for descriptors with a complete
 * status
 * @txq: TX queue to work with
 * Returns number of descriptors freed
 */
int
nfp_net_tx_free_bufs(struct nfp_net_txq *txq)
{
	uint32_t qcp_rd_p;
	int todo;

	PMD_TX_LOG(DEBUG, "queue %u. Check for descriptor with a complete"
		   " status", txq->qidx);

	/* Work out how many packets have been sent */
	qcp_rd_p = nfp_qcp_read(txq->qcp_q, NFP_QCP_READ_PTR);

	if (qcp_rd_p == txq->rd_p) {
		PMD_TX_LOG(DEBUG, "queue %u: It seems harrier is not sending "
			   "packets (%u, %u)", txq->qidx,
			   qcp_rd_p, txq->rd_p);
		return 0;
	}

	if (qcp_rd_p > txq->rd_p)
		todo = qcp_rd_p - txq->rd_p;
	else
		todo = qcp_rd_p + txq->tx_count - txq->rd_p;

	PMD_TX_LOG(DEBUG, "qcp_rd_p %u, txq->rd_p: %u, qcp->rd_p: %u",
		   qcp_rd_p, txq->rd_p, txq->rd_p);

	if (todo == 0)
		return todo;

	txq->rd_p += todo;
	if (unlikely(txq->rd_p >= txq->tx_count))
		txq->rd_p -= txq->tx_count;

	return todo;
}

static void
nfp_net_tx_queue_release_mbufs(struct nfp_net_txq *txq)
{
	unsigned int i;

	if (txq->txbufs == NULL)
		return;

	for (i = 0; i < txq->tx_count; i++) {
		if (txq->txbufs[i].mbuf) {
			rte_pktmbuf_free_seg(txq->txbufs[i].mbuf);
			txq->txbufs[i].mbuf = NULL;
		}
	}
}

void
nfp_net_tx_queue_release(struct rte_eth_dev *dev, uint16_t queue_idx)
{
	struct nfp_net_txq *txq = dev->data->tx_queues[queue_idx];

	if (txq) {
		nfp_net_tx_queue_release_mbufs(txq);
		rte_eth_dma_zone_free(dev, "tx_ring", queue_idx);
		rte_free(txq->txbufs);
		rte_free(txq);
	}
}

void
nfp_net_reset_tx_queue(struct nfp_net_txq *txq)
{
	nfp_net_tx_queue_release_mbufs(txq);
	txq->wr_p = 0;
	txq->rd_p = 0;
}

void
nfp_net_set_meta_vlan(struct nfp_net_meta_raw *meta_data,
		struct rte_mbuf *pkt,
		uint8_t layer)
{
	uint16_t vlan_tci;
	uint16_t tpid;

	tpid = RTE_ETHER_TYPE_VLAN;
	vlan_tci = pkt->vlan_tci;

	meta_data->data[layer] = rte_cpu_to_be_32(tpid << 16 | vlan_tci);
}

int
nfp_net_tx_queue_setup(struct rte_eth_dev *dev,
		uint16_t queue_idx,
		uint16_t nb_desc,
		unsigned int socket_id,
		const struct rte_eth_txconf *tx_conf)
{
	struct nfp_net_hw *hw;

	hw = NFP_NET_DEV_PRIVATE_TO_HW(dev->data->dev_private);

	switch (NFD_CFG_CLASS_VER_of(hw->ver)) {
	case NFP_NET_CFG_VERSION_DP_NFD3:
		return nfp_net_nfd3_tx_queue_setup(dev, queue_idx,
				nb_desc, socket_id, tx_conf);
	case NFP_NET_CFG_VERSION_DP_NFDK:
		if (NFD_CFG_MAJOR_VERSION_of(hw->ver) < 5) {
			PMD_DRV_LOG(ERR, "NFDK must use ABI 5 or newer, found: %d",
				NFD_CFG_MAJOR_VERSION_of(hw->ver));
			return -EINVAL;
		}
		return nfp_net_nfdk_tx_queue_setup(dev, queue_idx,
				nb_desc, socket_id, tx_conf);
	default:
		PMD_DRV_LOG(ERR, "The version of firmware is not correct.");
		return -EINVAL;
	}
}

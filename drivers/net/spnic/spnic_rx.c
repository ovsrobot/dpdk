/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#include <rte_ether.h>
#include <rte_mbuf.h>
#include <ethdev_driver.h>

#include "base/spnic_compat.h"
#include "base/spnic_cmd.h"
#include "base/spnic_hwif.h"
#include "base/spnic_hwdev.h"
#include "base/spnic_wq.h"
#include "base/spnic_mgmt.h"
#include "base/spnic_nic_cfg.h"
#include "spnic_io.h"
#include "spnic_rx.h"
#include "spnic_ethdev.h"

/**
 * Get receive queue wqe
 *
 * @param[in] rxq
 *   Receive queue
 * @param[out] pi
 *   Return current pi
 * @return
 *   RX wqe base address
 */
static inline void *spnic_get_rq_wqe(struct spnic_rxq *rxq, u16 *pi)
{
	*pi = MASKED_QUEUE_IDX(rxq, rxq->prod_idx);

	/* Get only one rq wqe for once */
	rxq->prod_idx++;
	rxq->delta--;

	return NIC_WQE_ADDR(rxq, *pi);
}

/**
 * Put receive queue wqe
 *
 * @param[in] rxq
 *   Receive queue
 * @param[in] wqe_cnt
 *   Wqebb counters
 */
static inline void spnic_put_rq_wqe(struct spnic_rxq *rxq, u16 wqe_cnt)
{
	rxq->delta += wqe_cnt;
	rxq->prod_idx -= wqe_cnt;
}

/**
 * Get receive queue local pi
 *
 * @param[in] rxq
 *   Receive queue
 * @return
 *   Receive queue local pi
 */
static inline u16 spnic_get_rq_local_pi(struct spnic_rxq *rxq)
{
	return MASKED_QUEUE_IDX(rxq, rxq->prod_idx);
}

int spnic_rx_fill_wqe(struct spnic_rxq *rxq)
{
	struct spnic_rq_wqe *rq_wqe = NULL;
	struct spnic_nic_dev *nic_dev = rxq->nic_dev;
	rte_iova_t cqe_dma;
	u16 pi = 0;
	int i;

	cqe_dma = rxq->cqe_start_paddr;
	for (i = 0; i < rxq->q_depth; i++) {
		rq_wqe = spnic_get_rq_wqe(rxq, &pi);
		if (!rq_wqe) {
			PMD_DRV_LOG(ERR, "Get rq wqe failed, rxq id: %d, wqe id: %d",
				    rxq->q_id, i);
			break;
		}

		if (rxq->wqe_type == SPNIC_EXTEND_RQ_WQE) {
			/* Unit of cqe length is 16B */
			spnic_set_sge(&rq_wqe->extend_wqe.cqe_sect.sge,
				       cqe_dma,
				       sizeof(struct spnic_rq_cqe) >>
				       SPNIC_CQE_SIZE_SHIFT);
			/* Use fixed len */
			rq_wqe->extend_wqe.buf_desc.sge.len =
							nic_dev->rx_buff_len;
		} else {
			rq_wqe->normal_wqe.cqe_hi_addr = upper_32_bits(cqe_dma);
			rq_wqe->normal_wqe.cqe_lo_addr = lower_32_bits(cqe_dma);
		}

		cqe_dma += sizeof(struct spnic_rq_cqe);
	}

	spnic_put_rq_wqe(rxq, (u16)i);

	return i;
}

static struct rte_mbuf *spnic_rx_alloc_mbuf(struct spnic_rxq *rxq,
					    rte_iova_t *dma_addr)
{
	struct rte_mbuf *mbuf = NULL;

	if (unlikely(rte_pktmbuf_alloc_bulk(rxq->mb_pool, &mbuf, 1) != 0))
		return NULL;

	*dma_addr = rte_mbuf_data_iova_default(mbuf);

	return mbuf;
}

u32 spnic_rx_fill_buffers(struct spnic_rxq *rxq)
{
	struct spnic_rq_wqe *rq_wqe = NULL;
	struct spnic_rx_info *rx_info = NULL;
	struct rte_mbuf *mb = NULL;
	rte_iova_t dma_addr;
	int i, free_wqebbs;

	free_wqebbs = rxq->delta - 1;
	for (i = 0; i < free_wqebbs; i++) {
		rx_info = &rxq->rx_info[rxq->next_to_update];

		mb = spnic_rx_alloc_mbuf(rxq, &dma_addr);
		if (!mb) {
			PMD_DRV_LOG(ERR, "Alloc mbuf failed");
			break;
		}

		rx_info->mbuf = mb;

		rq_wqe = NIC_WQE_ADDR(rxq, rxq->next_to_update);

		/* Fill buffer address only */
		if (rxq->wqe_type == SPNIC_EXTEND_RQ_WQE) {
			rq_wqe->extend_wqe.buf_desc.sge.hi_addr = upper_32_bits(dma_addr);
			rq_wqe->extend_wqe.buf_desc.sge.lo_addr = lower_32_bits(dma_addr);
		} else {
			rq_wqe->normal_wqe.buf_hi_addr = upper_32_bits(dma_addr);
			rq_wqe->normal_wqe.buf_lo_addr = lower_32_bits(dma_addr);
		}

		rxq->next_to_update = (rxq->next_to_update + 1) & rxq->q_mask;
	}

	if (likely(i > 0)) {
		spnic_write_db(rxq->db_addr, rxq->q_id, 0, RQ_CFLAG_DP,
				rxq->next_to_update << rxq->wqe_type);
		/* Init rq contxet used, need to optimization */
		rxq->prod_idx = rxq->next_to_update;
		rxq->delta -= i;
	} else {
		PMD_DRV_LOG(ERR, "Alloc rx buffers failed, rxq_id: %d",
			    rxq->q_id);
	}

	return i;
}

void spnic_free_rxq_mbufs(struct spnic_rxq *rxq)
{
	struct spnic_rx_info *rx_info = NULL;
	int free_wqebbs = spnic_get_rq_free_wqebb(rxq) + 1;
	volatile struct spnic_rq_cqe *rx_cqe = NULL;
	u16 ci;

	while (free_wqebbs++ < rxq->q_depth) {
		ci = spnic_get_rq_local_ci(rxq);

		rx_cqe = &rxq->rx_cqe[ci];

		/* Clear done bit */
		rx_cqe->status = 0;

		rx_info = &rxq->rx_info[ci];
		rte_pktmbuf_free(rx_info->mbuf);
		rx_info->mbuf = NULL;

		spnic_update_rq_local_ci(rxq, 1);
	}
}

void spnic_free_all_rxq_mbufs(struct spnic_nic_dev *nic_dev)
{
	u16 qid;

	for (qid = 0; qid < nic_dev->num_rqs; qid++)
		spnic_free_rxq_mbufs(nic_dev->rxqs[qid]);
}

static inline u32 spnic_rx_alloc_mbuf_bulk(struct spnic_rxq *rxq,
					   struct rte_mbuf **mbufs,
					   u32 exp_mbuf_cnt)
{
	u32 avail_cnt;
	int err;

	err = rte_pktmbuf_alloc_bulk(rxq->mb_pool, mbufs, exp_mbuf_cnt);
	if (likely(err == 0)) {
		avail_cnt = exp_mbuf_cnt;
	} else {
		avail_cnt = 0;
		rxq->rxq_stats.rx_nombuf += exp_mbuf_cnt;
	}

	return avail_cnt;
}

static inline void spnic_rearm_rxq_mbuf(struct spnic_rxq *rxq)
{
	struct spnic_rq_wqe *rq_wqe = NULL;
	struct rte_mbuf **rearm_mbufs;
	u32 i, free_wqebbs, rearm_wqebbs, exp_wqebbs;
	rte_iova_t dma_addr;
	u16 pi;

	/* Check free wqebb cnt fo rearm */
	free_wqebbs = spnic_get_rq_free_wqebb(rxq);
	if (unlikely(free_wqebbs < rxq->rx_free_thresh))
		return;

	/* Get rearm mbuf array */
	pi = spnic_get_rq_local_pi(rxq);
	rearm_mbufs = (struct rte_mbuf **)(&rxq->rx_info[pi]);

	/* Check rxq free wqebbs turn around */
	exp_wqebbs = rxq->q_depth - pi;
	if (free_wqebbs < exp_wqebbs)
		exp_wqebbs = free_wqebbs;

	/* Alloc mbuf in bulk */
	rearm_wqebbs = spnic_rx_alloc_mbuf_bulk(rxq, rearm_mbufs, exp_wqebbs);
	if (unlikely(rearm_wqebbs == 0))
		return;

	/* Rearm rx mbuf */
	rq_wqe = NIC_WQE_ADDR(rxq, pi);
	for (i = 0; i < rearm_wqebbs; i++) {
		dma_addr = rte_mbuf_data_iova_default(rearm_mbufs[i]);

		/* Fill buffer address only */
		if (rxq->wqe_type == SPNIC_EXTEND_RQ_WQE) {
			rq_wqe->extend_wqe.buf_desc.sge.hi_addr = upper_32_bits(dma_addr);
			rq_wqe->extend_wqe.buf_desc.sge.lo_addr = lower_32_bits(dma_addr);
		} else {
			rq_wqe->normal_wqe.buf_hi_addr = upper_32_bits(dma_addr);
			rq_wqe->normal_wqe.buf_lo_addr = lower_32_bits(dma_addr);
		}

		rq_wqe = (struct spnic_rq_wqe *)((u64)rq_wqe +
			 rxq->wqebb_size);
	}
	rxq->prod_idx += rearm_wqebbs;
	rxq->delta -= rearm_wqebbs;

	spnic_write_db(rxq->db_addr, rxq->q_id, 0, RQ_CFLAG_DP,
			((pi + rearm_wqebbs) & rxq->q_mask) << rxq->wqe_type);
}

static int spnic_init_rss_key(struct spnic_nic_dev *nic_dev,
			       struct rte_eth_rss_conf *rss_conf)
{
	u8 default_rss_key[SPNIC_RSS_KEY_SIZE] = {
			 0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
			 0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
			 0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
			 0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
			 0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa};
	u8 hashkey[SPNIC_RSS_KEY_SIZE] = {0};
	int err;

	if (rss_conf->rss_key == NULL ||
	    rss_conf->rss_key_len > SPNIC_RSS_KEY_SIZE)
		memcpy(hashkey, default_rss_key, SPNIC_RSS_KEY_SIZE);
	else
		memcpy(hashkey, rss_conf->rss_key, rss_conf->rss_key_len);

	err = spnic_rss_set_hash_key(nic_dev->hwdev, hashkey);
	if (err)
		return err;

	memcpy(nic_dev->rss_key, hashkey, SPNIC_RSS_KEY_SIZE);
	return 0;
}

void spnic_add_rq_to_rx_queue_list(struct spnic_nic_dev *nic_dev,
				    u16 queue_id)
{
	u8 rss_queue_count = nic_dev->num_rss;

	RTE_ASSERT(rss_queue_count <= (RTE_DIM(nic_dev->rx_queue_list) - 1));

	nic_dev->rx_queue_list[rss_queue_count] = (u8)queue_id;
	nic_dev->num_rss++;
}

void spnic_init_rx_queue_list(struct spnic_nic_dev *nic_dev)
{
	nic_dev->num_rss = 0;
}

static void spnic_fill_indir_tbl(struct spnic_nic_dev *nic_dev,
				  u32 *indir_tbl)
{
	u8 rss_queue_count = nic_dev->num_rss;
	int i = 0;
	int j;

	if (rss_queue_count == 0) {
		/* delete q_id from indir tbl */
		for (i = 0; i < SPNIC_RSS_INDIR_SIZE; i++)
			indir_tbl[i] = 0xFF; /* Invalid value in indir tbl */
	} else {
		while (i < SPNIC_RSS_INDIR_SIZE)
			for (j = 0; (j < rss_queue_count) &&
				    (i < SPNIC_RSS_INDIR_SIZE); j++)
				indir_tbl[i++] = nic_dev->rx_queue_list[j];
	}
}

int spnic_refill_indir_rqid(struct spnic_rxq *rxq)
{
	struct spnic_nic_dev *nic_dev = rxq->nic_dev;
	u32 *indir_tbl;
	int err;

	indir_tbl = rte_zmalloc(NULL, SPNIC_RSS_INDIR_SIZE * sizeof(u32), 0);
	if (!indir_tbl) {
		PMD_DRV_LOG(ERR, "Alloc indir_tbl mem failed, eth_dev:%s, queue_idx:%d\n",
			    nic_dev->dev_name, rxq->q_id);
		return -ENOMEM;
	}

	/* build indir tbl according to the number of rss queue */
	spnic_fill_indir_tbl(nic_dev, indir_tbl);

	err = spnic_rss_set_indir_tbl(nic_dev->hwdev, indir_tbl);
	if (err) {
		PMD_DRV_LOG(ERR, "Set indrect table failed, eth_dev:%s, queue_idx:%d\n",
			    nic_dev->dev_name, rxq->q_id);
		goto out;
	}

out:
	rte_free(indir_tbl);
	return err;
}

static int spnic_init_rss_type(struct spnic_nic_dev *nic_dev,
			       struct rte_eth_rss_conf *rss_conf)
{
	struct spnic_rss_type rss_type = {0};
	u64 rss_hf = rss_conf->rss_hf;
	int err;

	rss_type.ipv4 = (rss_hf & (ETH_RSS_IPV4 | ETH_RSS_FRAG_IPV4)) ? 1 : 0;
	rss_type.tcp_ipv4 = (rss_hf & ETH_RSS_NONFRAG_IPV4_TCP) ? 1 : 0;
	rss_type.ipv6 = (rss_hf & (ETH_RSS_IPV6 | ETH_RSS_FRAG_IPV6)) ? 1 : 0;
	rss_type.ipv6_ext = (rss_hf & ETH_RSS_IPV6_EX) ? 1 : 0;
	rss_type.tcp_ipv6 = (rss_hf & ETH_RSS_NONFRAG_IPV6_TCP) ? 1 : 0;
	rss_type.tcp_ipv6_ext = (rss_hf & ETH_RSS_IPV6_TCP_EX) ? 1 : 0;
	rss_type.udp_ipv4 = (rss_hf & ETH_RSS_NONFRAG_IPV4_UDP) ? 1 : 0;
	rss_type.udp_ipv6 = (rss_hf & ETH_RSS_NONFRAG_IPV6_UDP) ? 1 : 0;

	err = spnic_set_rss_type(nic_dev->hwdev, rss_type);
	return err;
}

int spnic_update_rss_config(struct rte_eth_dev *dev,
			    struct rte_eth_rss_conf *rss_conf)
{
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	u8 prio_tc[SPNIC_DCB_UP_MAX] = {0};
	u8 num_tc = 0;
	int err;

	if (rss_conf->rss_hf == 0) {
		rss_conf->rss_hf = SPNIC_RSS_OFFLOAD_ALL;
	} else if ((rss_conf->rss_hf & SPNIC_RSS_OFFLOAD_ALL) == 0) {
		PMD_DRV_LOG(ERR, "Doesn't support rss hash type: %" PRIu64 "",
			    rss_conf->rss_hf);
		return -EINVAL;
	}

	err = spnic_rss_template_alloc(nic_dev->hwdev);
	if (err) {
		PMD_DRV_LOG(ERR, "Alloc rss template failed, err: %d", err);
		return err;
	}

	err = spnic_init_rss_key(nic_dev, rss_conf);
	if (err) {
		PMD_DRV_LOG(ERR, "Init rss hash key failed, err: %d", err);
		goto init_rss_fail;
	}

	err = spnic_init_rss_type(nic_dev, rss_conf);
	if (err) {
		PMD_DRV_LOG(ERR, "Init rss hash type failed, err: %d", err);
		goto init_rss_fail;
	}

	err = spnic_rss_set_hash_engine(nic_dev->hwdev,
					 SPNIC_RSS_HASH_ENGINE_TYPE_TOEP);
	if (err) {
		PMD_DRV_LOG(ERR, "Init rss hash function failed, err: %d", err);
		goto init_rss_fail;
	}

	err = spnic_rss_cfg(nic_dev->hwdev, SPNIC_RSS_ENABLE, num_tc,
			     prio_tc);
	if (err) {
		PMD_DRV_LOG(ERR, "Enable rss failed, err: %d", err);
		goto init_rss_fail;
	}

	nic_dev->rss_state = SPNIC_RSS_ENABLE;
	return 0;

init_rss_fail:
	if (spnic_rss_template_free(nic_dev->hwdev))
		PMD_DRV_LOG(WARNING, "Free rss template failed");

	return err;
}

static u8 spnic_find_queue_pos_by_rq_id(u8 *queues, u8 queues_count,
					 u8 queue_id)
{
	u8 pos;

	for (pos = 0; pos < queues_count; pos++) {
		if (queue_id == queues[pos])
			break;
	}

	return pos;
}

void spnic_remove_rq_from_rx_queue_list(struct spnic_nic_dev *nic_dev,
					 u16 queue_id)
{
	u8 queue_pos;
	u8 rss_queue_count = nic_dev->num_rss;

	queue_pos = spnic_find_queue_pos_by_rq_id(nic_dev->rx_queue_list,
						   rss_queue_count,
						   (u8)queue_id);

	if (queue_pos < rss_queue_count) {
		rss_queue_count--;
		memmove(nic_dev->rx_queue_list + queue_pos,
			nic_dev->rx_queue_list + queue_pos + 1,
			(rss_queue_count - queue_pos) *
			sizeof(nic_dev->rx_queue_list[0]));
	}

	RTE_ASSERT(rss_queue_count < RTE_DIM(nic_dev->rx_queue_list));
	nic_dev->num_rss = rss_queue_count;
}


static inline uint64_t spnic_rx_vlan(uint32_t offload_type, uint32_t vlan_len,
				      uint16_t *vlan_tci)
{
	uint16_t vlan_tag;

	vlan_tag = SPNIC_GET_RX_VLAN_TAG(vlan_len);
	if (!SPNIC_GET_RX_VLAN_OFFLOAD_EN(offload_type) || vlan_tag == 0) {
		*vlan_tci = 0;
		return 0;
	}

	*vlan_tci = vlan_tag;

	return RTE_MBUF_F_RX_VLAN | RTE_MBUF_F_RX_VLAN_STRIPPED;
}

static inline uint64_t spnic_rx_csum(uint32_t status, struct spnic_rxq *rxq)
{
	struct spnic_nic_dev *nic_dev = rxq->nic_dev;
	uint32_t csum_err;
	uint64_t flags;

	if (unlikely(!(nic_dev->rx_csum_en & SPNIC_DEFAULT_RX_CSUM_OFFLOAD)))
		return RTE_MBUF_F_RX_IP_CKSUM_UNKNOWN;

	/* Most case checksum is ok */
	csum_err = SPNIC_GET_RX_CSUM_ERR(status);
	if (likely(csum_err == 0))
		return (RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_GOOD);

	/*
	 * If bypass bit is set, all other err status indications should be
	 * ignored
	 */
	if (unlikely(csum_err & SPNIC_RX_CSUM_HW_CHECK_NONE))
		return RTE_MBUF_F_RX_IP_CKSUM_UNKNOWN;

	flags = 0;

	/* IP checksum error */
	if (csum_err & SPNIC_RX_CSUM_IP_CSUM_ERR) {
		flags |= RTE_MBUF_F_RX_IP_CKSUM_BAD;
		rxq->rxq_stats.errors++;
	}

	/* L4 checksum error */
	if (csum_err & SPNIC_RX_CSUM_TCP_CSUM_ERR ||
	    csum_err & SPNIC_RX_CSUM_UDP_CSUM_ERR ||
	    csum_err & SPNIC_RX_CSUM_SCTP_CRC_ERR) {
		flags |= RTE_MBUF_F_RX_L4_CKSUM_BAD;
		rxq->rxq_stats.errors++;
	}

	if (unlikely(csum_err == SPNIC_RX_CSUM_IPSU_OTHER_ERR))
		rxq->rxq_stats.other_errors++;

	return flags;
}

static inline uint64_t spnic_rx_rss_hash(uint32_t offload_type,
					 uint32_t rss_hash_value,
					 uint32_t *rss_hash)
{
	uint32_t rss_type;

	rss_type = SPNIC_GET_RSS_TYPES(offload_type);
	if (likely(rss_type != 0)) {
		*rss_hash = rss_hash_value;
		return RTE_MBUF_F_RX_RSS_HASH;
	}

	return 0;
}

static void spnic_recv_jumbo_pkt(struct spnic_rxq *rxq,
				 struct rte_mbuf *head_mbuf,
				 u32 remain_pkt_len)
{
	struct rte_mbuf *cur_mbuf = NULL;
	struct rte_mbuf *rxm = NULL;
	struct spnic_rx_info *rx_info = NULL;
	u16 sw_ci, rx_buf_len = rxq->buf_len;
	u32 pkt_len;

	while (remain_pkt_len > 0) {
		sw_ci = spnic_get_rq_local_ci(rxq);
		rx_info = &rxq->rx_info[sw_ci];

		spnic_update_rq_local_ci(rxq, 1);

		pkt_len = remain_pkt_len > rx_buf_len ?
			rx_buf_len : remain_pkt_len;
		remain_pkt_len -= pkt_len;

		cur_mbuf = rx_info->mbuf;
		cur_mbuf->data_len = (u16)pkt_len;
		cur_mbuf->next = NULL;

		head_mbuf->pkt_len += cur_mbuf->data_len;
		head_mbuf->nb_segs++;

		if (!rxm)
			head_mbuf->next = cur_mbuf;
		else
			rxm->next = cur_mbuf;

		rxm = cur_mbuf;
	}
}

int spnic_start_all_rqs(struct rte_eth_dev *eth_dev)
{
	struct spnic_nic_dev *nic_dev = NULL;
	struct spnic_rxq *rxq = NULL;
	int err = 0;
	int i;

	nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(eth_dev);

	for (i = 0; i < nic_dev->num_rqs; i++) {
		rxq = eth_dev->data->rx_queues[i];
		spnic_add_rq_to_rx_queue_list(nic_dev, rxq->q_id);
		spnic_rearm_rxq_mbuf(rxq);
		eth_dev->data->rx_queue_state[i] = RTE_ETH_QUEUE_STATE_STARTED;
	}

	if (nic_dev->rss_state == SPNIC_RSS_ENABLE) {
		err = spnic_refill_indir_rqid(rxq);
		if (err) {
			PMD_DRV_LOG(ERR, "Refill rq to indrect table failed, eth_dev:%s, queue_idx:%d err:%d\n",
				    rxq->nic_dev->dev_name, rxq->q_id, err);
			goto out;
		}
	}

	return 0;
out:
	for (i = 0; i < nic_dev->num_rqs; i++) {
		rxq = eth_dev->data->rx_queues[i];
		spnic_remove_rq_from_rx_queue_list(nic_dev, rxq->q_id);
		spnic_free_rxq_mbufs(rxq);
		eth_dev->data->rx_queue_state[i] = RTE_ETH_QUEUE_STATE_STOPPED;
	}
	return err;
}

u16 spnic_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts, u16 nb_pkts)
{
	struct spnic_rxq *rxq = rx_queue;
	struct spnic_rx_info *rx_info = NULL;
	volatile struct spnic_rq_cqe *rx_cqe = NULL;
	struct rte_mbuf *rxm = NULL;
	u16 sw_ci, wqebb_cnt = 0;
	u32 status, pkt_len, vlan_len, offload_type, hash_value;
	u32 lro_num;
	u64 rx_bytes = 0;
	u16 rx_buf_len, pkts = 0;

	rx_buf_len = rxq->buf_len;
	sw_ci = spnic_get_rq_local_ci(rxq);

	while (pkts < nb_pkts) {
		rx_cqe = &rxq->rx_cqe[sw_ci];
		status = rx_cqe->status;
		if (!SPNIC_GET_RX_DONE(status))
			break;

		/* Make sure rx_done is read before packet length */
		rte_rmb();

		vlan_len = rx_cqe->vlan_len;
		pkt_len = SPNIC_GET_RX_PKT_LEN(vlan_len);

		rx_info = &rxq->rx_info[sw_ci];
		rxm = rx_info->mbuf;

		/* 1. Next ci point and prefetch */
		sw_ci++;
		sw_ci &= rxq->q_mask;

		/* 2. Prefetch next mbuf first 64B */
		rte_prefetch0(rxq->rx_info[sw_ci].mbuf);

		/* 3. Jumbo frame process */
		if (likely(pkt_len <= rx_buf_len)) {
			rxm->data_len = pkt_len;
			rxm->pkt_len = pkt_len;
			wqebb_cnt++;
		} else {
			rxm->data_len = rx_buf_len;
			rxm->pkt_len = rx_buf_len;

			/* If receive jumbo, updating ci will be done by
			 * spnic_recv_jumbo_pkt function.
			 */
			spnic_update_rq_local_ci(rxq, wqebb_cnt + 1);
			wqebb_cnt = 0;
			spnic_recv_jumbo_pkt(rxq, rxm, pkt_len - rx_buf_len);
			sw_ci = spnic_get_rq_local_ci(rxq);
		}

		rxm->data_off = RTE_PKTMBUF_HEADROOM;
		rxm->port = rxq->port_id;

		/* 4. Rx checksum offload */
		rxm->ol_flags |= spnic_rx_csum(status, rxq);

		/* 5. Vlan offload */
		offload_type = rx_cqe->offload_type;
		rxm->ol_flags |= spnic_rx_vlan(offload_type, vlan_len,
						&rxm->vlan_tci);
		/* 6. RSS */
		hash_value = rx_cqe->hash_val;
		rxm->ol_flags |= spnic_rx_rss_hash(offload_type, hash_value,
						    &rxm->hash.rss);
		/* 7. LRO */
		lro_num = SPNIC_GET_RX_NUM_LRO(status);
		if (unlikely(lro_num != 0)) {
			rxm->ol_flags |= RTE_MBUF_F_RX_LRO;
			rxm->tso_segsz = pkt_len / lro_num;
		}

		rx_cqe->status = 0;

		rx_bytes += pkt_len;
		rx_pkts[pkts++] = rxm;
	}

	if (pkts) {
		/* 8. Update local ci */
		spnic_update_rq_local_ci(rxq, wqebb_cnt);

		/* Update packet stats */
		rxq->rxq_stats.packets += pkts;
		rxq->rxq_stats.bytes += rx_bytes;
	}
	rxq->rxq_stats.burst_pkts = pkts;

	/* 9. Rearm mbuf to rxq */
	spnic_rearm_rxq_mbuf(rxq);

	return pkts;
}

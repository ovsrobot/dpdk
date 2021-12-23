/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_io.h>
#include <ethdev_driver.h>

#include "base/spnic_compat.h"
#include "base/spnic_cmd.h"
#include "base/spnic_wq.h"
#include "base/spnic_mgmt.h"
#include "base/spnic_hwdev.h"
#include "base/spnic_nic_cfg.h"
#include "spnic_io.h"
#include "spnic_tx.h"
#include "spnic_ethdev.h"

#define SPNIC_TX_TASK_WRAPPED		1
#define SPNIC_TX_BD_DESC_WRAPPED	2

#define TX_MSS_DEFAULT			0x3E00
#define TX_MSS_MIN			0x50

#define SPNIC_MAX_TX_FREE_BULK		64

#define	MAX_PAYLOAD_OFFSET		221

#define SPNIC_TX_OUTER_CHECKSUM_FLAG_SET       1
#define SPNIC_TX_OUTER_CHECKSUM_FLAG_NO_SET    0

#define SPNIC_TX_OFFLOAD_MASK (	\
		SPNIC_TX_CKSUM_OFFLOAD_MASK | \
		RTE_MBUF_F_TX_VLAN)

#define SPNIC_TX_CKSUM_OFFLOAD_MASK ( \
		RTE_MBUF_F_TX_IP_CKSUM | \
		RTE_MBUF_F_TX_TCP_CKSUM | \
		RTE_MBUF_F_TX_UDP_CKSUM | \
		RTE_MBUF_F_TX_SCTP_CKSUM | \
		RTE_MBUF_F_TX_OUTER_IP_CKSUM | \
		RTE_MBUF_F_TX_TCP_SEG)

/**
 * Get send queue free wqebb cnt
 *
 * @param[in] sq
 *   Send queue
 * @return
 *   Number of free wqebb
 */
static inline u16 spnic_get_sq_free_wqebbs(struct spnic_txq *sq)
{
	return (sq->q_depth -
		((sq->prod_idx - sq->cons_idx + sq->q_depth) & sq->q_mask) - 1);
}

/**
 * Update send queue local ci
 *
 * @param[in] sq
 *   Send queue
 * @param[in] wqe_cnt
 *   Number of wqebb
 */
static inline void spnic_update_sq_local_ci(struct spnic_txq *sq, u16 wqe_cnt)
{
	sq->cons_idx += wqe_cnt;
}

/**
 * Get send queue local ci
 *
 * @param[in] sq
 *   Send queue
 * @return
 *   Local ci
 */
static inline u16 spnic_get_sq_local_ci(struct spnic_txq *sq)
{
	return MASKED_QUEUE_IDX(sq, sq->cons_idx);
}

/**
 * Get send queue hardware ci
 *
 * @param[in] sq
 *   Send queue
 * @return
 *   Hardware ci
 */
static inline u16 spnic_get_sq_hw_ci(struct spnic_txq *sq)
{
	return MASKED_QUEUE_IDX(sq, *(u16 *)sq->ci_vaddr_base);
}

/**
 * Get send queue wqe
 *
 * @param[in] sq
 *   Send queue
 * @param[in] wqebb_cnt
 *   Num of wqebb counter
 * @param[out] pi
 *   Return current pi
 * @param[out] owner
 *   Owner bit for hardware
 * @param[out] wrapped
 *   Indicate whether wqe is wrapped
 * @return
 *   Send queue wqe base address
 */
static inline void *spnic_get_sq_wqe(struct spnic_txq *sq,
				     struct spnic_wqe_info *wqe_info)
{
	u16 cur_pi = MASKED_QUEUE_IDX(sq, sq->prod_idx);
	u32 end_pi;

	end_pi = cur_pi + wqe_info->wqebb_cnt;
	sq->prod_idx += wqe_info->wqebb_cnt;

	wqe_info->owner = sq->owner;
	wqe_info->pi = cur_pi;
	wqe_info->wrapped = 0;

	if (unlikely(end_pi >= sq->q_depth)) {
		sq->owner = !sq->owner;

		if (likely(end_pi > sq->q_depth))
			wqe_info->wrapped = sq->q_depth - cur_pi;
	}

	return NIC_WQE_ADDR(sq, cur_pi);
}

/**
 * Put send queue wqe
 *
 * @param[in] sq
 *   Send queue
 * @param[in] wqebb_cnt
 *   Num of wqebb counter
 * @param[out] owner
 *   Owner bit for hardware
 */
static inline void spnic_put_sq_wqe(struct spnic_txq *sq,
				    struct spnic_wqe_info *wqe_info)
{
	if (wqe_info->owner != sq->owner)
		sq->owner = wqe_info->owner;

	sq->prod_idx -= wqe_info->wqebb_cnt;
}

static inline void spnic_set_wqe_combo(struct spnic_txq *txq,
				    struct spnic_sq_wqe_combo *wqe_combo,
					struct spnic_sq_wqe *wqe,
					struct spnic_wqe_info *wqe_info)
{
	wqe_combo->hdr = &wqe->compact_wqe.wqe_desc;

	if (wqe_info->offload) {
		if (wqe_info->wrapped == SPNIC_TX_TASK_WRAPPED) {
			wqe_combo->task = (struct spnic_sq_task *)
				(void *)txq->sq_head_addr;
			wqe_combo->bds_head = (struct spnic_sq_bufdesc *)
				(void *)(txq->sq_head_addr + txq->wqebb_size);
		} else if (wqe_info->wrapped == SPNIC_TX_BD_DESC_WRAPPED) {
			wqe_combo->task = &wqe->extend_wqe.task;
			wqe_combo->bds_head = (struct spnic_sq_bufdesc *)
				(void *)(txq->sq_head_addr);
		} else {
			wqe_combo->task = &wqe->extend_wqe.task;
			wqe_combo->bds_head = wqe->extend_wqe.buf_desc;
		}

		wqe_combo->wqe_type = SQ_WQE_EXTENDED_TYPE;
		wqe_combo->task_type = SQ_WQE_TASKSECT_16BYTES;
		return;
	}

	if (wqe_info->wrapped == SPNIC_TX_TASK_WRAPPED) {
		wqe_combo->bds_head = (struct spnic_sq_bufdesc *)
				(void *)(txq->sq_head_addr);
	} else {
		wqe_combo->bds_head =
			(struct spnic_sq_bufdesc *)(&wqe->extend_wqe.task);
	}

	if (wqe_info->wqebb_cnt > 1) {
		wqe_combo->wqe_type = SQ_WQE_EXTENDED_TYPE;
		wqe_combo->task_type = SQ_WQE_TASKSECT_46BITS;
		/* This section used as vlan insert, needs to clear */
		wqe_combo->bds_head->rsvd = 0;
	} else {
		wqe_combo->wqe_type = SQ_WQE_COMPACT_TYPE;
	}
}

void spnic_free_txq_mbufs(struct spnic_txq *txq)
{
	struct spnic_tx_info *tx_info = NULL;
	u16 free_wqebbs;
	u16 ci;

	free_wqebbs = spnic_get_sq_free_wqebbs(txq) + 1;

	while (free_wqebbs < txq->q_depth) {
		ci = spnic_get_sq_local_ci(txq);

		tx_info = &txq->tx_info[ci];

		rte_pktmbuf_free(tx_info->mbuf);
		spnic_update_sq_local_ci(txq, tx_info->wqebb_cnt);

		free_wqebbs += tx_info->wqebb_cnt;
		tx_info->mbuf = NULL;
	}
}

void spnic_free_all_txq_mbufs(struct spnic_nic_dev *nic_dev)
{
	u16 qid;

	for (qid = 0; qid < nic_dev->num_sqs; qid++)
		spnic_free_txq_mbufs(nic_dev->txqs[qid]);
}

int spnic_start_all_sqs(struct rte_eth_dev *eth_dev)
{
	struct spnic_nic_dev *nic_dev = NULL;
	int i;

	nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(eth_dev);

	for (i = 0; i < nic_dev->num_rqs; i++)
		eth_dev->data->tx_queue_state[i] = RTE_ETH_QUEUE_STATE_STARTED;

	return 0;
}
static inline int spnic_xmit_mbuf_cleanup(struct spnic_txq *txq, u32 free_cnt)
{
	struct spnic_tx_info *tx_info = NULL;
	struct rte_mbuf *mbuf = NULL;
	struct rte_mbuf *mbuf_temp = NULL;
	struct rte_mbuf *mbuf_free[SPNIC_MAX_TX_FREE_BULK];
	int nb_free = 0;
	int wqebb_cnt = 0;
	u16 hw_ci, sw_ci, sq_mask;
	u32 i;

	hw_ci = spnic_get_sq_hw_ci(txq);
	sw_ci = spnic_get_sq_local_ci(txq);
	sq_mask = txq->q_mask;

	for (i = 0; i < free_cnt; ++i) {
		tx_info = &txq->tx_info[sw_ci];
		if (hw_ci == sw_ci ||
		    (((hw_ci - sw_ci) & sq_mask) < tx_info->wqebb_cnt))
			break;

		sw_ci = (sw_ci + tx_info->wqebb_cnt) & sq_mask;

		wqebb_cnt += tx_info->wqebb_cnt;
		mbuf = tx_info->mbuf;

		if (likely(mbuf->nb_segs == 1)) {
			mbuf_temp = rte_pktmbuf_prefree_seg(mbuf);
			tx_info->mbuf = NULL;

			if (unlikely(mbuf_temp == NULL))
				continue;

			mbuf_free[nb_free++] = mbuf_temp;
			if (unlikely(mbuf_temp->pool != mbuf_free[0]->pool ||
			    nb_free >= SPNIC_MAX_TX_FREE_BULK)) {
				rte_mempool_put_bulk(mbuf_free[0]->pool,
					(void **)mbuf_free, (nb_free - 1));
				nb_free = 0;
				mbuf_free[nb_free++] = mbuf_temp;
			}
		} else {
			rte_pktmbuf_free(mbuf);
			tx_info->mbuf = NULL;
		}
	}

	if (nb_free > 0)
		rte_mempool_put_bulk(mbuf_free[0]->pool, (void **)mbuf_free,
				     nb_free);

	spnic_update_sq_local_ci(txq, wqebb_cnt);
	return i;
}

static int spnic_tx_done_cleanup(void *txq, u32 free_cnt)
{
	struct spnic_txq *tx_queue = txq;
	u32 try_free_cnt = !free_cnt ? tx_queue->q_depth : free_cnt;

	return spnic_xmit_mbuf_cleanup(tx_queue, try_free_cnt);
}

static inline int spnic_tx_offload_pkt_prepare(struct rte_mbuf *mbuf,
					       u16 *inner_l3_offset)
{
	uint64_t ol_flags = mbuf->ol_flags;

	/* Only support vxlan offload */
	if ((ol_flags & RTE_MBUF_F_TX_TUNNEL_MASK) &&
		(!(ol_flags & RTE_MBUF_F_TX_TUNNEL_VXLAN)))
		return -EINVAL;

#ifdef RTE_LIBRTE_ETHDEV_DEBUG
	if (rte_validate_tx_offload(mbuf) != 0)
		return -EINVAL;
#endif
	if ((ol_flags & RTE_MBUF_F_TX_TUNNEL_VXLAN))  {
		if ((ol_flags & RTE_MBUF_F_TX_OUTER_IP_CKSUM) ||
		    (ol_flags & RTE_MBUF_F_TX_OUTER_IPV6) ||
		    (ol_flags & RTE_MBUF_F_TX_TCP_SEG)) {
			/*
			 * For this senmatic, l2_len of mbuf means
			 * len(out_udp + vxlan + in_eth)
			 */
			*inner_l3_offset = mbuf->l2_len + mbuf->outer_l2_len +
					   mbuf->outer_l3_len;
		} else {
			/*
			 * For this senmatic, l2_len of mbuf means
			 * len(out_eth + out_ip + out_udp + vxlan + in_eth)
			 */
			*inner_l3_offset = mbuf->l2_len;
		}
	} else {
		/* For non-tunnel type pkts */
		*inner_l3_offset = mbuf->l2_len;
	}

	return 0;
}

/**
 * Set vlan offload info
 *
 * @param[in] task
 *   Send queue wqe task section
 * @param[in] vlan_tag
 *   Vlan tag info
 * @param[in] vlan_type
 *   Vlan type in hardware
 */
static inline void spnic_set_vlan_tx_offload(struct spnic_sq_task *task,
					     u16 vlan_tag, u8 vlan_type)
{
	task->vlan_offload = SQ_TASK_INFO3_SET(vlan_tag, VLAN_TAG) |
			     SQ_TASK_INFO3_SET(vlan_type, VLAN_TYPE) |
			     SQ_TASK_INFO3_SET(1U, VLAN_TAG_VALID);
}

static inline int spnic_set_tx_offload(struct rte_mbuf *mbuf,
				       struct spnic_sq_task *task,
				       struct spnic_wqe_info *wqe_info)
{
	uint64_t ol_flags = mbuf->ol_flags;
	u16 pld_offset = 0;
	u32 queue_info = 0;
	u16 vlan_tag;

	task->pkt_info0 = 0;
	task->ip_identify = 0;
	task->pkt_info2 = 0;
	task->vlan_offload = 0;

	/* Vlan offload */
	if (unlikely(ol_flags & RTE_MBUF_F_TX_VLAN)) {
		vlan_tag = mbuf->vlan_tci;
		spnic_set_vlan_tx_offload(task, vlan_tag, SPNIC_TX_TPID0);
	}

	if (!(ol_flags & SPNIC_TX_CKSUM_OFFLOAD_MASK))
		return 0;

	/* Tso offload */
	if (ol_flags & RTE_MBUF_F_TX_TCP_SEG) {
		pld_offset = wqe_info->payload_offset;
		if ((pld_offset >> 1) > MAX_PAYLOAD_OFFSET)
			return -EINVAL;

		task->pkt_info0 |= SQ_TASK_INFO0_SET(1U, INNER_L4_EN);
		task->pkt_info0 |= SQ_TASK_INFO0_SET(1U, INNER_L3_EN);

		queue_info |= SQ_CTRL_QUEUE_INFO_SET(1U, TSO);
		queue_info |= SQ_CTRL_QUEUE_INFO_SET(pld_offset >> 1, PLDOFF);

		/* Set MSS value */
		queue_info = SQ_CTRL_QUEUE_INFO_CLEAR(queue_info, MSS);
		queue_info |= SQ_CTRL_QUEUE_INFO_SET(mbuf->tso_segsz, MSS);
	} else {
		if (ol_flags & RTE_MBUF_F_TX_IP_CKSUM)
			task->pkt_info0 |= SQ_TASK_INFO0_SET(1U, INNER_L3_EN);

		switch (ol_flags & RTE_MBUF_F_TX_L4_MASK) {
		case RTE_MBUF_F_TX_TCP_CKSUM:
		case RTE_MBUF_F_TX_UDP_CKSUM:
		case RTE_MBUF_F_TX_SCTP_CKSUM:
			task->pkt_info0 |= SQ_TASK_INFO0_SET(1U, INNER_L4_EN);

			break;

		case RTE_MBUF_F_TX_L4_NO_CKSUM:
			break;

		default:
			PMD_DRV_LOG(INFO, "not support pkt type");
			return -EINVAL;
		}
	}

	/* For vxlan, also can support PKT_TX_TUNNEL_GRE, etc */
	switch (ol_flags & RTE_MBUF_F_TX_TUNNEL_MASK) {
	case RTE_MBUF_F_TX_TUNNEL_VXLAN:
		task->pkt_info0 |= SQ_TASK_INFO0_SET(1U, TUNNEL_FLAG);
		break;

	case 0:
		break;

	default:
		/* For non UDP/GRE tunneling, drop the tunnel packet */
		PMD_DRV_LOG(INFO, "not support tunnel pkt type");
		return -EINVAL;
	}

	if (ol_flags & RTE_MBUF_F_TX_OUTER_IP_CKSUM)
		task->pkt_info0 |= SQ_TASK_INFO0_SET(1U, OUT_L3_EN);

	wqe_info->queue_info = queue_info;
	return 0;
}

static inline bool spnic_is_tso_sge_valid(struct rte_mbuf *mbuf,
					   struct spnic_wqe_info *wqe_info)
{
	u32 total_len, limit_len, checked_len, left_len, adjust_mss;
	u32 i, max_sges, left_sges, first_len;
	struct rte_mbuf *mbuf_head, *mbuf_pre, *mbuf_first;

	left_sges = mbuf->nb_segs;
	mbuf_head = mbuf;
	mbuf_first = mbuf;

	/* tso sge number validation */
	if (unlikely(left_sges >= SPNIC_NONTSO_PKT_MAX_SGE)) {
		checked_len = 0;
		total_len = 0;
		first_len = 0;
		adjust_mss = mbuf->tso_segsz >= TX_MSS_MIN ?
			     mbuf->tso_segsz : TX_MSS_MIN;
		max_sges = SPNIC_NONTSO_PKT_MAX_SGE - 1;
		limit_len = adjust_mss + wqe_info->payload_offset;

		for (i = 0; (i < max_sges) && (total_len < limit_len); i++) {
			total_len += mbuf->data_len;
			mbuf_pre = mbuf;
			mbuf = mbuf->next;
		}

		while (left_sges >= SPNIC_NONTSO_PKT_MAX_SGE) {
			if (total_len >= limit_len) {
				/* update the limit len */
				limit_len = adjust_mss;
				/* update checked len */
				checked_len += first_len;
				/* record the first len */
				first_len = mbuf_first->data_len;
				/* first mbuf move to the next */
				mbuf_first = mbuf_first->next;
				/* update total len */
				total_len -= first_len;
				left_sges--;
				i--;
				for (; (i < max_sges) &&
				     (total_len < limit_len); i++) {
					total_len += mbuf->data_len;
					mbuf_pre = mbuf;
					mbuf = mbuf->next;
				}
			} else {
				/* try to copy if not valid */
				checked_len += (total_len - mbuf_pre->data_len);

				left_len = mbuf_head->pkt_len - checked_len;
				if (left_len > SPNIC_COPY_MBUF_SIZE)
					return false;
				wqe_info->sge_cnt = (u16)(mbuf_head->nb_segs +
						    i - left_sges);
				wqe_info->cpy_mbuf_cnt = 1;

				return true;
			}
		}
	}

	wqe_info->sge_cnt = mbuf_head->nb_segs;
	return true;
}

static inline int spnic_get_tx_offload(struct rte_mbuf *mbuf,
					struct spnic_wqe_info *wqe_info)
{
	uint64_t ol_flags = mbuf->ol_flags;
	u16 i, total_len, inner_l3_offset = 0;
	struct rte_mbuf *mbuf_pkt = NULL;
	int err;

	wqe_info->sge_cnt = mbuf->nb_segs;
	if (!(ol_flags & SPNIC_TX_OFFLOAD_MASK)) {
		wqe_info->offload = 0;
		return 0;
	}

	wqe_info->offload = 1;
	err = spnic_tx_offload_pkt_prepare(mbuf, &inner_l3_offset);
	if (err)
		return err;

	/* non tso mbuf */
	if (likely(!(mbuf->ol_flags & RTE_MBUF_F_TX_TCP_SEG))) {
		if (unlikely(mbuf->pkt_len > MAX_SINGLE_SGE_SIZE))
			return -EINVAL;

		if (likely(SPNIC_NONTSO_SEG_NUM_VALID(mbuf->nb_segs)))
			return 0;

		total_len = 0;
		mbuf_pkt = mbuf;
		for (i = 0; i < (SPNIC_NONTSO_PKT_MAX_SGE - 1); i++) {
			total_len += mbuf_pkt->data_len;
			mbuf_pkt = mbuf_pkt->next;
		}

		if ((u32)(total_len + (u16)SPNIC_COPY_MBUF_SIZE) <
		    mbuf->pkt_len)
			return -EINVAL;

		wqe_info->sge_cnt = SPNIC_NONTSO_PKT_MAX_SGE;
		wqe_info->cpy_mbuf_cnt = 1;
		return 0;
	}

	/* tso mbuf */
	wqe_info->payload_offset = inner_l3_offset + mbuf->l3_len +
				   mbuf->l4_len;

	if (unlikely(SPNIC_TSO_SEG_NUM_INVALID(mbuf->nb_segs)))
		return -EINVAL;

	if (unlikely(!spnic_is_tso_sge_valid(mbuf, wqe_info)))
		return -EINVAL;

	return 0;
}

static inline void spnic_set_buf_desc(struct spnic_sq_bufdesc *buf_descs,
				      rte_iova_t addr, u32 len)
{
	buf_descs->hi_addr = upper_32_bits(addr);
	buf_descs->lo_addr = lower_32_bits(addr);
	buf_descs->len  = len;
}

static inline void *spnic_copy_tx_mbuf(struct spnic_nic_dev *nic_dev,
					struct rte_mbuf *mbuf, u16 sge_cnt)
{
	struct rte_mbuf *dst_mbuf;
	u32 offset = 0;
	u16 i;

	if (unlikely(!nic_dev->cpy_mpool))
		return NULL;

	dst_mbuf = rte_pktmbuf_alloc(nic_dev->cpy_mpool);
	if (unlikely(!dst_mbuf))
		return NULL;

	dst_mbuf->data_off = 0;
	dst_mbuf->data_len = 0;
	for (i = 0; i < sge_cnt; i++) {
		rte_memcpy((u8 *)dst_mbuf->buf_addr + offset,
			   (u8 *)mbuf->buf_addr + mbuf->data_off,
			   mbuf->data_len);
		dst_mbuf->data_len += mbuf->data_len;
		offset += mbuf->data_len;
		mbuf = mbuf->next;
	}
	dst_mbuf->pkt_len = dst_mbuf->data_len;
	return dst_mbuf;
}

static int spnic_mbuf_dma_map_sge(struct spnic_txq *txq, struct rte_mbuf *mbuf,
				  struct spnic_sq_wqe_combo *wqe_combo,
				  struct spnic_wqe_info *wqe_info)
{
	struct spnic_sq_wqe_desc *wqe_desc = wqe_combo->hdr;
	struct spnic_sq_bufdesc *buf_desc = wqe_combo->bds_head;
	uint16_t nb_segs = wqe_info->sge_cnt - wqe_info->cpy_mbuf_cnt;
	uint16_t real_segs = mbuf->nb_segs;

	rte_iova_t dma_addr;
	u32 i;

	for (i = 0; i < nb_segs; i++) {
		if (unlikely(mbuf == NULL)) {
			txq->txq_stats.mbuf_null++;
			return -EINVAL;
		}

		if (unlikely(mbuf->data_len == 0)) {
			txq->txq_stats.sge_len0++;
			return -EINVAL;
		}

		dma_addr = rte_mbuf_data_iova(mbuf);
		if (i == 0) {
			if (wqe_combo->wqe_type == SQ_WQE_COMPACT_TYPE &&
			    mbuf->data_len > COMPACT_WQE_MAX_CTRL_LEN) {
				txq->txq_stats.sge_len_too_large++;
				return -EINVAL;
			}
			wqe_desc->hi_addr = upper_32_bits(dma_addr);
			wqe_desc->lo_addr = lower_32_bits(dma_addr);
			wqe_desc->ctrl_len = mbuf->data_len;
		} else {
			/*
			 * Parts of wqe is in sq bottom while parts
			 * of wqe is in sq head
			 */
			if (unlikely(wqe_info->wrapped &&
			    (u64)buf_desc == txq->sq_bot_sge_addr))
				buf_desc = (struct spnic_sq_bufdesc *)
					   (void *)txq->sq_head_addr;

			spnic_set_buf_desc(buf_desc, dma_addr, mbuf->data_len);
			buf_desc++;
		}

		mbuf = mbuf->next;
	}

	if (unlikely(wqe_info->cpy_mbuf_cnt != 0)) {
		/* copy invalid mbuf segs to a valid buffer, lost performance */
		txq->txq_stats.cpy_pkts += 1;
		mbuf = spnic_copy_tx_mbuf(txq->nic_dev, mbuf,
					   real_segs - nb_segs);
		if (unlikely(!mbuf))
			return -EINVAL;

		txq->tx_info[wqe_info->pi].cpy_mbuf = mbuf;

		/* deal with the last mbuf */
		dma_addr = rte_mbuf_data_iova(mbuf);
		if (unlikely(mbuf->data_len == 0)) {
			txq->txq_stats.sge_len0++;
			return -EINVAL;
		}

		if (unlikely(wqe_info->wrapped &&
		    ((u64)buf_desc == txq->sq_bot_sge_addr)))
			buf_desc =
				(struct spnic_sq_bufdesc *)txq->sq_head_addr;

		spnic_set_buf_desc(buf_desc, dma_addr, mbuf->data_len);
	}
	return 0;
}

static inline void spnic_prepare_sq_ctrl(struct spnic_sq_wqe_combo *wqe_combo,
					 struct spnic_wqe_info *wqe_info)
{
	struct spnic_sq_wqe_desc *wqe_desc = wqe_combo->hdr;

	if (wqe_combo->wqe_type == SQ_WQE_COMPACT_TYPE) {
		wqe_desc->ctrl_len |= SQ_CTRL_SET(SQ_NORMAL_WQE, DATA_FORMAT) |
				SQ_CTRL_SET(wqe_combo->wqe_type, EXTENDED) |
				SQ_CTRL_SET(wqe_info->owner, OWNER);
		/* Compact wqe queue_info will transfer to ucode */
		wqe_desc->queue_info = 0;
		return;
	}

	wqe_desc->ctrl_len |= SQ_CTRL_SET(wqe_info->sge_cnt, BUFDESC_NUM) |
			SQ_CTRL_SET(wqe_combo->task_type, TASKSECT_LEN) |
			SQ_CTRL_SET(SQ_NORMAL_WQE, DATA_FORMAT) |
			SQ_CTRL_SET(wqe_combo->wqe_type, EXTENDED) |
			SQ_CTRL_SET(wqe_info->owner, OWNER);

	wqe_desc->queue_info = wqe_info->queue_info;
	wqe_desc->queue_info |= SQ_CTRL_QUEUE_INFO_SET(1U, UC);

	if (!SQ_CTRL_QUEUE_INFO_GET(wqe_desc->queue_info, MSS)) {
		wqe_desc->queue_info |=
			SQ_CTRL_QUEUE_INFO_SET(TX_MSS_DEFAULT, MSS);
	} else if (SQ_CTRL_QUEUE_INFO_GET(wqe_desc->queue_info, MSS) <
		   TX_MSS_MIN) {
		/* Mss should not less than 80 */
		wqe_desc->queue_info =
			SQ_CTRL_QUEUE_INFO_CLEAR(wqe_desc->queue_info, MSS);
		wqe_desc->queue_info |= SQ_CTRL_QUEUE_INFO_SET(TX_MSS_MIN, MSS);
	}
}

u16 spnic_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts, u16 nb_pkts)
{
	struct spnic_txq *txq = tx_queue;
	struct spnic_tx_info *tx_info = NULL;
	struct rte_mbuf *mbuf_pkt = NULL;
	struct spnic_sq_wqe_combo wqe_combo = {0};
	struct spnic_sq_wqe *sq_wqe = NULL;
	struct spnic_wqe_info wqe_info = {0};
	u32 offload_err, free_cnt;
	u64 tx_bytes = 0;
	u16 free_wqebb_cnt, nb_tx;
	int err;

	free_cnt = txq->tx_free_thresh;
	/* Reclaim tx mbuf before xmit new packets */
	spnic_xmit_mbuf_cleanup(txq, free_cnt);

	/* Tx loop routine */
	for (nb_tx = 0; nb_tx < nb_pkts; nb_tx++) {
		mbuf_pkt = *tx_pkts++;
		if (spnic_get_tx_offload(mbuf_pkt, &wqe_info)) {
			txq->txq_stats.off_errs++;
			break;
		}

		if (!wqe_info.offload)
			/*
			 * Use extended sq wqe with small TS, which can include
			 * multi sges, or compact sq normal wqe, which just
			 * supports one sge
			 */
			wqe_info.wqebb_cnt = mbuf_pkt->nb_segs;
		else
			/* Use extended sq wqe with normal TS */
			wqe_info.wqebb_cnt = mbuf_pkt->nb_segs + 1;

		free_wqebb_cnt = spnic_get_sq_free_wqebbs(txq);
		if (unlikely(wqe_info.wqebb_cnt > free_wqebb_cnt)) {
			/* Reclaim again */
			spnic_xmit_mbuf_cleanup(txq, free_cnt);
			free_wqebb_cnt = spnic_get_sq_free_wqebbs(txq);
			if (unlikely(wqe_info.wqebb_cnt > free_wqebb_cnt)) {
				txq->txq_stats.tx_busy += (nb_pkts - nb_tx);
				break;
			}
		}

		/* Get sq wqe address from wqe_page */
		sq_wqe = spnic_get_sq_wqe(txq, &wqe_info);
		if (unlikely(!sq_wqe)) {
			txq->txq_stats.tx_busy++;
			break;
		}

		/* Task or bd section maybe warpped for one wqe */
		spnic_set_wqe_combo(txq, &wqe_combo, sq_wqe, &wqe_info);

		wqe_info.queue_info = 0;
		/* Fill tx packet offload into qsf and task field */
		if (wqe_info.offload) {
			offload_err = spnic_set_tx_offload(mbuf_pkt,
							   wqe_combo.task,
							   &wqe_info);
			if (unlikely(offload_err)) {
				spnic_put_sq_wqe(txq, &wqe_info);
				txq->txq_stats.off_errs++;
				break;
			}
		}

		/* Fill sq_wqe buf_desc and bd_desc */
		err = spnic_mbuf_dma_map_sge(txq, mbuf_pkt, &wqe_combo,
					     &wqe_info);
		if (err) {
			spnic_put_sq_wqe(txq, &wqe_info);
			txq->txq_stats.off_errs++;
			break;
		}

		/* Record tx info */
		tx_info = &txq->tx_info[wqe_info.pi];
		tx_info->mbuf = mbuf_pkt;
		tx_info->wqebb_cnt = wqe_info.wqebb_cnt;

		spnic_prepare_sq_ctrl(&wqe_combo, &wqe_info);

		spnic_write_db(txq->db_addr, txq->q_id, txq->cos, SQ_CFLAG_DP,
			       MASKED_QUEUE_IDX(txq, txq->prod_idx));

		tx_bytes += mbuf_pkt->pkt_len;
	}

	/* Update txq stats */
	if (nb_tx) {
		txq->txq_stats.packets += nb_tx;
		txq->txq_stats.bytes += tx_bytes;
	}
	txq->txq_stats.burst_pkts = nb_tx;

	return nb_tx;
}

int spnic_stop_sq(struct spnic_txq *txq)
{
	struct spnic_nic_dev *nic_dev = txq->nic_dev;
	unsigned long timeout;
	int err = -EFAULT;
	int free_wqebbs;

	timeout = msecs_to_jiffies(SPNIC_FLUSH_QUEUE_TIMEOUT) + jiffies;
	do {
		spnic_tx_done_cleanup(txq, 0);
		free_wqebbs = spnic_get_sq_free_wqebbs(txq) + 1;
		if (free_wqebbs == txq->q_depth) {
			err = 0;
			break;
		}

		rte_delay_us(1);
	} while (time_before(jiffies, timeout));

	if (err)
		PMD_DRV_LOG(WARNING, "%s Wait sq empty timeout, queue_idx: %u, sw_ci: %u, "
			    "hw_ci: %u, sw_pi: %u, free_wqebbs: %u, q_depth:%u\n",
			    nic_dev->dev_name, txq->q_id,
			    spnic_get_sq_local_ci(txq),
			    spnic_get_sq_hw_ci(txq),
			    MASKED_QUEUE_IDX(txq, txq->prod_idx),
			    free_wqebbs, txq->q_depth);

	return err;
}

/* Should stop transmitting any packets before calling this function */
void spnic_flush_txqs(struct spnic_nic_dev *nic_dev)
{
	u16 qid;
	int err;

	for (qid = 0; qid < nic_dev->num_sqs; qid++) {
		err = spnic_stop_sq(nic_dev->txqs[qid]);
		if (err)
			PMD_DRV_LOG(ERR, "Stop sq%d failed", qid);
	}
}

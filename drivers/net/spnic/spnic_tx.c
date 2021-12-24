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

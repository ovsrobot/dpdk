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

int spnic_start_all_rqs(struct rte_eth_dev *eth_dev)
{
	struct spnic_nic_dev *nic_dev = NULL;
	struct spnic_rxq *rxq = NULL;
	int i;

	nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(eth_dev);

	for (i = 0; i < nic_dev->num_rqs; i++) {
		rxq = eth_dev->data->rx_queues[i];
		spnic_rearm_rxq_mbuf(rxq);
		eth_dev->data->rx_queue_state[i] = RTE_ETH_QUEUE_STATE_STARTED;
	}

	return 0;
}

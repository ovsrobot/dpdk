/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#ifndef _SPNIC_TX_H_
#define _SPNIC_TX_H_

/* Txq info */
struct spnic_txq_stats {
	u64 packets;
	u64 bytes;
	u64 tx_busy;
	u64 off_errs;
	u64 burst_pkts;
	u64 sge_len0;
	u64 mbuf_null;
	u64 cpy_pkts;
	u64 sge_len_too_large;
};

struct spnic_tx_info {
	struct rte_mbuf *mbuf;
	struct rte_mbuf *cpy_mbuf;
	int wqebb_cnt;
};

struct spnic_txq {
	struct spnic_nic_dev *nic_dev;

	u16 q_id;
	u16 q_depth;
	u16 q_mask;
	u16 wqebb_size;

	u16 wqebb_shift;
	u16 cons_idx;
	u16 prod_idx;

	u16 tx_free_thresh;
	u16 owner; /* Used for sq */

	void *db_addr;

	struct spnic_tx_info *tx_info;

	const struct rte_memzone *sq_mz;
	void *queue_buf_vaddr;
	rte_iova_t queue_buf_paddr; /* Sq dma info */

	const struct rte_memzone *ci_mz;
	void *ci_vaddr_base;
	rte_iova_t ci_dma_base;

	u64 sq_head_addr;
	u64 sq_bot_sge_addr;

	u32 cos;

	struct spnic_txq_stats txq_stats;
} __rte_cache_aligned;

#endif /* _SPNIC_TX_H_ */

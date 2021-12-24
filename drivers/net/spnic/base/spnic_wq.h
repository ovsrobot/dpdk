/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#ifndef _SPNIC_WQ_H_
#define _SPNIC_WQ_H_

/* Use 0-level CLA, page size must be: SQ 16B(wqe) * 64k(max_q_depth) */
#define SPNIC_DEFAULT_WQ_PAGE_SIZE	0x100000
#define SPNIC_HW_WQ_PAGE_SIZE		0x1000

#define CMDQ_BLOCKS_PER_PAGE		8
#define CMDQ_BLOCK_SIZE			512UL
#define CMDQ_PAGE_SIZE			RTE_ALIGN((CMDQ_BLOCKS_PER_PAGE * \
						CMDQ_BLOCK_SIZE), PAGE_SIZE)

#define CMDQ_BASE_VADDR(cmdq_pages, wq)	\
			((u64 *)(((u64)((cmdq_pages)->cmdq_page_vaddr)) \
				+ (u64)((wq)->block_idx * CMDQ_BLOCK_SIZE)))

#define CMDQ_BASE_PADDR(cmdq_pages, wq)	\
			(((u64)((cmdq_pages)->cmdq_page_paddr)) \
				+ (u64)(wq)->block_idx * CMDQ_BLOCK_SIZE)

#define CMDQ_BASE_ADDR(cmdq_pages, wq)	\
			((u64 *)(((u64)((cmdq_pages)->cmdq_shadow_page_vaddr)) \
				+ (u64)((wq)->block_idx * CMDQ_BLOCK_SIZE)))

#define MASKED_WQE_IDX(wq, idx)	((idx) & (wq)->mask)

#define	WQ_WQE_ADDR(wq, idx) ((void *)((u64)((wq)->queue_buf_vaddr) + \
			      ((idx) << (wq)->wqebb_shift)))

struct spnic_wq {
	/* The addresses are 64 bit in the HW */
	u64 queue_buf_vaddr;

	u16 q_depth;
	u16 mask;
	rte_atomic32_t delta;

	u32 cons_idx;
	u32 prod_idx;

	u64 queue_buf_paddr;

	u32 wqebb_size;
	u32 wqebb_shift;

	u32 wq_buf_size;

	const struct rte_memzone *wq_mz;

	u32 rsvd[5];
};

#endif /* _SPNIC_WQ_H_ :*/

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#ifndef _SPNIC_WQ_H_
#define _SPNIC_WQ_H_

/* Use 0-level CLA, page size must be: SQ 16B(wqe) * 64k(max_q_depth) */
#define SPNIC_DEFAULT_WQ_PAGE_SIZE	0x100000
#define SPNIC_HW_WQ_PAGE_SIZE		0x1000

#define WQS_BLOCKS_PER_PAGE		4

#define WQ_SIZE(wq)		((u32)((u64)(wq)->q_depth * (wq)->wqebb_size))

#define	WQE_PAGE_NUM(wq, idx)	(((idx) >> ((wq)->wqebbs_per_page_shift)) & \
				((wq)->num_q_pages - 1))

#define	WQE_PAGE_OFF(wq, idx)	((u64)((wq)->wqebb_size) * \
				((idx) & ((wq)->num_wqebbs_per_page - 1)))

#define WQ_PAGE_ADDR_SIZE		sizeof(u64)
#define WQ_PAGE_ADDR_SIZE_SHIFT		3
#define WQ_PAGE_ADDR(wq, idx)		\
		((u8 *)(*(u64 *)((u64)((wq)->shadow_block_vaddr) + \
		(WQE_PAGE_NUM(wq, idx) << WQ_PAGE_ADDR_SIZE_SHIFT))))

#define WQ_BLOCK_SIZE		4096UL
#define WQS_PAGE_SIZE		(WQS_BLOCKS_PER_PAGE * WQ_BLOCK_SIZE)
#define WQ_MAX_PAGES		(WQ_BLOCK_SIZE >> WQ_PAGE_ADDR_SIZE_SHIFT)

#define CMDQ_BLOCKS_PER_PAGE		8
#define CMDQ_BLOCK_SIZE			512UL
#define CMDQ_PAGE_SIZE			RTE_ALIGN((CMDQ_BLOCKS_PER_PAGE * \
						CMDQ_BLOCK_SIZE), PAGE_SIZE)

#define ADDR_4K_ALIGNED(addr)		(0 == ((addr) & 0xfff))
#define ADDR_256K_ALIGNED(addr)		(0 == ((addr) & 0x3ffff))

#define WQ_BASE_VADDR(wqs, wq)		\
		((u64 *)(((u64)((wqs)->page_vaddr[(wq)->page_idx])) \
				+ (wq)->block_idx * WQ_BLOCK_SIZE))

#define WQ_BASE_PADDR(wqs, wq)	(((wqs)->page_paddr[(wq)->page_idx]) \
				+ (u64)(wq)->block_idx * WQ_BLOCK_SIZE)

#define WQ_BASE_ADDR(wqs, wq)		\
		((u64 *)(((u64)((wqs)->shadow_page_vaddr[(wq)->page_idx])) \
				+ (wq)->block_idx * WQ_BLOCK_SIZE))

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

#define WQE_SHADOW_PAGE(wq, wqe)	\
		((u16)(((unsigned long)(wqe) - (unsigned long)(wq)->shadow_wqe) \
		/ (wq)->max_wqe_size))

#define WQE_IN_RANGE(wqe, start, end)	\
		(((unsigned long)(wqe) >= (unsigned long)(start)) && \
		((unsigned long)(wqe) < (unsigned long)(end)))

#define WQ_NUM_PAGES(num_wqs)	\
	(RTE_ALIGN((u32)(num_wqs), WQS_BLOCKS_PER_PAGE) / WQS_BLOCKS_PER_PAGE)

#define	WQ_WQE_ADDR(wq, idx) ((void *)((u64)((wq)->queue_buf_vaddr) + \
			      ((idx) << (wq)->wqebb_shift)))

struct spnic_sge {
	u32 hi_addr;
	u32 lo_addr;
	u32 len;
};

struct spnic_wq {
	/* The addresses are 64 bit in the HW */
	u64 queue_buf_vaddr;

	u16 q_depth;
	u16 mask;
	u32 delta;

	u32 cons_idx;
	u32 prod_idx;

	u64 queue_buf_paddr;

	u32 wqebb_size;
	u32 wqebb_shift;

	u32 wq_buf_size;

	const struct rte_memzone *wq_mz;

	u32 rsvd[5];
};

void spnic_wq_wqe_pg_clear(struct spnic_wq *wq);

int spnic_cmdq_alloc(struct spnic_wq *wq, void *dev, int cmdq_blocks,
		      u32 wq_buf_size, u32 wqebb_shift, u16 q_depth);

void spnic_cmdq_free(struct spnic_wq *wq, int cmdq_blocks);

void *spnic_get_wqe(struct spnic_wq *wq, int num_wqebbs, u16 *prod_idx);

void spnic_put_wqe(struct spnic_wq *wq, int num_wqebbs);

void *spnic_read_wqe(struct spnic_wq *wq, int num_wqebbs, u16 *cons_idx);

void spnic_set_sge(struct spnic_sge *sge, uint64_t addr, u32 len);

#endif /* _SPNIC_WQ_H_ */

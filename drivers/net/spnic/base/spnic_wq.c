/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#include <rte_pci.h>
#include <rte_bus_pci.h>
#include <ethdev_pci.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_mempool.h>
#include <rte_errno.h>
#include <rte_ether.h>

#include "spnic_compat.h"
#include "spnic_hwdev.h"
#include "spnic_wq.h"

static void free_wq_pages(struct spnic_wq *wq)
{
	rte_memzone_free(wq->wq_mz);

	wq->queue_buf_paddr = 0;
	wq->queue_buf_vaddr = 0;
}

static int alloc_wq_pages(struct spnic_hwdev *hwdev, struct spnic_wq *wq,
			  int qid)
{
	const struct rte_memzone *wq_mz;

	wq_mz = rte_eth_dma_zone_reserve(hwdev->eth_dev, "spnic_wq_mz",
					 (uint16_t)qid, wq->wq_buf_size,
					 RTE_PGSIZE_256K, SOCKET_ID_ANY);
	if (!wq_mz) {
		PMD_DRV_LOG(ERR, "Allocate wq[%d] rq_mz failed", qid);
		return -ENOMEM;
	}

	memset(wq_mz->addr, 0, wq->wq_buf_size);
	wq->wq_mz = wq_mz;
	wq->queue_buf_paddr = wq_mz->iova;
	wq->queue_buf_vaddr = (u64)(u64 *)wq_mz->addr;

	return 0;
}

void spnic_put_wqe(struct spnic_wq *wq, int num_wqebbs)
{
	wq->cons_idx += num_wqebbs;
	__atomic_add_fetch(&wq->delta, num_wqebbs, __ATOMIC_RELAXED);
}

void *spnic_read_wqe(struct spnic_wq *wq, int num_wqebbs, u16 *cons_idx)
{
	u16 curr_cons_idx;

	if ((__atomic_load_n(&wq->delta, __ATOMIC_RELAXED) + num_wqebbs) > wq->q_depth)
		return NULL;

	curr_cons_idx = (u16)(wq->cons_idx);

	curr_cons_idx = MASKED_WQE_IDX(wq, curr_cons_idx);

	*cons_idx = curr_cons_idx;

	return WQ_WQE_ADDR(wq, (u32)(*cons_idx));
}

int spnic_cmdq_alloc(struct spnic_wq *wq, void *dev, int cmdq_blocks,
		     u32 wq_buf_size, u32 wqebb_shift, u16 q_depth)
{
	struct spnic_hwdev *hwdev = (struct spnic_hwdev *)dev;
	int i, j;
	int err;

	/* Validate q_depth is power of 2 & wqebb_size is not 0 */
	for (i = 0; i < cmdq_blocks; i++) {
		wq[i].wqebb_size = 1 << wqebb_shift;
		wq[i].wqebb_shift = wqebb_shift;
		wq[i].wq_buf_size = wq_buf_size;
		wq[i].q_depth = q_depth;

		err = alloc_wq_pages(hwdev, &wq[i], i);
		if (err) {
			PMD_DRV_LOG(ERR, "Failed to alloc CMDQ blocks");
			goto cmdq_block_err;
		}

		wq[i].cons_idx = 0;
		wq[i].prod_idx = 0;
		__atomic_store_n(&wq[i].delta, q_depth, __ATOMIC_RELAXED);

		wq[i].mask = q_depth - 1;
	}

	return 0;

cmdq_block_err:
	for (j = 0; j < i; j++)
		free_wq_pages(&wq[j]);

	return err;
}

void spnic_cmdq_free(struct spnic_wq *wq, int cmdq_blocks)
{
	int i;

	for (i = 0; i < cmdq_blocks; i++)
		free_wq_pages(&wq[i]);
}

void spnic_wq_wqe_pg_clear(struct spnic_wq *wq)
{
	wq->cons_idx = 0;
	wq->prod_idx = 0;

	memset((void *)wq->queue_buf_vaddr, 0, wq->wq_buf_size);
}

void *spnic_get_wqe(struct spnic_wq *wq, int num_wqebbs, u16 *prod_idx)
{
	u16 curr_prod_idx;

	__atomic_fetch_sub(&wq->delta, num_wqebbs, __ATOMIC_RELAXED);
	curr_prod_idx = wq->prod_idx;
	wq->prod_idx += num_wqebbs;
	*prod_idx = MASKED_WQE_IDX(wq, curr_prod_idx);

	return WQ_WQE_ADDR(wq, (u32)(*prod_idx));
}

void spnic_set_sge(struct spnic_sge *sge, uint64_t addr, u32 len)
{
	sge->hi_addr = upper_32_bits(addr);
	sge->lo_addr = lower_32_bits(addr);
	sge->len  = len;
}

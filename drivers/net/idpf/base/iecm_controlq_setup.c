/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2001-2022 Intel Corporation
 */


#include "iecm_controlq.h"


/**
 * iecm_ctlq_alloc_desc_ring - Allocate Control Queue (CQ) rings
 * @hw: pointer to hw struct
 * @cq: pointer to the specific Control queue
 */
static int
iecm_ctlq_alloc_desc_ring(struct iecm_hw *hw,
			  struct iecm_ctlq_info *cq)
{
	size_t size = cq->ring_size * sizeof(struct iecm_ctlq_desc);

	cq->desc_ring.va = iecm_alloc_dma_mem(hw, &cq->desc_ring, size);
	if (!cq->desc_ring.va)
		return IECM_ERR_NO_MEMORY;

	return IECM_SUCCESS;
}

/**
 * iecm_ctlq_alloc_bufs - Allocate Control Queue (CQ) buffers
 * @hw: pointer to hw struct
 * @cq: pointer to the specific Control queue
 *
 * Allocate the buffer head for all control queues, and if it's a receive
 * queue, allocate DMA buffers
 */
static int iecm_ctlq_alloc_bufs(struct iecm_hw *hw,
				struct iecm_ctlq_info *cq)
{
	int i = 0;

	/* Do not allocate DMA buffers for transmit queues */
	if (cq->cq_type == IECM_CTLQ_TYPE_MAILBOX_TX)
		return IECM_SUCCESS;

	/* We'll be allocating the buffer info memory first, then we can
	 * allocate the mapped buffers for the event processing
	 */
	cq->bi.rx_buff = (struct iecm_dma_mem **)
		iecm_calloc(hw, cq->ring_size,
			    sizeof(struct iecm_dma_mem *));
	if (!cq->bi.rx_buff)
		return IECM_ERR_NO_MEMORY;

	/* allocate the mapped buffers (except for the last one) */
	for (i = 0; i < cq->ring_size - 1; i++) {
		struct iecm_dma_mem *bi;
		int num = 1; /* number of iecm_dma_mem to be allocated */

		cq->bi.rx_buff[i] = (struct iecm_dma_mem *)iecm_calloc(hw, num,
						sizeof(struct iecm_dma_mem));
		if (!cq->bi.rx_buff[i])
			goto unwind_alloc_cq_bufs;

		bi = cq->bi.rx_buff[i];

		bi->va = iecm_alloc_dma_mem(hw, bi, cq->buf_size);
		if (!bi->va) {
			/* unwind will not free the failed entry */
			iecm_free(hw, cq->bi.rx_buff[i]);
			goto unwind_alloc_cq_bufs;
		}
	}

	return IECM_SUCCESS;

unwind_alloc_cq_bufs:
	/* don't try to free the one that failed... */
	i--;
	for (; i >= 0; i--) {
		iecm_free_dma_mem(hw, cq->bi.rx_buff[i]);
		iecm_free(hw, cq->bi.rx_buff[i]);
	}
	iecm_free(hw, cq->bi.rx_buff);

	return IECM_ERR_NO_MEMORY;
}

/**
 * iecm_ctlq_free_desc_ring - Free Control Queue (CQ) rings
 * @hw: pointer to hw struct
 * @cq: pointer to the specific Control queue
 *
 * This assumes the posted send buffers have already been cleaned
 * and de-allocated
 */
static void iecm_ctlq_free_desc_ring(struct iecm_hw *hw,
				     struct iecm_ctlq_info *cq)
{
	iecm_free_dma_mem(hw, &cq->desc_ring);
}

/**
 * iecm_ctlq_free_bufs - Free CQ buffer info elements
 * @hw: pointer to hw struct
 * @cq: pointer to the specific Control queue
 *
 * Free the DMA buffers for RX queues, and DMA buffer header for both RX and TX
 * queues.  The upper layers are expected to manage freeing of TX DMA buffers
 */
static void iecm_ctlq_free_bufs(struct iecm_hw *hw, struct iecm_ctlq_info *cq)
{
	void *bi;

	if (cq->cq_type == IECM_CTLQ_TYPE_MAILBOX_RX) {
		int i;

		/* free DMA buffers for rx queues*/
		for (i = 0; i < cq->ring_size; i++) {
			if (cq->bi.rx_buff[i]) {
				iecm_free_dma_mem(hw, cq->bi.rx_buff[i]);
				iecm_free(hw, cq->bi.rx_buff[i]);
			}
		}

		bi = (void *)cq->bi.rx_buff;
	} else {
		bi = (void *)cq->bi.tx_msg;
	}

	/* free the buffer header */
	iecm_free(hw, bi);
}

/**
 * iecm_ctlq_dealloc_ring_res - Free memory allocated for control queue
 * @hw: pointer to hw struct
 * @cq: pointer to the specific Control queue
 *
 * Free the memory used by the ring, buffers and other related structures
 */
void iecm_ctlq_dealloc_ring_res(struct iecm_hw *hw, struct iecm_ctlq_info *cq)
{
	/* free ring buffers and the ring itself */
	iecm_ctlq_free_bufs(hw, cq);
	iecm_ctlq_free_desc_ring(hw, cq);
}

/**
 * iecm_ctlq_alloc_ring_res - allocate memory for descriptor ring and bufs
 * @hw: pointer to hw struct
 * @cq: pointer to control queue struct
 *
 * Do *NOT* hold the lock when calling this as the memory allocation routines
 * called are not going to be atomic context safe
 */
int iecm_ctlq_alloc_ring_res(struct iecm_hw *hw, struct iecm_ctlq_info *cq)
{
	int ret_code;

	/* verify input for valid configuration */
	if (!cq->ring_size || !cq->buf_size)
		return IECM_ERR_CFG;

	/* allocate the ring memory */
	ret_code = iecm_ctlq_alloc_desc_ring(hw, cq);
	if (ret_code)
		return ret_code;

	/* allocate buffers in the rings */
	ret_code = iecm_ctlq_alloc_bufs(hw, cq);
	if (ret_code)
		goto iecm_init_cq_free_ring;

	/* success! */
	return IECM_SUCCESS;

iecm_init_cq_free_ring:
	iecm_free_dma_mem(hw, &cq->desc_ring);
	return ret_code;
}

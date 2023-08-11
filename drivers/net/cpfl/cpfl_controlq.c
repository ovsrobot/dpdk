/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2001-2023 Intel Corporation
 */

#include "cpfl_controlq.h"
#include "base/idpf_controlq.h"
#include "rte_common.h"

/**
 * cpfl_check_dma_mem_parameters - verify DMA memory params from CP
 * @qinfo: pointer to create control queue info struct
 *
 * Verify that DMA parameter of each DMA memory struct is present and
 * consistent with control queue parameters
 */
static inline int
cpfl_check_dma_mem_parameters(struct cpfl_ctlq_create_info *qinfo)
{
	struct idpf_dma_mem *ring = &qinfo->ring_mem;
	struct idpf_dma_mem *buf = &qinfo->buf_mem;

	if (!ring->va || !ring->size)
		return -EBADR;

	if (ring->size != qinfo->len * sizeof(struct idpf_ctlq_desc))
		return -EINVAL;

	/* no need for buffer checks for TX queues */
	if (qinfo->type == IDPF_CTLQ_TYPE_MAILBOX_TX ||
	    qinfo->type == IDPF_CTLQ_TYPE_CONFIG_TX ||
	    qinfo->type == IDPF_CTLQ_TYPE_RDMA_TX)
		return 0;

	if (!buf->va || !buf->size)
		return -EBADR;

	/* accommodate different types of rx ring buffer sizes */
	if ((qinfo->type == IDPF_CTLQ_TYPE_MAILBOX_RX &&
	     buf->size != CPFL_CTLQ_MAILBOX_BUFFER_SIZE * qinfo->len) ||
	    (qinfo->type == IDPF_CTLQ_TYPE_CONFIG_RX &&
	     buf->size != CPFL_CFGQ_RING_LEN * CPFL_CTLQ_CFGQ_BUFFER_SIZE))
		return -EBADR;

	return 0;
}

/**
 * cpfl_ctlq_alloc_ring_res - store memory for descriptor ring and bufs
 * @hw: pointer to hw struct
 * @cq: pointer to control queue struct
 * @qinfo: pointer to create queue info struct
 *
 * The CP takes care of all DMA memory allocations. Store the allocated memory
 * information for the descriptor ring and buffers. If the memory for either the
 * descriptor ring or the buffers is not allocated properly and/or inconsistent
 * with the control queue parameters, this routine will free the memory for
 * both the descriptors and the buffers
 */
int
cpfl_ctlq_alloc_ring_res(struct idpf_hw *hw __rte_unused, struct idpf_ctlq_info *cq,
			 struct cpfl_ctlq_create_info *qinfo)
{
	int ret_code = 0;
	unsigned int elem_size;
	int i = 0;

	ret_code = cpfl_check_dma_mem_parameters(qinfo);
	if (ret_code)
		/* TODO: Log an error message per CP */
		goto err;

	cq->desc_ring.va = qinfo->ring_mem.va;
	cq->desc_ring.pa = qinfo->ring_mem.pa;
	cq->desc_ring.size = qinfo->ring_mem.size;

	switch (cq->cq_type) {
	case IDPF_CTLQ_TYPE_MAILBOX_RX:
	case IDPF_CTLQ_TYPE_CONFIG_RX:
	case IDPF_CTLQ_TYPE_EVENT_RX:
	case IDPF_CTLQ_TYPE_RDMA_RX:
		/* Only receive queues will have allocated buffers
		 * during init.  CP allocates one big chunk of DMA
		 * region who size is equal to ring_len * buff_size.
		 * In CPFLib, the block gets broken down to multiple
		 * smaller blocks that actually gets programmed in the hardware.
		 */

		cq->bi.rx_buff = (struct idpf_dma_mem **)
			idpf_calloc(hw, cq->ring_size,
				    sizeof(struct idpf_dma_mem *));
		if (!cq->bi.rx_buff) {
			ret_code = -ENOMEM;
			/* TODO: Log an error message per CP */
			goto err;
		}

		elem_size = qinfo->buf_size;
		for (i = 0; i < cq->ring_size; i++) {
			cq->bi.rx_buff[i] = (struct idpf_dma_mem *)idpf_calloc
					    (hw, 1,
					     sizeof(struct idpf_dma_mem));
			if (!cq->bi.rx_buff[i]) {
				ret_code = -ENOMEM;
				goto free_rx_buffs;
			}
			cq->bi.rx_buff[i]->va =
			    (uint64_t *)((char *)qinfo->buf_mem.va + (i * elem_size));
			cq->bi.rx_buff[i]->pa = qinfo->buf_mem.pa +
					       (i * elem_size);
			cq->bi.rx_buff[i]->size = elem_size;
		}
		break;
	case IDPF_CTLQ_TYPE_MAILBOX_TX:
	case IDPF_CTLQ_TYPE_CONFIG_TX:
	case IDPF_CTLQ_TYPE_RDMA_TX:
	case IDPF_CTLQ_TYPE_RDMA_COMPL:
		break;
	default:
		ret_code = -EBADR;
	}

	return ret_code;

free_rx_buffs:
	i--;
	for (; i >= 0; i--)
		idpf_free(hw, cq->bi.rx_buff[i]);

	if (!cq->bi.rx_buff)
		idpf_free(hw, cq->bi.rx_buff);

err:
	return ret_code;
}

/**
 * cpfl_ctlq_init_rxq_bufs - populate receive queue descriptors with buf
 * @cq: pointer to the specific Control queue
 *
 * Record the address of the receive queue DMA buffers in the descriptors.
 * The buffers must have been previously allocated.
 */
static void
cpfl_ctlq_init_rxq_bufs(struct idpf_ctlq_info *cq)
{
	int i = 0;

	for (i = 0; i < cq->ring_size; i++) {
		struct idpf_ctlq_desc *desc = IDPF_CTLQ_DESC(cq, i);
		struct idpf_dma_mem *bi = cq->bi.rx_buff[i];

		/* No buffer to post to descriptor, continue */
		if (!bi)
			continue;

		desc->flags =
			CPU_TO_LE16(IDPF_CTLQ_FLAG_BUF | IDPF_CTLQ_FLAG_RD);
		desc->opcode = 0;
		desc->datalen = CPU_TO_LE16(bi->size);
		desc->ret_val = 0;
		desc->cookie_high = 0;
		desc->cookie_low = 0;
		desc->params.indirect.addr_high =
			CPU_TO_LE32(IDPF_HI_DWORD(bi->pa));
		desc->params.indirect.addr_low =
			CPU_TO_LE32(IDPF_LO_DWORD(bi->pa));
		desc->params.indirect.param0 = 0;
		desc->params.indirect.param1 = 0;
	}
}

/**
 * cpfl_ctlq_setup_regs - initialize control queue registers
 * @cq: pointer to the specific control queue
 * @q_create_info: structs containing info for each queue to be initialized
 */
static void
cpfl_ctlq_setup_regs(struct idpf_ctlq_info *cq, struct cpfl_ctlq_create_info *q_create_info)
{
	/* set control queue registers in our local struct */
	cq->reg.head = q_create_info->reg.head;
	cq->reg.tail = q_create_info->reg.tail;
	cq->reg.len = q_create_info->reg.len;
	cq->reg.bah = q_create_info->reg.bah;
	cq->reg.bal = q_create_info->reg.bal;
	cq->reg.len_mask = q_create_info->reg.len_mask;
	cq->reg.len_ena_mask = q_create_info->reg.len_ena_mask;
	cq->reg.head_mask = q_create_info->reg.head_mask;
}

/**
 * cpfl_ctlq_init_regs - Initialize control queue registers
 * @hw: pointer to hw struct
 * @cq: pointer to the specific Control queue
 * @is_rxq: true if receive control queue, false otherwise
 *
 * Initialize registers. The caller is expected to have already initialized the
 * descriptor ring memory and buffer memory
 */
static void
cpfl_ctlq_init_regs(struct idpf_hw *hw, struct idpf_ctlq_info *cq, bool is_rxq)
{
	/* Update tail to post pre-allocated buffers for rx queues */
	if (is_rxq)
		wr32(hw, cq->reg.tail, (uint32_t)(cq->ring_size - 1));

	/* For non-Mailbox control queues only TAIL need to be set */
	if (cq->q_id != -1)
		return;

	/* Clear Head for both send or receive */
	wr32(hw, cq->reg.head, 0);

	/* set starting point */
	wr32(hw, cq->reg.bal, IDPF_LO_DWORD(cq->desc_ring.pa));
	wr32(hw, cq->reg.bah, IDPF_HI_DWORD(cq->desc_ring.pa));
	wr32(hw, cq->reg.len, (cq->ring_size | cq->reg.len_ena_mask));
}

/**
 * cpfl_ctlq_dealloc_ring_res - free up the descriptor buffer structure
 * @hw: context info for the callback
 * @cq: pointer to the specific control queue
 *
 * DMA buffers are released by the CP itself
 */
static void
cpfl_ctlq_dealloc_ring_res(struct idpf_hw *hw __rte_unused, struct idpf_ctlq_info *cq)
{
	int i;

	if (cq->cq_type == IDPF_CTLQ_TYPE_MAILBOX_RX ||
	    cq->cq_type == IDPF_CTLQ_TYPE_CONFIG_RX) {
		for (i = 0; i < cq->ring_size; i++)
			idpf_free(hw, cq->bi.rx_buff[i]);
		/* free the buffer header */
		idpf_free(hw, cq->bi.rx_buff);
	} else {
		idpf_free(hw, cq->bi.tx_msg);
	}
}

/**
 * cpfl_ctlq_add - add one control queue
 * @hw: pointer to hardware struct
 * @qinfo: info for queue to be created
 * @cq_out: (output) double pointer to control queue to be created
 *
 * Allocate and initialize a control queue and add it to the control queue list.
 * The cq parameter will be allocated/initialized and passed back to the caller
 * if no errors occur.
 */
int
cpfl_ctlq_add(struct idpf_hw *hw, struct cpfl_ctlq_create_info *qinfo,
	      struct idpf_ctlq_info **cq_out)
{
	struct idpf_ctlq_info *cq;
	bool is_rxq = false;
	int status = 0;

	if (!qinfo->len || !qinfo->buf_size ||
	    qinfo->len > IDPF_CTLQ_MAX_RING_SIZE ||
	    qinfo->buf_size > IDPF_CTLQ_MAX_BUF_LEN)
		return -EINVAL;

	cq = (struct idpf_ctlq_info *)
	     idpf_calloc(hw, 1, sizeof(struct idpf_ctlq_info));

	if (!cq)
		return -ENOMEM;

	cq->cq_type = qinfo->type;
	cq->q_id = qinfo->id;
	cq->buf_size = qinfo->buf_size;
	cq->ring_size = qinfo->len;

	cq->next_to_use = 0;
	cq->next_to_clean = 0;
	cq->next_to_post = cq->ring_size - 1;

	switch (qinfo->type) {
	case IDPF_CTLQ_TYPE_EVENT_RX:
	case IDPF_CTLQ_TYPE_CONFIG_RX:
	case IDPF_CTLQ_TYPE_MAILBOX_RX:
		is_rxq = true;
		/* fallthrough */
	case IDPF_CTLQ_TYPE_CONFIG_TX:
	case IDPF_CTLQ_TYPE_MAILBOX_TX:
		status = cpfl_ctlq_alloc_ring_res(hw, cq, qinfo);
		break;

	default:
		status = -EINVAL;
		break;
	}

	if (status)
		goto init_free_q;

	if (is_rxq) {
		cpfl_ctlq_init_rxq_bufs(cq);
	} else {
		/* Allocate the array of msg pointers for TX queues */
		cq->bi.tx_msg = (struct idpf_ctlq_msg **)
			idpf_calloc(hw, qinfo->len,
				    sizeof(struct idpf_ctlq_msg *));
		if (!cq->bi.tx_msg) {
			status = -ENOMEM;
			goto init_dealloc_q_mem;
		}
	}

	cpfl_ctlq_setup_regs(cq, qinfo);

	cpfl_ctlq_init_regs(hw, cq, is_rxq);

	idpf_init_lock(&cq->cq_lock);

	LIST_INSERT_HEAD(&hw->cq_list_head, cq, cq_list);

	*cq_out = cq;
	return status;

init_dealloc_q_mem:
	/* free ring buffers and the ring itself */
	cpfl_ctlq_dealloc_ring_res(hw, cq);
init_free_q:
	idpf_free(hw, cq);
	cq = NULL;

	return status;
}

int
cpfl_vport_ctlq_add(struct idpf_hw *hw, struct cpfl_ctlq_create_info *qinfo,
		    struct idpf_ctlq_info **cq)
{
	return cpfl_ctlq_add(hw, qinfo, cq);
}

/**
 * cpfl_ctlq_shutdown - shutdown the CQ
 * The main shutdown routine for any controq queue
 */
static void
cpfl_ctlq_shutdown(struct idpf_hw *hw, struct idpf_ctlq_info *cq)
{
	idpf_acquire_lock(&cq->cq_lock);

	if (!cq->ring_size)
		goto shutdown_sq_out;

	/* free ring buffers and the ring itself */
	cpfl_ctlq_dealloc_ring_res(hw, cq);

	/* Set ring_size to 0 to indicate uninitialized queue */
	cq->ring_size = 0;

shutdown_sq_out:
	idpf_release_lock(&cq->cq_lock);
	idpf_destroy_lock(&cq->cq_lock);
}

/**
 * cpfl_ctlq_remove - deallocate and remove specified control queue
 */
static void
cpfl_ctlq_remove(struct idpf_hw *hw, struct idpf_ctlq_info *cq)
{
	LIST_REMOVE(cq, cq_list);
	cpfl_ctlq_shutdown(hw, cq);
	idpf_free(hw, cq);
}

void
cpfl_vport_ctlq_remove(struct idpf_hw *hw, struct idpf_ctlq_info *cq)
{
	cpfl_ctlq_remove(hw, cq);
}

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Advanced Micro Devices, Inc. All rights reserved.
 */
#ifndef _RTE_PTDMA_RAWDEV_FNS_H_
#define _RTE_PTDMA_RAWDEV_FNS_H_

#include <x86intrin.h>
#include <rte_rawdev.h>
#include <rte_memzone.h>
#include <rte_prefetch.h>
#include "ptdma_rawdev_spec.h"
#include "ptdma_pmd_private.h"

/**
 * @internal
 * some statistics for tracking, if added/changed update xstats fns
 */
struct rte_ptdma_xstats {
	uint64_t enqueue_failed;
	uint64_t enqueued;
	uint64_t started;
	uint64_t completed;
};

/**
 * @internal
 * Structure representing an PTDMA device instance
 */
struct rte_ptdma_rawdev {
	struct rte_rawdev *rawdev;
	struct rte_ptdma_xstats xstats;
	unsigned short ring_size;
	bool hdls_disable;
	const struct rte_memzone *mz;

	__m128i *hdls; /* completion handles for returning to user */
	unsigned short next_read;
	unsigned short next_write;
	struct ptdma_device *ptdma_dev;

};

static __rte_always_inline void
ptdma_dump_registers(int dev_id)
{
	struct rte_ptdma_rawdev *ptdma_priv =
		(struct rte_ptdma_rawdev *)rte_rawdevs[dev_id].dev_private;
	struct ptdma_cmd_queue *cmd_q;
	uint32_t cur_head_offset;
	uint32_t cur_tail_offset;

	cmd_q = &ptdma_priv->ptdma_dev->cmd_q[0];

	PTDMA_PMD_DEBUG("cmd_q->head_offset	= %d\n", cmd_q->head_offset);
	PTDMA_PMD_DEBUG("cmd_q->tail_offset	= %d\n", cmd_q->tail_offset);
	PTDMA_PMD_DEBUG("cmd_q->id		= %ld\n", cmd_q->id);
	PTDMA_PMD_DEBUG("cmd_q->qidx		= %ld\n", cmd_q->qidx);
	PTDMA_PMD_DEBUG("cmd_q->qsize		= %ld\n", cmd_q->qsize);

	cur_head_offset = PTDMA_READ_REG(cmd_q->reg_base,
			CMD_Q_HEAD_LO_BASE);
	cur_tail_offset = PTDMA_READ_REG(cmd_q->reg_base,
			CMD_Q_TAIL_LO_BASE);

	PTDMA_PMD_DEBUG("cur_head_offset	= %d\n", cur_head_offset);
	PTDMA_PMD_DEBUG("cur_tail_offset	= %d\n", cur_tail_offset);
	PTDMA_PMD_DEBUG("Q_CONTROL_BASE		= 0x%x\n",
						PTDMA_READ_REG(cmd_q->reg_base,
						CMD_Q_CONTROL_BASE));
	PTDMA_PMD_DEBUG("Q_STATUS_BASE		= 0x%x\n",
						PTDMA_READ_REG(cmd_q->reg_base,
						CMD_Q_STATUS_BASE));
	PTDMA_PMD_DEBUG("Q_INT_STATUS_BASE	= 0x%x\n",
						PTDMA_READ_REG(cmd_q->reg_base,
						CMD_Q_INT_STATUS_BASE));
	PTDMA_PMD_DEBUG("Q_DMA_STATUS_BASE	= 0x%x\n",
						PTDMA_READ_REG(cmd_q->reg_base,
						CMD_Q_DMA_STATUS_BASE));
	PTDMA_PMD_DEBUG("Q_DMA_RD_STS_BASE	= 0x%x\n",
						PTDMA_READ_REG(cmd_q->reg_base,
						CMD_Q_DMA_READ_STATUS_BASE));
	PTDMA_PMD_DEBUG("Q_DMA_WRT_STS_BASE	= 0x%x\n",
						PTDMA_READ_REG(cmd_q->reg_base,
						CMD_Q_DMA_WRITE_STATUS_BASE));
}

static __rte_always_inline void
ptdma_perform_passthru(struct ptdma_passthru *pst,
		struct ptdma_cmd_queue *cmd_q)
{
	struct ptdma_desc *desc;
	union ptdma_function function;

	desc = &cmd_q->qbase_desc[cmd_q->qidx];

	PTDMA_CMD_ENGINE(desc) = PTDMA_ENGINE_PASSTHRU;

	PTDMA_CMD_SOC(desc) = 0;
	PTDMA_CMD_IOC(desc) = 0;
	PTDMA_CMD_INIT(desc) = 0;
	PTDMA_CMD_EOM(desc) = 0;
	PTDMA_CMD_PROT(desc) = 0;

	function.raw = 0;
	PTDMA_PT_BYTESWAP(&function) = pst->byte_swap;
	PTDMA_PT_BITWISE(&function) = pst->bit_mod;
	PTDMA_CMD_FUNCTION(desc) = function.raw;
	PTDMA_CMD_LEN(desc) = pst->len;

	PTDMA_CMD_SRC_LO(desc) = (uint32_t)(pst->src_addr);
	PTDMA_CMD_SRC_HI(desc) = high32_value(pst->src_addr);
	PTDMA_CMD_SRC_MEM(desc) = PTDMA_MEMTYPE_SYSTEM;

	PTDMA_CMD_DST_LO(desc) = (uint32_t)(pst->dest_addr);
	PTDMA_CMD_DST_HI(desc) = high32_value(pst->dest_addr);
	PTDMA_CMD_DST_MEM(desc) = PTDMA_MEMTYPE_SYSTEM;

	cmd_q->qidx = (cmd_q->qidx + 1) % COMMANDS_PER_QUEUE;

}


static __rte_always_inline int
ptdma_ops_to_enqueue(int dev_id, uint32_t op, uint64_t src, phys_addr_t dst,
		unsigned int length, uintptr_t src_hdl, uintptr_t dst_hdl)
{
	struct rte_ptdma_rawdev *ptdma_priv =
		(struct rte_ptdma_rawdev *)rte_rawdevs[dev_id].dev_private;
	struct ptdma_cmd_queue *cmd_q;
	struct ptdma_passthru pst;
	unsigned short write	= ptdma_priv->next_write;

	if (!op)
		pst.src_addr	= src;
	else
		PTDMA_PMD_DEBUG("Operation not supported by PTDMA\n");

	pst.dest_addr	= dst;
	pst.len		= length;
	pst.bit_mod	= PTDMA_PASSTHRU_BITWISE_NOOP;
	pst.byte_swap	= PTDMA_PASSTHRU_BYTESWAP_NOOP;

	cmd_q = &ptdma_priv->ptdma_dev->cmd_q[0];

	cmd_q->head_offset = (uint32_t)(PTDMA_READ_REG(cmd_q->reg_base,
				CMD_Q_HEAD_LO_BASE));

	ptdma_perform_passthru(&pst, cmd_q);

	cmd_q->tail_offset = (uint32_t)(cmd_q->qbase_phys_addr + cmd_q->qidx *
				Q_DESC_SIZE);
	rte_wmb();
	/* Write the new tail address back to the queue register */
	PTDMA_WRITE_REG(cmd_q->reg_base, CMD_Q_TAIL_LO_BASE,
			cmd_q->tail_offset);

	if (!ptdma_priv->hdls_disable)
		ptdma_priv->hdls[write % COMMANDS_PER_QUEUE] =
					_mm_set_epi64x((int64_t)dst_hdl,
							(int64_t)src_hdl);
	ptdma_priv->next_write++;
	ptdma_priv->xstats.enqueued++;

	return 1;
}

static __rte_always_inline int
ptdma_ops_to_dequeue(int dev_id, int max_copies, uintptr_t *src_hdls,
						uintptr_t *dst_hdls)
{
	struct rte_ptdma_rawdev *ptdma_priv =
		(struct rte_ptdma_rawdev *)rte_rawdevs[dev_id].dev_private;
	struct ptdma_cmd_queue *cmd_q;
	uint32_t cur_head_offset;
	uint32_t cmd_q_ctrl;
	unsigned short count;
	unsigned short read = ptdma_priv->next_read;
	int i = 0;

	cmd_q = &ptdma_priv->ptdma_dev->cmd_q[0];
	cmd_q_ctrl = PTDMA_READ_REG(cmd_q->reg_base, CMD_Q_CONTROL_BASE);

	/* Wait for the operation to complete */
	while (!(cmd_q_ctrl && CMD_Q_HALT))
		;

	cur_head_offset = PTDMA_READ_REG(cmd_q->reg_base,
			CMD_Q_HEAD_LO_BASE);
	count = (cur_head_offset - cmd_q->head_offset);

	if (ptdma_priv->hdls_disable) {
		read += count;
		goto end;
	}

	if (count > max_copies)
		count = max_copies;

	for (; i < count - 1; i += 2, read += 2) {
		__m128i hdls0 =
			_mm_load_si128(&ptdma_priv->hdls[read %
					COMMANDS_PER_QUEUE]);
		__m128i hdls1 =
			_mm_load_si128(&ptdma_priv->hdls[(read + 1) %
					COMMANDS_PER_QUEUE]);
		_mm_storeu_si128((__m128i *)&src_hdls[i],
				_mm_unpacklo_epi64(hdls0, hdls1));
		_mm_storeu_si128((__m128i *)&dst_hdls[i],
				_mm_unpackhi_epi64(hdls0, hdls1));
	}

	for (; i < count; i++, read++) {
		uintptr_t *hdls =
			(uintptr_t *)&ptdma_priv->hdls[read %
			COMMANDS_PER_QUEUE];
		src_hdls[i] = hdls[0];
		dst_hdls[i] = hdls[1];
	}
end:
	ptdma_priv->next_read = read;
	ptdma_priv->xstats.completed += count;

	return count;
}

static inline int
rte_ptdma_enqueue_copy(int dev_id, phys_addr_t src, phys_addr_t dst,
		unsigned int length, uintptr_t src_hdl, uintptr_t dst_hdl)
{
	return ptdma_ops_to_enqueue(dev_id, 0, src, dst, length,
					src_hdl, dst_hdl);
}

static inline void
rte_ptdma_perform_ops(int dev_id)
{
	struct rte_ptdma_rawdev *ptdma_priv =
		(struct rte_ptdma_rawdev *)rte_rawdevs[dev_id].dev_private;
	struct ptdma_cmd_queue *cmd_q;

	cmd_q = &ptdma_priv->ptdma_dev->cmd_q[0];

	 /* Turn the queue back on using our cached control register */
	PTDMA_WRITE_REG(cmd_q->reg_base, CMD_Q_CONTROL_BASE,
			cmd_q->qcontrol | CMD_Q_RUN);

	ptdma_priv->xstats.started = ptdma_priv->xstats.enqueued;
}

static inline int
rte_ptdma_completed_ops(int dev_id, uint8_t max_copies,
		uintptr_t *src_hdls, uintptr_t *dst_hdls)
{
	int ret = 0;

	ret = ptdma_ops_to_dequeue(dev_id, max_copies, src_hdls, dst_hdls);

	return ret;
}

#endif

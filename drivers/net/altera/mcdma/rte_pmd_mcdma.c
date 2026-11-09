/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020-2026 Altera Corporation
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <eal_export.h>
#include <ethdev_driver.h>
#include <rte_compat.h>

#include "mcdma_eth.h"
#include "rte_pmd_mcdma.h"

#define MCDMA_PMD_NAME "net_mcdma"

static int
mcdma_pmd_port_get(uint16_t port_id, struct rte_eth_dev **eth_dev)
{
	struct rte_eth_dev *dev;

	if (eth_dev == NULL)
		return -EINVAL;

	if (!rte_eth_dev_is_valid_port(port_id))
		return -EINVAL;

	dev = &rte_eth_devices[port_id];
	if (dev->state != RTE_ETH_DEV_ATTACHED)
		return -ENODEV;

	if (dev->device == NULL || dev->device->driver == NULL ||
	    strcmp(dev->device->driver->name, MCDMA_PMD_NAME) != 0)
		return -ENODEV;

	*eth_dev = dev;
	return 0;
}

static struct mcdma_queue *
mcdma_pmd_queue_get(struct rte_eth_dev *dev, uint16_t queue_id,
		    enum rte_pmd_mcdma_queue_dir dir)
{
	if (dir == RTE_PMD_MCDMA_QUEUE_TX) {
		if (queue_id >= dev->data->nb_tx_queues)
			return NULL;
		return dev->data->tx_queues[queue_id];
	}

	if (queue_id >= dev->data->nb_rx_queues)
		return NULL;

	return dev->data->rx_queues[queue_id];
}

static void
mcdma_qcsr_regs_read(struct mcdma_queue *q, struct rte_pmd_mcdma_qcsr *regs)
{
	regs->q_ctrl = mcdma_qcsr_reg_readl(q->qcsr, MCDMA_QCSR_Q_CTRL);
	regs->q_start_addr_l = mcdma_qcsr_reg_readl(q->qcsr,
						    MCDMA_QCSR_Q_START_ADDR_L);
	regs->q_start_addr_h = mcdma_qcsr_reg_readl(q->qcsr,
						    MCDMA_QCSR_Q_START_ADDR_H);
	regs->q_size = mcdma_qcsr_reg_readl(q->qcsr, MCDMA_QCSR_Q_SIZE);
	regs->q_tail_pointer = mcdma_qcsr_reg_readl(q->qcsr,
						    MCDMA_QCSR_Q_TAIL_POINTER);
	regs->q_head_pointer = mcdma_qcsr_reg_readl(q->qcsr,
						    MCDMA_QCSR_Q_HEAD_POINTER);
	regs->q_completed_pointer = mcdma_qcsr_reg_readl(q->qcsr,
							 MCDMA_QCSR_Q_COMPLETED_POINTER);
	regs->q_consumed_head_addr_l = mcdma_qcsr_reg_readl(q->qcsr,
			MCDMA_QCSR_Q_CONSUMED_HEAD_ADDR_L);
	regs->q_consumed_head_addr_h = mcdma_qcsr_reg_readl(q->qcsr,
			MCDMA_QCSR_Q_CONSUMED_HEAD_ADDR_H);
	regs->q_batch_delay = mcdma_qcsr_reg_readl(q->qcsr,
						   MCDMA_QCSR_Q_BATCH_DELAY);
	regs->q_debug_status_1 = mcdma_qcsr_reg_readl(q->qcsr,
						      MCDMA_QCSR_Q_DEBUG_STATUS_1);
	regs->q_debug_status_2 = mcdma_qcsr_reg_readl(q->qcsr,
						      MCDMA_QCSR_Q_DEBUG_STATUS_2);
	regs->q_data_drp_err_ctr = mcdma_qcsr_reg_readl(q->qcsr,
			MCDMA_QCSR_Q_DATA_DRP_ERR_CTR);
	regs->q_payload_count = mcdma_qcsr_reg_readl(q->qcsr,
						     MCDMA_QCSR_Q_PAYLOAD_COUNT);
	regs->q_reset = mcdma_qcsr_reg_readl(q->qcsr, MCDMA_QCSR_Q_RESET);
	regs->q_cpl_timeout = mcdma_qcsr_reg_readl(q->qcsr,
						   MCDMA_QCSR_Q_CPL_TIMEOUT);

	rte_rmb();
	regs->prod_didx = q->prod_didx;
	regs->cons_didx = q->cons_didx;
	regs->freed_cons_didx = q->freed_cons_didx;
	regs->submitted_didx = q->submitted_didx;
	regs->num_descs = q->num_descs;
}

static void
mcdma_qcsr_dump_decoded(FILE *f, const struct rte_pmd_mcdma_qcsr *regs)
{
	mcdma_qcsr_q_ctrl_t q_ctrl;

	q_ctrl.val = regs->q_ctrl;
	fprintf(f, "  Q_CTRL decoded: q_en=%u q_wb_en=%u q_intr_en=%u\n",
		q_ctrl.field.q_en, q_ctrl.field.q_wb_en, q_ctrl.field.q_intr_en);

	if (regs->q_head_pointer & MCDMA_QCSR_PTR_ERR_MASK)
		fprintf(f, "  Q_HEAD_POINTER error bit set\n");
	if (regs->q_completed_pointer & MCDMA_QCSR_PTR_ERR_MASK)
		fprintf(f, "  Q_COMPLETED_POINTER error bit set\n");
	if (regs->q_data_drp_err_ctr & MCDMA_QCSR_DRP_CTR_VALID) {
		fprintf(f, "  Q_DATA_DRP_ERR_CTR drop_count=%u\n",
			regs->q_data_drp_err_ctr & MCDMA_QCSR_DRP_CTR_CNT_MASK);
	}
}

static int
mcdma_pio_offset_check(const struct mcdma_pci_device *priv, uint64_t offset)
{
	if (priv->pio == NULL || priv->pio_bar_len == 0)
		return -ENODEV;

	if ((offset & (sizeof(uint64_t) - 1)) != 0)
		return -EINVAL;

	if (priv->pio_bar_len < sizeof(uint64_t) ||
	    offset > priv->pio_bar_len - sizeof(uint64_t))
		return -EINVAL;

	return 0;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_pmd_mcdma_pio_read64, 26.11)
int
rte_pmd_mcdma_pio_read64(uint16_t port_id, uint64_t offset, uint64_t *val)
{
	struct rte_eth_dev *dev;
	struct mcdma_pci_device *priv;
	int ret;

	if (val == NULL)
		return -EINVAL;

	ret = mcdma_pmd_port_get(port_id, &dev);
	if (ret != 0)
		return ret;

	priv = dev->data->dev_private;
	if (priv == NULL)
		return -EINVAL;

	ret = mcdma_pio_offset_check(priv, offset);
	if (ret != 0)
		return ret;

	*val = mcdma_pio_reg_read64(priv->pio, offset);
	return 0;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_pmd_mcdma_pio_write64, 26.11)
int
rte_pmd_mcdma_pio_write64(uint16_t port_id, uint64_t offset, uint64_t val)
{
	struct rte_eth_dev *dev;
	struct mcdma_pci_device *priv;
	int ret;

	ret = mcdma_pmd_port_get(port_id, &dev);
	if (ret != 0)
		return ret;

	priv = dev->data->dev_private;
	if (priv == NULL)
		return -EINVAL;

	ret = mcdma_pio_offset_check(priv, offset);
	if (ret != 0)
		return ret;

	mcdma_pio_reg_write64(priv->pio, offset, val);
	return 0;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_pmd_mcdma_qcsr_read, 26.11)
int
rte_pmd_mcdma_qcsr_read(uint16_t port_id, uint16_t queue_id,
			enum rte_pmd_mcdma_queue_dir dir,
			struct rte_pmd_mcdma_qcsr *regs)
{
	struct rte_eth_dev *dev;
	struct mcdma_queue *q;
	int ret;

	if (regs == NULL)
		return -EINVAL;

	if (dir != RTE_PMD_MCDMA_QUEUE_RX && dir != RTE_PMD_MCDMA_QUEUE_TX)
		return -EINVAL;

	ret = mcdma_pmd_port_get(port_id, &dev);
	if (ret != 0)
		return ret;

	q = mcdma_pmd_queue_get(dev, queue_id, dir);
	if (q == NULL || q->qcsr == NULL)
		return -EINVAL;

	memset(regs, 0, sizeof(*regs));
	mcdma_qcsr_regs_read(q, regs);
	return 0;
}

static void
mcdma_qcsr_dump_reg(FILE *f, const char *name, uint32_t offset, uint32_t val)
{
	fprintf(f, "  %s @ 0x%03x = 0x%08x (%u)\n", name, offset, val, val);
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_pmd_mcdma_qcsr_dump, 26.11)
int
rte_pmd_mcdma_qcsr_dump(uint16_t port_id, uint16_t queue_id,
			enum rte_pmd_mcdma_queue_dir dir, FILE *f)
{
	struct rte_pmd_mcdma_qcsr regs;
	uint64_t qbuf_dma;
	int ret;

	if (f == NULL)
		f = stdout;

	ret = rte_pmd_mcdma_qcsr_read(port_id, queue_id, dir, &regs);
	if (ret != 0)
		return ret;

	qbuf_dma = ((uint64_t)regs.q_start_addr_h << 32) | regs.q_start_addr_l;

	fprintf(f, "MCDMA QCSR dump port %u queue %u %s\n",
		port_id, queue_id,
		dir == RTE_PMD_MCDMA_QUEUE_TX ? "TX" : "RX");
	fprintf(f, "  ring_dma=0x%016llx ring_size_log2=%u\n",
		(unsigned long long)qbuf_dma, regs.q_size);

	mcdma_qcsr_dump_reg(f, "Q_CTRL", MCDMA_QCSR_Q_CTRL, regs.q_ctrl);
	mcdma_qcsr_dump_reg(f, "Q_START_ADDR_L", MCDMA_QCSR_Q_START_ADDR_L,
			    regs.q_start_addr_l);
	mcdma_qcsr_dump_reg(f, "Q_START_ADDR_H", MCDMA_QCSR_Q_START_ADDR_H,
			    regs.q_start_addr_h);
	mcdma_qcsr_dump_reg(f, "Q_SIZE", MCDMA_QCSR_Q_SIZE, regs.q_size);
	mcdma_qcsr_dump_reg(f, "Q_TAIL_POINTER", MCDMA_QCSR_Q_TAIL_POINTER,
			    regs.q_tail_pointer);
	mcdma_qcsr_dump_reg(f, "Q_HEAD_POINTER", MCDMA_QCSR_Q_HEAD_POINTER,
			    regs.q_head_pointer);
	mcdma_qcsr_dump_reg(f, "Q_COMPLETED_POINTER",
			    MCDMA_QCSR_Q_COMPLETED_POINTER,
			    regs.q_completed_pointer);
	mcdma_qcsr_dump_reg(f, "Q_CONSUMED_HEAD_ADDR_L",
			    MCDMA_QCSR_Q_CONSUMED_HEAD_ADDR_L,
			    regs.q_consumed_head_addr_l);
	mcdma_qcsr_dump_reg(f, "Q_CONSUMED_HEAD_ADDR_H",
			    MCDMA_QCSR_Q_CONSUMED_HEAD_ADDR_H,
			    regs.q_consumed_head_addr_h);
	mcdma_qcsr_dump_reg(f, "Q_BATCH_DELAY", MCDMA_QCSR_Q_BATCH_DELAY,
			    regs.q_batch_delay);
	mcdma_qcsr_dump_reg(f, "Q_DEBUG_STATUS_1", MCDMA_QCSR_Q_DEBUG_STATUS_1,
			    regs.q_debug_status_1);
	mcdma_qcsr_dump_reg(f, "Q_DEBUG_STATUS_2", MCDMA_QCSR_Q_DEBUG_STATUS_2,
			    regs.q_debug_status_2);
	mcdma_qcsr_dump_reg(f, "Q_DATA_DRP_ERR_CTR",
			    MCDMA_QCSR_Q_DATA_DRP_ERR_CTR,
			    regs.q_data_drp_err_ctr);
	mcdma_qcsr_dump_reg(f, "Q_PAYLOAD_COUNT", MCDMA_QCSR_Q_PAYLOAD_COUNT,
			    regs.q_payload_count);
	mcdma_qcsr_dump_reg(f, "Q_RESET", MCDMA_QCSR_Q_RESET, regs.q_reset);
	mcdma_qcsr_dump_reg(f, "Q_CPL_TIMEOUT", MCDMA_QCSR_Q_CPL_TIMEOUT,
			    regs.q_cpl_timeout);

	fprintf(f, "  SW prod_didx=%u cons_didx=%u freed_cons_didx=%u "
		"submitted_didx=%u num_descs=%u\n",
		regs.prod_didx, regs.cons_didx, regs.freed_cons_didx,
		regs.submitted_didx, regs.num_descs);

	mcdma_qcsr_dump_decoded(f, &regs);
	return 0;
}

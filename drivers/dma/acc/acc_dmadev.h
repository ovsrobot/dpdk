/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#ifndef ACC_DMADEV_H
#define ACC_DMADEV_H

#include <bus_uacce_driver.h>
#include <rte_bitops.h>
#include <rte_common.h>
#include <rte_dmadev_pmd.h>

#define ACC_DMA_DEVARG_QUEUES		"queues"
#define ACC_DMA_DEFAULT_QUEUES		1

struct acc_dma_config {
	uint16_t queues;

	/* The following fields are config contexts. */
	struct rte_uacce_device *dev;
	uint16_t avail_queues;
};

#define ACC_DMA_DOORBELL_OFFSET		0x1000u

struct acc_dma_sqe {};
struct acc_dma_cqe {};

struct acc_dma_dev {
	struct acc_dma_sqe *sqe;
	struct acc_dma_cqe *cqe;
	uint16_t *status;             /* the completion status array of SQEs. */

	volatile void *doorbell_reg;  /**< register address for doorbell. */
	volatile uint32_t *sq_status; /**< SQ status pointer. */
	volatile uint32_t *cq_status; /**< CQ status pointer. */

	uint16_t sqn;           /**< SQ global number, inited when created. */
	uint16_t sq_depth_mask; /**< SQ depth - 1, the SQ depth is power of 2. */

	uint16_t cq_depth;      /**< CQ depth, inited when created. */

	/**
	 * The following fields are not accessed in the I/O path, so they are
	 * placed at the end.
	 */
	struct rte_dma_dev_data *data;
	struct rte_uacce_qcontex qctx;
	void *io_base;
	void *dus_base;
	uint32_t sqe_size;
	uint16_t sq_depth;
};

#endif /* ACC_DMADEV_H */

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#ifndef __SXE_IRQ_H__
#define __SXE_IRQ_H__

#include <ethdev_driver.h>
#include "sxe_compat_platform.h"
#include "sxe_compat_version.h"

#define SXE_QUEUE_IRQ_NUM_MAX	15

#define SXE_QUEUE_ITR_INTERVAL_DEFAULT   500
#define SXE_QUEUE_ITR_INTERVAL   3

#define SXE_EITR_INTERVAL_UNIT_NS	2048
#define SXE_EITR_ITR_INT_SHIFT		  3
#define SXE_IRQ_ITR_MASK				(0x00000FF8)
#define SXE_EITR_INTERVAL_US(us) \
	(((us) * 1000 / SXE_EITR_INTERVAL_UNIT_NS << SXE_EITR_ITR_INT_SHIFT) & \
		SXE_IRQ_ITR_MASK)

struct sxe_irq_context {
	u32 action;
	u32 enable_mask;
	u32 enable_mask_original;
	rte_spinlock_t event_irq_lock;
	bool to_pcs_init;
};

void sxe_event_irq_delayed_handler(void *param);

void sxe_irq_init(struct rte_eth_dev *eth_dev);

s32 sxe_irq_configure(struct rte_eth_dev *dev);

void sxe_irq_enable(struct rte_eth_dev *eth_dev);

void sxe_irq_disable(struct rte_eth_dev *eth_dev);

void sxe_irq_uninit(struct rte_eth_dev *eth_dev);

s32 sxe_rx_queue_intr_enable(struct rte_eth_dev *eth_dev, u16 queue_id);

s32 sxe_rx_queue_intr_disable(struct rte_eth_dev *eth_dev, u16 queue_id);

void sxe_irq_vec_free(struct rte_intr_handle *handle);

#endif

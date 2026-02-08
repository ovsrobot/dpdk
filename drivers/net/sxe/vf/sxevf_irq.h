/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#ifndef __SXEVF_IRQ_H__
#define __SXEVF_IRQ_H__

#include <ethdev_driver.h>
#include "sxe_compat_platform.h"

struct sxevf_irq_context {
	u32 enable_mask;
	u32 enable_mask_original;
};

void sxevf_intr_disable(struct rte_eth_dev *eth_dev);

void sxevf_intr_enable(struct rte_eth_dev *eth_dev);

void sxevf_irq_init(struct rte_eth_dev *eth_dev);

s32 sxevf_irq_configure(struct rte_eth_dev *eth_dev);

void sxevf_irq_free(struct rte_eth_dev *eth_dev);

void sxevf_irq_unregister(struct rte_eth_dev *eth_dev);

s32 sxevf_rx_queue_intr_disable(struct rte_eth_dev *dev, u16 queue_id);

s32 sxevf_rx_queue_intr_enable(struct rte_eth_dev *dev, u16 queue_id);

s32 sxevf_link_update(struct rte_eth_dev *dev, int wait_to_complete);

#endif

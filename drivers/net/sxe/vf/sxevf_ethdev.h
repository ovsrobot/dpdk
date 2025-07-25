/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#ifndef __SXEVF_ETHDEV_H__
#define __SXEVF_ETHDEV_H__

s32 sxevf_ethdev_init(struct rte_eth_dev *eth_dev);

s32 sxevf_ethdev_uninit(struct rte_eth_dev *eth_dev);

u32 sxevf_regs_group_num_get(void);

void sxevf_regs_group_read(struct sxevf_hw *hw, u32 *data);

#endif

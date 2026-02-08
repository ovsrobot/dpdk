/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#ifndef __SXE_ETHDEV_H__
#define __SXE_ETHDEV_H__

#include "sxe.h"

#define SXE_MMW_SIZE_DEFAULT		0x4
#define SXE_MMW_SIZE_JUMBO_FRAME	0x14
#define SXE_MAX_JUMBO_FRAME_SIZE	0x2600

#define SXE_ETH_MAX_LEN  (RTE_ETHER_MTU + SXE_ETH_OVERHEAD)

#define SXE_HKEY_MAX_INDEX 10
#define SXE_ETH_OVERHEAD (RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN)
#define SXE_ETH_DEAD_LOAD (SXE_ETH_OVERHEAD + 2 * SXE_VLAN_TAG_SIZE)

struct sxe_adapter;
s32 sxe_ethdev_init(struct rte_eth_dev *eth_dev, void *param __rte_unused);

s32 sxe_ethdev_uninit(struct rte_eth_dev *eth_dev);

void sxe_secondary_proc_init(struct rte_eth_dev *eth_dev,
	bool rx_batch_alloc_allowed, bool *rx_vec_allowed);

#endif

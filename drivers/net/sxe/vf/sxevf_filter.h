/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#ifndef __SXEVF_FILTER_H__
#define __SXEVF_FILTER_H__

#include <rte_ether.h>
#include <ethdev_driver.h>

#define SXEVF_MTA_ENTRY_NUM_MAX		128
#define SXEVF_UTA_HASH_BIT_MAX		 4096
#define VLAN_N_VID	 4096
#define BYTE_BIT_NUM   8

#define  SXEVF_VLAN_ID_SHIFT		 (5)
#define  SXEVF_VLAN_ID_REG_MASK	  (0x7F)
#define  SXEVF_VLAN_ID_BIT_MASK	  (0x1F)

#define SXEVF_VLAN_STRIP_BITMAP_SIZE \
		(SXEVF_HW_TXRX_RING_NUM_MAX / (sizeof(u32) * BYTE_BIT_NUM))

struct sxevf_vlan_context {
	u32 vlan_table[SXEVF_VFT_TBL_SIZE];
	u32 strip_bitmap[SXEVF_VLAN_STRIP_BITMAP_SIZE];
	u32 vlan_table_size;
};

struct sxevf_mac_filter_context {
	struct rte_ether_addr def_mac_addr;
	u8  mc_filter_type;
	u32 uc_table_size;
};

void sxevf_vlan_filter_init(struct rte_eth_dev *eth_dev);

s32 sxevf_mac_addr_init(struct rte_eth_dev *eth_dev);

void sxevf_vlan_filter_configure(struct rte_eth_dev *eth_dev);

void sxevf_vfta_sync(struct rte_eth_dev *eth_dev, bool on);

s32 sxevf_promiscuous_disable(struct rte_eth_dev *eth_dev);

s32 sxevf_promiscuous_enable(struct rte_eth_dev *eth_dev);

s32 sxevf_allmulticast_disable(struct rte_eth_dev *eth_dev);

s32 sxevf_allmulticast_enable(struct rte_eth_dev *eth_dev);

s32 sxevf_vlan_filter_set(struct rte_eth_dev *eth_dev,  u16 vlan_id, s32 on);

void sxevf_vlan_strip_queue_set(struct rte_eth_dev *dev, u16 queue, s32 on);

s32 sxevf_vlan_offload_set(struct rte_eth_dev *dev, s32 mask);

s32 sxevf_default_mac_addr_set(struct rte_eth_dev *dev,
				 struct rte_ether_addr *mac_addr);

void sxevf_mac_addr_remove(struct rte_eth_dev *dev, u32 index);

s32 sxevf_mac_addr_add(struct rte_eth_dev *dev,
				 struct rte_ether_addr *mac_addr,
				 __rte_unused u32 rar_idx, __rte_unused u32 pool);

s32 sxevf_set_mc_addr_list(struct rte_eth_dev *dev,
			  struct rte_ether_addr *mc_addr_list,
			  u32 nb_mc_addr);

#endif

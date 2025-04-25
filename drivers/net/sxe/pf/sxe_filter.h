/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#ifndef __SXE_FILTER_H__
#define __SXE_FILTER_H__

#include <rte_ether.h>
#include "sxe_dpdk_version.h"
#if defined DPDK_20_11_5 || defined DPDK_19_11_6
#include <rte_ethdev_driver.h>
#else
#include <ethdev_driver.h>
#endif

#include "sxe_types.h"
#include "sxe_hw.h"

struct sxe_adapter;

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"

#define BYTE_BIT_NUM   8

#define SXE_VLAN_STRIP_BITMAP_SIZE	\
		RTE_ALIGN((SXE_HW_TXRX_RING_NUM_MAX / (sizeof(u32) * BYTE_BIT_NUM)), \
		sizeof(u32))

struct sxe_mac_filter_context {
	struct rte_ether_addr def_mac_addr;
	struct rte_ether_addr cur_mac_addr;

	struct rte_ether_addr fc_mac_addr;

	bool promiscuous_mode;
	u32 uta_used_count;
	u32 uta_hash_table[SXE_UTA_ENTRY_NUM_MAX];

	u32 mta_hash_table[SXE_MTA_ENTRY_NUM_MAX];
	struct sxe_uc_addr_table *uc_addr_table;
};

s32 sxe_mac_addr_init(struct rte_eth_dev *eth_dev);

s32 sxe_mac_addr_add(struct rte_eth_dev *dev,
				 struct rte_ether_addr *mac_addr,
				 u32 rar_idx, u32 pool);

void sxe_mac_addr_remove(struct rte_eth_dev *dev, u32 rar_idx);

s32 sxe_mac_addr_set(struct rte_eth_dev *dev,
				 struct rte_ether_addr *mac_addr);

s32 sxe_vlan_filter_set(struct rte_eth_dev *eth_dev, u16 vlan_id, s32 on);

s32 sxe_vlan_tpid_set(struct rte_eth_dev *eth_dev,
			enum rte_vlan_type vlan_type, u16 tpid);

s32 sxe_vlan_offload_set(struct rte_eth_dev *dev, s32 vlan_mask);

void sxe_vlan_strip_queue_set(struct rte_eth_dev *dev, u16 queue, s32 on);

void sxe_vlan_filter_configure(struct rte_eth_dev *dev);

s32 sxe_set_mc_addr_list(struct rte_eth_dev *dev,
			  struct rte_ether_addr *mc_addr_list,
			  u32 nb_mc_addr);

void sxe_vlan_strip_switch_set(struct rte_eth_dev *dev);

void sxe_fc_mac_addr_set(struct sxe_adapter *adapter);

#endif

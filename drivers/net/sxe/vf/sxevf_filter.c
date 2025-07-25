/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SRIOV

#include <string.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>

#include "sxevf.h"
#include "sxe_logs.h"
#include "sxevf_msg.h"
#include "sxe_errno.h"
#include "sxevf_filter.h"
#include "sxevf_rx.h"
#include "sxevf_queue.h"
#include "sxe_compat_version.h"

#define  SXEVF_MAC_ADDR_EXTRACT_MASK  (0xFFF)
#define  SXEVF_MAC_ADDR_SHIFT		 (5)
#define  SXEVF_MAC_ADDR_REG_MASK	  (0x7F)
#define  SXEVF_MAC_ADDR_BIT_MASK	  (0x1F)

#define SXEVF_STRIP_BITMAP_SET(h, q) \
	do { \
		u32 idx = (q) / (sizeof((h)->strip_bitmap[0]) * BYTE_BIT_NUM); \
		u32 bit = (q) % (sizeof((h)->strip_bitmap[0]) * BYTE_BIT_NUM); \
		(h)->strip_bitmap[idx] |= 1 << bit;\
	} while (0)

#define SXEVF_STRIP_BITMAP_CLEAR(h, q) \
	do {\
		u32 idx = (q) / (sizeof((h)->strip_bitmap[0]) * BYTE_BIT_NUM); \
		u32 bit = (q) % (sizeof((h)->strip_bitmap[0]) * BYTE_BIT_NUM); \
		(h)->strip_bitmap[idx] &= ~(1 << bit);\
	} while (0)

#define SXEVF_STRIP_BITMAP_GET(h, q, r) \
	do {\
		u32 idx = (q) / (sizeof((h)->strip_bitmap[0]) * BYTE_BIT_NUM); \
		u32 bit = (q) % (sizeof((h)->strip_bitmap[0]) * BYTE_BIT_NUM); \
		(r) = (h)->strip_bitmap[idx] >> bit & 1;\
	} while (0)

static void sxevf_random_mac_addr_generate(struct rte_ether_addr *mac_addr)
{
	u64 random;

	mac_addr->addr_bytes[0] = 0xe4;
	mac_addr->addr_bytes[1] = 0xb6;
	mac_addr->addr_bytes[2] = 0x33;

	mac_addr->addr_bytes[0] |= RTE_ETHER_LOCAL_ADMIN_ADDR;

	random = rte_rand();
	memcpy(&mac_addr->addr_bytes[3], &random, 3);
}

s32 sxevf_mac_addr_init(struct rte_eth_dev *eth_dev)
{
	struct sxevf_adapter *adapter = eth_dev->data->dev_private;
	struct sxevf_hw *hw = &adapter->hw;
	struct sxevf_mac_filter_context *mac_filter = &adapter->mac_filter_ctxt;
	s32 ret = 0;
	u8 *mac_addr;

	UNUSED(mac_addr);
	eth_dev->data->mac_addrs = rte_zmalloc("sxe",
				RTE_ETHER_ADDR_LEN * SXEVF_HW_UC_ENTRY_NUM_MAX, 0);
	if (eth_dev->data->mac_addrs == NULL) {
		LOG_ERROR_BDF("mac addr allocate %u B fail.",
				 RTE_ETHER_ADDR_LEN * SXEVF_HW_UC_ENTRY_NUM_MAX);
		ret = -ENOMEM;
		goto l_out;
	}

	if (rte_is_zero_ether_addr(&mac_filter->def_mac_addr)) {
		sxevf_random_mac_addr_generate(&mac_filter->def_mac_addr);
		ret = sxevf_mac_addr_set(hw, mac_filter->def_mac_addr.addr_bytes);
		if (ret) {
			LOG_ERROR_BDF("vf uc mac addr set fail.(err:%d)", ret);
			goto l_free;
		}
		mac_addr = mac_filter->def_mac_addr.addr_bytes;
		LOG_INFO_BDF("generate random mac_addr:" RTE_ETHER_ADDR_PRT_FMT,
			mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3],
			mac_addr[4], mac_addr[5]);
	}

	rte_ether_addr_copy(&mac_filter->def_mac_addr, &eth_dev->data->mac_addrs[0]);

	mac_filter->uc_table_size = SXEVF_HW_UC_ENTRY_NUM_MAX;

l_out:
	return ret;

l_free:
	rte_free(eth_dev->data->mac_addrs);
	eth_dev->data->mac_addrs = NULL;
	return ret;
}

void sxevf_vfta_sync(struct rte_eth_dev *eth_dev, bool on)
{
	struct sxevf_adapter *adapter = eth_dev->data->dev_private;
	struct sxevf_hw *hw = &adapter->hw;
	struct sxevf_vlan_context *vlan_ctxt = &adapter->vlan_ctxt;
	u32 reg_idx;
	u32 bit_idx;
	u32 vfta;
	u32 mask;
	u32 vlan_id;

	for (reg_idx = 0; reg_idx < SXEVF_VFT_TBL_SIZE; reg_idx++) {
		vfta = vlan_ctxt->vlan_table[reg_idx];
		if (vfta) {
			mask = 1;
			for (bit_idx = 0; bit_idx < 32; bit_idx++) {
				vlan_id = (reg_idx << 5) + bit_idx;
				if (vfta & mask)
					sxevf_vlan_id_set(hw, vlan_id, on);
				mask <<= 1;
			}
		}
	}
}

static void sxevf_vlan_strip_bitmap_set(struct rte_eth_dev *dev, u16 queue_idx, bool on)
{
	struct sxevf_adapter *adapter = dev->data->dev_private;
	struct sxevf_vlan_context *vlan_ctxt = &adapter->vlan_ctxt;
	sxevf_rx_queue_s *rxq;

	if (queue_idx >= adapter->max_rx_queue) {
		LOG_ERROR_BDF("invalid queue idx:%u exceed max"
			   " queue  number:%u.",
			   queue_idx, adapter->max_rx_queue);
		return;
	}

	if (on)
		SXEVF_STRIP_BITMAP_SET(vlan_ctxt, queue_idx);
	else
		SXEVF_STRIP_BITMAP_CLEAR(vlan_ctxt, queue_idx);

	if (queue_idx >= dev->data->nb_rx_queues) {
		LOG_ERROR_BDF("invalid queue_idx id:%u exceed rx "
			   " queue number:%u.",
			   queue_idx, dev->data->nb_rx_queues);
		return;
	}

	rxq = dev->data->rx_queues[queue_idx];

	if (on) {
		rxq->vlan_flags = RTE_MBUF_F_RX_VLAN | RTE_MBUF_F_RX_VLAN_STRIPPED;
		rxq->offloads |= RTE_ETH_RX_OFFLOAD_VLAN_STRIP;
	} else {
		rxq->vlan_flags = RTE_MBUF_F_RX_VLAN;
		rxq->offloads &= ~RTE_ETH_RX_OFFLOAD_VLAN_STRIP;
	}

	LOG_INFO_BDF("queue idx:%u vlan strip on:%d set bitmap and offload done.",
			 queue_idx, on);
}

static void sxevf_vlan_strip_switch_set(struct rte_eth_dev *dev)
{
	struct sxevf_adapter *adapter = dev->data->dev_private;
	struct sxevf_hw *hw = &adapter->hw;
	u16 i;
	sxevf_rx_queue_s *rxq;
	bool on;

	PMD_INIT_FUNC_TRACE();

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rxq = dev->data->rx_queues[i];

		if (rxq->offloads & RTE_ETH_RX_OFFLOAD_VLAN_STRIP)
			on = true;
		else
			on = false;

		sxevf_hw_vlan_tag_strip_switch(hw, i, on);

		sxevf_vlan_strip_bitmap_set(dev, i, on);
	}
}

static void sxevf_vlan_offload_configure(struct rte_eth_dev *dev, s32 mask)
{
	if (mask & RTE_ETH_VLAN_STRIP_MASK)
		sxevf_vlan_strip_switch_set(dev);
}

void sxevf_vlan_filter_configure(struct rte_eth_dev *eth_dev)
{
	u32 vlan_mask;

	sxevf_vfta_sync(eth_dev, true);

	vlan_mask = RTE_ETH_VLAN_STRIP_MASK | RTE_ETH_VLAN_FILTER_MASK |
			RTE_ETH_VLAN_EXTEND_MASK;

	sxevf_vlan_offload_configure(eth_dev, vlan_mask);
}

s32 sxevf_promiscuous_enable(struct rte_eth_dev *eth_dev)
{
	struct sxevf_adapter *adapter = eth_dev->data->dev_private;
	struct sxevf_hw *hw = &adapter->hw;
	s32 ret;

	ret = sxevf_cast_mode_set(hw, SXEVF_CAST_MODE_PROMISC);
	if (ret) {
		LOG_ERROR_BDF("cast mode:0x%x set fail.(err:%d)",
				  SXEVF_CAST_MODE_PROMISC, ret);
	}

	return ret;
}

s32 sxevf_promiscuous_disable(struct rte_eth_dev *eth_dev)
{
	struct sxevf_adapter *adapter = eth_dev->data->dev_private;
	struct sxevf_hw *hw = &adapter->hw;
	s32 mode = SXEVF_CAST_MODE_NONE;
	s32 ret;

	if (eth_dev->data->all_multicast)
		mode = SXEVF_CAST_MODE_ALLMULTI;
	ret = sxevf_cast_mode_set(hw, mode);
	if (ret)
		LOG_ERROR_BDF("disable mc promiscuous fail.(err:%d)", ret);

	return ret;
}

s32 sxevf_allmulticast_enable(struct rte_eth_dev *eth_dev)
{
	struct sxevf_adapter *adapter = eth_dev->data->dev_private;
	struct sxevf_hw *hw = &adapter->hw;
	s32 ret = 0;

	if (eth_dev->data->promiscuous)
		goto l_out;

	ret = sxevf_cast_mode_set(hw, SXEVF_CAST_MODE_ALLMULTI);
	if (ret)
		LOG_ERROR_BDF("cast mode:0x%x set fail.(err:%d)",
				  SXEVF_CAST_MODE_ALLMULTI, ret);

l_out:
	return ret;
}

s32 sxevf_allmulticast_disable(struct rte_eth_dev *eth_dev)
{
	struct sxevf_adapter *adapter = eth_dev->data->dev_private;
	struct sxevf_hw *hw = &adapter->hw;
	s32 ret = 0;

	if (eth_dev->data->promiscuous)
		goto l_out;

	ret = sxevf_cast_mode_set(hw, SXEVF_CAST_MODE_MULTI);
	if (ret)
		LOG_ERROR_BDF("disable mc promiscuous fail.(err:%d)", ret);

l_out:
	return ret;
}

s32 sxevf_vlan_filter_set(struct rte_eth_dev *eth_dev,  u16 vlan_id, s32 on)
{
	struct sxevf_adapter *adapter = eth_dev->data->dev_private;
	struct sxevf_hw *hw = &adapter->hw;
	struct sxevf_vlan_context *vlan_ctxt = &adapter->vlan_ctxt;
	s32 ret;
	u8 reg_idx;
	u8 bit_idx;

	ret = sxevf_vlan_id_set(hw, vlan_id, on);
	if (ret) {
		LOG_ERROR_BDF("vlan_id:0x%x status:%u set fail.(err:%d)",
				  vlan_id, on, ret);
		goto l_out;
	}

	reg_idx = (vlan_id >> SXEVF_VLAN_ID_SHIFT) & SXEVF_VLAN_ID_REG_MASK;
	bit_idx = (vlan_id & SXEVF_VLAN_ID_BIT_MASK);

	if (on)
		vlan_ctxt->vlan_table[reg_idx] |= (1 << bit_idx);
	else
		vlan_ctxt->vlan_table[reg_idx] &= ~(1 << bit_idx);

	LOG_INFO_BDF("vlan_id:0x%x status:%u set success.", vlan_id, on);

l_out:
	return ret;
}

void sxevf_vlan_strip_queue_set(struct rte_eth_dev *dev, u16 queue, s32 on)
{
	struct sxevf_adapter *adapter = dev->data->dev_private;
	struct sxevf_hw *hw = &adapter->hw;

	if (queue > adapter->max_rx_queue) {
		LOG_ERROR_BDF("queue id:%u invalid exceed max rx queue num:%u",
				  queue, adapter->max_rx_queue);
		return;
	}

	sxevf_hw_vlan_tag_strip_switch(hw, queue, on);

	sxevf_vlan_strip_bitmap_set(dev, queue, on);

	LOG_INFO_BDF("queue:%u vlan tag strip on:%u done", queue, on);
}

static void sxevf_vlan_strip_offload_configure(struct rte_eth_dev *dev, s32 mask)
{
	u16 i;
	struct rte_eth_rxmode *rxmode = &dev->data->dev_conf.rxmode;
	sxevf_rx_queue_s *rxq;

	if (mask & RTE_ETH_VLAN_STRIP_MASK) {
		if (rxmode->offloads & RTE_ETH_RX_OFFLOAD_VLAN_STRIP) {
			for (i = 0; i < dev->data->nb_rx_queues; i++) {
				rxq = dev->data->rx_queues[i];
				rxq->offloads |= RTE_ETH_RX_OFFLOAD_VLAN_STRIP;
			}
		} else {
			for (i = 0; i < dev->data->nb_rx_queues; i++) {
				rxq = dev->data->rx_queues[i];
				rxq->offloads &= ~RTE_ETH_RX_OFFLOAD_VLAN_STRIP;
			}
		}
	}

	PMD_LOG_INFO(DRV, "mask:0x%x rx mode offload:0x%" SXE_PRIX64
			 " all queue vlan strip offload flag configure done",
			 mask, rxmode->offloads);
}

s32 sxevf_vlan_offload_set(struct rte_eth_dev *dev, s32 mask)
{
	sxevf_vlan_strip_offload_configure(dev, mask);

	sxevf_vlan_offload_configure(dev, mask);

	PMD_LOG_INFO(DRV, "vlan offload mask:0x%x set done.", mask);

	return 0;
}

s32 sxevf_default_mac_addr_set(struct rte_eth_dev *dev,
				 struct rte_ether_addr *mac_addr)
{
	s32 ret;
	struct sxevf_adapter *adapter = dev->data->dev_private;
	struct sxevf_hw *hw = &adapter->hw;
	u8 *addr = mac_addr->addr_bytes;

	UNUSED(addr);
	ret = sxevf_mac_addr_set(hw, mac_addr->addr_bytes);
	if (ret) {
		LOG_ERROR_BDF("modify default mac addr to " RTE_ETHER_ADDR_PRT_FMT " fail.(err:%d)",
				  addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], ret);
	}

	LOG_INFO_BDF("modify default mac addr to " RTE_ETHER_ADDR_PRT_FMT " success.",
			  addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

	return ret;
}

s32 sxevf_mac_addr_add(struct rte_eth_dev *dev,
				 struct rte_ether_addr *mac_addr,
				 __rte_unused u32 rar_idx, __rte_unused u32 pool)
{
	s32 ret;
	struct sxevf_adapter *adapter = dev->data->dev_private;
	struct sxevf_hw *hw = &adapter->hw;
	struct sxevf_mac_filter_context *mac_ctxt = &adapter->mac_filter_ctxt;
	u8 *addr = mac_addr->addr_bytes;

	UNUSED(addr);
	if (memcmp(mac_ctxt->def_mac_addr.addr_bytes, mac_addr->addr_bytes,
			sizeof(*mac_addr)) == 0) {
		ret = -EINVAL;
		LOG_ERROR_BDF("mac_addr:" RTE_ETHER_ADDR_PRT_FMT " eaqual to defalut mac addr"
				 " skip mac addr add.(err:%d)",
				 addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], ret);
		goto l_out;
	}

	ret = sxevf_uc_addr_add(hw, 2, mac_addr->addr_bytes);
	if (ret) {
		LOG_ERROR_BDF("mac_addr:" RTE_ETHER_ADDR_PRT_FMT " add fail.(err:%d)",
				  addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], ret);
		goto l_out;
	}

	LOG_INFO_BDF("mac_addr:" RTE_ETHER_ADDR_PRT_FMT " add success.",
				addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

l_out:
	return ret;
}

void sxevf_mac_addr_remove(struct rte_eth_dev *dev, u32 index)
{
	struct sxevf_adapter *adapter = dev->data->dev_private;
	struct sxevf_hw *hw = &adapter->hw;
	struct sxevf_mac_filter_context *mac_ctxt = &adapter->mac_filter_ctxt;
	struct rte_ether_addr *mac_addr;
	u8 *addr;
	u8 i;

	sxevf_uc_addr_add(hw, 0, NULL);

	for (i = 0, mac_addr = dev->data->mac_addrs; i < mac_ctxt->uc_table_size;
		 i++, mac_addr++) {
		if (i == index || rte_is_zero_ether_addr(mac_addr) ||
		(memcmp(mac_ctxt->def_mac_addr.addr_bytes, mac_addr->addr_bytes,
				sizeof(*mac_addr)) == 0)) {
			continue;
		}
		sxevf_uc_addr_add(hw, 2, mac_addr->addr_bytes);
	}
	addr = dev->data->mac_addrs[index].addr_bytes;
	UNUSED(addr);
	LOG_INFO_BDF("index:%u mac addr" RTE_ETHER_ADDR_PRT_FMT " remove success.",
			  index, addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

static u16 sxevf_hash_mac_addr_parse(u8 *mac_addr)
{
	u16 extracted = ((mac_addr[4] >> 4) |
			(((u16)mac_addr[5]) << 4));

	extracted &= SXEVF_MAC_ADDR_EXTRACT_MASK;

	PMD_LOG_DEBUG(DRV, "mac_addr:" RTE_ETHER_ADDR_PRT_FMT " parse result:0x%x",
			 mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3],
			 mac_addr[4], mac_addr[5], extracted);

	return extracted;
}

s32 sxevf_set_mc_addr_list(struct rte_eth_dev *dev,
			  struct rte_ether_addr *mc_addr_list,
			  u32 nb_mc_addr)
{
	s32 ret;
	u32 result;
	struct sxevf_mc_sync_msg msg;
	struct sxevf_adapter *adapter = dev->data->dev_private;
	struct sxevf_hw *hw = &adapter->hw;
	u32 i;

	msg.msg_type = SXEVF_MC_ADDR_SYNC;
	msg.mc_cnt = RTE_MIN(nb_mc_addr, (u32)SXEVF_MC_ENTRY_NUM_MAX);

	for (i = 0; i < msg.mc_cnt; i++) {
		msg.mc_addr_extract[i] = sxevf_hash_mac_addr_parse(mc_addr_list->addr_bytes);
		mc_addr_list++;
	}

	ret = sxevf_send_and_rcv_msg(hw, (u32 *)&msg, SXEVF_MSG_NUM(sizeof(msg)));
	result = (msg.mc_cnt << 16) | msg.msg_type;

	if (ret || ((result & SXEVF_MC_ADDR_SYNC) &&
			(result & SXEVF_MSGTYPE_NACK))) {
		ret = ret ? ret : -SXEVF_ERR_MSG_HANDLE_ERR;
		goto l_out;
	}

	PMD_LOG_DEBUG(DRV, "msg_type:0x%x len:%zu mc_cnt:%d msg "
		  "result:0x%x.(ret:%d)",
		  msg.msg_type, SXEVF_MSG_NUM(sizeof(msg)),
		  msg.mc_cnt, result, ret);

l_out:
	return ret;
}

#endif

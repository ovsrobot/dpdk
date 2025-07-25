/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */
#include <ethdev_driver.h>
#include <bus_pci_driver.h>
#include <rte_malloc.h>
#include <rte_ethdev.h>
#include "sxe_filter.h"
#include "sxe_logs.h"
#include "sxe.h"
#include "sxe_queue.h"
#include "sxe_pmd_hdc.h"
#include "sxe_compat_version.h"

#define PF_POOL_INDEX(p)		(p)

#define SXE_STRIP_BITMAP_SET(h, q) \
	do { \
		const typeof(h) _sxe_h = (h); \
		const typeof(q) _sxe_q = (q); \
		u32 idx = (_sxe_q) / (sizeof((_sxe_h)->strip_bitmap[0]) * BYTE_BIT_NUM); \
		u32 bit = (_sxe_q) % (sizeof((_sxe_h)->strip_bitmap[0]) * BYTE_BIT_NUM); \
		(_sxe_h)->strip_bitmap[idx] |= 1 << bit;\
	} while (0)

#define SXE_STRIP_BITMAP_CLEAR(h, q) \
	do {\
		const typeof(h) _sxe_h = (h); \
		const typeof(q) _sxe_q = (q); \
		u32 idx = (_sxe_q) / (sizeof((_sxe_h)->strip_bitmap[0]) * BYTE_BIT_NUM); \
		u32 bit = (_sxe_q) % (sizeof((_sxe_h)->strip_bitmap[0]) * BYTE_BIT_NUM); \
		(_sxe_h)->strip_bitmap[idx] &= ~(1 << bit);\
	} while (0)

#define SXE_STRIP_BITMAP_GET(h, q, r) \
	do {\
		const typeof(h) _sxe_h = (h); \
		const typeof(q) _sxe_q = (q); \
		u32 idx = (_sxe_q) / (sizeof((_sxe_h)->strip_bitmap[0]) * BYTE_BIT_NUM); \
		u32 bit = (_sxe_q) % (sizeof((_sxe_h)->strip_bitmap[0]) * BYTE_BIT_NUM); \
		(r) = (_sxe_h)->strip_bitmap[idx] >> bit & 1;\
	} while (0)

static s32 sxe_get_mac_addr_from_fw(struct sxe_adapter *adapter,
						u8 *mac_addr)
{
	s32 ret;
	struct sxe_default_mac_addr_resp mac;
	struct sxe_hw *hw = &adapter->hw;

	/* Get default mac address from firmware */
	ret = sxe_driver_cmd_trans(hw, SXE_CMD_R0_MAC_GET, NULL, 0,
				(void *)&mac, sizeof(mac));
	if (ret) {
		LOG_ERROR_BDF("hdc trans failed ret=%d, cmd:mac addr get", ret);
		ret = -EIO;
	} else {
		memcpy(mac_addr, mac.addr, SXE_MAC_ADDR_LEN);
	}

	return ret;
}

static void sxe_default_mac_addr_get(struct sxe_adapter *adapter)
{
	s32 ret;
	struct rte_ether_addr mac_addr = { {0} };
	u8 *addr;

	UNUSED(addr);
	ret = sxe_get_mac_addr_from_fw(adapter, mac_addr.addr_bytes);
	addr = mac_addr.addr_bytes;
	if (ret || !rte_is_valid_assigned_ether_addr(&mac_addr)) {
		LOG_DEBUG("invalid default mac addr:" RTE_ETHER_ADDR_PRT_FMT " result:%d",
					addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], ret);
		return;
	}

	LOG_DEBUG("default mac addr = " RTE_ETHER_ADDR_PRT_FMT "", addr[0], addr[1], addr[2],
				addr[3], addr[4], addr[5]);
	rte_ether_addr_copy(&mac_addr, &adapter->mac_filter_ctxt.def_mac_addr);
	rte_ether_addr_copy(&mac_addr, &adapter->mac_filter_ctxt.fc_mac_addr);
}

s32 sxe_mac_addr_init(struct rte_eth_dev *eth_dev)
{
	struct sxe_adapter *adapter = eth_dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	s32 ret = 0;
	u8 rar_idx;

	eth_dev->data->mac_addrs = rte_zmalloc("sxe",
				RTE_ETHER_ADDR_LEN * SXE_UC_ENTRY_NUM_MAX, 0);
	if (eth_dev->data->mac_addrs == NULL) {
		LOG_ERROR("mac addr allocate %u B fail.",
			RTE_ETHER_ADDR_LEN * SXE_UC_ENTRY_NUM_MAX);
		ret = -ENOMEM;
		goto l_out;
	}

	eth_dev->data->hash_mac_addrs = rte_zmalloc("sxe",
				RTE_ETHER_ADDR_LEN * SXE_UTA_ENTRY_NUM_MAX, 0);
	if (eth_dev->data->hash_mac_addrs == NULL) {
		LOG_ERROR("uta table allocate %u B fail.",
			RTE_ETHER_ADDR_LEN * SXE_UTA_ENTRY_NUM_MAX);
		ret = -ENOMEM;
		goto l_free_mac_addr;
	}

	adapter->mac_filter_ctxt.uc_addr_table = rte_zmalloc("sxe",
		sizeof(struct sxe_uc_addr_table) * SXE_UC_ENTRY_NUM_MAX, 0);
	if (adapter->mac_filter_ctxt.uc_addr_table == NULL) {
		LOG_ERROR("uc table allocate %u B fail.",
			sizeof(struct sxe_uc_addr_table) * SXE_UC_ENTRY_NUM_MAX);
		ret = -ENOMEM;
		goto l_free_hash_mac;
	}

	sxe_default_mac_addr_get(adapter);

	rte_ether_addr_copy(&adapter->mac_filter_ctxt.def_mac_addr,
				eth_dev->data->mac_addrs);

	rte_ether_addr_copy(&adapter->mac_filter_ctxt.def_mac_addr,
				&adapter->mac_filter_ctxt.cur_mac_addr);

	rar_idx = sxe_sw_uc_entry_add(eth_dev, 0, adapter->mac_filter_ctxt.def_mac_addr.addr_bytes);

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SRIOV
	sxe_hw_uc_addr_add(hw, rar_idx,
			adapter->mac_filter_ctxt.def_mac_addr.addr_bytes,
			sxe_vf_num_get(eth_dev));
#else
	sxe_hw_uc_addr_add(hw, rar_idx,
		adapter->mac_filter_ctxt.def_mac_addr.addr_bytes,
		0);
#endif

l_out:
	return ret;

l_free_hash_mac:
	rte_free(eth_dev->data->hash_mac_addrs);
	eth_dev->data->hash_mac_addrs = NULL;

l_free_mac_addr:
	rte_free(eth_dev->data->mac_addrs);
	eth_dev->data->mac_addrs = NULL;
	goto l_out;
}

s32 sxe_mac_addr_add(struct rte_eth_dev *dev,
				 struct rte_ether_addr *mac_addr,
				 u32 index, u32 pool)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	s32 ret;
	u8 *addr;
	u8 rar_idx = sxe_sw_uc_entry_add(dev, index, mac_addr->addr_bytes);

	UNUSED(pool);
	ret = sxe_hw_uc_addr_add(hw, rar_idx,
					mac_addr->addr_bytes, sxe_vf_num_get(dev));

	addr = mac_addr->addr_bytes;
	if (ret) {
		LOG_ERROR("rar_idx:%u pool:%u mac_addr:" RTE_ETHER_ADDR_PRT_FMT "add fail.(err:%d)",
				rar_idx, pool,
				addr[0], addr[1], addr[2], addr[3],
				addr[4], addr[5], ret);
		goto l_out;
	}

	sxe_hw_mac_reuse_add(dev, mac_addr->addr_bytes, rar_idx);

	sxe_vf_promisc_mac_update(dev, rar_idx);

	PMD_LOG_INFO(DRV, "rar_idx:%u pool:%u mac_addr:" RTE_ETHER_ADDR_PRT_FMT " add done",
			rar_idx, sxe_vf_num_get(dev),
			addr[0], addr[1], addr[2],
			addr[3], addr[4], addr[5]);

l_out:
	return ret;
}

void sxe_mac_addr_remove(struct rte_eth_dev *dev, u32 index)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	s32 ret;
	u8 rar_idx = sxe_sw_uc_entry_del(adapter, index);
	u8 *mac_addr;
	u8 pool_idx;

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SRIOV
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(dev);

	pool_idx = pci_dev->max_vfs;
#else
	pool_idx = 0;
#endif

	ret = sxe_hw_uc_addr_del(hw, rar_idx);
	if (ret) {
		PMD_LOG_ERR(DRV, "rar_idx:%u remove fail.(err:%d)",
				rar_idx, ret);
		return;
	}

	mac_addr = dev->data->mac_addrs[rar_idx].addr_bytes;
	sxe_hw_mac_reuse_del(dev, dev->data->mac_addrs[rar_idx].addr_bytes,
			pool_idx, rar_idx);

	sxe_vf_promisc_mac_update_all(dev);

	PMD_LOG_INFO(DRV, "rar_idx:%u mac_addr:" RTE_ETHER_ADDR_PRT_FMT " remove done",
			rar_idx,
			mac_addr[0], mac_addr[1], mac_addr[2],
			mac_addr[3], mac_addr[4], mac_addr[5]);
}

void sxe_fc_mac_addr_set(struct sxe_adapter *adapter)
{
	struct sxe_hw *hw = &adapter->hw;

	sxe_hw_fc_mac_addr_set(hw,
			adapter->mac_filter_ctxt.fc_mac_addr.addr_bytes);
}

s32 sxe_mac_addr_set(struct rte_eth_dev *dev,
				 struct rte_ether_addr *mac_addr)
{
	u8 pool_idx;
	struct sxe_adapter *adapter = dev->data->dev_private;
	u8 *addr = mac_addr->addr_bytes;

	sxe_mac_addr_remove(dev, 0);

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SRIOV
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(dev);

	pool_idx = pci_dev->max_vfs;
#else
	pool_idx = 0;
#endif

	sxe_mac_addr_add(dev, mac_addr, 0, pool_idx);
	rte_ether_addr_copy(mac_addr, &adapter->mac_filter_ctxt.fc_mac_addr);

	sxe_fc_mac_addr_set(adapter);

	PMD_LOG_INFO(DRV, "pool:%u mac_addr:" RTE_ETHER_ADDR_PRT_FMT " set to be cur mac addr done",
			pool_idx, addr[0], addr[1], addr[2],
			addr[3], addr[4], addr[5]);

	return 0;
}

static void sxe_hash_mac_addr_parse(u8 *mac_addr, u16 *reg_idx,
						u16 *bit_idx)
{
	u16 extracted;

	extracted = ((mac_addr[4] >> 4) |
			(((u16)mac_addr[5]) << 4));

	extracted &= SXE_MAC_ADDR_EXTRACT_MASK;

	*reg_idx = (extracted >> SXE_MAC_ADDR_SHIFT) & SXE_MAC_ADDR_REG_MASK;

	*bit_idx = extracted & SXE_MAC_ADDR_BIT_MASK;

	PMD_LOG_DEBUG(DRV, "mac_addr:" RTE_ETHER_ADDR_PRT_FMT " hash reg_idx:%u bit_idx:%u",
			 mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3],
			 mac_addr[4], mac_addr[5], *reg_idx, *bit_idx);
}

s32 sxe_vlan_filter_set(struct rte_eth_dev *eth_dev, u16 vlan_id, s32 on)
{
	struct sxe_adapter *adapter = eth_dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	struct sxe_vlan_context *vlan_ctxt = &adapter->vlan_ctxt;
	u8 reg_idx;
	u8 bit_idx;
	u32 value;

	reg_idx = (vlan_id >> SXE_VLAN_ID_SHIFT) & SXE_VLAN_ID_REG_MASK;
	bit_idx = (vlan_id & SXE_VLAN_ID_BIT_MASK);

	value = sxe_hw_vlan_filter_array_read(hw, reg_idx);
	if (on)
		value |= (1 << bit_idx);
	else
		value &= ~(1 << bit_idx);

	sxe_hw_vlan_filter_array_write(hw, reg_idx, value);

	vlan_ctxt->vlan_hash_table[reg_idx] = value;

	PMD_LOG_INFO(DRV, "vlan_id:0x%x on:%d set done", vlan_id, on);

	return 0;
}

static void sxe_vlan_tpid_write(struct sxe_hw *hw, u16 tpid)
{
	u32 value;

	value = sxe_hw_vlan_type_get(hw);
	value = (value & (~SXE_VLNCTRL_VET)) | tpid;
	sxe_hw_vlan_type_set(hw, value);

	value = sxe_hw_txctl_vlan_type_get(hw);
	value = (value & (~SXE_DMATXCTL_VT_MASK)) |
		(tpid << SXE_DMATXCTL_VT_SHIFT);
	sxe_hw_txctl_vlan_type_set(hw, value);
}

s32 sxe_vlan_tpid_set(struct rte_eth_dev *eth_dev,
			enum rte_vlan_type vlan_type, u16 tpid)
{
	struct sxe_adapter *adapter = eth_dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	s32 ret = 0;
	u32 txctl;
	bool double_vlan;

	txctl = sxe_hw_txctl_vlan_type_get(hw);
	double_vlan = txctl & SXE_DMATXCTL_GDV;

	switch (vlan_type) {
	case RTE_ETH_VLAN_TYPE_INNER:
		if (double_vlan) {
			sxe_vlan_tpid_write(hw, tpid);
		} else {
			ret = -ENOTSUP;
			PMD_LOG_ERR(DRV, "unsupported inner vlan without "
					 "global double vlan.");
		}
		break;
	case RTE_ETH_VLAN_TYPE_OUTER:
		if (double_vlan) {
			sxe_hw_vlan_ext_type_set(hw,
				(tpid << SXE_EXVET_VET_EXT_SHIFT));
		} else {
			sxe_vlan_tpid_write(hw, tpid);
		}
		break;
	default:
		ret = -EINVAL;
		PMD_LOG_ERR(DRV, "unsupported VLAN type %d", vlan_type);
		break;
	}

	PMD_LOG_INFO(DRV, "double_vlan:%d vlan_type:%d tpid:0x%x set done ret:%d",
			   double_vlan, vlan_type, tpid, ret);
	return ret;
}

static void sxe_vlan_strip_bitmap_set(struct rte_eth_dev *dev, u16 queue_idx, bool on)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_vlan_context *vlan_ctxt = &adapter->vlan_ctxt;

	sxe_rx_queue_s *rxq;

	if (queue_idx >= SXE_HW_TXRX_RING_NUM_MAX ||
		queue_idx >= dev->data->nb_rx_queues) {
		PMD_LOG_ERR(DRV, "invalid queue idx:%u exceed max"
			   " queue number:%u or nb_rx_queues:%u.",
			   queue_idx, SXE_HW_TXRX_RING_NUM_MAX,
			   dev->data->nb_rx_queues);
		return;
	}

	if (on)
		SXE_STRIP_BITMAP_SET(vlan_ctxt, queue_idx);
	else
		SXE_STRIP_BITMAP_CLEAR(vlan_ctxt, queue_idx);

	rxq = dev->data->rx_queues[queue_idx];

	if (on) {
		rxq->vlan_flags = RTE_MBUF_F_RX_VLAN | RTE_MBUF_F_RX_VLAN_STRIPPED;
		rxq->offloads |= RTE_ETH_RX_OFFLOAD_VLAN_STRIP;
	} else {
		rxq->vlan_flags = RTE_MBUF_F_RX_VLAN;
		rxq->offloads &= ~RTE_ETH_RX_OFFLOAD_VLAN_STRIP;
	}

	PMD_LOG_INFO(DRV, "queue idx:%u vlan strip on:%d set bitmap and offload done.",
			 queue_idx, on);
}

void sxe_vlan_strip_switch_set(struct rte_eth_dev *dev)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	u16 i;
	sxe_rx_queue_s *rxq;
	bool on;

	PMD_INIT_FUNC_TRACE();

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rxq = dev->data->rx_queues[i];

		if (rxq->offloads & RTE_ETH_RX_OFFLOAD_VLAN_STRIP)
			on = true;
		else
			on = false;
		sxe_hw_vlan_tag_strip_switch(hw, i, on);

		sxe_vlan_strip_bitmap_set(dev, i, on);
	}
}

static void sxe_vlan_filter_disable(struct rte_eth_dev *dev)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;

	PMD_INIT_FUNC_TRACE();

	sxe_hw_vlan_filter_switch(hw, 0);
}

static void sxe_vlan_filter_enable(struct rte_eth_dev *dev)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	struct sxe_vlan_context *vlan_ctxt = &adapter->vlan_ctxt;
	u32 vlan_ctl;
	u16 i;

	PMD_INIT_FUNC_TRACE();

	vlan_ctl = sxe_hw_vlan_type_get(hw);
	vlan_ctl &= ~SXE_VLNCTRL_CFI;
	vlan_ctl |= SXE_VLNCTRL_VFE;
	sxe_hw_vlan_type_set(hw, vlan_ctl);

	for (i = 0; i < SXE_VFT_TBL_SIZE; i++)
		sxe_hw_vlan_filter_array_write(hw, i, vlan_ctxt->vlan_hash_table[i]);
}

static void sxe_vlan_extend_disable(struct rte_eth_dev *dev)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	u32 ctrl;

	PMD_INIT_FUNC_TRACE();

	ctrl = sxe_hw_txctl_vlan_type_get(hw);
	ctrl &= ~SXE_DMATXCTL_GDV;
	sxe_hw_txctl_vlan_type_set(hw, ctrl);

	ctrl = sxe_hw_ext_vlan_get(hw);
	ctrl &= ~SXE_EXTENDED_VLAN;
	sxe_hw_ext_vlan_set(hw, ctrl);
}

static void sxe_vlan_extend_enable(struct rte_eth_dev *dev)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	u32 ctrl;

	PMD_INIT_FUNC_TRACE();

	ctrl = sxe_hw_txctl_vlan_type_get(hw);
	ctrl |= SXE_DMATXCTL_GDV;
	sxe_hw_txctl_vlan_type_set(hw, ctrl);

	ctrl = sxe_hw_ext_vlan_get(hw);
	ctrl |= SXE_EXTENDED_VLAN;
	sxe_hw_ext_vlan_set(hw, ctrl);
}

static s32 sxe_vlan_offload_configure(struct rte_eth_dev *dev, s32 mask)
{
	struct rte_eth_rxmode *rxmode = &dev->data->dev_conf.rxmode;

	if (mask & RTE_ETH_VLAN_STRIP_MASK)
		sxe_vlan_strip_switch_set(dev);

	if (mask & RTE_ETH_VLAN_FILTER_MASK) {
		if (rxmode->offloads & RTE_ETH_RX_OFFLOAD_VLAN_FILTER)
			sxe_vlan_filter_enable(dev);
		else
			sxe_vlan_filter_disable(dev);
	}

	if (mask & RTE_ETH_VLAN_EXTEND_MASK) {
		if (rxmode->offloads & RTE_ETH_RX_OFFLOAD_VLAN_EXTEND)
			sxe_vlan_extend_enable(dev);
		else
			sxe_vlan_extend_disable(dev);
	}

	PMD_LOG_INFO(DRV, "mask:0x%x rx mode offload:0x%" SXE_PRIX64
			 " vlan offload set done", mask, rxmode->offloads);

	return 0;
}

s32 sxe_vlan_offload_set(struct rte_eth_dev *dev, s32 vlan_mask)
{
	s32 mask;
	s32 ret = 0;

	if (vlan_mask & RTE_ETH_VLAN_STRIP_MASK) {
		PMD_LOG_WARN(DRV, "please set vlan strip before device start, not at this stage.");
		ret = -1;
		goto l_out;
	}
	mask = vlan_mask & ~RTE_ETH_VLAN_STRIP_MASK;

	sxe_vlan_offload_configure(dev, mask);

	PMD_LOG_INFO(DRV, "vlan offload mask:0x%x set done.", vlan_mask);

l_out:
	return ret;
}

void sxe_vlan_strip_queue_set(struct rte_eth_dev *dev, u16 queue, s32 on)
{
	UNUSED(dev);
	UNUSED(queue);
	UNUSED(on);
	PMD_LOG_WARN(DRV, "please set vlan strip before device start, not at this stage.");
}

void sxe_vlan_filter_configure(struct rte_eth_dev *dev)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	u32 vlan_mask;
	u32 vlan_ctl;

	vlan_mask = RTE_ETH_VLAN_STRIP_MASK | RTE_ETH_VLAN_FILTER_MASK |
			RTE_ETH_VLAN_EXTEND_MASK;
	sxe_vlan_offload_configure(dev, vlan_mask);

	if (dev->data->dev_conf.rxmode.mq_mode == RTE_ETH_MQ_RX_VMDQ_ONLY) {
		vlan_ctl = sxe_hw_vlan_type_get(hw);
		vlan_ctl |= SXE_VLNCTRL_VFE;
		sxe_hw_vlan_type_set(hw, vlan_ctl);
		LOG_DEBUG_BDF("vmdq mode enable vlan filter done.");
	}
}

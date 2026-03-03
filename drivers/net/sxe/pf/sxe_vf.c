/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */
#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SRIOV

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_memcpy.h>
#include <ethdev_driver.h>
#include <ethdev_pci.h>
#include <bus_pci_driver.h>
#include "sxe_logs.h"
#include "sxe_vf.h"
#include "sxe_hw.h"
#include "sxe.h"
#include "sxe_errno.h"
#include "sxe_filter.h"
#include "sxe_offload.h"
#include "sxe_ethdev.h"
#include "sxe_rx.h"
#include "rte_pmd_sxe.h"

#define SXE_MR_VLAN_MASK  0xFFFFFFFF
#define SXE_MR_VLAN_MSB_BIT_OFFSET 32

#define SXE_MR_VIRTUAL_POOL_MASK		 0xFFFFFFFF
#define SXE_MR_VIRTUAL_POOL_MSB_BIT_MASK 32

#define SXE_UC_MAC_UNSET 0
#define SXE_UC_MAC_SET 1

static inline s32 sxe_vf_mac_addr_generate(struct rte_eth_dev *eth_dev, u16 vf_num)
{
	u8 vf_mac_addr[RTE_ETHER_ADDR_LEN];
	struct sxe_adapter *adapter = eth_dev->data->dev_private;
	struct sxe_vf_info *vf_info = adapter->vt_ctxt.vf_info;
	u16 idx;

	for (idx = 0; idx < vf_num; idx++) {
		rte_eth_random_addr(vf_mac_addr);
		memcpy(vf_info[idx].mac_addr, vf_mac_addr, RTE_ETHER_ADDR_LEN);
	}

	return 0;
}

static void sxe_vt_mode_configure(struct rte_eth_dev *eth_dev)
{
	struct sxe_adapter *adapter = eth_dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	u32 gpie;
	u32 pcie_ext;

	pcie_ext = sxe_hw_pcie_vt_mode_get(hw);
	pcie_ext &= ~SXE_GCR_EXT_VT_MODE_MASK;

	gpie = sxe_hw_irq_general_reg_get(hw);
	gpie &= ~SXE_GPIE_VTMODE_MASK;
	gpie |= SXE_GPIE_MSIX_MODE;

	switch (RTE_ETH_DEV_SRIOV(eth_dev).active) {
	case RTE_ETH_64_POOLS:
		pcie_ext |= SXE_GCR_EXT_VT_MODE_64;
		gpie |= SXE_GPIE_VTMODE_64;
		break;
	case RTE_ETH_32_POOLS:
		pcie_ext |= SXE_GCR_EXT_VT_MODE_32;
		gpie |= SXE_GPIE_VTMODE_32;
		break;
	case RTE_ETH_16_POOLS:
		pcie_ext |= SXE_GCR_EXT_VT_MODE_16;
		gpie |= SXE_GPIE_VTMODE_16;
		break;
	}

	sxe_hw_pcie_vt_mode_set(hw, pcie_ext);
	sxe_hw_irq_general_reg_set(hw, gpie);
}

s32 sxe_vt_init(struct rte_eth_dev *eth_dev)
{
	struct sxe_adapter *adapter = eth_dev->data->dev_private;
	struct sxe_vf_info **vf_info = &adapter->vt_ctxt.vf_info;
	struct sxe_hw *hw = &adapter->hw;
	struct sxe_irq_context *irq = &adapter->irq_ctxt;
	u16 vf_num;
	s32 ret = 0;
	u8 nb_queue;

	PMD_INIT_FUNC_TRACE();

	RTE_ETH_DEV_SRIOV(eth_dev).active = 0;
	/* get vf num from max_vfs or sriov_numvfs */
	vf_num = sxe_vf_num_get(eth_dev);
	if (vf_num == 0) {
		LOG_WARN_BDF("no vf, no need init vt");
		goto l_out;
	}

	*vf_info = rte_zmalloc("vf_info", sizeof(struct sxe_vf_info) * vf_num, 0);
	if (*vf_info == NULL) {
		LOG_WARN_BDF("vf_info allocate memory fail.");
		ret = -ENOMEM;
		goto l_out;
	}

	ret = rte_eth_switch_domain_alloc(&(*vf_info)->domain_id);
	if (ret) {
		LOG_ERROR_BDF("failed to allocate switch domain for device %d", ret);
		goto l_free_vf_info;
	}

	if (vf_num >= RTE_ETH_32_POOLS) {
		nb_queue = 2;
		RTE_ETH_DEV_SRIOV(eth_dev).active = RTE_ETH_64_POOLS;
	} else if (vf_num >= RTE_ETH_16_POOLS) {
		nb_queue = 4;
		RTE_ETH_DEV_SRIOV(eth_dev).active = RTE_ETH_32_POOLS;
	} else {
		nb_queue = 8;
		RTE_ETH_DEV_SRIOV(eth_dev).active = RTE_ETH_16_POOLS;
	}

	RTE_ETH_DEV_SRIOV(eth_dev).nb_q_per_pool = nb_queue;
	RTE_ETH_DEV_SRIOV(eth_dev).def_vmdq_idx = vf_num;
	RTE_ETH_DEV_SRIOV(eth_dev).def_pool_q_idx = (u16)(vf_num * nb_queue);

	sxe_vf_mac_addr_generate(eth_dev, vf_num);

	sxe_hw_mbx_init(hw);

	irq->enable_mask |= SXE_EIMS_MAILBOX;

	adapter->vt_ctxt.promisc_cnt = 0;

	sxe_vt_mode_configure(eth_dev);

	LOG_INFO_BDF("vf_num:%d domain id:%u init done.",
			  vf_num, (*vf_info)->domain_id);

l_out:
	return ret;

l_free_vf_info:
	rte_free(*vf_info);
	*vf_info = NULL;
	return ret;
}

static void sxe_pf_pool_enable(struct rte_eth_dev *eth_dev, u16 vf_num)
{
	struct sxe_adapter *adapter = eth_dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	u32 enable_mask = ~0;
	u8 vf_reg_idx = ((vf_num >> 5) > 0) ? 1 : 0;
	u8 vf_bit_index = vf_num & ((1 << 5) - 1);

	sxe_hw_rx_pool_bitmap_set(hw, vf_reg_idx, enable_mask << vf_bit_index);
	sxe_hw_rx_pool_bitmap_set(hw, (vf_reg_idx ^ 1), (vf_reg_idx - 1));

	sxe_hw_tx_pool_bitmap_set(hw, vf_reg_idx, enable_mask << vf_bit_index);
	sxe_hw_tx_pool_bitmap_set(hw, (vf_reg_idx ^ 1), (vf_reg_idx - 1));
}

static void sxe_vf_vlan_filter_enable(struct rte_eth_dev *eth_dev)
{
	struct sxe_adapter *adapter = eth_dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	u32 enable_mask = ~0;
	u32 vlan_ctl;
	u8 i;

	vlan_ctl = sxe_hw_vlan_type_get(hw);
	vlan_ctl |= SXE_VLNCTRL_VFE;
	sxe_hw_vlan_type_set(hw, vlan_ctl);

	for (i = 0; i < SXE_VFT_TBL_SIZE; i++)
		sxe_hw_vlan_filter_array_write(hw, i, enable_mask);
}

static void sxe_uc_mac_table_init(struct rte_eth_dev *eth_dev)
{
	struct sxe_adapter *adapter = eth_dev->data->dev_private;
	struct sxe_vf_info *vf_info = adapter->vt_ctxt.vf_info;
	u8 vf_num = sxe_vf_num_get(eth_dev);
	u8 i;

	for (i = 0; i < vf_num; i++)
		memset(vf_info[i].uc_mac_table, SXE_UC_MAC_UNSET, SXE_UC_ENTRY_NUM_MAX);
}

void sxe_vt_configure(struct rte_eth_dev *eth_dev)
{
	struct sxe_adapter *adapter = eth_dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	u16 vf_num;
	u16 pf_pool_idx = RTE_ETH_DEV_SRIOV(eth_dev).def_vmdq_idx;

	vf_num = sxe_vf_num_get(eth_dev);
	if (vf_num == 0) {
		LOG_WARN_BDF("no vf, no need configure vt");
		return;
	}

	sxe_hw_vt_ctrl_cfg(hw, pf_pool_idx);

	sxe_pf_pool_enable(eth_dev, vf_num);

	sxe_hw_vt_pool_loopback_switch(hw, true);

	sxe_hw_mac_pool_clear(hw, 0);
	sxe_hw_mac_pool_clear(hw, SXE_UC_ENTRY_NUM_MAX - 1);

	sxe_hw_uc_addr_pool_enable(hw, 0, pf_pool_idx);

	sxe_vt_mode_configure(eth_dev);

	sxe_vf_vlan_filter_enable(eth_dev);

	sxe_hw_pool_mac_anti_spoof_set(hw, vf_num, 0);

	sxe_uc_mac_table_init(eth_dev);

	sxe_rx_fc_threshold_set(hw);
}

void sxe_vt_uninit(struct rte_eth_dev *eth_dev)
{
	struct sxe_adapter *adapter = eth_dev->data->dev_private;
	struct sxe_vf_info **vf_info = &adapter->vt_ctxt.vf_info;
	u16 vf_num;
	int ret;

	PMD_INIT_FUNC_TRACE();

	RTE_ETH_DEV_SRIOV(eth_dev).active = 0;
	RTE_ETH_DEV_SRIOV(eth_dev).nb_q_per_pool = 0;
	RTE_ETH_DEV_SRIOV(eth_dev).def_vmdq_idx = 0;
	RTE_ETH_DEV_SRIOV(eth_dev).def_pool_q_idx = 0;

	vf_num = sxe_vf_num_get(eth_dev);
	if (vf_num == 0 || (*vf_info) == NULL) {
		LOG_INFO_BDF("vf_num:%u vf_info:%p, no need free vf_info.",
				 vf_num, *vf_info);
		return;
	}

	ret = rte_eth_switch_domain_free((*vf_info)->domain_id);
	if (ret)
		LOG_ERROR_BDF("failed to free switch domain: %d", ret);

	rte_free(*vf_info);
	*vf_info = NULL;
}

s32 sxe_vf_rss_configure(struct rte_eth_dev *dev)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	bool is_4q_per_pool;
	s32 ret = 0;

	sxe_rss_configure(dev);

	switch (RTE_ETH_DEV_SRIOV(dev).active) {
	case RTE_ETH_64_POOLS:
		is_4q_per_pool = false;
		break;

	case RTE_ETH_32_POOLS:
		is_4q_per_pool = true;
		break;

	default:
		ret = -EINVAL;
		LOG_ERROR_BDF("invalid pool number:%u in iov mode with rss.(err:%d)",
				  RTE_ETH_DEV_SRIOV(dev).active, ret);
		goto l_out;
	}

	sxe_hw_rx_multi_ring_configure(hw, 0, is_4q_per_pool, true);

	LOG_INFO_BDF("pool num:%u is_4q_per_pool:%u configure done.",
			RTE_ETH_DEV_SRIOV(dev).active, is_4q_per_pool);

l_out:
	return ret;
}

s32 sxe_vf_default_mode_configure(struct rte_eth_dev *dev)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	s32 ret = 0;
	u8 tcs = 0;
	bool is_4q_per_pool = false;

	switch (RTE_ETH_DEV_SRIOV(dev).active) {
	case RTE_ETH_64_POOLS:
		is_4q_per_pool = false;
		break;

	case RTE_ETH_32_POOLS:
		is_4q_per_pool = true;
		break;

	case RTE_ETH_16_POOLS:
		tcs = 8;
		break;
	default:
		ret = -SXE_ERR_CONFIG;
		LOG_ERROR_BDF("invalid pool number:%u (err:%d)",
				  RTE_ETH_DEV_SRIOV(dev).active, ret);
		goto l_out;
	}

	sxe_hw_rx_multi_ring_configure(hw, tcs, is_4q_per_pool, true);

l_out:
	return ret;
}

static void sxe_filter_mode_configure(struct rte_eth_dev *dev)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	u16 vf_num = sxe_vf_num_get(dev);
	u32 filter_ctrl = sxe_hw_rx_mode_get(hw);
	u32 vm_l2_ctrl = SXE_VMOLR_AUPE | SXE_VMOLR_BAM;

	filter_ctrl &= ~(SXE_FCTRL_SBP | SXE_FCTRL_UPE | SXE_FCTRL_MPE);

	filter_ctrl |= SXE_FCTRL_BAM;

	if (dev->data->promiscuous) {
		filter_ctrl |= (SXE_FCTRL_UPE | SXE_FCTRL_MPE);
		vm_l2_ctrl |= (SXE_VMOLR_ROPE | SXE_VMOLR_MPE);
	} else {
		if (dev->data->all_multicast) {
			filter_ctrl |= SXE_FCTRL_MPE;
			vm_l2_ctrl |= SXE_VMOLR_MPE;
		} else {
			vm_l2_ctrl |= SXE_VMOLR_ROMPE;
		}
	}

	vm_l2_ctrl |= sxe_hw_pool_rx_mode_get(hw, vf_num) &
			~(SXE_VMOLR_MPE | SXE_VMOLR_ROMPE | SXE_VMOLR_ROPE);

	sxe_hw_pool_rx_mode_set(hw, vm_l2_ctrl, vf_num);

	sxe_hw_rx_mode_set(hw, filter_ctrl);

	sxe_vlan_strip_switch_set(dev);
}

static inline void sxe_vf_flr_handle(struct rte_eth_dev *dev, u16 vf)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	struct sxe_vf_info *vf_info = adapter->vt_ctxt.vf_info;
	u32 vm_l2_ctrl = sxe_hw_pool_rx_mode_get(hw, vf);

	sxe_sw_uc_entry_vf_del(adapter, vf, false);

	vm_l2_ctrl |= (SXE_VMOLR_AUPE | SXE_VMOLR_ROPE | SXE_VMOLR_BAM);

	sxe_hw_pool_rx_mode_set(hw, vm_l2_ctrl, vf);

	sxe_hw_tx_vlan_tag_clear(hw, vf);

	vf_info[vf].mc_hash_used = 0;

	sxe_filter_mode_configure(dev);
}

static void sxe_vf_promisc_mac_update(struct rte_eth_dev *dev, u32 vf,
		u32 rar_idx)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_vf_info *vf_info = adapter->vt_ctxt.vf_info;
	u16 vf_num = sxe_vf_num_get(dev);
	u8 vf_idx;

	for (vf_idx = 0; vf_idx < vf_num; vf_idx++) {
		if (vf_info[vf_idx].cast_mode == SXE_CAST_MODE_PROMISC &&
				vf_idx != vf)
			sxe_hw_uc_addr_pool_enable(&adapter->hw, rar_idx, vf_idx);
	}
}

static void sxe_vf_promisc_mac_update_all(struct rte_eth_dev *dev)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_vf_info *vf_info = adapter->vt_ctxt.vf_info;
	struct sxe_uc_addr_table *uc_table = adapter->mac_filter_ctxt.uc_addr_table;
	s32 i;
	u16 vf_num = sxe_vf_num_get(dev);
	u8 vf_idx;

	for (vf_idx = 0; vf_idx < vf_num; vf_idx++) {
		if (vf_info[vf_idx].cast_mode == SXE_CAST_MODE_PROMISC) {
			for (i = 0; i < SXE_UC_ENTRY_NUM_MAX; i++) {
				if (uc_table[i].used) {
					sxe_hw_uc_addr_pool_enable(&adapter->hw,
						uc_table[i].rar_idx, vf_idx);
				}
			}
		}
	}
}

static void sxe_vf_uc_clean(struct rte_eth_dev *dev, u32 vf)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_uc_addr_table *uc_table = adapter->mac_filter_ctxt.uc_addr_table;
	struct sxe_vf_info *vf_info = &adapter->vt_ctxt.vf_info[vf];
	u8 i;

	sxe_sw_uc_entry_vf_del(adapter, vf, true);
	for (i = 0; i < SXE_UC_ENTRY_NUM_MAX; i++) {
		if (vf_info->uc_mac_table[i] == SXE_UC_MAC_SET)
			sxe_hw_mac_reuse_del(dev, uc_table[i].addr, vf,
					uc_table[i].rar_idx);
	}
	vf_info->uc_mac_cnt = 0;
	memset(vf_info->uc_mac_table, SXE_UC_MAC_UNSET, SXE_UC_ENTRY_NUM_MAX);
	sxe_vf_promisc_mac_update_all(dev);
}

static s32 sxe_vf_dev_mac_addr_set_handler(struct rte_eth_dev *dev, u32 *msgbuf, u32 vf)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_uc_addr_msg mac_msg = *(struct sxe_uc_addr_msg *)msgbuf;
	struct sxe_vf_info *vf_info = adapter->vt_ctxt.vf_info;
	u32 rar_idx = sxe_sw_uc_entry_vf_add(adapter, vf, mac_msg.uc_addr, false);
	s32 ret = -SXE_ERR_PARAM;
	u8 *mac_addr = mac_msg.uc_addr;

	UNUSED(mac_addr);
	if (rte_is_valid_assigned_ether_addr((struct rte_ether_addr *)mac_msg.uc_addr)) {
		rte_memcpy(vf_info[vf].mac_addr, mac_msg.uc_addr, RTE_ETHER_ADDR_LEN);
		ret = sxe_hw_uc_addr_add(&adapter->hw, rar_idx, mac_msg.uc_addr, vf);
		if (ret) {
			LOG_ERROR_BDF("vf:%u mac addr:" RTE_ETHER_ADDR_PRT_FMT " set fail.(err:%d)",
					  vf, mac_addr[0], mac_addr[1], mac_addr[2],
					  mac_addr[3], mac_addr[4], mac_addr[5], ret);
		}
		sxe_vf_promisc_mac_update(dev, vf, rar_idx);
	}

	return ret;
}

static s32 sxe_mbx_api_set_handler(struct rte_eth_dev *dev,
							u32 *msg, u32 vf_idx)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_mbx_api_msg *api_msg = (struct sxe_mbx_api_msg *)msg;
	struct sxe_vf_info *vf_info = &adapter->vt_ctxt.vf_info[vf_idx];
	s32 ret = 0;

	switch (api_msg->api_version) {
	case SXE_MBX_API_10:
	case SXE_MBX_API_11:
	case SXE_MBX_API_12:
	case SXE_MBX_API_13:
		vf_info->mbx_version = api_msg->api_version;
		break;
	default:
		ret = -SXE_ERR_PARAM;
		LOG_ERROR_BDF("invalid mailbox api version:%u.",
			  api_msg->api_version);
		break;
	}

	LOG_INFO_BDF("mailbox api version:0x%x.(err:%d)",
					vf_info->mbx_version, ret);

	return ret;
}

static s32 sxe_pf_ring_info_get(struct rte_eth_dev *dev, u32 *msgbuf, u32 vf)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	struct sxe_vf_info *vf_info = &adapter->vt_ctxt.vf_info[vf];
	struct sxe_ring_info_msg *ring_msg = (struct sxe_ring_info_msg *)msgbuf;
	u32 default_q = vf * RTE_ETH_DEV_SRIOV(dev).nb_q_per_pool;
	struct rte_eth_vmdq_dcb_tx_conf *vmdq_dcb_tx_conf;
	u8 num_tcs;
	u32 vmvir;
	u32 vlan_action;
	u32 vlan_id;
	u32 user_priority;
	s32 ret = 0;

	switch (vf_info->mbx_version) {
	case SXE_MBX_API_11:
	case SXE_MBX_API_12:
	case SXE_MBX_API_13:
		break;
	default:
		ret = -SXE_ERR_CONFIG;
		LOG_ERROR_BDF("mailbod version:0x%x not support get ring"
				  " info.(err:%d)",
				  vf_info->mbx_version, ret);
		goto l_out;
	}

	ring_msg->max_rx_num = RTE_ETH_DEV_SRIOV(dev).nb_q_per_pool;
	ring_msg->max_tx_num  = RTE_ETH_DEV_SRIOV(dev).nb_q_per_pool;

	ring_msg->default_tc = default_q;

	switch (dev->data->dev_conf.txmode.mq_mode) {
	case RTE_ETH_MQ_TX_NONE:
	case RTE_ETH_MQ_TX_DCB:
		ret = -SXE_ERR_CONFIG;
		LOG_ERROR_BDF("vf_idx:%u sriov eanble, not support tx queue mode:0x%x.",
			vf,
			dev->data->dev_conf.txmode.mq_mode);
		goto l_out;

	case RTE_ETH_MQ_TX_VMDQ_DCB:
		vmdq_dcb_tx_conf = &dev->data->dev_conf.tx_adv_conf.vmdq_dcb_tx_conf;
		switch (vmdq_dcb_tx_conf->nb_queue_pools) {
		case RTE_ETH_16_POOLS:
			num_tcs = RTE_ETH_8_TCS;
			break;
		case RTE_ETH_32_POOLS:
			num_tcs = RTE_ETH_4_TCS;
			break;
		default:
			ret = -SXE_ERR_CONFIG;
			LOG_ERROR_BDF("vf:%u sriov enable, tx queue mode:0x%x "
					  "invalid pool num:%u.(err:%d)",
					vf,
					dev->data->dev_conf.txmode.mq_mode,
					vmdq_dcb_tx_conf->nb_queue_pools,
					ret);
			goto l_out;
		}
		break;

	case RTE_ETH_MQ_TX_VMDQ_ONLY:
		vmvir = sxe_hw_tx_vlan_insert_get(hw, vf);
		vlan_action = vmvir & SXE_VMVIR_VLANA_MASK;
		vlan_id = vmvir & SXE_VMVIR_VLAN_VID_MASK;
		user_priority = (vmvir & SXE_VMVIR_VLAN_UP_MASK) >> VLAN_PRIO_SHIFT;
		if (vlan_action == SXE_VMVIR_VLANA_DEFAULT &&
			(vlan_id !=  0 || user_priority != 0)) {
			num_tcs = 1;
		} else {
			num_tcs = 0;
		}
		break;

	default:
		ret = -SXE_ERR_CONFIG;
		LOG_ERROR_BDF("vf_idx:%u sriov eanble, invalid tx queue mode:0x%x.",
			vf,
			dev->data->dev_conf.txmode.mq_mode);
		goto l_out;
	}

	ring_msg->tc_num = num_tcs;

	LOG_INFO_BDF("max_rx_num:%u max_tx_num:%u default queue:%u tc_num:%u.",
			ring_msg->max_rx_num, ring_msg->max_tx_num,
			ring_msg->default_tc, ring_msg->tc_num);

l_out:
	return ret;
}

static s32 sxe_vf_rss_hash_conf_get(struct rte_eth_dev *dev, u32 *msgbuf, u32 vf)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct rte_eth_rss_conf rss_conf;
	struct sxe_rss_hash_msg *rss_msg = (struct sxe_rss_hash_msg *)msgbuf;

	UNUSED(vf);
	rss_conf.rss_key = malloc(SXE_RSS_KEY_SIZE);
	sxe_rss_hash_conf_get(dev, &rss_conf);

	memcpy(rss_msg->hash_key, rss_conf.rss_key, SXE_RSS_KEY_SIZE);
	rss_msg->rss_hf = rss_conf.rss_hf;

	free(rss_conf.rss_key);

	LOG_INFO_BDF("vf[%u] rss hash conf get, rss_key:%s, rss_hf:%" SXE_PRID64 "",
			vf, rss_msg->hash_key, rss_msg->rss_hf);

	return 0;
}

static s32 sxe_vf_vlan_id_set_handler(struct rte_eth_dev *dev,
						u32 *msgbuf, u32 vf)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	struct sxe_vf_info *vf_info = adapter->vt_ctxt.vf_info;
	struct sxe_vlan_msg *vlan_msg = (struct sxe_vlan_msg *)msgbuf;
	u32 vlan_id = (vlan_msg->vlan_id & SXE_VLVF_VLANID_MASK);
	s32 ret;

	ret = sxe_hw_vlan_filter_configure(hw, vlan_id, vf, vlan_msg->add, false);
	if (ret == 0) {
		if (vlan_msg->add)
			vf_info[vf].vlan_cnt++;
		else if (vf_info[vf].vlan_cnt)
			vf_info[vf].vlan_cnt--;
	}

	LOG_INFO_BDF("vf[%u] %s vid[%u] done vlan_cnt:%u ret = %d",
			vf, vlan_msg->add ? "add" : "delete",
			vlan_id,
			vf_info[vf].vlan_cnt, ret);

	return ret;
}

static s32 sxe_vf_max_frame_set_handler(struct rte_eth_dev *dev,
						u32 *msgbuf, u32 vf)

{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	struct sxe_vf_info *vf_info = &adapter->vt_ctxt.vf_info[vf];
	struct sxe_max_frame_msg *msg = (struct sxe_max_frame_msg *)msgbuf;
	u32 vf_max_frame = msg->max_frame + SXE_ETH_OVERHEAD;
	s32 ret = 0;
	u32 cur_max_frs;
	u32 frame_size = SXE_GET_FRAME_SIZE(dev);

	switch (vf_info->mbx_version) {
	case SXE_MBX_API_11:
	case SXE_MBX_API_12:
	case SXE_MBX_API_13:
		if (frame_size > SXE_ETH_MAX_LEN) {
			LOG_WARN_BDF("pf jumbo frame enabled.");
			break;
		}
		// fall through
	default:
		if (vf_max_frame > SXE_ETH_MAX_LEN ||
			frame_size > SXE_ETH_MAX_LEN) {
			ret = -SXE_ERR_PARAM;
			LOG_ERROR_BDF("mbx version:0x%x pf max pkt len:0x%x vf:%u"
					  " max_frames:0x%x max_len:0x%x.(err:%d)",
					  vf_info->mbx_version,
					  frame_size,
					  vf, vf_max_frame,
					  SXE_ETH_MAX_LEN, ret);
			goto l_out;
		}
		break;
	}

	if (vf_max_frame < RTE_ETHER_MIN_LEN ||
		vf_max_frame > RTE_ETHER_MAX_JUMBO_FRAME_LEN) {
		ret = -SXE_ERR_PARAM;
		LOG_ERROR_BDF("mbx version:0x%x vf:%u invalid max_frame:%u (err:%d)",
				  vf_info->mbx_version,
				  vf,
				  vf_max_frame,
				  ret);
		goto l_out;
	}

	cur_max_frs = sxe_hw_mac_max_frame_get(hw);
	if (vf_max_frame > cur_max_frs) {
		ret = -SXE_ERR_PARAM;
		LOG_ERROR_BDF("mbx version:0x%x vf:%u invalid max_frame:%u >= cur_max_frs:%u",
				  vf_info->mbx_version,
				  vf,
				  vf_max_frame,
				  cur_max_frs);
		goto l_out;
	}

l_out:
	return ret;
}

static void sxe_vf_mc_promisc_disable(struct rte_eth_dev *dev, u32 vf)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	u32 vm_l2_ctrl = sxe_hw_pool_rx_mode_get(hw, vf);

	vm_l2_ctrl &= ~SXE_VMOLR_MPE;

	sxe_hw_pool_rx_mode_set(hw, vm_l2_ctrl, vf);
}

static void sxe_vf_promisc_disable(struct rte_eth_dev *dev, u32 vf)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	struct sxe_vf_info *vf_info = &adapter->vt_ctxt.vf_info[vf];
	u32 disable;
	u32 vm_l2_filter;

	if (vf_info->cast_mode != SXE_CAST_MODE_PROMISC)
		goto out;

	disable = SXE_VMOLR_BAM | SXE_VMOLR_ROMPE |
				SXE_VMOLR_MPE | SXE_VMOLR_ROPE;

	vf_info->cast_mode = SXE_CAST_MODE_NONE;

	vm_l2_filter = sxe_hw_pool_rx_mode_get(hw, vf);
	vm_l2_filter &= ~disable;
	sxe_hw_pool_rx_mode_set(hw, vm_l2_filter, vf);

	adapter->vt_ctxt.promisc_cnt--;
	if (adapter->vt_ctxt.promisc_cnt == 0)
		sxe_uc_all_hash_table_set(dev, false);

out:
	return;
}

static s32 sxe_vf_mc_addr_sync(struct rte_eth_dev *dev,
					u32 *msgbuf, u32 vf)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	struct sxe_vf_info *vf_info = &adapter->vt_ctxt.vf_info[vf];
	struct sxe_mc_sync_msg *mc_msg = (struct sxe_mc_sync_msg *)msgbuf;
	u8 mc_cnt = RTE_MIN(mc_msg->mc_cnt, SXE_VF_MC_ENTRY_NUM_MAX);
	u32 mta_idx;
	u32 mta_shift;
	u32 vm_l2_filter = sxe_hw_pool_rx_mode_get(hw, vf);
	int i;

	sxe_vf_mc_promisc_disable(dev, vf);

	vf_info->mc_hash_used = mc_cnt;
	for (i = 0; i < mc_cnt; i++) {
		vf_info->mc_hash[i] = mc_msg->mc_addr_extract[i];
		LOG_INFO_BDF("vf_idx:%u mc_cnt:%u mc_hash[%d]:0x%x",
				 vf, mc_cnt, i, vf_info->mc_hash[i]);
	}

	if (mc_cnt == 0) {
		vm_l2_filter &= ~SXE_VMOLR_ROMPE;
		sxe_hw_pool_rx_mode_set(hw, vm_l2_filter, vf);
		LOG_WARN_BDF("vf:%u request disable mta filter.", vf);
	} else {
		for (i = 0; i < mc_cnt; i++) {
			mta_idx = (vf_info->mc_hash[i] >> SXE_MC_ADDR_SHIFT) &
				  SXE_MC_ADDR_REG_MASK;
			mta_shift = vf_info->mc_hash[i] & SXE_MC_ADDR_BIT_MASK;
			sxe_hw_mta_hash_table_update(hw, mta_idx, mta_shift);

			LOG_INFO_BDF("vf_idx:%u mc_cnt:%u mc_hash[%d]:0x%x "
				"reg_idx=%u, bit_idx=%u.",
				vf, mc_cnt, i, vf_info->mc_hash[i],
				mta_idx, mta_shift);
		}

		vm_l2_filter |= SXE_VMOLR_ROMPE;
		sxe_hw_pool_rx_mode_set(hw, vm_l2_filter, vf);
		sxe_hw_mc_filter_enable(hw);
	}

	return 0;
}

static void sxe_vf_mac_reuse_rebuild(struct sxe_adapter *adapter,
					u8 rar_idx, u32 vf)
{
	struct sxe_hw *hw = &adapter->hw;
	struct sxe_vf_info *vf_info = &adapter->vt_ctxt.vf_info[vf];
	struct sxe_uc_addr_table *uc_table = adapter->mac_filter_ctxt.uc_addr_table;
	u8 i;

	for (i = 0; i < SXE_UC_ENTRY_NUM_MAX; i++) {
		if (vf_info->uc_mac_table[i] == SXE_UC_MAC_SET &&
				memcmp(uc_table[rar_idx].addr, uc_table[rar_idx].addr,
					SXE_MAC_ADDR_LEN) == 0) {
			sxe_hw_uc_addr_pool_enable(hw, rar_idx, vf);
			break;
		}
	}
}

static s32 sxe_vf_cast_mode_handler(struct rte_eth_dev *dev,
					u32 *msgbuf, u32 vf)

{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	struct sxe_vf_info *vf_info = &adapter->vt_ctxt.vf_info[vf];
	struct sxe_cast_mode_msg *cast_msg = (struct sxe_cast_mode_msg *)msgbuf;
	struct sxe_uc_addr_table *uc_table = adapter->mac_filter_ctxt.uc_addr_table;
	u32 enable;
	u32 disable;
	u32 flt_ctrl = 0;
	u32 vm_l2_filter;
	s32 ret = 0;
	u8 i;
	bool allmulti = false;

	switch (vf_info->mbx_version) {
	case SXE_MBX_API_12:
	case SXE_MBX_API_13:
		break;
	default:
		ret = -SXE_ERR_PARAM;
		LOG_ERROR_BDF("vf:%u invalid mbx api version:0x%x.",
				 vf, vf_info->mbx_version);
		goto l_out;
	}

	if (vf_info->cast_mode == cast_msg->cast_mode) {
		LOG_INFO_BDF("vf:%d currut mode equal set mode:0x%x, skip set.",
				 vf, cast_msg->cast_mode);
		goto l_out;
	}

	switch (cast_msg->cast_mode) {
	case SXE_CAST_MODE_NONE:
		disable = SXE_VMOLR_BAM | SXE_VMOLR_ROMPE |
				SXE_VMOLR_MPE | SXE_VMOLR_ROPE;
		enable = 0;
		break;

	case SXE_CAST_MODE_MULTI:
		disable = SXE_VMOLR_MPE | SXE_VMOLR_ROPE;
		enable = SXE_VMOLR_BAM | SXE_VMOLR_ROMPE;
		break;

	case SXE_CAST_MODE_ALLMULTI:
		disable = SXE_VMOLR_ROPE;
		enable = SXE_VMOLR_BAM | SXE_VMOLR_ROMPE |
					SXE_VMOLR_MPE;
		allmulti = true;
		break;

	case SXE_CAST_MODE_PROMISC:
		disable = 0;
		enable = SXE_VMOLR_MPE | SXE_VMOLR_ROPE |
					SXE_VMOLR_BAM | SXE_VMOLR_ROMPE;
		allmulti = true;
		break;

	default:
		ret = -SXE_ERR_PARAM;
		LOG_ERROR_BDF("vf:%u invalid cast mode:0x%x.",
				vf, cast_msg->cast_mode);
		goto l_out;
	}

	vm_l2_filter = sxe_hw_pool_rx_mode_get(hw, vf);
	vm_l2_filter &= ~disable;
	vm_l2_filter |= enable;
	sxe_hw_pool_rx_mode_set(hw, vm_l2_filter, vf);

	if (allmulti) {
		flt_ctrl = sxe_hw_rx_mode_get(hw) | SXE_FCTRL_MPE;
		sxe_hw_rx_mode_set(hw, flt_ctrl);
	}

	if (cast_msg->cast_mode == SXE_CAST_MODE_PROMISC) {
		sxe_uc_all_hash_table_set(dev, true);
		adapter->vt_ctxt.promisc_cnt++;
		for (i = 0; i < SXE_UC_ENTRY_NUM_MAX; i++) {
			if (uc_table[i].used)
				sxe_hw_uc_addr_pool_enable(hw, i, vf);
		}
	} else if (vf_info->cast_mode == SXE_CAST_MODE_PROMISC) {
		adapter->vt_ctxt.promisc_cnt--;
		if (adapter->vt_ctxt.promisc_cnt == 0)
			sxe_uc_all_hash_table_set(dev, false);

		for (i = 0; i < SXE_UC_ENTRY_NUM_MAX; i++) {
			if (uc_table[i].used && uc_table[i].pool_idx != vf) {
				sxe_hw_uc_addr_pool_del(hw, i, vf);
				sxe_vf_mac_reuse_rebuild(adapter, i, vf);
			}
		}
	}

	vf_info->cast_mode = cast_msg->cast_mode;
	LOG_INFO_BDF("vf:%d filter reg:0x%x mode:%d promisc vfs:%d.",
			 vf, vm_l2_filter, cast_msg->cast_mode, adapter->vt_ctxt.promisc_cnt);

l_out:
	return ret;
}

static s32 sxe_vf_uc_addr_sync_handler(struct rte_eth_dev *dev,
					u32 *msgbuf, u32 vf)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	struct sxe_vf_info *vf_info = &adapter->vt_ctxt.vf_info[vf];
	struct sxe_uc_sync_msg *uc_msg = (struct sxe_uc_sync_msg *)msgbuf;
	s32 ret = 0;
	u8 rar_idx;
	u8 *mac_addr = (u8 *)uc_msg->addr;

	UNUSED(mac_addr);
	if (uc_msg->index) {
		if (!rte_is_valid_assigned_ether_addr((struct rte_ether_addr *)uc_msg->addr)) {
			ret = -SXE_ERR_PARAM;
			LOG_ERROR_BDF("vf:%u mac addr:" RTE_ETHER_ADDR_PRT_FMT " invalid.(err:%d).",
					  vf, mac_addr[0], mac_addr[1], mac_addr[2],
					  mac_addr[3], mac_addr[4], mac_addr[5], ret);
			goto l_out;
		}

		vf_info->uc_mac_cnt++;
		rar_idx = sxe_sw_uc_entry_vf_add(adapter, vf, (u8 *)uc_msg->addr, true);
		if (rar_idx < SXE_UC_ENTRY_NUM_MAX) {
			vf_info->uc_mac_table[rar_idx] = SXE_UC_MAC_SET;
			sxe_hw_uc_addr_add(hw, rar_idx, (u8 *)uc_msg->addr, vf);
			sxe_hw_mac_reuse_add(dev, (u8 *)uc_msg->addr, rar_idx);
			sxe_vf_promisc_mac_update(dev, vf, rar_idx);
		}
	} else {
		if (vf_info->uc_mac_cnt)
			sxe_vf_uc_clean(dev, vf);
	}

	LOG_INFO_BDF("vf:%u mac addr:" RTE_ETHER_ADDR_PRT_FMT " opt:%d.",
					vf, mac_addr[0], mac_addr[1], mac_addr[2],
					mac_addr[3], mac_addr[4], mac_addr[5], uc_msg->index);

l_out:
	return ret;
}

static struct sxe_msg_table msg_table[] = {
	[SXE_VFREQ_MAC_ADDR_SET] = {SXE_VFREQ_MAC_ADDR_SET, sxe_vf_dev_mac_addr_set_handler},
	[SXE_VFREQ_MC_ADDR_SYNC] = {SXE_VFREQ_MC_ADDR_SYNC, sxe_vf_mc_addr_sync},
	[SXE_VFREQ_VLAN_SET] = {SXE_VFREQ_VLAN_SET, sxe_vf_vlan_id_set_handler},
	[SXE_VFREQ_LPE_SET] = {SXE_VFREQ_LPE_SET, sxe_vf_max_frame_set_handler},
	[SXE_VFREQ_UC_ADDR_SYNC] = {SXE_VFREQ_UC_ADDR_SYNC, sxe_vf_uc_addr_sync_handler},
	[SXE_VFREQ_API_NEGOTIATE] = {SXE_VFREQ_API_NEGOTIATE, sxe_mbx_api_set_handler},
	[SXE_VFREQ_RING_INFO_GET] = {SXE_VFREQ_RING_INFO_GET, sxe_pf_ring_info_get},
	[SXE_VFREQ_CAST_MODE_SET] = {SXE_VFREQ_CAST_MODE_SET, sxe_vf_cast_mode_handler},
	[SXE_VFREQ_RSS_CONF_GET] = {SXE_VFREQ_RSS_CONF_GET, sxe_vf_rss_hash_conf_get},
};

static void sxe_vf_pool_enable(struct rte_eth_dev *dev, u8 vf_idx)
{
	u32 enable_pool;
	struct sxe_adapter *adapter = dev->data->dev_private;
	u8 reg_idx = vf_idx / 32;
	u8 bit_idx = vf_idx % 32;
	struct sxe_hw *hw = &adapter->hw;
	struct sxe_vf_info *vf_info = &adapter->vt_ctxt.vf_info[vf_idx];

	enable_pool = sxe_hw_tx_pool_bitmap_get(hw, reg_idx);
	enable_pool |= BIT(bit_idx);
	sxe_hw_tx_pool_bitmap_set(hw, reg_idx, enable_pool);

	sxe_hw_vf_queue_drop_enable(hw, vf_idx,
				RTE_ETH_DEV_SRIOV(dev).nb_q_per_pool);

	enable_pool = sxe_hw_rx_pool_bitmap_get(hw, reg_idx);
	enable_pool |= BIT(bit_idx);
	sxe_hw_rx_pool_bitmap_set(hw, reg_idx, enable_pool);

	vf_info->is_ready = true;

	sxe_hw_spoof_count_enable(hw, reg_idx, bit_idx);
}

static void sxe_vf_reset_msg_handle(struct rte_eth_dev *dev, u8 vf_idx)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	struct sxe_rst_reply reply = {};
	u8 *mac_addr = adapter->vt_ctxt.vf_info[vf_idx].mac_addr;
	u8 *addr_bytes = (u8 *)(((struct rte_ether_addr *)mac_addr)->addr_bytes);
	u32 rar_idx = sxe_sw_uc_entry_vf_add(adapter, vf_idx, addr_bytes, false);

	LOG_INFO_BDF("receive vf_idx:%d reset msg.", vf_idx);

	sxe_vf_pool_enable(dev, vf_idx);

	sxe_vf_flr_handle(dev, vf_idx);

	sxe_hw_uc_addr_add(&adapter->hw, rar_idx, addr_bytes, vf_idx);

	sxe_vf_mc_promisc_disable(dev, vf_idx);

	sxe_vf_promisc_disable(dev, vf_idx);

	reply.msg_type = SXE_VFREQ_RESET | SXE_MSGTYPE_ACK;
	reply.mc_filter_type = SXE_MC_FILTER_TYPE0;
	rte_memcpy(reply.mac_addr, mac_addr, RTE_ETHER_ADDR_LEN);

	sxe_hw_send_msg_to_vf(hw, (u32 *)&reply,
				SXE_MSG_NUM(sizeof(reply)), vf_idx);

	adapter->vt_ctxt.vf_info->is_ready = true;

	LOG_INFO_BDF("vf_idx:%d reset msg:0x%x handle done.send mac addr:" RTE_ETHER_ADDR_PRT_FMT
			" mc type:%d to vf.",
			vf_idx, reply.msg_type,
			mac_addr[0], mac_addr[1], mac_addr[2],
			mac_addr[3], mac_addr[4], mac_addr[5],
			SXE_MC_FILTER_TYPE0);
}

static s32 sxe_req_msg_handle(struct rte_eth_dev *dev, u32 *msg,
					u8 vf_idx)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	s32 ret = 0;
	u16 cmd_id = msg[0] & SXE_VFREQ_MASK;
	struct rte_pmd_sxe_mb_event_param user_param;

	if (cmd_id > SXE_VFREQ_CAST_MODE_SET &&
		cmd_id <= SXE_VFREQ_IPSEC_DEL) {
		ret = -SXE_ERR_PARAM;
		LOG_ERROR_BDF("vf_idx:%u msg:0x%x invalid cmd_id:0x%x.",
			   vf_idx, msg[0], cmd_id);
		goto l_out;
	}

	user_param.ret = RTE_PMD_SXE_MB_EVENT_PROCEED;
	user_param.vf_idx = vf_idx;
	user_param.msg_type = msg[0] & 0xFFFF;
	user_param.msg = (void *)msg;

	if (cmd_id == SXE_VFREQ_RESET) {
		ret = 0;
		sxe_vf_reset_msg_handle(dev, vf_idx);

		sxe_eth_dev_callback_process(dev, RTE_ETH_EVENT_VF_MBOX,
						  &user_param);
		goto l_out;
	}

	sxe_eth_dev_callback_process(dev, RTE_ETH_EVENT_VF_MBOX,
						  &user_param);

	LOG_INFO_BDF("vf_idx:%u cmd_id:0x%x user configure:0x%x.",
			vf_idx, cmd_id, user_param.ret);

	if (!adapter->vt_ctxt.vf_info[vf_idx].is_ready) {
		msg[0] |= SXE_MSGTYPE_NACK;
		ret = sxe_hw_send_msg_to_vf(hw, msg,
					SXE_MSG_NUM(sizeof(msg[0])), vf_idx);
		LOG_WARN_BDF("vf_idx:%d not ready now, send nack to vf.ret:%d.",
			  vf_idx, ret);
		goto l_out;
	}

	if (msg_table[cmd_id].msg_func) {
		if (user_param.ret == RTE_PMD_SXE_MB_EVENT_PROCEED ||
			cmd_id == SXE_VFREQ_API_NEGOTIATE ||
			cmd_id == SXE_VFREQ_RING_INFO_GET) {
			ret = msg_table[cmd_id].msg_func(dev, msg, vf_idx);
		}
		LOG_INFO_BDF("msg:0x%x cmd_id:0x%x handle done.ret:%d",
			 msg[0], cmd_id, ret);
	} else {
		ret = -SXE_ERR_PARAM;
	}

	if (!ret) {
		msg[0] |= SXE_MSGTYPE_ACK;
	} else {
		msg[0] |= SXE_MSGTYPE_NACK;
		LOG_ERROR_BDF("vf_idx:%u msg_type:0x%x cmdId:0x%x invalid.(err:%d)",
				  vf_idx, msg[0], cmd_id, ret);
	}

	ret = sxe_hw_send_msg_to_vf(hw, msg, SXE_MBX_MSG_NUM, vf_idx);
	if (ret) {
		LOG_ERROR_BDF("vf:%d msg:0x%x reply fail.(err:%d).",
			   vf_idx, msg[0], ret);
	}

	LOG_INFO_BDF("pf reply vf:%d msg:0x%x done.ret:%d", vf_idx, msg[0], ret);

l_out:
	return ret;
}

static s32 sxe_vf_req_msg_handle(struct rte_eth_dev *dev, u8 vf_idx)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	u32 msg[SXE_MBX_MSG_NUM] = {0};
	s32 ret;

	ret = sxe_hw_rcv_msg_from_vf(hw, msg, SXE_MBX_MSG_NUM, vf_idx);
	if (ret) {
		LOG_ERROR_BDF("rcv vf:0x%x req msg:0x%x fail.(err:%d)",
			   vf_idx, msg[0], ret);
		goto l_out;
	}

	LOG_INFO_BDF("rcv vf_idx:%d req msg:0x%x.", vf_idx, msg[0]);

	if (msg[0] & (SXE_MSGTYPE_ACK | SXE_MSGTYPE_NACK)) {
		LOG_WARN_BDF("msg:0x%x has handled, no need dup handle.",
			  msg[0]);
		goto l_out;
	}

	ret = sxe_req_msg_handle(dev, msg, vf_idx);
	if (ret) {
		LOG_ERROR_BDF("vf:%d request msg handle fail.(err:%d)",
			  vf_idx, ret);
	}

l_out:
	return ret;
}

static void sxe_vf_ack_msg_handle(struct rte_eth_dev *eth_dev, u8 vf_idx)
{
	struct sxe_adapter *adapter = eth_dev->data->dev_private;
	u32 msg = SXE_MSGTYPE_NACK;

	if (!adapter->vt_ctxt.vf_info[vf_idx].is_ready) {
		sxe_hw_send_msg_to_vf(&adapter->hw, &msg,
					SXE_MSG_NUM(sizeof(msg)), vf_idx);
	}
}

void sxe_mbx_irq_handler(struct rte_eth_dev *eth_dev)
{
	struct sxe_adapter *adapter = eth_dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	u16 vf_num = sxe_vf_num_get(eth_dev);
	u8 vf_idx;

	LOG_DEBUG_BDF("mailbox irq triggered vf_num:%u.", vf_num);

	for (vf_idx = 0; vf_idx < vf_num; vf_idx++) {
		if (sxe_hw_vf_rst_check(hw, vf_idx)) {
			LOG_WARN_BDF("vf_idx:%d flr triggered.", vf_idx);
			sxe_vf_flr_handle(eth_dev, vf_idx);
		}

		if (sxe_hw_vf_req_check(hw, vf_idx))
			sxe_vf_req_msg_handle(eth_dev, vf_idx);

		if (sxe_hw_vf_ack_check(hw, vf_idx))
			sxe_vf_ack_msg_handle(eth_dev, vf_idx);
	}
}

int rte_pmd_sxe_set_vf_rxmode(u16 port, u16 vf,
				u16 rx_mask, u8 on)
{
	u32 val = 0;
	struct rte_eth_dev *dev;
	struct rte_pci_device *pci_dev;
	struct sxe_adapter *adapter;
	struct sxe_hw *hw;
	u32 vmolr;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port, -ENODEV);

	dev = &rte_eth_devices[port];
	pci_dev = RTE_ETH_DEV_TO_PCI(dev);

	if (!sxe_is_supported(dev))
		return -ENOTSUP;

	if (vf >= pci_dev->max_vfs)
		return -EINVAL;

	if (on > 1)
		return -EINVAL;

	adapter = dev->data->dev_private;
	hw = &adapter->hw;
	vmolr = sxe_hw_pool_rx_mode_get(hw, vf);

	if (sxe_hw_vt_status(hw) == false)
		return -ENOTSUP;

	sxe_vmdq_rx_mode_get((u32)rx_mask, &val);

	if (on)
		vmolr |= val;
	else
		vmolr &= ~val;

	sxe_hw_pool_rx_mode_set(hw, vmolr, vf);

	return 0;
}
#endif

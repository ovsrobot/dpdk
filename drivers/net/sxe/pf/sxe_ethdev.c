/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */
#include <bus_pci_driver.h>
#include <ethdev_driver.h>
#include <dev_driver.h>
#include <ethdev_pci.h>
#include <rte_ethdev.h>
#include <rte_alarm.h>
#include <rte_pmd_sxe.h>
#include <eal_export.h>
#include "sxe_types.h"
#include "sxe_logs.h"
#include "sxe_compat_platform.h"
#include "sxe_errno.h"
#include "sxe.h"
#include "sxe_hw.h"
#include "sxe_offload.h"
#include "sxe_ethdev.h"
#include "sxe_filter.h"
#include "sxe_rx.h"
#include "sxe_tx.h"
#include "sxe_queue.h"
#include "sxe_irq.h"
#include "sxe_stats.h"
#include "sxe_phy.h"
#include "sxe_pmd_hdc.h"
#include "sxe_flow_ctrl.h"
#include "sxe_ptp.h"
#include "sxe_cli.h"
#include "drv_msg.h"
#include "sxe_vf.h"
#include "sxe_dcb.h"
#include "sxe_version.h"
#include "sxe_compat_version.h"
#include <rte_string_fns.h>


#define SXE_DEFAULT_MTU			 1500
#define SXE_ETH_HLEN				14
#define SXE_ETH_FCS_LEN			 4
#define SXE_ETH_FRAME_LEN		   1514

#define SXE_ETH_MAX_LEN  (RTE_ETHER_MTU + SXE_ETH_OVERHEAD)

static const struct rte_eth_desc_lim sxe_rx_desc_lim = {
	.nb_max = SXE_MAX_RING_DESC,
	.nb_min = SXE_MIN_RING_DESC,
	.nb_align = SXE_RX_DESC_RING_ALIGN,
};

static const struct rte_eth_desc_lim sxe_tx_desc_lim = {
	.nb_max = SXE_MAX_RING_DESC,
	.nb_min = SXE_MIN_RING_DESC,
	.nb_align = SXE_TX_DESC_RING_ALIGN,
	.nb_seg_max = SXE_TX_MAX_SEG,
	.nb_mtu_seg_max = SXE_TX_MAX_SEG,
};

static s32 sxe_dev_reset(struct rte_eth_dev *eth_dev);

static s32 sxe_dev_configure(struct rte_eth_dev *dev)
{
	s32 ret;
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_irq_context *irq = &adapter->irq_ctxt;

	PMD_INIT_FUNC_TRACE();

	/* Rx mode check */
	if (dev->data->dev_conf.rxmode.mq_mode & RTE_ETH_MQ_RX_RSS_FLAG) {
		PMD_LOG_DEBUG(INIT, "rx offload rss hash");
		dev->data->dev_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_RSS_HASH;
	}

	/* Multi queue mode check */
	ret  = sxe_mq_mode_check(dev);
	if (ret != 0) {
		PMD_LOG_ERR(INIT, "sxe mq mode check fails with %d.",
				ret);
		goto l_end;
	}

	irq->action |= SXE_IRQ_LINK_UPDATE;

	/* Default use batch alloc  */
	adapter->rx_batch_alloc_allowed = true;

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SIMD
	adapter->rx_vec_allowed = true;
#endif

l_end:
	return ret;
}

static void sxe_txrx_start(struct rte_eth_dev *dev)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw	 *hw = &adapter->hw;

	sxe_hw_rx_cap_switch_on(hw);

	sxe_hw_mac_txrx_enable(hw);
}

static s32 sxe_link_configure(struct rte_eth_dev *dev)
{
	s32 ret = 0;
	bool link_up = false;
	u32 conf_speeds;
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;

	/* Disable loopback */
	sxe_hw_loopback_switch(hw, false);

	sxe_sfp_tx_laser_enable(adapter);

	dev->data->dev_link.link_status = link_up;

	/* Rate of obtaining user configuration */
	ret = sxe_conf_speed_get(dev, &conf_speeds);
	if (ret) {
		PMD_LOG_ERR(INIT, "invalid link setting");
		goto l_end;
	}

	if (adapter->phy_ctxt.sfp_info.multispeed_fiber)
		ret = sxe_multispeed_sfp_link_configure(dev, conf_speeds, false);
	else
		ret = sxe_sfp_link_configure(dev);

	if (ret) {
		PMD_LOG_ERR(INIT, "link config failed, speed=%x",
						conf_speeds);
		ret = -EIO;
		goto l_end;
	}

l_end:
	return ret;
}

static s32 sxe_loopback_pcs_init(struct sxe_adapter *adapter,
				sxe_pcs_mode_e mode, u32 max_frame)
{
	s32 ret;
	sxe_pcs_cfg_s pcs_cfg;
	struct sxe_hw *hw = &adapter->hw;
	struct sxe_irq_context *irq = &adapter->irq_ctxt;

	pcs_cfg.mode = mode;
	pcs_cfg.mtu  = max_frame;
	ret = sxe_driver_cmd_trans(hw, SXE_CMD_PCS_SDS_INIT,
				(void *)&pcs_cfg, sizeof(pcs_cfg),
				NULL, 0);
	irq->to_pcs_init = false;
	if (ret) {
		LOG_ERROR_BDF("hdc trans failed ret=%d, cmd:pcs init", ret);
		goto l_end;
	}

	/* Set flow control mac address */
	sxe_fc_mac_addr_set(adapter);

	LOG_INFO_BDF("mode:%u max_frame:0x%x loopback pcs init done.",
			 mode, max_frame);
l_end:
	return ret;
}

static s32 sxe_loopback_configure(struct sxe_adapter *adapter)
{
	s32 ret;
	u32 max_frame = SXE_DEFAULT_MTU + SXE_ETH_DEAD_LOAD;

	(void)sxe_sfp_tx_laser_disable(adapter);

	/* Initialize sds and pcs modules */
	ret = sxe_loopback_pcs_init(adapter, SXE_PCS_MODE_10GBASE_KR_WO, max_frame);
	if (ret) {
		LOG_ERROR_BDF("pcs sds init failed, mode=%d, ret=%d",
					SXE_PCS_MODE_10GBASE_KR_WO, ret);
		goto l_out;
	}

	ret = sxe_loopback_pcs_init(adapter, SXE_PCS_MODE_LPBK_PHY_TX2RX, max_frame);
	if (ret) {
		LOG_ERROR_BDF("pcs sds init failed, mode=%d, ret=%d",
					SXE_PCS_MODE_LPBK_PHY_TX2RX, ret);
		goto l_out;
	}

	usleep_range(10000, 20000);

	LOG_DEBUG_BDF("loolback configure success max_frame:0x%x.", max_frame);

l_out:
	return ret;
}

static s32 sxe_dev_start(struct rte_eth_dev *dev)
{
	s32 ret;
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(dev);
	struct rte_intr_handle *handle = SXE_PCI_INTR_HANDLE(pci_dev);
	struct sxe_irq_context *irq = &adapter->irq_ctxt;

	ret = sxe_fw_time_sync(hw);

	sxe_wait_setup_link_complete(dev, 0);

	rte_intr_disable(handle);

	adapter->is_stopped = false;
	rte_atomic_store_explicit(&adapter->is_stopping, 0, rte_memory_order_seq_cst);
	ret = sxe_phy_init(adapter);
	if (ret == -SXE_ERR_SFF_NOT_SUPPORTED) {
		PMD_LOG_ERR(INIT, "sfp is not sfp+, not supported, ret=%d", ret);
		ret = -EPERM;
		goto l_end;
	} else if (ret) {
		PMD_LOG_ERR(INIT, "phy init failed, ret=%d", ret);
	}

	ret = sxe_hw_reset(hw);
	if (ret < 0) {
		PMD_LOG_ERR(INIT, "hw init failed, ret=%d", ret);
		goto l_end;
	}

	sxe_hw_start(hw);

	sxe_mac_addr_set(dev, &dev->data->mac_addrs[0]);

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SRIOV
	sxe_hw_pf_rst_done_set(hw);

	/* Configure virtualization */
	sxe_vt_configure(dev);
#endif
	sxe_tx_configure(dev);

	ret = sxe_rx_configure(dev);
	if (ret) {
		PMD_LOG_ERR(INIT, "unable to initialize RX hardware");
		goto l_error;
	}

	ret = sxe_irq_configure(dev);
	if (ret) {
		PMD_LOG_ERR(INIT, "irq config fail.");
		goto l_error;
	}

	sxe_vlan_filter_configure(dev);

	sxe_queue_stats_map_restore(dev);

	sxe_txrx_start(dev);

	irq->to_pcs_init = true;

	if (dev->data->dev_conf.lpbk_mode == SXE_LPBK_DISABLED) {
		sxe_link_configure(dev);
	} else if (dev->data->dev_conf.lpbk_mode == SXE_LPBK_ENABLED) {
		sxe_loopback_configure(adapter);
	} else {
		ret = -ENOTSUP;
		PMD_LOG_ERR(INIT, "unsupported loopback mode:%u.",
				dev->data->dev_conf.lpbk_mode);
		goto l_end;
	}

	sxe_link_update(dev, false);

	ret = sxe_flow_ctrl_enable(dev);
	if (ret < 0) {
		PMD_LOG_ERR(INIT, "enable flow ctrl err");
		goto l_error;
	}

	sxe_dcb_configure(dev);
l_end:
	return ret;

l_error:
	PMD_LOG_ERR(INIT, "dev start err, ret=%d", ret);
	sxe_irq_vec_free(handle);
	sxe_txrx_queues_clear(dev, adapter->rx_batch_alloc_allowed);
	ret = -EIO;
	goto l_end;
}

static s32 sxe_dev_stop(struct rte_eth_dev *dev)
{
	s32 ret = 0;
	s32 num;
	struct rte_eth_link link;
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;

	PMD_INIT_FUNC_TRACE();

	if (adapter->is_stopped) {
		LOG_ERROR("adapter[%p] is stopped", adapter);
		goto l_end;
	}

	sxe_hw_all_irq_disable(hw);

	sxe_sfp_tx_laser_disable(adapter);

	(void)rte_atomic_exchange_explicit(&adapter->is_stopping, 1, rte_memory_order_seq_cst);

	sxe_wait_setup_link_complete(dev, 0);
	ret = sxe_hw_reset(hw);
	if (ret < 0) {
		PMD_LOG_ERR(INIT, "hw init failed, ret=%d", ret);
		goto l_end;
	}

	sxe_mac_addr_set(dev, &dev->data->mac_addrs[0]);

	sxe_irq_disable(dev);

	sxe_txrx_queues_clear(dev, adapter->rx_batch_alloc_allowed);

	dev->data->scattered_rx = 0;
	dev->data->lro = 0;

	memset(&link, 0, sizeof(link));
	rte_eth_linkstatus_set(dev, &link);

	adapter->rss_reta_updated = false;

	dev->data->dev_started = 0;
	adapter->is_stopped = true;

	num = rte_eal_alarm_cancel(sxe_event_irq_delayed_handler, dev);
	if (num > 0)
		sxe_eth_dev_callback_process(dev, RTE_ETH_EVENT_INTR_LSC, NULL);

	LOG_DEBUG_BDF("dev stop success.");

l_end:
	return ret;
}

static s32 sxe_dev_close(struct rte_eth_dev *dev)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	s32 ret = 0;

	PMD_INIT_FUNC_TRACE();

	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		PMD_LOG_INFO(INIT, "not primary, do nothing");
		goto l_end;
	}

	sxe_hw_hdc_drv_status_set(hw, (u32)false);

	ret = sxe_hw_reset(hw);
	if (ret < 0) {
		PMD_LOG_ERR(INIT, "hw init failed, ret=%d", ret);
		goto l_end;
	}
	ret = sxe_dev_stop(dev);
	if (ret)
		PMD_LOG_ERR(INIT, "dev stop fail.(err:%d)", ret);
	sxe_queues_free(dev);
	sxe_mac_addr_set(dev, &adapter->mac_filter_ctxt.def_mac_addr);
	sxe_irq_uninit(dev);
#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SRIOV
	sxe_vt_uninit(dev);
#endif

l_end:
	return ret;
}

static s32 sxe_dev_infos_get(struct rte_eth_dev *dev,
					struct rte_eth_dev_info *dev_info)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(dev);
	struct rte_eth_conf *dev_conf = &dev->data->dev_conf;

	dev_info->max_rx_queues = SXE_HW_TXRX_RING_NUM_MAX;
	dev_info->max_tx_queues = SXE_HW_TXRX_RING_NUM_MAX;
	if (RTE_ETH_DEV_SRIOV(dev).active == 0) {
		if (dev_conf->txmode.mq_mode == RTE_ETH_MQ_TX_NONE)
			dev_info->max_tx_queues = SXE_HW_TX_NONE_MODE_Q_NUM;
	}

	dev_info->min_rx_bufsize = 1024;
	dev_info->max_rx_pktlen = 15872;
	dev_info->max_mac_addrs = SXE_UC_ENTRY_NUM_MAX;
	dev_info->max_hash_mac_addrs = SXE_HASH_UC_NUM_MAX;
	dev_info->max_vfs = pci_dev->max_vfs;
	dev_info->max_mtu =  dev_info->max_rx_pktlen - SXE_ETH_OVERHEAD;
	dev_info->min_mtu = RTE_ETHER_MIN_MTU;
	dev_info->max_vmdq_pools = RTE_ETH_64_POOLS;
	dev_info->vmdq_queue_num = dev_info->max_rx_queues;

	dev_info->rx_queue_offload_capa = sxe_rx_queue_offload_capa_get(dev);
	dev_info->rx_offload_capa = (sxe_rx_port_offload_capa_get(dev) |
					 dev_info->rx_queue_offload_capa);
	dev_info->tx_queue_offload_capa = sxe_tx_queue_offload_capa_get(dev);
	dev_info->tx_offload_capa = sxe_tx_port_offload_capa_get(dev);

	dev_info->default_rxconf = (struct rte_eth_rxconf) {
		.rx_thresh = {
			.pthresh = SXE_DEFAULT_RX_PTHRESH,
			.hthresh = SXE_DEFAULT_RX_HTHRESH,
			.wthresh = SXE_DEFAULT_RX_WTHRESH,
		},
		.rx_free_thresh = SXE_DEFAULT_RX_FREE_THRESH,
		.rx_drop_en = 0,
		.offloads = 0,
	};

	dev_info->default_txconf = (struct rte_eth_txconf) {
		.tx_thresh = {
			.pthresh = SXE_DEFAULT_TX_PTHRESH,
			.hthresh = SXE_DEFAULT_TX_HTHRESH,
			.wthresh = SXE_DEFAULT_TX_WTHRESH,
		},
		.tx_free_thresh = SXE_DEFAULT_TX_FREE_THRESH,
		.tx_rs_thresh = SXE_DEFAULT_TX_RSBIT_THRESH,
		.offloads = 0,
	};

	dev_info->rx_desc_lim = sxe_rx_desc_lim;
	dev_info->tx_desc_lim = sxe_tx_desc_lim;

	dev_info->hash_key_size = SXE_HKEY_MAX_INDEX * sizeof(u32);
	dev_info->reta_size = RTE_ETH_RSS_RETA_SIZE_128;
	dev_info->flow_type_rss_offloads = SXE_RSS_OFFLOAD_ALL;

	dev_info->speed_capa = RTE_ETH_LINK_SPEED_1G | RTE_ETH_LINK_SPEED_10G;

	dev_info->default_rxportconf.burst_size = 32;
	dev_info->default_txportconf.burst_size = 32;
	dev_info->default_rxportconf.nb_queues = 1;
	dev_info->default_txportconf.nb_queues = 1;
	dev_info->default_rxportconf.ring_size = 256;
	dev_info->default_txportconf.ring_size = 256;

	return 0;
}

static s32 sxe_mtu_set(struct rte_eth_dev *dev, u16 mtu)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct rte_eth_dev_info dev_info;
	u32 frame_size = mtu + SXE_ETH_OVERHEAD;
	struct rte_eth_dev_data *dev_data = dev->data;
	s32 ret;

	ret = sxe_dev_infos_get(dev, &dev_info);
	if (ret != 0) {
		PMD_LOG_ERR(INIT, "get dev info fails with ret=%d", ret);
		goto l_end;
	}

	if (mtu < RTE_ETHER_MTU || frame_size > dev_info.max_rx_pktlen) {
		PMD_LOG_ERR(INIT, "mtu=%u < %u or frame_size=%u > max_rx_pktlen=%u",
			mtu, RTE_ETHER_MTU, frame_size, dev_info.max_rx_pktlen);
		ret = -EINVAL;
		goto l_end;
	}

	if (dev_data->dev_started && !dev_data->scattered_rx &&
		(frame_size + 2 * SXE_VLAN_TAG_SIZE >
		dev->data->min_rx_buf_size - RTE_PKTMBUF_HEADROOM)) {
		PMD_LOG_ERR(INIT, "stop port first.");
		ret = -EINVAL;
		goto l_end;
	}

	adapter->mtu = mtu;
	PMD_LOG_NOTICE(DRV, "mtu set success, take effect after port-restart.");

l_end:
	return ret;
}

static int sxe_get_regs(struct rte_eth_dev *dev,
		  struct rte_dev_reg_info *regs)
{
	s32 ret = 0;
	u32 *data = regs->data;
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	u32 length = sxe_hw_all_regs_group_num_get();

	if (data == NULL) {
		regs->length = length;
		regs->width = sizeof(uint32_t);
		goto l_end;
	}

	if (regs->length == 0 || regs->length == length) {
		sxe_hw_all_regs_group_read(hw, data);

		goto l_end;
	}

	ret = -ENOTSUP;
	LOG_ERROR("get regs: inval param: regs_len=%u, regs->data=%p, "
			"regs_offset=%u,  regs_width=%u, regs_version=%u",
			regs->length, regs->data,
			regs->offset, regs->width,
			regs->version);

l_end:
	return ret;
}

static s32 sxe_led_reset(struct rte_eth_dev *dev)
{
	s32 ret;
	s32 resp;
	struct sxe_led_ctrl ctrl;
	struct sxe_adapter *adapter = (struct sxe_adapter *)(dev->data->dev_private);
	struct sxe_hw *hw = &adapter->hw;

	ctrl.mode = SXE_IDENTIFY_LED_RESET;
	ctrl.duration = 0;

	ret = sxe_driver_cmd_trans(hw, SXE_CMD_LED_CTRL,
				(void *)&ctrl, sizeof(ctrl),
				(void *)&resp, sizeof(resp));
	if (ret) {
		LOG_ERROR_BDF("hdc trans failed ret=%d, cmd:led reset", ret);
		ret = -EIO;
	} else {
		LOG_DEBUG_BDF("led reset success");
	}

	return ret;
}

static s32 sxe_led_ctrl(struct sxe_adapter *adapter, bool is_on)
{
	s32 ret;
	s32 resp;
	struct sxe_led_ctrl ctrl;
	struct sxe_hw *hw = &adapter->hw;

	ctrl.mode = is_on ? SXE_IDENTIFY_LED_ON : SXE_IDENTIFY_LED_OFF;
	ctrl.duration = 0;

	ret = sxe_driver_cmd_trans(hw, SXE_CMD_LED_CTRL,
				(void *)&ctrl, sizeof(ctrl),
				(void *)&resp, sizeof(resp));
	if (ret) {
		LOG_ERROR_BDF("hdc trans failed ret=%d, cmd:led ctrl", ret);
		ret = -EIO;
	}

	return ret;
}

static int sxe_led_on(struct rte_eth_dev *dev)
{
	int ret;

	struct sxe_adapter *adapter = dev->data->dev_private;

	ret = sxe_led_ctrl(adapter, true);

	return ret;
}

static int sxe_led_off(struct rte_eth_dev *dev)
{
	int ret;

	struct sxe_adapter *adapter = dev->data->dev_private;

	ret = sxe_led_ctrl(adapter, false);

	return ret;
}

static int sxe_fw_version_get(struct rte_eth_dev *dev, char *fw_version,
						size_t fw_size)
{
	int ret;
	sxe_version_resp_s resp;
	struct sxe_adapter *adapter = (struct sxe_adapter *)(dev->data->dev_private);
	struct sxe_hw *hw = &adapter->hw;

	ret = sxe_driver_cmd_trans(hw, SXE_CMD_FW_VER_GET,
				NULL, 0,
				(void *)&resp, sizeof(resp));
	if (ret) {
		LOG_ERROR_BDF("get version failed, ret=%d", ret);
		ret = -EIO;
		goto l_end;
	}

	ret = snprintf(fw_version, fw_size, "%s", resp.fw_version);
	if (ret < 0) {
		ret = -EINVAL;
		goto l_end;
	}

	ret += 1;

	if (fw_size >= (size_t)ret)
		ret = 0;

l_end:
	return ret;
}

static const struct eth_dev_ops sxe_eth_dev_ops = {
	.dev_configure		= sxe_dev_configure,
	.dev_start		= sxe_dev_start,
	.dev_stop		= sxe_dev_stop,
	.dev_close		= sxe_dev_close,
	.dev_reset		= sxe_dev_reset,

	.rx_queue_start		= sxe_rx_queue_start,
	.rx_queue_stop		= sxe_rx_queue_stop,
	.rx_queue_setup		= sxe_rx_queue_setup,
	.rx_queue_release	= sxe_rx_queue_release,
	.rxq_info_get		= sxe_rx_queue_info_get,
	.dev_infos_get		= sxe_dev_infos_get,

	.tx_queue_start		= sxe_tx_queue_start,
	.tx_queue_stop		= sxe_tx_queue_stop,
	.tx_queue_setup		= sxe_tx_queue_setup,
	.tx_queue_release	= sxe_tx_queue_release,
	.tx_done_cleanup	= sxe_tx_done_cleanup,
	.txq_info_get		= sxe_tx_queue_info_get,

	.recycle_rxq_info_get	= sxe_recycle_rxq_info_get,


	.promiscuous_enable	= sxe_promiscuous_enable,
	.promiscuous_disable	= sxe_promiscuous_disable,
	.allmulticast_enable	= sxe_allmulticast_enable,
	.allmulticast_disable	= sxe_allmulticast_disable,

	.rx_queue_intr_enable	= sxe_rx_queue_intr_enable,
	.rx_queue_intr_disable	= sxe_rx_queue_intr_disable,

	.mtu_set		= sxe_mtu_set,
	.reta_update		= sxe_rss_reta_update,
	.reta_query		= sxe_rss_reta_query,
	.rss_hash_update	= sxe_rss_hash_update,
	.rss_hash_conf_get	= sxe_rss_hash_conf_get,

	.mac_addr_add		= sxe_mac_addr_add,
	.mac_addr_remove	= sxe_mac_addr_remove,
	.mac_addr_set		= sxe_mac_addr_set,

	.set_mc_addr_list	= sxe_set_mc_addr_list,

	.stats_get		= sxe_eth_stats_get,
	.stats_reset		= sxe_stats_reset,

	.xstats_get		= sxe_xstats_get,
	.xstats_reset		= sxe_xstats_reset,
	.xstats_get_by_id	= sxe_xstats_get_by_id,
	.xstats_get_names	= sxe_xstats_names_get,
	.xstats_get_names_by_id	= sxe_xstats_names_get_by_id,
	.queue_stats_mapping_set = sxe_queue_stats_mapping_set,

	.get_module_info	= sxe_get_module_info,
	.get_module_eeprom	= sxe_get_module_eeprom,

	.flow_ctrl_get		= sxe_flow_ctrl_get,
	.flow_ctrl_set		= sxe_flow_ctrl_set,
	.priority_flow_ctrl_set = sxe_priority_flow_ctrl_set,

	.timesync_enable	= sxe_timesync_enable,
	.timesync_disable	= sxe_timesync_disable,
	.timesync_read_rx_timestamp = sxe_timesync_read_rx_timestamp,
	.timesync_read_tx_timestamp = sxe_timesync_read_tx_timestamp,
	.timesync_adjust_time	= sxe_timesync_adjust_time,
	.timesync_read_time	= sxe_timesync_read_time,
	.timesync_write_time	= sxe_timesync_write_time,

	.vlan_filter_set	= sxe_vlan_filter_set,
	.vlan_tpid_set		= sxe_vlan_tpid_set,
	.vlan_offload_set	= sxe_vlan_offload_set,
	.vlan_strip_queue_set   = sxe_vlan_strip_queue_set,

	.get_reg		= sxe_get_regs,

	.dev_set_link_up	= sxe_dev_set_link_up,
	.dev_set_link_down	= sxe_dev_set_link_down,
	.dev_led_on		= sxe_led_on,
	.dev_led_off		= sxe_led_off,
	.link_update		= sxe_link_update,

	.dev_supported_ptypes_get = sxe_dev_supported_ptypes_get,

	.get_dcb_info		= sxe_get_dcb_info,

	.set_queue_rate_limit	= sxe_queue_rate_limit_set,
	.fw_version_get		= sxe_fw_version_get,
};

static s32 sxe_hw_base_init(struct rte_eth_dev *eth_dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	struct sxe_adapter *adapter = eth_dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	s32 ret;

	hw->reg_base_addr = (void *)pci_dev->mem_resource[0].addr;
	PMD_LOG_INFO(INIT, "eth_dev[%u] got reg_base_addr=%p",
			eth_dev->data->port_id, hw->reg_base_addr);
	hw->adapter = adapter;

	strlcpy(adapter->name, pci_dev->device.name, sizeof(adapter->name) - 1);

	sxe_hw_hdc_drv_status_set(hw, (u32)true);

	ret = sxe_phy_init(adapter);
	if (ret == -SXE_ERR_SFF_NOT_SUPPORTED) {
		PMD_LOG_ERR(INIT, "sfp is not sfp+, not supported, ret=%d", ret);
		ret = -EPERM;
		goto l_out;
	} else if (ret) {
		PMD_LOG_ERR(INIT, "phy init failed, ret=%d", ret);
	}

	ret = sxe_hw_reset(hw);
	if (ret) {
		PMD_LOG_ERR(INIT, "hw init failed, ret=%d", ret);
		goto l_out;
	} else {
		sxe_hw_start(hw);
	}

	ret = sxe_mac_addr_init(eth_dev);
	if (ret) {
		PMD_LOG_ERR(INIT, "mac addr init fail, ret=%d", ret);
		goto l_out;
	}

	sxe_hw_fc_base_init(hw);

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SRIOV
	sxe_hw_pf_rst_done_set(hw);
#endif

l_out:
	if (ret)
		sxe_hw_hdc_drv_status_set(hw, (u32)false);

	return ret;
}

void sxe_secondary_proc_init(struct rte_eth_dev *eth_dev,
	bool rx_batch_alloc_allowed, bool *rx_vec_allowed)
{
	__sxe_secondary_proc_init(eth_dev, rx_batch_alloc_allowed, rx_vec_allowed);
}

static void sxe_ethdev_mac_mem_free(struct rte_eth_dev *eth_dev)
{
	struct sxe_adapter *adapter = eth_dev->data->dev_private;

	if (eth_dev->data->mac_addrs) {
		rte_free(eth_dev->data->mac_addrs);
		eth_dev->data->mac_addrs = NULL;
	}

	if (eth_dev->data->hash_mac_addrs) {
		rte_free(eth_dev->data->hash_mac_addrs);
		eth_dev->data->hash_mac_addrs = NULL;
	}

	if (adapter->mac_filter_ctxt.uc_addr_table) {
		rte_free(adapter->mac_filter_ctxt.uc_addr_table);
		adapter->mac_filter_ctxt.uc_addr_table = NULL;
	}
}

s32 sxe_ethdev_init(struct rte_eth_dev *eth_dev, void *param __rte_unused)
{
	s32 ret = 0;
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	struct sxe_adapter *adapter = eth_dev->data->dev_private;
#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_FILTER_CTRL
	struct sxe_filter_context *filter_info = &adapter->filter_ctxt;
#endif

	eth_dev->dev_ops = &sxe_eth_dev_ops;

	eth_dev->rx_queue_count	   = sxe_rx_queue_count;
	eth_dev->rx_descriptor_status = sxe_rx_descriptor_status;
	eth_dev->tx_descriptor_status = sxe_tx_descriptor_status;

	eth_dev->rx_pkt_burst		  = &sxe_pkts_recv;
	eth_dev->tx_pkt_burst = &sxe_pkts_xmit_with_offload;
	eth_dev->tx_pkt_prepare = &sxe_prep_pkts;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SIMD
		sxe_secondary_proc_init(eth_dev, adapter->rx_batch_alloc_allowed,
				&adapter->rx_vec_allowed);
#else
		bool rx_vec_allowed = 0;
		sxe_secondary_proc_init(eth_dev, adapter->rx_batch_alloc_allowed,
			&rx_vec_allowed);
#endif
		goto l_out;
	}

	rte_atomic_store_explicit(&adapter->link_thread_running, 0, rte_memory_order_seq_cst);

	rte_eth_copy_pci_info(eth_dev, pci_dev);


	ret = sxe_hw_base_init(eth_dev);
	if (ret) {
		PMD_LOG_ERR(INIT, "hw base init fail.(err:%d)", ret);
		goto l_out;
	}

	sxe_led_reset(eth_dev);

	sxe_dcb_init(eth_dev);

	/* Reset stats info */
	sxe_stats_reset(eth_dev);

	sxe_queue_stats_map_reset(eth_dev);

	eth_dev->data->dev_flags |= RTE_ETH_DEV_AUTOFILL_QUEUE_XSTATS;

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SRIOV
	sxe_vt_init(eth_dev);
#endif
	adapter->mtu = RTE_ETHER_MTU;

	sxe_irq_init(eth_dev);

	PMD_LOG_INFO(INIT, "sxe eth dev init done.");

l_out:
	return ret;
}

s32 sxe_ethdev_uninit(struct rte_eth_dev *eth_dev)
{
	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		PMD_LOG_INFO(INIT, "not primary process ,do nothing");
		goto l_end;
	}

	sxe_dev_close(eth_dev);

	sxe_ethdev_mac_mem_free(eth_dev);

l_end:
	return 0;
}

static s32 sxe_dev_reset(struct rte_eth_dev *eth_dev)
{
	s32 ret;

	if (eth_dev->data->sriov.active) {
		ret = -ENOTSUP;
		PMD_LOG_ERR(INIT, "sriov activated, not support reset pf port[%u]",
			eth_dev->data->port_id);
		goto l_end;
	}

	ret = sxe_ethdev_uninit(eth_dev);
	if (ret) {
		PMD_LOG_ERR(INIT, "port[%u] dev uninit failed",
			eth_dev->data->port_id);
		goto l_end;
	}

	ret = sxe_ethdev_init(eth_dev, NULL);
	if (ret) {
		PMD_LOG_ERR(INIT, "port[%u] dev init failed",
			eth_dev->data->port_id);
	}

l_end:
	return ret;
}

s32 rte_pmd_sxe_tx_loopback_set(u16 port, u8 on)
{
	struct rte_eth_dev *dev;
	struct sxe_adapter *adapter;
	s32 ret = 0;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port, -ENODEV);

	dev = &rte_eth_devices[port];

	if (!sxe_is_supported(dev)) {
		ret = -ENOTSUP;
		PMD_LOG_ERR(DRV, "port:%u not support tx loopback set.", port);
		goto l_out;
	}

	if (on > 1) {
		ret = -EINVAL;
		PMD_LOG_ERR(DRV, "port:%u invalid user configure value:%u.",
					port, on);
		goto l_out;
	}

	adapter = dev->data->dev_private;

	sxe_hw_vt_pool_loopback_switch(&adapter->hw, on);

	PMD_LOG_ERR(DRV, "port:%u set tx loopback:%u success.", port, on);

l_out:
	return ret;
}

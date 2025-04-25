/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#include "sxe_dpdk_version.h"
#if defined DPDK_20_11_5 || defined DPDK_19_11_6
#include <rte_bus_pci.h>
#include <rte_ethdev_driver.h>
#include <rte_ethdev_pci.h>
#elif defined DPDK_21_11_5
#include <rte_bus_pci.h>
#include <ethdev_driver.h>
#include <rte_dev.h>
#include <ethdev_pci.h>
#else
#include <bus_pci_driver.h>
#include <ethdev_driver.h>
#include <dev_driver.h>
#include <ethdev_pci.h>
#endif

#include <rte_ethdev.h>
#include <rte_pmd_sxe.h>
#include <rte_alarm.h>

#include "sxe_types.h"
#include "sxe_logs.h"
#include "sxe_compat_platform.h"
#include "sxe_errno.h"
#include "sxe.h"
#include "sxe_hw.h"
#include "sxe_ethdev.h"
#include "sxe_filter.h"
#include "sxe_rx.h"
#include "sxe_tx.h"
#include "sxe_offload.h"
#include "sxe_queue.h"
#include "sxe_irq.h"
#include "sxe_pmd_hdc.h"
#include "drv_msg.h"
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


static s32 sxe_dev_start(struct rte_eth_dev *dev)
{
	s32 ret;
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(dev);
	struct rte_intr_handle *handle = SXE_PCI_INTR_HANDLE(pci_dev);
	struct sxe_irq_context *irq = &adapter->irq_ctxt;

	ret = sxe_fw_time_sync(hw);

	rte_intr_disable(handle);

	ret = sxe_hw_reset(hw);
	if (ret < 0) {
		PMD_LOG_ERR(INIT, "hw init failed, ret=%d", ret);
		goto l_end;
	}

	sxe_hw_start(hw);
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

	sxe_txrx_start(dev);
l_end:
	return ret;

l_error:
	PMD_LOG_ERR(INIT, "dev start err, ret=%d", ret);
	sxe_irq_vec_free(handle);
	sxe_txrx_queues_clear(dev, adapter->rx_batch_alloc_allowed);
	ret = -EIO;
	goto l_end;
}

#ifdef DPDK_19_11_6
static void sxe_dev_stop(struct rte_eth_dev *dev)
#else
static s32 sxe_dev_stop(struct rte_eth_dev *dev)
#endif
{
	s32 ret = 0;
	s32 num;
	struct rte_eth_link link;
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;

	PMD_INIT_FUNC_TRACE();

	sxe_hw_all_irq_disable(hw);

	ret = sxe_hw_reset(hw);
	if (ret < 0) {
		PMD_LOG_ERR(INIT, "hw init failed, ret=%d", ret);
		goto l_end;
	}

	sxe_irq_disable(dev);

	sxe_txrx_queues_clear(dev, adapter->rx_batch_alloc_allowed);

	dev->data->scattered_rx = 0;
	dev->data->lro = 0;
l_end:
	#ifdef DPDK_19_11_6
	LOG_DEBUG_BDF("at end of dev stop.");
#else
	return ret;
#endif
}

#ifdef DPDK_19_11_6
static void sxe_dev_close(struct rte_eth_dev *dev)
#else
static s32 sxe_dev_close(struct rte_eth_dev *dev)
#endif
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

#ifdef DPDK_19_11_6
	sxe_dev_stop(dev);
#else
	ret = sxe_dev_stop(dev);
	if (ret)
		PMD_LOG_ERR(INIT, "dev stop fail.(err:%d)", ret);
#endif

	sxe_queues_free(dev);

	sxe_irq_uninit(dev);

l_end:
#ifdef DPDK_19_11_6
	LOG_DEBUG_BDF("at end of dev close.");
#else
	return ret;
#endif
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

	dev_info->default_rxportconf.burst_size = 32;
	dev_info->default_txportconf.burst_size = 32;
	dev_info->default_rxportconf.nb_queues = 1;
	dev_info->default_txportconf.nb_queues = 1;
	dev_info->default_rxportconf.ring_size = 256;
	dev_info->default_txportconf.ring_size = 256;

	return 0;
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
#if defined DPDK_23_11_3 || defined DPDK_24_11_1
#ifndef DPDK_23_7
	.recycle_rxq_info_get	= sxe_recycle_rxq_info_get,
#endif
#endif

	.rx_queue_intr_enable	= sxe_rx_queue_intr_enable,
	.rx_queue_intr_disable	= sxe_rx_queue_intr_disable,

	.get_reg		= sxe_get_regs,

	.dev_supported_ptypes_get = sxe_dev_supported_ptypes_get,

	.set_queue_rate_limit	= sxe_queue_rate_limit_set,
#ifdef ETH_DEV_OPS_HAS_DESC_RELATE
	.rx_queue_count	   = sxe_rx_queue_count,
	.rx_descriptor_status = sxe_rx_descriptor_status,
	.tx_descriptor_status = sxe_tx_descriptor_status,
#ifdef ETH_DEV_RX_DESC_DONE
	.rx_descriptor_done   = sxe_rx_descriptor_done,
#endif
#endif
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

	ret = sxe_hw_reset(hw);
	if (ret) {
		PMD_LOG_ERR(INIT, "hw init failed, ret=%d", ret);
		goto l_out;
	} else {
		sxe_hw_start(hw);
	}

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

s32 sxe_ethdev_init(struct rte_eth_dev *eth_dev, void *param __rte_unused)
{
	s32 ret = 0;
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	struct sxe_adapter *adapter = eth_dev->data->dev_private;
#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_FILTER_CTRL
	struct sxe_filter_context *filter_info = &adapter->filter_ctxt;
#endif

	eth_dev->dev_ops = &sxe_eth_dev_ops;

#ifndef ETH_DEV_OPS_HAS_DESC_RELATE
	eth_dev->rx_queue_count	   = sxe_rx_queue_count;
	eth_dev->rx_descriptor_status = sxe_rx_descriptor_status;
	eth_dev->tx_descriptor_status = sxe_tx_descriptor_status;
#ifdef ETH_DEV_RX_DESC_DONE
	eth_dev->rx_descriptor_done   = sxe_rx_descriptor_done;
#endif
#endif

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
	rte_eth_copy_pci_info(eth_dev, pci_dev);

#ifdef DPDK_19_11_6
	eth_dev->data->dev_flags |= RTE_ETH_DEV_CLOSE_REMOVE;
#endif
	ret = sxe_hw_base_init(eth_dev);
	if (ret) {
		PMD_LOG_ERR(INIT, "hw base init fail.(err:%d)", ret);
		goto l_out;
	}

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

	if (!is_sxe_supported(dev)) {
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

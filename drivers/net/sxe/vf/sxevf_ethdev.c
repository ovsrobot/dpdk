/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SRIOV

#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <inttypes.h>

#include <ethdev_driver.h>
#include <ethdev_pci.h>
#include <bus_pci_driver.h>

#include <rte_ethdev.h>
#include <rte_kvargs.h>
#include <rte_common.h>
#include <rte_string_fns.h>

#include "sxevf.h"
#include "sxe_rx.h"
#include "sxe_logs.h"
#include "sxevf_msg.h"
#include "sxe_errno.h"
#include "sxevf_tx.h"
#include "sxevf_rx.h"
#include "sxevf_ethdev.h"
#include "sxevf_queue.h"
#include "sxevf_offload.h"
#include "sxe_compat_version.h"

#define SXEVF_ETH_OVERHEAD	 (RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN)
#define SXEVF_HKEY_MAX_INDEX   (10)
#define SXEVF_RSS_OFFLOAD_ALL ( \
	RTE_ETH_RSS_IPV4 | \
	RTE_ETH_RSS_NONFRAG_IPV4_TCP | \
	RTE_ETH_RSS_NONFRAG_IPV4_UDP | \
	RTE_ETH_RSS_IPV6 | \
	RTE_ETH_RSS_NONFRAG_IPV6_TCP | \
	RTE_ETH_RSS_NONFRAG_IPV6_UDP | \
	RTE_ETH_RSS_IPV6_EX | \
	RTE_ETH_RSS_IPV6_TCP_EX | \
	RTE_ETH_RSS_IPV6_UDP_EX)

#define SXEVF_DEFAULT_RX_FREE_THRESH  32
#define SXEVF_DEFAULT_RX_PTHRESH	  8
#define SXEVF_DEFAULT_RX_HTHRESH	  8
#define SXEVF_DEFAULT_RX_WTHRESH	  0

#define SXEVF_DEFAULT_TX_FREE_THRESH  32
#define SXEVF_DEFAULT_TX_PTHRESH	  32
#define SXEVF_DEFAULT_TX_HTHRESH	  0
#define SXEVF_DEFAULT_TX_WTHRESH	  0
#define SXEVF_DEFAULT_TX_RSBIT_THRESH 32

#define	SXEVF_MIN_RING_DESC	 32
#define	SXEVF_MAX_RING_DESC	 4096

#define	SXEVF_ALIGN			 128
#define SXEVF_RXD_ALIGN		(SXEVF_ALIGN / sizeof(sxevf_rx_data_desc_u))
#define SXEVF_TXD_ALIGN		(SXEVF_ALIGN / sizeof(sxevf_tx_data_desc_u))

#define SXEVF_TX_MAX_SEG			40
#define SXEVF_DEFAULT_TX_QUEUE_NUM  1
#define SXEVF_DEFAULT_RX_QUEUE_NUM  1
#define SXEVF_RX_BUF_MIN	  1024
#define SXEVF_RX_BUF_LEN_MAX  9728

static const struct rte_eth_desc_lim rx_desc_lim = {
	.nb_max = SXEVF_MAX_RING_DESC,
	.nb_min = SXEVF_MIN_RING_DESC,
	.nb_align = SXEVF_RXD_ALIGN,
};

static const struct rte_eth_desc_lim tx_desc_lim = {
	.nb_max = SXEVF_MAX_RING_DESC,
	.nb_min = SXEVF_MIN_RING_DESC,
	.nb_align = SXEVF_TXD_ALIGN,
	.nb_seg_max = SXEVF_TX_MAX_SEG,
	.nb_mtu_seg_max = SXEVF_TX_MAX_SEG,
};

static const char * const sxevf_valid_arguments[] = {
	SXEVF_DEVARG_LINK_CHECK,
	NULL
};

static s32 sxevf_devargs_handle(__rte_unused const char *key, const char *value,
		  void *extra_args)
{
	u16 *n = extra_args;
	s32 ret;

	if (value == NULL || extra_args == NULL) {
		ret = -EINVAL;
		LOG_ERROR("invalid args.(err:%d)", ret);
		goto l_out;
	}

	*n = (u16)strtoul(value, NULL, 0);
	if (*n == USHRT_MAX && errno == ERANGE) {
		ret = -ERANGE;
		LOG_ERROR("invalid args.(err:%d)", ret);
		goto l_out;
	}

	ret = 0;

l_out:
	return ret;
}

static void sxevf_devargs_parse(struct sxevf_adapter *adapter,
			  struct rte_devargs *devargs)
{
	struct rte_kvargs *kvlist;
	u16 check;

	if (devargs == NULL) {
		LOG_INFO_BDF("no dev args.");
		return;
	}

	kvlist = rte_kvargs_parse(devargs->args, sxevf_valid_arguments);
	if (kvlist == NULL)
		return;

	if (rte_kvargs_count(kvlist, SXEVF_DEVARG_LINK_CHECK) == 1 &&
		rte_kvargs_process(kvlist, SXEVF_DEVARG_LINK_CHECK,
				   sxevf_devargs_handle, &check) == 0 &&
		check == 1) {
		adapter->link_check = 1;
	}

	LOG_INFO_BDF("dev args link_check:%u", adapter->link_check);

	rte_kvargs_free(kvlist);
}

static s32 sxevf_hw_dev_reset(struct sxevf_hw *hw)
{
	u32 retry = SXEVF_RST_CHECK_NUM;
	s32 ret;
	struct sxevf_rst_msg msg = {};
	struct sxevf_adapter *adapter = hw->adapter;
	u8 *mac_addr = adapter->mac_filter_ctxt.def_mac_addr.addr_bytes;

	UNUSED(mac_addr);
	adapter->stop = true;

	sxevf_hw_stop(hw);

	/* Mail box init */
	sxevf_mbx_init(hw);


	sxevf_hw_reset(hw);

	while (!sxevf_pf_rst_check(hw) && retry) {
		retry--;
		sxe_udelay(5);
	}

	if (!retry) {
		ret = -SXEVF_ERR_RESET_FAILED;
		LOG_ERROR_BDF("retry: %u use up, pf has not reset done.(err:%d)",
						SXEVF_RST_CHECK_NUM, ret);
		goto l_out;
	}

	LOG_INFO_BDF("pf reset done.");

	hw->mbx.retry = SXEVF_MBX_RETRY_COUNT;

	sxevf_rxtx_reg_init(hw);

	/* Send reset message to pf */
	msg.msg_type = SXEVF_RESET;
	ret = sxevf_send_and_rcv_msg(hw, (u32 *)&msg,
					SXEVF_MSG_NUM(sizeof(msg)));
	if (ret) {
		LOG_ERROR_BDF("vf reset msg:%d len:%zu mailbox fail.(err:%d)",
			  msg.msg_type, SXEVF_MSG_NUM(sizeof(msg)), ret);
		goto l_out;
	}

	if (msg.msg_type == (SXEVF_RESET | SXEVF_MSGTYPE_ACK)) {
		memcpy(&adapter->mac_filter_ctxt.def_mac_addr,
			(u8 *)(msg.mac_addr), SXEVF_MAC_ADDR_LEN);
	}

	adapter->mac_filter_ctxt.mc_filter_type = msg.mc_fiter_type;

	LOG_INFO_BDF("vf get mc filter type:%d default mac addr:" RTE_ETHER_ADDR_PRT_FMT " from pf.",
		  adapter->mac_filter_ctxt.mc_filter_type,
		  mac_addr[0], mac_addr[1], mac_addr[2],
		  mac_addr[3], mac_addr[4], mac_addr[5]);

l_out:
	return ret;
}

static s32 sxevf_hw_base_init(struct rte_eth_dev *eth_dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	struct sxevf_adapter *adapter = eth_dev->data->dev_private;
	struct sxevf_hw *hw = &adapter->hw;
	s32 ret;

	hw->reg_base_addr = (void *)pci_dev->mem_resource[0].addr;
	PMD_LOG_INFO(INIT, "eth_dev[%u] got reg_base_addr=%p",
			eth_dev->data->port_id, hw->reg_base_addr);
	hw->adapter = adapter;

	strlcpy(adapter->name, pci_dev->device.name, sizeof(adapter->name) - 1);
	adapter->stop = true;

	adapter->max_rx_queue = SXEVF_DEFAULT_RX_QUEUE_NUM;
	adapter->max_tx_queue = SXEVF_DEFAULT_TX_QUEUE_NUM;

	ret = sxevf_hw_dev_reset(hw);
	if (ret < 0) {
		PMD_LOG_ERR(INIT, "hw dev reset failed, ret=%d", ret);
		goto l_out;
	} else {
		adapter->stop = false;
	}

	ret = sxevf_mac_addr_init(eth_dev);
	if (ret) {
		PMD_LOG_ERR(INIT, "mac addr init fail, ret=%d", ret);
		goto l_out;
	}

l_out:
	return ret;
}

static void sxevf_txrx_start(struct rte_eth_dev *eth_dev)
{
	struct sxevf_adapter *adapter = eth_dev->data->dev_private;
	struct sxevf_hw *hw = &adapter->hw;
	sxevf_tx_queue_s *txq;
	sxevf_rx_queue_s *rxq;
	u16 i;

	for (i = 0; i < eth_dev->data->nb_tx_queues; i++) {
		txq = eth_dev->data->tx_queues[i];
		sxevf_tx_ring_switch(hw, txq->reg_idx, true);
		eth_dev->data->tx_queue_state[i] = RTE_ETH_QUEUE_STATE_STARTED;

	}

	for (i = 0; i < eth_dev->data->nb_rx_queues; i++) {
		rxq = eth_dev->data->rx_queues[i];
		sxevf_rx_ring_switch(hw, rxq->reg_idx, true);
		eth_dev->data->rx_queue_state[i] = RTE_ETH_QUEUE_STATE_STARTED;
		rte_wmb();

		sxevf_rx_desc_tail_set(hw, rxq->reg_idx, rxq->ring_depth - 1);
	}
}

static s32 sxevf_dev_start(struct rte_eth_dev *dev)
{
	s32 ret;
	struct sxevf_adapter *adapter = dev->data->dev_private;
	struct sxevf_stats_info *stats_info = &adapter->stats_info;
	struct sxevf_hw *hw = &adapter->hw;

	PMD_INIT_FUNC_TRACE();

	ret = sxevf_hw_dev_reset(hw);
	if (ret) {
		LOG_ERROR_BDF("dev reset fail.");
		goto l_out;
	}

	sxevf_mbx_api_version_init(adapter);

	sxevf_tx_configure(dev);

	ret = sxevf_rx_configure(dev);
	if (ret) {
		LOG_ERROR_BDF("rx configure fail.(err:%d)", ret);
		goto l_clear_queue;
	}

	sxevf_vlan_filter_configure(dev);

	sxevf_txrx_start(dev);

	sxevf_irq_configure(dev);

	sxevf_stats_init_value_get(hw, &stats_info->hw_stats);

	adapter->stop = false;

l_out:
	return ret;

l_clear_queue:
	sxevf_txrx_queues_clear(dev, adapter->rx_batch_alloc_allowed);
	return ret;
}

static s32 sxevf_dev_stop(struct rte_eth_dev *dev)
{
	struct sxevf_adapter *adapter = dev->data->dev_private;
	struct sxevf_hw *hw = &adapter->hw;

	PMD_INIT_FUNC_TRACE();

	if (adapter->stop) {
		LOG_INFO_BDF("eth dev has been stopped.");
		goto l_out;
	}

	adapter->stop = false;
	dev->data->dev_started = false;
	dev->data->scattered_rx = false;

	sxevf_hw_stop(hw);

	sxevf_vfta_sync(dev, false);

	sxevf_txrx_queues_clear(dev, adapter->rx_batch_alloc_allowed);

	sxevf_irq_free(dev);

l_out:
	return 0;
}

static s32 sxevf_dev_close(struct rte_eth_dev *dev)
{
	s32 ret = 0;
	struct sxevf_adapter *adapter = dev->data->dev_private;
	struct sxevf_stats_info *stats_info = &adapter->stats_info;
	struct sxevf_hw *hw = &adapter->hw;

	PMD_INIT_FUNC_TRACE();
	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		LOG_INFO_BDF("secondery procee can't close dev.");
		goto l_out;
	}

	ret = sxevf_hw_dev_reset(hw);
	if (ret)
		LOG_ERROR_BDF("dev reset fail.");

	sxevf_dev_stop(dev);

	sxevf_stats_init_value_get(hw, &stats_info->hw_stats);

	sxevf_queues_free(dev);

	sxevf_irq_unregister(dev);

l_out:
	return ret;
}

static s32 sxevf_dev_reset(struct rte_eth_dev *dev)
{
	s32 ret;

	ret = sxevf_ethdev_uninit(dev);
	if (ret) {
		PMD_LOG_ERR(INIT, "dev uninit fail.");
		goto l_out;
	}

	ret = sxevf_ethdev_init(dev);
	if (ret)
		PMD_LOG_ERR(INIT, "dev init fail.");

l_out:
	return ret;
}

static s32 sxevf_dev_info_get(struct rte_eth_dev *dev,
			 struct rte_eth_dev_info *dev_info)
{
	struct sxevf_adapter *adapter = dev->data->dev_private;
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(dev);

	dev_info->max_rx_queues = adapter->max_rx_queue;
	dev_info->max_tx_queues = adapter->max_tx_queue;
	dev_info->min_rx_bufsize = SXEVF_RX_BUF_MIN;
	dev_info->max_rx_pktlen = SXEVF_RX_BUF_LEN_MAX;
	dev_info->max_mtu = dev_info->max_rx_pktlen - SXEVF_ETH_OVERHEAD;
	dev_info->max_mac_addrs = adapter->mac_filter_ctxt.uc_table_size;
	dev_info->max_hash_mac_addrs = SXEVF_UTA_HASH_BIT_MAX;
	dev_info->max_vfs = pci_dev->max_vfs;
	dev_info->max_vmdq_pools = RTE_ETH_64_POOLS;

	dev_info->rx_queue_offload_capa = sxevf_rx_queue_offloads_get(dev);
	dev_info->rx_offload_capa = (sxevf_rx_port_offloads_get(dev) |
					 dev_info->rx_queue_offload_capa);
	dev_info->tx_queue_offload_capa = sxevf_tx_queue_offloads_get(dev);
	dev_info->tx_offload_capa = sxevf_tx_port_offloads_get(dev);

	dev_info->hash_key_size = SXEVF_HKEY_MAX_INDEX * sizeof(u32);
	dev_info->reta_size = 0;
	dev_info->flow_type_rss_offloads = SXEVF_RSS_OFFLOAD_ALL;

	dev_info->default_rxconf = (struct rte_eth_rxconf) {
		.rx_thresh = {
			.pthresh = SXEVF_DEFAULT_RX_PTHRESH,
			.hthresh = SXEVF_DEFAULT_RX_HTHRESH,
			.wthresh = SXEVF_DEFAULT_RX_WTHRESH,
		},
		.rx_free_thresh = SXEVF_DEFAULT_RX_FREE_THRESH,
		.rx_drop_en = 0,
		.offloads = 0,
	};

	dev_info->default_txconf = (struct rte_eth_txconf) {
		.tx_thresh = {
			.pthresh = SXEVF_DEFAULT_TX_PTHRESH,
			.hthresh = SXEVF_DEFAULT_TX_HTHRESH,
			.wthresh = SXEVF_DEFAULT_TX_WTHRESH,
		},
		.tx_free_thresh = SXEVF_DEFAULT_TX_FREE_THRESH,
		.tx_rs_thresh = SXEVF_DEFAULT_TX_RSBIT_THRESH,
		.offloads = 0,
	};

	dev_info->rx_desc_lim = rx_desc_lim;
	dev_info->tx_desc_lim = tx_desc_lim;

	dev_info->err_handle_mode = RTE_ETH_ERROR_HANDLE_MODE_PASSIVE;

	return 0;
}

static s32 sxevf_mtu_set(struct rte_eth_dev *dev, u16 mtu)
{
	struct sxevf_adapter *adapter = dev->data->dev_private;
	struct sxevf_hw *hw = &adapter->hw;
	u32 max_frame = mtu + SXEVF_ETH_OVERHEAD;
	s32 ret;

	if (mtu < RTE_ETHER_MIN_MTU ||
			max_frame > RTE_ETHER_MAX_JUMBO_FRAME_LEN) {
		ret = -EINVAL;
		LOG_ERROR_BDF("invalid mtu:%u.", mtu);
		goto l_out;
	}

	if (dev->data->dev_started && !dev->data->scattered_rx &&
		((max_frame + 2 * SXEVF_VLAN_TAG_SIZE) >
		 (dev->data->min_rx_buf_size - RTE_PKTMBUF_HEADROOM))) {
		ret = -EINVAL;
		LOG_ERROR_BDF("max_frame:%u stop port first.(err:%d)",
				  max_frame, ret);
		goto l_out;
	}

	ret = sxevf_rx_max_frame_set(hw, mtu);
	if (ret) {
		LOG_ERROR_BDF("max_frame:%u set fail.(err:%d)", max_frame, ret);
		ret = -EINVAL;
		goto l_out;
	}

	LOG_INFO_BDF("change max frame size to %u success.", max_frame);

l_out:
	return ret;
}

static s32 sxevf_dev_configure(struct rte_eth_dev *dev)
{
	struct rte_eth_conf *conf = &dev->data->dev_conf;
	struct sxevf_adapter *adapter = dev->data->dev_private;

	LOG_INFO_BDF("Configured Virtual Function port id: %d",
			 dev->data->port_id);

	if (dev->data->dev_conf.rxmode.mq_mode & RTE_ETH_MQ_RX_RSS_FLAG)
		dev->data->dev_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_RSS_HASH;

#ifndef RTE_LIBRTE_SXEVF_PF_DISABLE_STRIP_CRC
	if (conf->rxmode.offloads & RTE_ETH_RX_OFFLOAD_KEEP_CRC) {
		LOG_INFO_BDF("VF can't disable HW CRC Strip");
		conf->rxmode.offloads &= ~RTE_ETH_RX_OFFLOAD_KEEP_CRC;
	}
#else
	if (!(conf->rxmode.offloads & RTE_ETH_RX_OFFLOAD_KEEP_CRC)) {
		LOG_INFO_BDF("VF can't enable HW CRC Strip");
		conf->rxmode.offloads |= RTE_ETH_RX_OFFLOAD_KEEP_CRC;
	}
#endif

	adapter->rx_batch_alloc_allowed = true;

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SIMD
	adapter->rx_vec_allowed = true;
#endif

	return 0;
}

static const struct sxevf_reg_info sxevf_regs_general[] = {
	{SXE_VFCTRL, 1, 1, "SXE_VFCTRL"},
	{SXE_VFSTATUS, 1, 1, "SXE_VFSTATUS"},
	{SXE_VFLINKS, 1, 1, "SXE_VFLINKS"},
	{SXE_VFFRTIMER, 1, 1, "SXE_VFFRTIMER"},
	{SXE_VFMAILBOX, 1, 1, "SXE_VFMAILBOX"},
	{SXE_VFMBMEM, 16, 4, "SXE_VFMBMEM"},
	{SXE_VFRXMEMWRAP, 1, 1, "SXE_VFRXMEMWRAP"},
	{0, 0, 0, ""}
};

static const struct sxevf_reg_info sxevf_regs_interrupt[] = {
	{SXE_VFEICR, 1, 1, "SXE_VFEICR"},
	{SXE_VFEICS, 1, 1, "SXE_VFEICS"},
	{SXE_VFEIMS, 1, 1, "SXE_VFEIMS"},
	{SXE_VFEIMC, 1, 1, "SXE_VFEIMC"},
	{SXE_VFEIAM, 1, 1, "SXE_VFEIAM"},
	{SXE_VFEITR(0), 2, 4, "SXE_VFEITR"},
	{SXE_VFIVAR(0), 4, 4, "SXE_VFIVAR"},
	{SXE_VFIVAR_MISC, 1, 1, "SXE_VFIVAR_MISC"},
	{0, 0, 0, ""}
};

static const struct sxevf_reg_info sxevf_regs_rxdma[] = {
	{SXE_VFRDBAL(0), 8, 0x40, "SXE_VFRDBAL"},
	{SXE_VFRDBAH(0), 8, 0x40, "SXE_VFRDBAH"},
	{SXE_VFRDLEN(0), 8, 0x40, "SXE_VFRDLEN"},
	{SXE_VFRDH(0), 8, 0x40, "SXE_VFRDH"},
	{SXE_VFRDT(0), 8, 0x40, "SXE_VFRDT"},
	{SXE_VFRXDCTL(0), 8, 0x40, "SXE_VFRXDCTL"},
	{SXE_VFSRRCTL(0), 8, 0x40, "SXE_VFSRRCTL"},
	{SXE_VFPSRTYPE, 1, 1,	"SXE_VFPSRTYPE"},
	{SXE_VFLROCTL(0), 8, 0x40, "SXE_VFRSCCTL"},
	{SXE_VFDCA_RXCTRL(0), 8, 0x40, "SXE_VFDCA_RXCTRL"},
	{SXE_VFDCA_TXCTRL(0), 8, 0x40, "SXE_VFDCA_TXCTRL"},
	{0, 0, 0, ""}
};

static const struct sxevf_reg_info sxevf_regs_tx[] = {
	{SXE_VFTDBAL(0), 4, 0x40, "SXE_VFTDBAL"},
	{SXE_VFTDBAH(0), 4, 0x40, "SXE_VFTDBAH"},
	{SXE_VFTDLEN(0), 4, 0x40, "SXE_VFTDLEN"},
	{SXE_VFTDH(0), 4, 0x40, "SXE_VFTDH"},
	{SXE_VFTDT(0), 4, 0x40, "SXE_VFTDT"},
	{SXE_VFTXDCTL(0), 4, 0x40, "SXE_VFTXDCTL"},
	{SXE_VFTDWBAL(0), 4, 0x40, "SXE_VFTDWBAL"},
	{SXE_VFTDWBAH(0), 4, 0x40, "SXE_VFTDWBAH"},
	{0, 0, 0, ""}
};

static const struct sxevf_reg_info *sxevf_regs_group[] = {
				sxevf_regs_general,
				sxevf_regs_interrupt,
				sxevf_regs_rxdma,
				sxevf_regs_tx,
				NULL};

static u32 sxevf_regs_group_count(const struct sxevf_reg_info *regs)
{
	int i = 0;
	int count = 0;

	while (regs[i].count)
		count += regs[i++].count;

	return count;
};

u32 sxevf_regs_group_num_get(void)
{
	u32 i = 0;
	u32 count = 0;
	const struct sxevf_reg_info *reg_group;
	const struct sxevf_reg_info **reg_set = sxevf_regs_group;

	while ((reg_group = reg_set[i++]))
		count += sxevf_regs_group_count(reg_group);

	PMD_LOG_INFO(INIT, "read regs cnt=%u", count);

	return count;
}

void sxevf_regs_group_read(struct sxevf_hw *hw, u32 *data)
{
	u32 cnt = 0, i = 0;
	const struct sxevf_reg_info *reg_group;
	const struct sxevf_reg_info **reg_set = sxevf_regs_group;

	while ((reg_group = reg_set[i++]))
		cnt += sxevf_hw_regs_group_read(hw, reg_group, &data[cnt]);

	PMD_LOG_INFO(INIT, "read regs cnt=%u, regs num=%u",
				 cnt, sxevf_regs_group_num_get());
}

static int sxevf_get_regs(struct rte_eth_dev *dev,
		  struct rte_dev_reg_info *regs)
{
	s32 ret = 0;
	u32 *data = regs->data;
	struct sxevf_adapter *adapter = dev->data->dev_private;
	struct sxevf_hw *hw = &adapter->hw;
	u32 length = sxevf_regs_group_num_get();

	if (data == NULL) {
		regs->length = length;
		regs->width = sizeof(u32);
		goto l_end;
	}

	if (regs->length == 0 || regs->length == length) {
		sxevf_regs_group_read(hw, data);

		goto l_end;
	}

	ret = -ENOTSUP;
	PMD_LOG_ERR(INIT, "get regs: inval param: regs_len=%u, regs->data=%p, "
			  "regs_offset=%u,  regs_width=%u, regs_version=%u",
			  regs->length, regs->data,
			  regs->offset, regs->width,
			  regs->version);

l_end:
	return ret;
}

static const struct eth_dev_ops sxevf_eth_dev_ops = {
	.dev_configure		= sxevf_dev_configure,
	.dev_start		= sxevf_dev_start,
	.dev_stop		= sxevf_dev_stop,
	.link_update		= sxevf_link_update,
	.stats_get		= sxevf_eth_stats_get,
	.xstats_get		= sxevf_xstats_get,
	.stats_reset		= sxevf_dev_stats_reset,
	.xstats_reset		= sxevf_dev_stats_reset,
	.xstats_get_names	= sxevf_xstats_names_get,
	.dev_close		= sxevf_dev_close,
	.dev_reset		= sxevf_dev_reset,
	.promiscuous_enable	= sxevf_promiscuous_enable,
	.promiscuous_disable	= sxevf_promiscuous_disable,
	.allmulticast_enable	= sxevf_allmulticast_enable,
	.allmulticast_disable	= sxevf_allmulticast_disable,
	.dev_infos_get		= sxevf_dev_info_get,
	.dev_supported_ptypes_get = sxevf_dev_supported_ptypes_get,
	.mtu_set		= sxevf_mtu_set,
	.vlan_filter_set	= sxevf_vlan_filter_set,
	.vlan_strip_queue_set	= sxevf_vlan_strip_queue_set,
	.vlan_offload_set	= sxevf_vlan_offload_set,
	.rx_queue_setup		= sxevf_rx_queue_setup,
	.rx_queue_release	= sxevf_rx_queue_release,
	.tx_queue_setup		= sxevf_tx_queue_setup,
	.tx_queue_release	= sxevf_tx_queue_release,
	.rx_queue_intr_enable	= sxevf_rx_queue_intr_enable,
	.rx_queue_intr_disable	= sxevf_rx_queue_intr_disable,
	.mac_addr_add		= sxevf_mac_addr_add,
	.mac_addr_remove	= sxevf_mac_addr_remove,
	.set_mc_addr_list	= sxevf_set_mc_addr_list,
	.rxq_info_get		= sxevf_rx_queue_info_get,
	.txq_info_get		= sxevf_tx_queue_info_get,
	.mac_addr_set		= sxevf_default_mac_addr_set,
	.get_reg		= sxevf_get_regs,
	.reta_update		= sxevf_rss_reta_update,
	.reta_query		= sxevf_rss_reta_query,
	.rss_hash_update	= sxevf_rss_hash_update,
	.rss_hash_conf_get	= sxevf_rss_hash_conf_get,
	.tx_done_cleanup	= sxevf_tx_done_cleanup,
	.get_monitor_addr	= sxe_monitor_addr_get,
};

s32 sxevf_ethdev_init(struct rte_eth_dev *eth_dev)
{
	s32 ret = 0;
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	struct sxevf_adapter *adapter = eth_dev->data->dev_private;
	struct sxevf_stats_info *stats_info = &adapter->stats_info;
	struct sxevf_hw *hw = &adapter->hw;
	u8 default_tc;
	u8 tc_num;

	PMD_INIT_FUNC_TRACE();

	eth_dev->dev_ops = &sxevf_eth_dev_ops;

	eth_dev->rx_descriptor_status = sxevf_rx_descriptor_status;
	eth_dev->tx_descriptor_status = sxevf_tx_descriptor_status;

	eth_dev->rx_pkt_burst = &sxevf_pkts_recv;
	eth_dev->tx_pkt_burst = &sxevf_pkts_xmit_with_offload;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		sxevf_secondary_proc_init(eth_dev);
		goto l_out;
	}

	sxevf_devargs_parse(eth_dev->data->dev_private,
				  pci_dev->device.devargs);

	rte_eth_copy_pci_info(eth_dev, pci_dev);

	eth_dev->data->dev_flags |= RTE_ETH_DEV_AUTOFILL_QUEUE_XSTATS;

	ret = sxevf_hw_base_init(eth_dev);
	if (ret) {
		ret = -EIO;
		LOG_ERROR_BDF("hw base init fail.(err:%d)", ret);
		goto l_out;
	}

	sxevf_dev_stats_reset(eth_dev);

	sxevf_stats_init_value_get(hw, &stats_info->hw_stats);

	sxevf_mbx_api_version_init(adapter);

	sxevf_ring_info_get(adapter, &default_tc, &tc_num);

	sxevf_irq_init(eth_dev);

	LOG_INFO_BDF("sxevf eth dev init done.");

l_out:
	return ret;
}

s32 sxevf_ethdev_uninit(struct rte_eth_dev *eth_dev)
{
	s32 ret = 0;

	PMD_INIT_FUNC_TRACE();
	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		PMD_LOG_WARN(INIT, "secondery procee can't unint.");
		goto l_out;
	}

	sxevf_dev_close(eth_dev);

l_out:
	return ret;
}

#endif

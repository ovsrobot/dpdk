/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Realtek Corporation. All rights reserved
 */

#include <sys/queue.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>

#include <rte_eal.h>

#include <rte_string_fns.h>
#include <rte_common.h>
#include <rte_interrupts.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_pci.h>
#include <bus_pci_driver.h>
#include <rte_ether.h>
#include <ethdev_driver.h>
#include <ethdev_pci.h>
#include <rte_memory.h>
#include <rte_malloc.h>
#include <dev_driver.h>

#include "r8125_ethdev.h"
#include "r8125_hw.h"
#include "r8125_phy.h"
#include "r8125_logs.h"
#include "r8125_dash.h"

static int rtl8125_dev_start(struct rte_eth_dev *dev);
static int rtl8125_dev_stop(struct rte_eth_dev *dev);
static int rtl8125_dev_reset(struct rte_eth_dev *dev);
static int rtl8125_dev_set_link_up(struct rte_eth_dev *dev);
static int rtl8125_dev_set_link_down(struct rte_eth_dev *dev);
static int rtl8125_dev_close(struct rte_eth_dev *dev);
static int rtl8125_dev_configure(struct rte_eth_dev *dev __rte_unused);

static int rtl8125_fw_version_get(struct rte_eth_dev *dev, char *fw_version,
                                  size_t fw_size);
static int rtl8125_dev_infos_get(struct rte_eth_dev *dev,
                                 struct rte_eth_dev_info *dev_info);
static int rtl8125_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu);

static int rtl8125_promiscuous_enable(struct rte_eth_dev *dev);
static int rtl8125_promiscuous_disable(struct rte_eth_dev *dev);
static int rtl8125_allmulticast_enable(struct rte_eth_dev *dev);
static int rtl8125_allmulticast_disable(struct rte_eth_dev *dev);

static void rtl8125_dev_interrupt_handler(void *param);

static int rtl8125_dev_link_update(struct rte_eth_dev *dev,
                                   int wait __rte_unused);
static int rtl8125_dev_stats_get(struct rte_eth_dev *dev,
                                 struct rte_eth_stats *rte_stats);
static int rtl8125_dev_stats_reset(struct rte_eth_dev *dev);

/*
 * The set of PCI devices this driver supports
 */
static const struct rte_pci_id pci_id_r8125_map[] = {
	{ RTE_PCI_DEVICE(R8125_REALTEK_VENDOR_ID, 0x8125) },
	{ RTE_PCI_DEVICE(R8125_REALTEK_VENDOR_ID, 0x8162) },
	{ RTE_PCI_DEVICE(R8125_REALTEK_VENDOR_ID, 0x3000) },
	{ .vendor_id = 0, /* sentinel */ },
};


static const struct rte_eth_desc_lim rx_desc_lim = {
	.nb_max   = R8125_MAX_RX_DESC,
	.nb_min   = R8125_MIN_RX_DESC,
	.nb_align = R8125_DESC_ALIGN,
};

static const struct rte_eth_desc_lim tx_desc_lim = {
	.nb_max         = R8125_MAX_TX_DESC,
	.nb_min         = R8125_MIN_TX_DESC,
	.nb_align       = R8125_DESC_ALIGN,
	.nb_seg_max     = R8125_MAX_TX_SEG,
	.nb_mtu_seg_max = R8125_MAX_TX_SEG,
};

static const struct eth_dev_ops rtl8125_eth_dev_ops = {
	.dev_configure	      = rtl8125_dev_configure,
	.dev_start	      = rtl8125_dev_start,
	.dev_stop	      = rtl8125_dev_stop,
	.dev_set_link_up      = rtl8125_dev_set_link_up,
	.dev_set_link_down    = rtl8125_dev_set_link_down,
	.dev_close	      = rtl8125_dev_close,
	.dev_reset	      = rtl8125_dev_reset,

	.promiscuous_enable   = rtl8125_promiscuous_enable,
	.promiscuous_disable  = rtl8125_promiscuous_disable,
	.allmulticast_enable  = rtl8125_allmulticast_enable,
	.allmulticast_disable = rtl8125_allmulticast_disable,

	.link_update          = rtl8125_dev_link_update,
	.stats_get            = rtl8125_dev_stats_get,
	.stats_reset          = rtl8125_dev_stats_reset,

	.fw_version_get       = rtl8125_fw_version_get,
	.dev_infos_get        = rtl8125_dev_infos_get,

	.mtu_set              = rtl8125_dev_mtu_set,

	.rx_queue_setup       = rtl8125_rx_queue_setup,
	.rx_queue_release     = rtl8125_rx_queue_release,
	.rxq_info_get         = rtl8125_rxq_info_get,

	.tx_queue_setup       = rtl8125_tx_queue_setup,
	.tx_queue_release     = rtl8125_tx_queue_release,
	.tx_done_cleanup      = rtl8125_tx_done_cleanup,
	.txq_info_get         = rtl8125_txq_info_get,
};

static int
rtl8125_dev_configure(struct rte_eth_dev *dev __rte_unused)
{
	return 0;
}

static int
rtl8125_fw_version_get(struct rte_eth_dev *dev, char *fw_version,
                       size_t fw_size)
{
	struct rtl8125_adapter *adapter = RTL8125_DEV_PRIVATE(dev);
	struct rtl8125_hw *hw = &adapter->hw;
	int ret;

	ret = snprintf(fw_version, fw_size, "0x%08x", hw->hw_ram_code_ver);

	ret += 1; /* Add the size of '\0' */
	if (fw_size < (u32)ret)
		return ret;
	else
		return 0;
}

static int
rtl8125_dev_infos_get(struct rte_eth_dev *dev __rte_unused,
                      struct rte_eth_dev_info *dev_info)
{
	dev_info->min_rx_bufsize = 1024;
	dev_info->max_rx_pktlen = Jumbo_Frame_9k;
	dev_info->max_mac_addrs = 1;

	dev_info->max_rx_queues = 1;
	dev_info->max_tx_queues = 1;

	dev_info->default_rxconf = (struct rte_eth_rxconf) {
		.rx_free_thresh = R8125_RX_FREE_THRESH,
	};

	dev_info->default_txconf = (struct rte_eth_txconf) {
		.tx_free_thresh = R8125_TX_FREE_THRESH,
	};

	dev_info->rx_desc_lim = rx_desc_lim;
	dev_info->tx_desc_lim = tx_desc_lim;

	dev_info->speed_capa = RTE_ETH_LINK_SPEED_10M_HD | RTE_ETH_LINK_SPEED_10M |
	                       RTE_ETH_LINK_SPEED_100M_HD | RTE_ETH_LINK_SPEED_100M |
	                       RTE_ETH_LINK_SPEED_1G | RTE_ETH_LINK_SPEED_2_5G;

	dev_info->min_mtu = RTE_ETHER_MIN_MTU;
	dev_info->max_mtu = dev_info->max_rx_pktlen - R8125_ETH_OVERHEAD;

	dev_info->rx_offload_capa = (rtl8125_get_rx_port_offloads() |
	                             dev_info->rx_queue_offload_capa);
	dev_info->tx_offload_capa = rtl8125_get_tx_port_offloads();

	return 0;
}

static int
rtl8125_dev_stats_reset(struct rte_eth_dev *dev)
{

	struct rtl8125_adapter *adapter = RTL8125_DEV_PRIVATE(dev);
	struct rtl8125_hw *hw = &adapter->hw;

	rtl8125_clear_tally_stats(hw);

	memset(&adapter->sw_stats, 0, sizeof(adapter->sw_stats));

	return 0;
}

static void
rtl8125_sw_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *rte_stats)
{
	struct rtl8125_adapter *adapter = RTL8125_DEV_PRIVATE(dev);
	struct rtl8125_sw_stats *sw_stats = &adapter->sw_stats;

	rte_stats->ibytes = sw_stats->rx_bytes;
	rte_stats->obytes = sw_stats->tx_bytes;
}

static int
rtl8125_dev_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *rte_stats)
{
	struct rtl8125_adapter *adapter = RTL8125_DEV_PRIVATE(dev);
	struct rtl8125_hw *hw = &adapter->hw;

	if (rte_stats == NULL)
		return -EINVAL;

	rtl8125_get_tally_stats(hw, rte_stats);
	rtl8125_sw_stats_get(dev, rte_stats);

	return 0;
}

/* Return 0 means link status changed, -1 means not changed */
static int
rtl8125_dev_link_update(struct rte_eth_dev *dev, int wait __rte_unused)
{
	struct rte_eth_link link, old;
	struct rtl8125_adapter *adapter = RTL8125_DEV_PRIVATE(dev);
	struct rtl8125_hw *hw = &adapter->hw;
	u32 speed;
	u16 status;

	link.link_status = RTE_ETH_LINK_DOWN;
	link.link_speed = 0;
	link.link_duplex = RTE_ETH_LINK_FULL_DUPLEX;
	link.link_autoneg = RTE_ETH_LINK_AUTONEG;

	memset(&old, 0, sizeof(old));

	/* Load old link status */
	rte_eth_linkstatus_get(dev, &old);

	/* Read current link status */
	status = RTL_R16(hw, PHYstatus);

	if (status & LinkStatus) {
		link.link_status = RTE_ETH_LINK_UP;

		if (status & FullDup) {
			link.link_duplex = RTE_ETH_LINK_FULL_DUPLEX;
			if (hw->mcfg == CFG_METHOD_2)
				RTL_W32(hw, TxConfig, (RTL_R32(hw, TxConfig) |
				                       (BIT_24 | BIT_25)) & ~BIT_19);

		} else {
			link.link_duplex = RTE_ETH_LINK_HALF_DUPLEX;
			if (hw->mcfg == CFG_METHOD_2)
				RTL_W32(hw, TxConfig, (RTL_R32(hw, TxConfig) | BIT_25) &
				        ~(BIT_19 | BIT_24));
		}

		if (status & _2500bpsF)
			speed = 2500;
		else if (status & _1000bpsF)
			speed = 1000;
		else if (status & _100bps)
			speed = 100;
		else
			speed = 10;

		link.link_speed = speed;
	}

	if (link.link_status == old.link_status)
		return -1;

	rte_eth_linkstatus_set(dev, &link);

	return 0;
}

static int
rtl8125_dev_set_link_up(struct rte_eth_dev *dev)
{
	struct rtl8125_adapter *adapter = RTL8125_DEV_PRIVATE(dev);
	struct rtl8125_hw *hw = &adapter->hw;

	rtl8125_powerup_pll(hw);

	return 0;
}

static int
rtl8125_dev_set_link_down(struct rte_eth_dev *dev)
{
	struct rtl8125_adapter *adapter = RTL8125_DEV_PRIVATE(dev);
	struct rtl8125_hw *hw = &adapter->hw;

	/* Mcu pme intr masks */
	switch (hw->mcfg) {
	case CFG_METHOD_2 ... CFG_METHOD_11:
		rtl8125_mac_ocp_write(hw, 0xE00A, hw->mcu_pme_setting & ~(BIT_11 | BIT_14));
		break;
	}

	rtl8125_powerdown_pll(hw);

	return 0;
}

static int
rtl8125_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu)
{
	struct rte_eth_dev_info dev_info;
	struct rtl8125_adapter *adapter = RTL8125_DEV_PRIVATE(dev);
	struct rtl8125_hw *hw = &adapter->hw;
	int ret;
	uint32_t frame_size = mtu + R8125_ETH_OVERHEAD;

	ret = rtl8125_dev_infos_get(dev, &dev_info);
	if (ret != 0)
		return ret;

	if (mtu < RTE_ETHER_MIN_MTU || frame_size > dev_info.max_rx_pktlen)
		return -EINVAL;

	hw->mtu = mtu;

	RTL_W16(hw, RxMaxSize, frame_size);

	return 0;
}

static int
rtl8125_promiscuous_enable(struct rte_eth_dev *dev)
{
	struct rtl8125_adapter *adapter = RTL8125_DEV_PRIVATE(dev);
	struct rtl8125_hw *hw = &adapter->hw;

	int rx_mode = AcceptBroadcast | AcceptMulticast | AcceptMyPhys | AcceptAllPhys;

	RTL_W32(hw, RxConfig, rx_mode | RTL_R32(hw, RxConfig));
	RTL_W32(hw, MAR0 + 0, 0xffffffff);
	RTL_W32(hw, MAR0 + 4, 0xffffffff);

	return 0;
}

static int
rtl8125_promiscuous_disable(struct rte_eth_dev *dev)
{
	struct rtl8125_adapter *adapter = RTL8125_DEV_PRIVATE(dev);
	struct rtl8125_hw *hw = &adapter->hw;
	int rx_mode = ~AcceptAllPhys;

	RTL_W32(hw, RxConfig, rx_mode & RTL_R32(hw, RxConfig));

	if (dev->data->all_multicast == 1) {
		RTL_W32(hw, MAR0 + 0, 0xffffffff);
		RTL_W32(hw, MAR0 + 4, 0xffffffff);
	}

	return 0;
}

static int
rtl8125_allmulticast_enable(struct rte_eth_dev *dev)
{
	struct rtl8125_adapter *adapter = RTL8125_DEV_PRIVATE(dev);
	struct rtl8125_hw *hw = &adapter->hw;

	RTL_W32(hw, MAR0 + 0, 0xffffffff);
	RTL_W32(hw, MAR0 + 4, 0xffffffff);

	return 0;
}

static int
rtl8125_allmulticast_disable(struct rte_eth_dev *dev)
{
	struct rtl8125_adapter *adapter = RTL8125_DEV_PRIVATE(dev);
	struct rtl8125_hw *hw = &adapter->hw;

	if (dev->data->promiscuous == 1)
		return 0; /* Must remain in all_multicast mode */

	RTL_W32(hw, MAR0 + 0, 0);
	RTL_W32(hw, MAR0 + 4, 0);

	return 0;
}

static void
rtl8125_disable_intr(struct rtl8125_hw *hw)
{
	PMD_INIT_FUNC_TRACE();
	RTL_W32(hw, IMR0_8125, 0x0000);
	RTL_W32(hw, ISR0_8125, RTL_R32(hw, ISR0_8125));
}

static void
rtl8125_enable_intr(struct rtl8125_hw *hw)
{
	PMD_INIT_FUNC_TRACE();
	RTL_W32(hw, IMR0_8125, LinkChg);
}

static void
rtl8125_hw_init(struct rtl8125_hw *hw)
{
	switch (hw->mcfg) {
	case CFG_METHOD_2 ... CFG_METHOD_11:
		rtl8125_enable_aspm_clkreq_lock(hw, 0);
		rtl8125_enable_force_clkreq(hw, 0);
		break;
	}

	rtl8125_disable_ups(hw);

	hw->hw_ops.hw_mac_mcu_config(hw);

	/* Disable ocp phy power saving */
	rtl8125_disable_ocp_phy_power_saving(hw);
}

static void
rtl8125_hw_ephy_config(struct rtl8125_hw *hw)
{
	hw->hw_ops.hw_ephy_config(hw);
}

static void
rtl8125_disable_eee_plus(struct rtl8125_hw *hw)
{
	switch (hw->mcfg) {
	case CFG_METHOD_2 ... CFG_METHOD_11:
		rtl8125_mac_ocp_write(hw, 0xE080, rtl8125_mac_ocp_read(hw, 0xE080) & ~BIT_1);
		break;
	default:
		/* Not support EEEPlus */
		break;
	}
}

static void
rtl8125_hw_clear_timer_int(struct rtl8125_hw *hw)
{
	switch (hw->mcfg) {
	case CFG_METHOD_2 ... CFG_METHOD_11:
		RTL_W32(hw, TIMER_INT0_8125, 0x0000);
		RTL_W32(hw, TIMER_INT1_8125, 0x0000);
		RTL_W32(hw, TIMER_INT2_8125, 0x0000);
		RTL_W32(hw, TIMER_INT3_8125, 0x0000);
		break;
	}
}

static void
rtl8125_hw_clear_int_miti(struct rtl8125_hw *hw)
{
	int i;
	switch (hw->HwSuppIntMitiVer) {
	case 3:
	case 6:
		/* IntMITI_0-IntMITI_31 */
		for (i = 0xA00; i < 0xB00; i += 4)
			RTL_W32(hw, i, 0x0000);
		break;
	case 4:
		/* IntMITI_0-IntMITI_15 */
		for (i = 0xA00; i < 0xA80; i += 4)
			RTL_W32(hw, i, 0x0000);

		RTL_W8(hw, INT_CFG0_8125, RTL_R8(hw, INT_CFG0_8125) &
		       ~(INT_CFG0_TIMEOUT0_BYPASS_8125 | INT_CFG0_MITIGATION_BYPASS_8125));

		RTL_W16(hw, INT_CFG1_8125, 0x0000);
		break;
	}
}

static void
rtl8125_hw_config(struct rtl8125_hw *hw)
{
	u32 mac_ocp_data;

	/* Set RxConfig to default */
	RTL_W32(hw, RxConfig, (RX_DMA_BURST_unlimited << RxCfgDMAShift));

	rtl8125_nic_reset(hw);

	rtl8125_enable_cfg9346_write(hw);

	/* Disable aspm clkreq internal */
	switch (hw->mcfg) {
	case CFG_METHOD_2 ... CFG_METHOD_11:
		rtl8125_enable_force_clkreq(hw, 0);
		rtl8125_enable_aspm_clkreq_lock(hw, 0);
		break;
	}

	/* Disable magic packet */
	switch (hw->mcfg) {
	case CFG_METHOD_2 ... CFG_METHOD_11:
		mac_ocp_data = 0;
		rtl8125_mac_ocp_write(hw, 0xC0B6, mac_ocp_data);
		break;
	}

	/* Set DMA burst size and interframe gap time */
	RTL_W32(hw, TxConfig, (TX_DMA_BURST_unlimited << TxDMAShift) |
	        (InterFrameGap << TxInterFrameGapShift));

	if (hw->EnableTxNoClose)
		RTL_W32(hw, TxConfig, (RTL_R32(hw, TxConfig) | BIT_6));

	/* TCAM */
	switch (hw->mcfg) {
	case CFG_METHOD_2 ... CFG_METHOD_7:
		RTL_W16(hw, 0x382, 0x221B);
		break;
	}

	switch (hw->mcfg) {
	case CFG_METHOD_2 ... CFG_METHOD_11:
		/* RSS_control_0 */
		RTL_W32(hw, RSS_CTRL_8125, 0x00);

		/* VMQ_control */
		RTL_W16(hw, Q_NUM_CTRL_8125, 0x0000);

		/* Disable speed down */
		RTL_W8(hw, Config1, RTL_R8(hw, Config1) & ~0x10);

		/* CRC disable set */
		rtl8125_mac_ocp_write(hw, 0xC140, 0xFFFF);
		rtl8125_mac_ocp_write(hw, 0xC142, 0xFFFF);

		/* New TX desc format */
		mac_ocp_data = rtl8125_mac_ocp_read(hw, 0xEB58);
		mac_ocp_data |= BIT_0;
		rtl8125_mac_ocp_write(hw, 0xEB58, mac_ocp_data);

		/*
		 * MTPS
		 * 15-8 maximum tx use credit number
		 * 7-0 reserved for pcie product line
		 */
		mac_ocp_data = rtl8125_mac_ocp_read(hw, 0xE614);
		mac_ocp_data &= ~(BIT_10 | BIT_9 | BIT_8);
		if (hw->mcfg == CFG_METHOD_4 || hw->mcfg == CFG_METHOD_5 ||
		    hw->mcfg == CFG_METHOD_7)
			mac_ocp_data |= ((2 & 0x07) << 8);
		else
			mac_ocp_data |= ((3 & 0x07) << 8);
		rtl8125_mac_ocp_write(hw, 0xE614, mac_ocp_data);

		mac_ocp_data = rtl8125_mac_ocp_read(hw, 0xE63E);
		mac_ocp_data &= ~(BIT_5 | BIT_4);
		if (hw->mcfg == CFG_METHOD_2 || hw->mcfg == CFG_METHOD_3 ||
		    hw->mcfg == CFG_METHOD_6)
			mac_ocp_data |= ((0x02 & 0x03) << 4);
		rtl8125_mac_ocp_write(hw, 0xE63E, mac_ocp_data);

		/*
		 * FTR_MCU_CTRL
		 * 3-2 txpla packet valid start
		 */
		mac_ocp_data = rtl8125_mac_ocp_read(hw, 0xC0B4);
		mac_ocp_data &= ~BIT_0;
		rtl8125_mac_ocp_write(hw, 0xC0B4, mac_ocp_data);
		mac_ocp_data |= BIT_0;
		rtl8125_mac_ocp_write(hw, 0xC0B4, mac_ocp_data);

		mac_ocp_data = rtl8125_mac_ocp_read(hw, 0xC0B4);
		mac_ocp_data |= (BIT_3 | BIT_2);
		rtl8125_mac_ocp_write(hw, 0xC0B4, mac_ocp_data);

		mac_ocp_data = rtl8125_mac_ocp_read(hw, 0xEB6A);
		mac_ocp_data &= ~(BIT_7 | BIT_6 | BIT_5 | BIT_4 | BIT_3 | BIT_2 | BIT_1 |
		                  BIT_0);
		mac_ocp_data |= (BIT_5 | BIT_4 | BIT_1 | BIT_0);
		rtl8125_mac_ocp_write(hw, 0xEB6A, mac_ocp_data);

		mac_ocp_data = rtl8125_mac_ocp_read(hw, 0xEB50);
		mac_ocp_data &= ~(BIT_9 | BIT_8 | BIT_7 | BIT_6 | BIT_5);
		mac_ocp_data |= (BIT_6);
		rtl8125_mac_ocp_write(hw, 0xEB50, mac_ocp_data);

		mac_ocp_data = rtl8125_mac_ocp_read(hw, 0xE056);
		mac_ocp_data &= ~(BIT_7 | BIT_6 | BIT_5 | BIT_4);
		rtl8125_mac_ocp_write(hw, 0xE056, mac_ocp_data);

		/* EEE_CR */
		mac_ocp_data = rtl8125_mac_ocp_read(hw, 0xE040);
		mac_ocp_data &= ~(BIT_12);
		rtl8125_mac_ocp_write(hw, 0xE040, mac_ocp_data);

		mac_ocp_data = rtl8125_mac_ocp_read(hw, 0xEA1C);
		mac_ocp_data &= ~(BIT_1 | BIT_0);
		mac_ocp_data |= (BIT_0);
		rtl8125_mac_ocp_write(hw, 0xEA1C, mac_ocp_data);

		switch (hw->mcfg) {
		case CFG_METHOD_2:
		case CFG_METHOD_3:
		case CFG_METHOD_6:
		case CFG_METHOD_8:
		case CFG_METHOD_9:
			rtl8125_oob_mutex_lock(hw);
			break;
		}

		/* MAC_PWRDWN_CR0 */
		rtl8125_mac_ocp_write(hw, 0xE0C0, 0x4000);

		rtl8125_set_mac_ocp_bit(hw, 0xE052, (BIT_6 | BIT_5));
		rtl8125_clear_mac_ocp_bit(hw, 0xE052, BIT_3 | BIT_7);

		switch (hw->mcfg) {
		case CFG_METHOD_2:
		case CFG_METHOD_3:
		case CFG_METHOD_6:
		case CFG_METHOD_8:
		case CFG_METHOD_9:
			rtl8125_oob_mutex_unlock(hw);
			break;
		}

		/*
		 * DMY_PWR_REG_0
		 * (1)ERI(0xD4)(OCP 0xC0AC).bit[7:12]=6'b111111, L1 Mask
		 */
		rtl8125_set_mac_ocp_bit(hw, 0xC0AC,
		                        (BIT_7 | BIT_8 | BIT_9 | BIT_10 | BIT_11 | BIT_12));

		mac_ocp_data = rtl8125_mac_ocp_read(hw, 0xD430);
		mac_ocp_data &= ~(BIT_11 | BIT_10 | BIT_9 | BIT_8 | BIT_7 | BIT_6 | BIT_5 |
		                  BIT_4 | BIT_3 | BIT_2 | BIT_1 | BIT_0);
		mac_ocp_data |= 0x45F;
		rtl8125_mac_ocp_write(hw, 0xD430, mac_ocp_data);

		if (!hw->DASH)
			RTL_W8(hw, 0xD0, RTL_R8(hw, 0xD0) | BIT_6 | BIT_7);
		else
			RTL_W8(hw, 0xD0, RTL_R8(hw, 0xD0) & ~(BIT_6 | BIT_7));

		if (hw->mcfg == CFG_METHOD_2 || hw->mcfg == CFG_METHOD_3 ||
		    hw->mcfg == CFG_METHOD_6)
			RTL_W8(hw, MCUCmd_reg, RTL_R8(hw, MCUCmd_reg) | BIT_0);

		rtl8125_disable_eee_plus(hw);

		mac_ocp_data = rtl8125_mac_ocp_read(hw, 0xEA1C);
		mac_ocp_data &= ~BIT_2;
		rtl8125_mac_ocp_write(hw, 0xEA1C, mac_ocp_data);

		/* Clear TCAM entries */
		rtl8125_set_mac_ocp_bit(hw, 0xEB54, BIT_0);
		udelay(1);
		rtl8125_clear_mac_ocp_bit(hw, 0xEB54, BIT_0);

		RTL_W16(hw, 0x1880, RTL_R16(hw, 0x1880) & ~(BIT_4 | BIT_5));

		if (hw->mcfg == CFG_METHOD_8 || hw->mcfg == CFG_METHOD_9 ||
		    hw->mcfg == CFG_METHOD_10 || hw->mcfg == CFG_METHOD_11)
			RTL_W8(hw, 0xd8, RTL_R8(hw, 0xd8) & ~EnableRxDescV4_0);
	}

	/* Other hw parameters */
	rtl8125_hw_clear_timer_int(hw);

	rtl8125_hw_clear_int_miti(hw);

	switch (hw->mcfg) {
	case CFG_METHOD_2 ... CFG_METHOD_11:
		rtl8125_mac_ocp_write(hw, 0xE098, 0xC302);
		break;
	}

	rtl8125_disable_cfg9346_write(hw);

	udelay(10);
}

static void
rtl8125_hw_initialize(struct rtl8125_hw *hw)
{
	rtl8125_init_software_variable(hw);

	rtl8125_exit_oob(hw);

	rtl8125_hw_init(hw);

	rtl8125_nic_reset(hw);
}

static void
rtl8125_dev_interrupt_handler(void *param)
{
	struct rte_eth_dev *dev = (struct rte_eth_dev *)param;
	struct rtl8125_adapter *adapter = RTL8125_DEV_PRIVATE(dev);
	struct rtl8125_hw *hw = &adapter->hw;
	uint32_t intr;

	intr = RTL_R32(hw, ISR0_8125);

	/* Clear all cause mask */
	rtl8125_disable_intr(hw);

	if (intr & LinkChg)
		rtl8125_dev_link_update(dev, 0);
	else
		PMD_DRV_LOG(ERR, "r8125: interrupt unhandled.");

	rtl8125_enable_intr(hw);
}

static int
rtl8125_dev_init(struct rte_eth_dev *dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(dev);
	struct rte_intr_handle *intr_handle = pci_dev->intr_handle;
	struct rtl8125_adapter *adapter = RTL8125_DEV_PRIVATE(dev);
	struct rtl8125_hw *hw = &adapter->hw;
	struct rte_ether_addr *perm_addr =
	        (struct rte_ether_addr *)hw->mac_addr;

	dev->dev_ops = &rtl8125_eth_dev_ops;
	dev->tx_pkt_burst = &rtl8125_xmit_pkts;
	dev->rx_pkt_burst = &rtl8125_recv_pkts;

	/* For secondary processes, the primary process has done all the work */
	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		if (dev->data->scattered_rx)
			dev->rx_pkt_burst = &rtl8125_recv_scattered_pkts;
		return 0;
	}

	rte_eth_copy_pci_info(dev, pci_dev);

	hw->mmio_addr = (u8 *)pci_dev->mem_resource[2].addr; /* RTL8125 uses BAR2 */
	rtl8125_get_mac_version(hw, pci_dev);

	if (rtl8125_set_hw_ops(hw))
		return -ENOTSUP;

	rtl8125_disable_intr(hw);

	rtl8125_hw_initialize(hw);

	/* Read the permanent MAC address out of ROM */
	rtl8125_get_mac_address(hw, perm_addr);

	if (!rte_is_valid_assigned_ether_addr(perm_addr)) {
		rte_eth_random_addr(&perm_addr->addr_bytes[0]);

		PMD_INIT_LOG(NOTICE, "r8125: Assign randomly generated MAC address "
		             "%02x:%02x:%02x:%02x:%02x:%02x",
		             perm_addr->addr_bytes[0],
		             perm_addr->addr_bytes[1],
		             perm_addr->addr_bytes[2],
		             perm_addr->addr_bytes[3],
		             perm_addr->addr_bytes[4],
		             perm_addr->addr_bytes[5]);
	}

	/* Allocate memory for storing MAC addresses */
	dev->data->mac_addrs = rte_zmalloc("r8125", RTE_ETHER_ADDR_LEN, 0);

	if (dev->data->mac_addrs == NULL) {
		PMD_INIT_LOG(ERR, "MAC Malloc failed");
		return -ENOMEM;
	}

	/* Copy the permanent MAC address */
	rte_ether_addr_copy(perm_addr, &dev->data->mac_addrs[0]);

	rtl8125_rar_set(hw, &perm_addr->addr_bytes[0]);

	rte_intr_callback_register(intr_handle,
	                           rtl8125_dev_interrupt_handler, dev);

	/* Enable uio/vfio intr/eventfd mapping */
	rte_intr_enable(intr_handle);

	return 0;
}

/*
 * Reset and stop device.
 */
static int
rtl8125_dev_close(struct rte_eth_dev *dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(dev);
	struct rte_intr_handle *intr_handle = pci_dev->intr_handle;
	struct rtl8125_adapter *adapter = RTL8125_DEV_PRIVATE(dev);
	struct rtl8125_hw *hw = &adapter->hw;
	int retries = 0;
	int ret_unreg, ret_stp;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	if (HW_DASH_SUPPORT_DASH(hw))
		rtl8125_driver_stop(hw);

	ret_stp = rtl8125_dev_stop(dev);

	rtl8125_free_queues(dev);

	/* Reprogram the RAR[0] in case user changed it. */
	rtl8125_rar_set(hw, hw->mac_addr);

	/* Disable uio intr before callback unregister */
	rte_intr_disable(intr_handle);

	do {
		ret_unreg = rte_intr_callback_unregister(intr_handle,
		                rtl8125_dev_interrupt_handler,
		                dev);
		if (ret_unreg >= 0 || ret_unreg == -ENOENT)
			break;
		else if (ret_unreg != -EAGAIN)
			PMD_DRV_LOG(ERR, "r8125: intr callback unregister failed: %d", ret_unreg);

		rte_delay_ms(100);
	} while (retries++ < (10 + 90));

	return ret_stp;
}

static int
rtl8125_dev_uninit(struct rte_eth_dev *dev)
{
	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return -EPERM;

	rtl8125_dev_close(dev);

	return 0;
}

static int
rtl8125_tally_init(struct rte_eth_dev *dev)
{
	struct rtl8125_adapter *adapter = RTL8125_DEV_PRIVATE(dev);
	struct rtl8125_hw *hw = &adapter->hw;
	const struct rte_memzone *mz;

	mz = rte_eth_dma_zone_reserve(dev, "tally_counters", 0,
	                              sizeof(struct rtl8125_counters),
	                              64, rte_socket_id());
	if (mz == NULL)
		return -ENOMEM;

	hw->tally_vaddr = mz->addr;
	hw->tally_paddr = mz->iova;

	/* Fill tally addrs */
	RTL_W32(hw, CounterAddrHigh, (u64)hw->tally_paddr >> 32);
	RTL_W32(hw, CounterAddrLow, (u64)hw->tally_paddr & (DMA_BIT_MASK(32)));

	/* Reset the hw statistics */
	rtl8125_clear_tally_stats(hw);

	return 0;
}

#if RTE_VERSION >= RTE_VERSION_NUM(20, 8, 0, 0)
static void
rtl8125_tally_free(struct rte_eth_dev *dev)
#else
static void
rtl8125_tally_free(struct rte_eth_dev *dev __rte_unused)
#endif
{
	rtl8125_eth_dma_zone_free(dev, "tally_counters", 0);
}

static int
_rtl8125_setup_link(struct rte_eth_dev *dev)
{
	struct rtl8125_adapter *adapter = RTL8125_DEV_PRIVATE(dev);
	struct rtl8125_hw *hw = &adapter->hw;
	u64 adv = 0;
	u32 *link_speeds = &dev->data->dev_conf.link_speeds;

	/* Setup link speed and duplex */
	if (*link_speeds == RTE_ETH_LINK_SPEED_AUTONEG) {
		hw->autoneg = AUTONEG_ENABLE;
		hw->speed = SPEED_2500;
		hw->duplex = DUPLEX_FULL;
		hw->advertising = RTL8125_ALL_SPEED_DUPLEX;
	} else if (*link_speeds != 0) {

		if (*link_speeds & ~(RTE_ETH_LINK_SPEED_10M_HD | RTE_ETH_LINK_SPEED_10M |
		                     RTE_ETH_LINK_SPEED_100M_HD | RTE_ETH_LINK_SPEED_100M |
		                     RTE_ETH_LINK_SPEED_1G | RTE_ETH_LINK_SPEED_2_5G | RTE_ETH_LINK_SPEED_FIXED))
			goto error_invalid_config;

		if (*link_speeds & RTE_ETH_LINK_SPEED_10M_HD) {
			hw->speed = SPEED_10;
			hw->duplex = DUPLEX_HALF;
			adv |= ADVERTISE_10_HALF;
		}
		if (*link_speeds & RTE_ETH_LINK_SPEED_10M) {
			hw->speed = SPEED_10;
			hw->duplex = DUPLEX_FULL;
			adv |= ADVERTISE_10_FULL;
		}
		if (*link_speeds & RTE_ETH_LINK_SPEED_100M_HD) {
			hw->speed = SPEED_100;
			hw->duplex = DUPLEX_HALF;
			adv |= ADVERTISE_100_HALF;
		}
		if (*link_speeds & RTE_ETH_LINK_SPEED_100M) {
			hw->speed = SPEED_100;
			hw->duplex = DUPLEX_FULL;
			adv |= ADVERTISE_100_FULL;
		}
		if (*link_speeds & RTE_ETH_LINK_SPEED_1G) {
			hw->speed = SPEED_1000;
			hw->duplex = DUPLEX_FULL;
			adv |= ADVERTISE_1000_FULL;
		}
		if (*link_speeds & RTE_ETH_LINK_SPEED_2_5G) {
			hw->speed = SPEED_2500;
			hw->duplex = DUPLEX_FULL;
			adv |= ADVERTISE_2500_FULL;
		}

		hw->autoneg = AUTONEG_ENABLE;
		hw->advertising = adv;
	}

	rtl8125_set_speed(hw);

	return 0;

error_invalid_config:
	PMD_INIT_LOG(ERR, "Invalid advertised speeds (%u) for port %u",
	             dev->data->dev_conf.link_speeds, dev->data->port_id);
	rtl8125_stop_queues(dev);
	return -EINVAL;
}

static int
rtl8125_setup_link(struct rte_eth_dev *dev)
{
#ifdef RTE_EXEC_ENV_FREEBSD
	struct rtl8125_adapter *adapter = RTL8125_DEV_PRIVATE(dev);
	struct rtl8125_hw *hw = &adapter->hw;
	struct rte_eth_link link;
	int count;
#endif

	_rtl8125_setup_link(dev);

#ifdef RTE_EXEC_ENV_FREEBSD
	for (count = 0; count < R8125_LINK_CHECK_TIMEOUT; count ++) {
		if (!(RTL_R16(hw, PHYstatus) & LinkStatus)) {
			msleep(R8125_LINK_CHECK_INTERVAL);
			continue;
		}

		rtl8125_dev_link_update(dev, 0);

		rte_eth_linkstatus_get(dev, &link);

		return 0;
	}
#endif
	return 0;
}

/*
 * Configure device link speed and setup link.
 * It returns 0 on success.
 */
static int
rtl8125_dev_start(struct rte_eth_dev *dev)
{
	struct rtl8125_adapter *adapter = RTL8125_DEV_PRIVATE(dev);
	struct rtl8125_hw *hw = &adapter->hw;
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(dev);
	struct rte_intr_handle *intr_handle = pci_dev->intr_handle;
	int err;

	/* Disable uio/vfio intr/eventfd mapping */
	rte_intr_disable(intr_handle);

	rtl8125_powerup_pll(hw);

	rtl8125_hw_ephy_config(hw);

	rtl8125_hw_phy_config(hw);

	rtl8125_hw_config(hw);

	rtl8125_tx_init(dev);

	/* This can fail when allocating mbufs for descriptor rings */
	err = rtl8125_rx_init(dev);
	if (err) {
		PMD_INIT_LOG(ERR, "Unable to initialize RX hardware");
		goto error;
	}

	/* This can fail when allocating mem for tally counters */
	err = rtl8125_tally_init(dev);
	if (err)
		goto error;

	/* Enable uio/vfio intr/eventfd mapping */
	rte_intr_enable(intr_handle);

	/* Resume enabled intr since hw reset */
	rtl8125_enable_intr(hw);

	rtl8125_setup_link(dev);

	rtl8125_mdio_write(hw, 0x1F, 0x0000);

	hw->adapter_stopped = 0;

	return 0;

error:
	rtl8125_stop_queues(dev);
	return -EIO;
}


/*
 * Stop device: disable RX and TX functions to allow for reconfiguring.
 */
static int
rtl8125_dev_stop(struct rte_eth_dev *dev)
{
	struct rtl8125_adapter *adapter = RTL8125_DEV_PRIVATE(dev);
	struct rtl8125_hw *hw = &adapter->hw;
	struct rte_eth_link link;

	if (hw->adapter_stopped)
		return 0;

	rtl8125_disable_intr(hw);

	rtl8125_nic_reset(hw);

	switch (hw->mcfg) {
	case CFG_METHOD_2 ... CFG_METHOD_11:
		rtl8125_mac_ocp_write(hw, 0xE00A, hw->mcu_pme_setting);
		break;
	}

	rtl8125_powerdown_pll(hw);

	rtl8125_stop_queues(dev);

	rtl8125_tally_free(dev);

	/* Clear the recorded link status */
	memset(&link, 0, sizeof(link));
	rte_eth_linkstatus_set(dev, &link);

	hw->adapter_stopped = 1;
	dev->data->dev_started = 0;

	return 0;
}

static int
rtl8125_dev_reset(struct rte_eth_dev *dev)
{
	int ret;

	ret = rtl8125_dev_uninit(dev);
	if (ret)
		return ret;

	ret = rtl8125_dev_init(dev);

	return ret;
}

static int
rtl8125_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
                  struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_probe(pci_dev,
	                                     sizeof(struct rtl8125_adapter), rtl8125_dev_init);

}

static int
rtl8125_pci_remove(struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_remove(pci_dev, rtl8125_dev_uninit);
}

static struct rte_pci_driver rte_r8125_pmd = {
	.id_table = pci_id_r8125_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING | RTE_PCI_DRV_INTR_LSC,
	.probe = rtl8125_pci_probe,
	.remove = rtl8125_pci_remove,
};

RTE_PMD_REGISTER_PCI(net_r8125, rte_r8125_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_r8125, pci_id_r8125_map);
RTE_PMD_REGISTER_KMOD_DEP(net_r8125, "* igb_uio | uio_pci_generic | vfio-pci");

#if RTE_VERSION >= RTE_VERSION_NUM(20, 8, 0, 0)
RTE_LOG_REGISTER(r8125_logtype_init, pmd.net.r8125.init, NOTICE);
RTE_LOG_REGISTER(r8125_logtype_driver, pmd.net.r8125.driver, NOTICE);

#ifdef RTE_LIBRTE_R8125_DEBUG_RX
RTE_LOG_REGISTER(r8125_logtype_rx, pmd.net.r8125.rx, DEBUG);
#endif
#ifdef RTE_LIBRTE_R8125_DEBUG_TX
RTE_LOG_REGISTER(r8125_logtype_tx, pmd.net.r8125.tx, DEBUG);
#endif
#ifdef RTE_LIBRTE_R8125_DEBUG_TX_FREE
RTE_LOG_REGISTER(r8125_logtype_tx_free, pmd.net.r8125.tx_free, DEBUG);
#endif

#else /* RTE_VERSION >= RTE_VERSION_NUM(20, 8, 0, 0) */

int r8125_logtype_init;
int r8125_logtype_driver;

#ifdef RTE_LIBRTE_R8125_DEBUG_RX
int r8125_logtype_rx;
#endif
#ifdef RTE_LIBRTE_R8125_DEBUG_TX
int r8125_logtype_tx;
#endif
#ifdef RTE_LIBRTE_R8125_DEBUG_TX_FREE
int r8125_logtype_tx_free;
#endif

RTE_INIT(r8125_init_log)
{
	r8125_logtype_init = rte_log_register("pmd.net.r8125.init");
	if (r8125_logtype_init >= 0)
		rte_log_set_level(r8125_logtype_init, RTE_LOG_NOTICE);
	r8125_logtype_driver = rte_log_register("pmd.net.r8125.driver");
	if (r8125_logtype_driver >= 0)
		rte_log_set_level(r8125_logtype_driver, RTE_LOG_NOTICE);
#ifdef RTE_LIBRTE_R8125_DEBUG_RX
	r8125_logtype_rx = rte_log_register("pmd.net.r8125.rx");
	if (r8125_logtype_rx >= 0)
		rte_log_set_level(r8125_logtype_rx, RTE_LOG_DEBUG);
#endif

#ifdef RTE_LIBRTE_R8125_DEBUG_TX
	r8125_logtype_tx = rte_log_register("pmd.net.r8125.tx");
	if (r8125_logtype_tx >= 0)
		rte_log_set_level(r8125_logtype_tx, RTE_LOG_DEBUG);
#endif

#ifdef RTE_LIBRTE_R8125_DEBUG_TX_FREE
	r8125_logtype_tx_free = rte_log_register("pmd.net.r8125.tx_free");
	if (r8125_logtype_tx_free >= 0)
		rte_log_set_level(r8125_logtype_tx_free, RTE_LOG_DEBUG);
#endif
}

#endif /* RTE_VERSION >= RTE_VERSION_NUM(20, 8, 0, 0) */

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Realtek Corporation. All rights reserved
 */

#include <sys/queue.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>

#include <rte_ether.h>
#include <ethdev_driver.h>

#include "r8126_hw.h"
#include "r8126_logs.h"

void
rtl8126_mac_ocp_write(struct rtl8126_hw *hw, u16 addr, u16 value)
{
	u32 data32;

	data32 = addr / 2;
	data32 <<= OCPR_Addr_Reg_shift;
	data32 += value;
	data32 |= OCPR_Write;

	RTL_W32(hw, MACOCP, data32);
}

u16
rtl8126_mac_ocp_read(struct rtl8126_hw *hw, u16 addr)
{
	u32 data32;
	u16 data16 = 0;

	data32 = addr / 2;
	data32 <<= OCPR_Addr_Reg_shift;

	RTL_W32(hw, MACOCP, data32);
	data16 = (u16)RTL_R32(hw, MACOCP);

	return data16;
}

u32
rtl8126_csi_read(struct rtl8126_hw *hw, u32 addr)
{
	u32 cmd;
	int i;
	u32 value = 0;

	cmd = CSIAR_Read | CSIAR_ByteEn << CSIAR_ByteEn_shift |
	      (addr & CSIAR_Addr_Mask);

	RTL_W32(hw, CSIAR, cmd);

	for (i = 0; i < 10; i++) {
		udelay(100);

		/* Check if the RTL8126 has completed CSI read */
		if (RTL_R32(hw, CSIAR) & CSIAR_Flag) {
			value = RTL_R32(hw, CSIDR);
			break;
		}
	}

	udelay(20);

	return value;
}

void
rtl8126_csi_write(struct rtl8126_hw *hw, u32 addr, u32 value)
{
	u32 cmd;
	int i;

	RTL_W32(hw, CSIDR, value);
	cmd = CSIAR_Write | CSIAR_ByteEn << CSIAR_ByteEn_shift |
	      (addr & CSIAR_Addr_Mask);

	RTL_W32(hw, CSIAR, cmd);

	for (i = 0; i < R8126_CHANNEL_WAIT_COUNT; i++) {
		udelay(R8126_CHANNEL_WAIT_TIME);

		/* Check if the RTL8126 has completed CSI write */
		if (!(RTL_R32(hw, CSIAR) & CSIAR_Flag))
			break;
	}

	udelay(R8126_CHANNEL_EXIT_DELAY_TIME);
}

void
rtl8126_disable_l1_timeout(struct rtl8126_hw *hw)
{
	rtl8126_csi_write(hw, 0x890, rtl8126_csi_read(hw, 0x890) & ~BIT_0);
}

void
rtl8126_get_mac_version(struct rtl8126_hw *hw)
{
	u32 reg, val32;
	u32 ic_version_id;

	val32 = RTL_R32(hw, TxConfig);
	reg = val32 & 0x7c800000;
	ic_version_id = val32 & 0x00700000;

	switch (reg) {
	case 0x64800000:
		if (ic_version_id == 0x00000000)
			hw->mcfg = CFG_METHOD_1;
		else if (ic_version_id == 0x100000)
			hw->mcfg = CFG_METHOD_2;
		else if (ic_version_id == 0x200000)
			hw->mcfg = CFG_METHOD_3;
		else {
			hw->mcfg = CFG_METHOD_3;
			hw->HwIcVerUnknown = TRUE;
		}

		hw->efuse_ver = EFUSE_SUPPORT_V4;
		break;
	default:
		PMD_INIT_LOG(NOTICE, "unknown chip version (%x)", reg);
		hw->mcfg = CFG_METHOD_DEFAULT;
		hw->HwIcVerUnknown = TRUE;
		hw->efuse_ver = EFUSE_NOT_SUPPORT;
		break;
	}
}

void
rtl8126_enable_cfg9346_write(struct rtl8126_hw *hw)
{
	RTL_W8(hw, Cfg9346, RTL_R8(hw, Cfg9346) | Cfg9346_Unlock);
}

void
rtl8126_disable_cfg9346_write(struct rtl8126_hw *hw)
{
	RTL_W8(hw, Cfg9346, RTL_R8(hw, Cfg9346) & ~Cfg9346_Unlock);
}

void
rtl8126_rar_set(struct rtl8126_hw *hw, uint8_t *addr)
{
	uint32_t rar_low = 0;
	uint32_t rar_high = 0;

	rar_low = ((uint32_t) addr[0] |
	           ((uint32_t) addr[1] << 8) |
	           ((uint32_t) addr[2] << 16) |
	           ((uint32_t) addr[3] << 24));

	rar_high = ((uint32_t) addr[4] |
	            ((uint32_t) addr[5] << 8));

	rtl8126_enable_cfg9346_write(hw);
	RTL_W32(hw, MAC0, rar_low);
	RTL_W32(hw, MAC4, rar_high);

	rtl8126_disable_cfg9346_write(hw);
}

int
rtl8126_get_mac_address(struct rtl8126_hw *hw, struct rte_ether_addr *ea)
{
	u8 mac_addr[MAC_ADDR_LEN];

	switch (hw->mcfg) {
	case CFG_METHOD_1 ... CFG_METHOD_3:
		*(u32 *)&mac_addr[0] = RTL_R32(hw, BACKUP_ADDR0_8125);
		*(u16 *)&mac_addr[4] = RTL_R16(hw, BACKUP_ADDR1_8125);
		break;
	default:
		break;
	}

	rte_ether_addr_copy((struct rte_ether_addr *)mac_addr, ea);

	return 0;
}

int
rtl8126_set_hw_ops(struct rtl8126_hw *hw)
{
	switch (hw->mcfg) {
	/* 8126A */
	case CFG_METHOD_1 ... CFG_METHOD_3:
		hw->hw_ops = rtl8126a_ops;
		return 0;
	default:
		return -ENOTSUP;
	}
}

static void
rtl8126_stop_all_request(struct rtl8126_hw *hw)
{
	RTL_W8(hw, ChipCmd, RTL_R8(hw, ChipCmd) | StopReq);
}

static void
rtl8126_wait_txrx_fifo_empty(struct rtl8126_hw *hw)
{
	int i;
	switch (hw->mcfg) {
	case CFG_METHOD_1 ... CFG_METHOD_3:
		for (i = 0; i < 3000; i++) {
			udelay(50);
			if ((RTL_R8(hw, MCUCmd_reg) & (Txfifo_empty | Rxfifo_empty)) ==
			    (Txfifo_empty | Rxfifo_empty))
				break;
		}
		break;
	}

	switch (hw->mcfg) {
	case CFG_METHOD_1 ... CFG_METHOD_3:
		for (i = 0; i < 3000; i++) {
			udelay(50);
			if ((RTL_R16(hw, IntrMitigate) & (BIT_0 | BIT_1 | BIT_8)) ==
			    (BIT_0 | BIT_1 | BIT_8))
				break;
		}
		break;
	}
}

static void
rtl8126_wait_ll_share_fifo_ready(struct rtl8126_hw *hw)
{
	int i;

	for (i = 0; i < 10; i++) {
		udelay(100);
		if (RTL_R16(hw, 0xD2) & BIT_9)
			break;
	}
}

static void
rtl8126_disable_now_is_oob(struct rtl8126_hw *hw)
{
	if (hw->HwSuppNowIsOobVer == 1)
		RTL_W8(hw, MCUCmd_reg, RTL_R8(hw, MCUCmd_reg) & ~Now_is_oob);
}

void
rtl8126_enable_force_clkreq(struct rtl8126_hw *hw, bool enable)
{
	if (enable)
		RTL_W8(hw, 0xF1, RTL_R8(hw, 0xF1) | BIT_7);
	else
		RTL_W8(hw, 0xF1, RTL_R8(hw, 0xF1) & ~BIT_7);
}

void
rtl8126_enable_aspm_clkreq_lock(struct rtl8126_hw *hw, bool enable)
{
	switch (hw->mcfg) {
	case CFG_METHOD_1:
		rtl8126_enable_cfg9346_write(hw);
		if (enable) {
			RTL_W8(hw, Config2, RTL_R8(hw, Config2) | BIT_7);
			RTL_W8(hw, Config5, RTL_R8(hw, Config5) | BIT_0);
		} else {
			RTL_W8(hw, Config2, RTL_R8(hw, Config2) & ~BIT_7);
			RTL_W8(hw, Config5, RTL_R8(hw, Config5) & ~BIT_0);
		}
		rtl8126_disable_cfg9346_write(hw);
		break;
	case CFG_METHOD_2:
	case CFG_METHOD_3:
		rtl8126_enable_cfg9346_write(hw);
		if (enable) {
			RTL_W8(hw, INT_CFG0_8125, RTL_R8(hw, INT_CFG0_8125) | BIT_3);
			RTL_W8(hw, Config5, RTL_R8(hw, Config5) | BIT_0);
		} else {
			RTL_W8(hw, INT_CFG0_8125, RTL_R8(hw, INT_CFG0_8125) & ~BIT_3);
			RTL_W8(hw, Config5, RTL_R8(hw, Config5) & ~BIT_0);
		}
		rtl8126_disable_cfg9346_write(hw);
		break;
	}
}

void
rtl8126_hw_disable_mac_mcu_bps(struct rtl8126_hw *hw)
{
	u16 reg_addr;

	switch (hw->mcfg) {
	case CFG_METHOD_1 ... CFG_METHOD_3:
		rtl8126_enable_aspm_clkreq_lock(hw, 0);
		break;
	}

	switch (hw->mcfg) {
	case CFG_METHOD_1 ... CFG_METHOD_3:
		rtl8126_mac_ocp_write(hw, 0xFC48, 0x0000);
		break;
	}

	switch (hw->mcfg) {
	case CFG_METHOD_1 ... CFG_METHOD_3:
		for (reg_addr = 0xFC28; reg_addr < 0xFC48; reg_addr += 2)
			rtl8126_mac_ocp_write(hw, reg_addr, 0x0000);

		mdelay(3);

		rtl8126_mac_ocp_write(hw, 0xFC26, 0x0000);
		break;
	}
}

static void
rtl8126_enable_rxdvgate(struct rtl8126_hw *hw)
{
	switch (hw->mcfg) {
	case CFG_METHOD_1 ... CFG_METHOD_3:
		RTL_W8(hw, 0xF2, RTL_R8(hw, 0xF2) | BIT_3);
		mdelay(2);
	}
}

void
rtl8126_disable_rxdvgate(struct rtl8126_hw *hw)
{
	switch (hw->mcfg) {
	case CFG_METHOD_1 ... CFG_METHOD_3:
		RTL_W8(hw, 0xF2, RTL_R8(hw, 0xF2) & ~BIT_3);
		mdelay(2);
	}
}

void
rtl8126_nic_reset(struct rtl8126_hw *hw)
{
	int i;

	RTL_W32(hw, RxConfig, (RX_DMA_BURST_unlimited << RxCfgDMAShift));

	rtl8126_enable_rxdvgate(hw);

	rtl8126_stop_all_request(hw);

	rtl8126_wait_txrx_fifo_empty(hw);

	mdelay(2);

	/* Soft reset the chip. */
	RTL_W8(hw, ChipCmd, CmdReset);

	/* Check that the chip has finished the reset. */
	for (i = 100; i > 0; i--) {
		udelay(100);
		if ((RTL_R8(hw, ChipCmd) & CmdReset) == 0)
			break;
	}
}

static void
rtl8126_exit_realwow(struct rtl8126_hw *hw)
{
	/* Disable realwow function */
	switch (hw->mcfg) {
	case CFG_METHOD_1 ... CFG_METHOD_3:
		rtl8126_mac_ocp_write(hw, 0xC0BC, 0x00FF);
		break;
	}
}

void
rtl8126_exit_oob(struct rtl8126_hw *hw)
{
	u16 data16;

	RTL_W32(hw, RxConfig, RTL_R32(hw, RxConfig) &
	        ~(AcceptErr | AcceptRunt | AcceptBroadcast | AcceptMulticast |
	          AcceptMyPhys |  AcceptAllPhys));

	rtl8126_exit_realwow(hw);

	rtl8126_nic_reset(hw);

	switch (hw->mcfg) {
	case CFG_METHOD_1 ... CFG_METHOD_3:
		rtl8126_disable_now_is_oob(hw);

		data16 = rtl8126_mac_ocp_read(hw, 0xE8DE) & ~BIT_14;
		rtl8126_mac_ocp_write(hw, 0xE8DE, data16);
		rtl8126_wait_ll_share_fifo_ready(hw);

		rtl8126_mac_ocp_write(hw, 0xC0AA, 0x07D0);

		rtl8126_mac_ocp_write(hw, 0xC0A6, 0x01B5);

		rtl8126_mac_ocp_write(hw, 0xC01E, 0x5555);

		rtl8126_wait_ll_share_fifo_ready(hw);
		break;
	}
}

void
rtl8126_disable_ups(struct rtl8126_hw *hw)
{
	switch (hw->mcfg) {
	case CFG_METHOD_1 ... CFG_METHOD_3:
		rtl8126_mac_ocp_write(hw, 0xD40A, rtl8126_mac_ocp_read(hw, 0xD40A) & ~(BIT_4));
		break;
	}
}

static bool
rtl8126_is_autoneg_mode_valid(u32 autoneg)
{
	switch (autoneg) {
	case AUTONEG_ENABLE:
	case AUTONEG_DISABLE:
		return true;
	default:
		return false;
	}
}

bool
rtl8126_is_speed_mode_valid(u32 speed)
{
	switch (speed) {
	case SPEED_5000:
	case SPEED_2500:
	case SPEED_1000:
	case SPEED_100:
	case SPEED_10:
		return true;
	default:
		return false;
	}
}

static bool
rtl8126_is_duplex_mode_valid(u8 duplex)
{
	switch (duplex) {
	case DUPLEX_FULL:
	case DUPLEX_HALF:
		return true;
	default:
		return false;
	}
}

static void
rtl8126_set_link_option(struct rtl8126_hw *hw,
                        u8 autoneg,
                        u32 speed,
                        u8 duplex,
                        enum rtl8126_fc_mode fc)
{
	u64 adv;

	if (!rtl8126_is_speed_mode_valid(speed))
		speed = SPEED_5000;

	if (!rtl8126_is_duplex_mode_valid(duplex))
		duplex = DUPLEX_FULL;

	if (!rtl8126_is_autoneg_mode_valid(autoneg))
		autoneg = AUTONEG_ENABLE;

	speed = RTE_MIN(speed, hw->HwSuppMaxPhyLinkSpeed);

	adv = 0;
	switch (speed) {
	case SPEED_5000:
		adv |= ADVERTISE_5000_FULL;
	/* Fall through */
	case SPEED_2500:
		adv |= ADVERTISE_2500_FULL;
	/* Fall through */
	default:
		adv |= (ADVERTISE_10_HALF | ADVERTISE_10_FULL |
		        ADVERTISE_100_HALF | ADVERTISE_100_FULL |
		        ADVERTISE_1000_HALF | ADVERTISE_1000_FULL);
		break;
	}

	hw->autoneg = autoneg;
	hw->speed = speed;
	hw->duplex = duplex;
	hw->advertising = adv;
	hw->fcpause = fc;
}

void
rtl8126_init_software_variable(struct rtl8126_hw *hw)
{
	int tx_no_close_enable = 1;
	unsigned int speed_mode = SPEED_5000;
	unsigned int duplex_mode = DUPLEX_FULL;
	unsigned int autoneg_mode = AUTONEG_ENABLE;

	switch (hw->mcfg) {
	case CFG_METHOD_1 ... CFG_METHOD_3:
		hw->chipset_name = RTL8126A;
		break;
	default:
		hw->chipset_name = UNKNOWN;
		break;
	}

	switch (hw->mcfg) {
	case CFG_METHOD_1 ... CFG_METHOD_3:
		hw->HwSuppNowIsOobVer = 1;
	}

	switch (hw->mcfg) {
	case CFG_METHOD_1 ... CFG_METHOD_3:
		hw->HwSuppCheckPhyDisableModeVer = 3;
	}

	switch (hw->mcfg) {
	case CFG_METHOD_1:
	case CFG_METHOD_2:
	case CFG_METHOD_3:
	default:
		hw->HwSuppMaxPhyLinkSpeed = 5000;
		break;
	}

	switch (hw->mcfg) {
	case CFG_METHOD_1:
		hw->HwSuppTxNoCloseVer = 4;
		break;
	case CFG_METHOD_2:
	case CFG_METHOD_3:
		hw->HwSuppTxNoCloseVer = 5;
		break;
	}

	switch (hw->HwSuppTxNoCloseVer) {
	case 5:
	case 6:
		hw->MaxTxDescPtrMask = MAX_TX_NO_CLOSE_DESC_PTR_MASK_V4;
		break;
	case 4:
		hw->MaxTxDescPtrMask = MAX_TX_NO_CLOSE_DESC_PTR_MASK_V3;
		break;
	case 3:
		hw->MaxTxDescPtrMask = MAX_TX_NO_CLOSE_DESC_PTR_MASK_V2;
		break;
	default:
		tx_no_close_enable = 0;
		break;
	}

	if (hw->HwSuppTxNoCloseVer > 0 && tx_no_close_enable == 1)
		hw->EnableTxNoClose = TRUE;

	switch (hw->HwSuppTxNoCloseVer) {
	case 4:
	case 5:
		hw->hw_clo_ptr_reg = HW_CLO_PTR0_8126;
		hw->sw_tail_ptr_reg = SW_TAIL_PTR0_8126;
		break;
	default:
		hw->hw_clo_ptr_reg = HW_CLO_PTR0_8125;
		hw->sw_tail_ptr_reg = SW_TAIL_PTR0_8125;
		break;
	}

	switch (hw->mcfg) {
	case CFG_METHOD_1 ... CFG_METHOD_3:
		hw->HwSuppMacMcuVer = 2;
		break;
	}

	switch (hw->mcfg) {
	case CFG_METHOD_1 ... CFG_METHOD_3:
		hw->MacMcuPageSize = RTL8126_MAC_MCU_PAGE_SIZE;
		break;
	}

	switch (hw->mcfg) {
	case CFG_METHOD_1:
		hw->sw_ram_code_ver = NIC_RAMCODE_VERSION_CFG_METHOD_1;
		break;
	case CFG_METHOD_2:
		hw->sw_ram_code_ver = NIC_RAMCODE_VERSION_CFG_METHOD_2;
		break;
	case CFG_METHOD_3:
		hw->sw_ram_code_ver = NIC_RAMCODE_VERSION_CFG_METHOD_3;
		break;
	}
	if (hw->HwIcVerUnknown) {
		hw->NotWrRamCodeToMicroP = TRUE;
		hw->NotWrMcuPatchCode = TRUE;
	}

	rtl8126_set_link_option(hw, autoneg_mode, speed_mode, duplex_mode,
	                        rtl8126_fc_full);

	switch (hw->mcfg) {
	case CFG_METHOD_1 ... CFG_METHOD_3:
		hw->mcu_pme_setting = rtl8126_mac_ocp_read(hw, 0xE00A);
		break;
	}
}

void
rtl8126_get_tally_stats(struct rtl8126_hw *hw, struct rte_eth_stats *rte_stats)
{
	struct rtl8126_counters *counters;
	uint64_t paddr;
	u32 cmd;
	u32 wait_cnt;

	counters = hw->tally_vaddr;
	paddr = hw->tally_paddr;
	if (!counters)
		return;

	RTL_W32(hw, CounterAddrHigh, (u64)paddr >> 32);
	cmd = (u64)paddr & DMA_BIT_MASK(32);
	RTL_W32(hw, CounterAddrLow, cmd);
	RTL_W32(hw, CounterAddrLow, cmd | CounterDump);

	wait_cnt = 0;
	while (RTL_R32(hw, CounterAddrLow) & CounterDump) {
		udelay(10);

		wait_cnt++;
		if (wait_cnt > 20)
			break;
	}

	/* RX errors */
	rte_stats->imissed = rte_le_to_cpu_64(counters->rx_missed);
	rte_stats->ierrors = rte_le_to_cpu_64(counters->rx_errors);

	/* TX errors */
	rte_stats->oerrors = rte_le_to_cpu_64(counters->tx_errors);

	rte_stats->ipackets = rte_le_to_cpu_64(counters->rx_packets);
	rte_stats->opackets = rte_le_to_cpu_64(counters->tx_packets);
}

void
rtl8126_clear_tally_stats(struct rtl8126_hw *hw)
{
	if (!hw->tally_paddr)
		return;

	RTL_W32(hw, CounterAddrHigh, (u64)hw->tally_paddr >> 32);
	RTL_W32(hw, CounterAddrLow,
	        ((u64)hw->tally_paddr & (DMA_BIT_MASK(32))) | CounterReset);
}

static void
rtl8126_switch_mac_mcu_ram_code_page(struct rtl8126_hw *hw, u16 page)
{
	u16 tmp_ushort;

	page &= (BIT_1 | BIT_0);
	tmp_ushort = rtl8126_mac_ocp_read(hw, 0xE446);
	tmp_ushort &= ~(BIT_1 | BIT_0);
	tmp_ushort |= page;
	rtl8126_mac_ocp_write(hw, 0xE446, tmp_ushort);
}

static void
_rtl8126_write_mac_mcu_ram_code(struct rtl8126_hw *hw, const u16 *entry,
                                u16 entry_cnt)
{
	u16 i;

	for (i = 0; i < entry_cnt; i++)
		rtl8126_mac_ocp_write(hw, 0xF800 + i * 2, entry[i]);
}

static void
_rtl8126_write_mac_mcu_ram_code_with_page(struct rtl8126_hw *hw,
                const u16 *entry, u16 entry_cnt, u16 page_size)
{
	u16 i;
	u16 offset;

	if (page_size == 0) return;

	for (i = 0; i < entry_cnt; i++) {
		offset = i % page_size;
		if (offset == 0) {
			u16 page = (i / page_size);
			rtl8126_switch_mac_mcu_ram_code_page(hw, page);
		}
		rtl8126_mac_ocp_write(hw, 0xF800 + offset * 2, entry[i]);
	}
}

void
rtl8126_write_mac_mcu_ram_code(struct rtl8126_hw *hw, const u16 *entry,
                               u16 entry_cnt)
{
	if (FALSE == HW_SUPPORT_MAC_MCU(hw))
		return;
	if (entry == NULL || entry_cnt == 0)
		return;

	if (hw->MacMcuPageSize > 0)
		_rtl8126_write_mac_mcu_ram_code_with_page(hw, entry, entry_cnt,
		                hw->MacMcuPageSize);
	else
		_rtl8126_write_mac_mcu_ram_code(hw, entry, entry_cnt);
}
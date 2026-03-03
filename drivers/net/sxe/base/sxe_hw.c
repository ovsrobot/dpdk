/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */
#include <rte_byteorder.h>
#if defined(__KERNEL__) || defined(SXE_KERNEL_TEST)
#include "sxe_pci.h"
#include "sxe_log.h"
#include "sxe_debug.h"
#include "sxe_host_hdc.h"
#include "sxe_sriov.h"
#include "sxe_compat.h"
#else
#include "sxe_errno.h"
#include "sxe_logs.h"
#include "sxe.h"
#include "sxe_hw.h"
#endif

#define SXE_PFMSG_MASK  (0xFF00)
#define SXE_MSGID_MASK  (0xFFFFFFFF)
#define SXE_CTRL_MSG_MASK		  (0x700)

#define SXE_RING_WAIT_LOOP		10
#define SXE_LPBK_EN			   0x00000001
#define SXE_RSS_FIELD_MASK		0xffff0000
#define SXE_MRQE_MASK			 0x0000000f

static u32 sxe_read_reg(struct sxe_hw *hw, u32 reg);
static void sxe_write_reg(struct sxe_hw *hw, u32 reg, u32 value);
static void sxe_write_reg64(struct sxe_hw *hw, u32 reg, u64 value);

#define SXE_WRITE_REG_ARRAY_32(a, reg, offset, value) \
	sxe_write_reg(a, (reg) + ((offset) << 2), value)
#define SXE_READ_REG_ARRAY_32(a, reg, offset) \
	sxe_read_reg(a, (reg) + ((offset) << 2))

#define SXE_REG_READ(hw, addr)		sxe_read_reg(hw, addr)
#define SXE_REG_WRITE(hw, reg, value) sxe_write_reg(hw, reg, value)
#define SXE_WRITE_FLUSH(a) sxe_read_reg(a, SXE_STATUS)
#define SXE_REG64_WRITE(a, reg, value) sxe_write_reg64((a), (reg), (value))

static u32 sxe_read_reg(struct sxe_hw *hw, u32 reg)
{
	u32 i, value;
	u8  __iomem *base_addr = hw->reg_base_addr;

	value = rte_le_to_cpu_32(rte_read32(base_addr + reg));
	if (unlikely(value == SXE_REG_READ_FAIL)) {
		value = rte_le_to_cpu_32(rte_read32(base_addr + SXE_STATUS));
		if (unlikely(value != SXE_REG_READ_FAIL)) {
			value = rte_le_to_cpu_32(rte_read32(base_addr + reg));
		} else {
			LOG_ERROR("reg[0x%x] and reg[0x%x] read failed, ret=%#x",
							reg, SXE_STATUS, value);
			for (i = 0; i < SXE_REG_READ_RETRY; i++) {
				value = rte_le_to_cpu_32(rte_read32(base_addr + SXE_STATUS));
				if (unlikely(value != SXE_REG_READ_FAIL)) {
					value = rte_le_to_cpu_32(rte_read32(base_addr + reg));
					LOG_INFO("reg[0x%x] read ok, value=%#x",
									reg, value);
					break;
				}
				LOG_ERROR("reg[0x%x] and reg[0x%x] read failed, ret=%#x",
						reg, SXE_STATUS, value);

				mdelay(3);
			}
		}
	}

	return value;
}

static void sxe_write_reg(struct sxe_hw *hw, u32 reg, u32 value)
{
	u8 __iomem *base_addr = hw->reg_base_addr;

	rte_write32((rte_cpu_to_le_32(value)), (base_addr + reg));
}

static void sxe_write_reg64(struct sxe_hw *hw, u32 reg, u64 value)
{
	u8 __iomem *reg_addr = hw->reg_base_addr;

	if (sxe_is_hw_fault(hw))
		return;

	writeq(value, reg_addr + reg);
}

void sxe_hw_no_snoop_disable(struct sxe_hw *hw)
{
	u32 ctrl_ext;

	ctrl_ext = SXE_REG_READ(hw, SXE_CTRL_EXT);
	ctrl_ext |= SXE_CTRL_EXT_NS_DIS;
	SXE_REG_WRITE(hw, SXE_CTRL_EXT, ctrl_ext);
	SXE_WRITE_FLUSH(hw);
}

void sxe_hw_uc_addr_pool_del(struct sxe_hw *hw, u32 rar_idx, u32 pool_idx)
{
	u32 value;

	if (sxe_is_hw_fault(hw))
		goto l_end;

	if (pool_idx < 32) {
		value = SXE_REG_READ(hw, SXE_MPSAR_LOW(rar_idx));
		value &= ~BIT(pool_idx);
		SXE_REG_WRITE(hw, SXE_MPSAR_LOW(rar_idx), value);
	} else {
		value = SXE_REG_READ(hw, SXE_MPSAR_HIGH(rar_idx));
		value &= ~BIT(pool_idx - 32);
		SXE_REG_WRITE(hw, SXE_MPSAR_HIGH(rar_idx), value);
	}

l_end:
	return;
}

s32 sxe_hw_uc_addr_pool_enable(struct sxe_hw *hw, u8 rar_idx, u8 pool_idx)
{
	s32 ret = 0;
	u32 value;
	struct sxe_adapter *adapter = hw->adapter;

	if (rar_idx > SXE_UC_ENTRY_NUM_MAX) {
		ret = -SXE_ERR_PARAM;
		LOG_DEV_ERR("pool_idx:%d rar_idx:%d invalid.",
			  pool_idx, rar_idx);
		goto l_end;
	}

	if (pool_idx < 32) {
		value = SXE_REG_READ(hw, SXE_MPSAR_LOW(rar_idx));
		value |= BIT(pool_idx);
		SXE_REG_WRITE(hw, SXE_MPSAR_LOW(rar_idx), value);
	} else {
		value = SXE_REG_READ(hw, SXE_MPSAR_HIGH(rar_idx));
		value |= BIT(pool_idx - 32);
		SXE_REG_WRITE(hw, SXE_MPSAR_HIGH(rar_idx), value);
	}

l_end:
	return ret;
}

static s32 sxe_hw_uc_addr_pool_disable(struct sxe_hw *hw, u8 rar_idx)
{
	u32 hi;
	u32 low;
	struct sxe_adapter *adapter = hw->adapter;

	hi = SXE_REG_READ(hw, SXE_MPSAR_HIGH(rar_idx));
	low = SXE_REG_READ(hw, SXE_MPSAR_LOW(rar_idx));

	if (sxe_is_hw_fault(hw))
		goto l_end;

	if (!hi & !low) {
		LOG_DEBUG_BDF("no need clear rar-pool relation register.");
		goto l_end;
	}

	if (low)
		SXE_REG_WRITE(hw, SXE_MPSAR_LOW(rar_idx), 0);

	if (hi)
		SXE_REG_WRITE(hw, SXE_MPSAR_HIGH(rar_idx), 0);


l_end:
	return 0;
}

s32 sxe_hw_nic_reset(struct sxe_hw *hw)
{
	s32 ret = 0;
	u32 ctrl, i;
	struct sxe_adapter *adapter = hw->adapter;

	ctrl = SXE_CTRL_RST;
	ctrl |= SXE_REG_READ(hw, SXE_CTRL);
	ctrl &= ~SXE_CTRL_GIO_DIS;
	SXE_REG_WRITE(hw, SXE_CTRL, ctrl);

	SXE_WRITE_FLUSH(hw);
	usleep_range(1000, 1200);

	for (i = 0; i < 10; i++) {
		ctrl = SXE_REG_READ(hw, SXE_CTRL);
		if (!(ctrl & SXE_CTRL_RST_MASK))
			break;

		sxe_udelay(1);
	}

	if (ctrl & SXE_CTRL_RST_MASK) {
		ret = -SXE_ERR_RESET_FAILED;
		LOG_DEV_ERR("reset polling failed to complete");
	}

	return ret;
}

void sxe_hw_pf_rst_done_set(struct sxe_hw *hw)
{
	u32 value;

	value = SXE_REG_READ(hw, SXE_CTRL_EXT);
	value |= SXE_CTRL_EXT_PFRSTD;
	SXE_REG_WRITE(hw, SXE_CTRL_EXT, value);
}

u32 sxe_hw_pending_irq_read_clear(struct sxe_hw *hw)
{
	return SXE_REG_READ(hw, SXE_EICR);
}

void sxe_hw_pending_irq_write_clear(struct sxe_hw *hw, u32 value)
{
	SXE_REG_WRITE(hw, SXE_EICR, value);
}

u32 sxe_hw_irq_cause_get(struct sxe_hw *hw)
{
	return SXE_REG_READ(hw, SXE_EICS);
}

void sxe_hw_ring_irq_auto_disable(struct sxe_hw *hw,
					bool is_msix)
{
	if (is_msix) {
		SXE_REG_WRITE(hw, SXE_EIAM_EX(0), 0xFFFFFFFF);
		SXE_REG_WRITE(hw, SXE_EIAM_EX(1), 0xFFFFFFFF);
	} else {
		SXE_REG_WRITE(hw, SXE_EIAM, SXE_EICS_RTX_QUEUE);
	}
}

void sxe_hw_irq_general_reg_set(struct sxe_hw *hw, u32 value)
{
	SXE_REG_WRITE(hw, SXE_GPIE, value);
}

u32 sxe_hw_irq_general_reg_get(struct sxe_hw *hw)
{
	return SXE_REG_READ(hw, SXE_GPIE);
}

void sxe_hw_event_irq_map(struct sxe_hw *hw, u8 offset, u16 irq_idx)
{
	u8  allocation;
	u32 ivar, position;

	allocation = irq_idx | SXE_IVAR_ALLOC_VALID;

	position = (offset & 1) * 8;

	ivar = SXE_REG_READ(hw, SXE_IVAR_MISC);
	ivar &= ~(0xFF << position);
	ivar |= (allocation << position);

	SXE_REG_WRITE(hw, SXE_IVAR_MISC, ivar);
}

void sxe_hw_ring_irq_map(struct sxe_hw *hw, bool is_tx,
						u16 reg_idx, u16 irq_idx)
{
	u8  allocation;
	u32 ivar, position;

	allocation = irq_idx | SXE_IVAR_ALLOC_VALID;

	position = ((reg_idx & 1) * 16) + (8 * is_tx);

	ivar = SXE_REG_READ(hw, SXE_IVAR(reg_idx >> 1));
	ivar &= ~(0xFF << position);
	ivar |= (allocation << position);

	SXE_REG_WRITE(hw, SXE_IVAR(reg_idx >> 1), ivar);
}

void sxe_hw_ring_irq_interval_set(struct sxe_hw *hw,
						u16 irq_idx, u32 interval)
{
	u32 eitr = interval & SXE_EITR_ITR_MASK;

	eitr |= SXE_EITR_CNT_WDIS;

	SXE_REG_WRITE(hw, SXE_EITR(irq_idx), eitr);
}

void sxe_hw_event_irq_auto_clear_set(struct sxe_hw *hw, u32 value)
{
	SXE_REG_WRITE(hw, SXE_EIAC, value);
}

void sxe_hw_specific_irq_disable(struct sxe_hw *hw, u32 value)
{
	SXE_REG_WRITE(hw, SXE_EIMC, value);
}

void sxe_hw_specific_irq_enable(struct sxe_hw *hw, u32 value)
{
	SXE_REG_WRITE(hw, SXE_EIMS, value);
}

void sxe_hw_all_irq_disable(struct sxe_hw *hw)
{
	SXE_REG_WRITE(hw, SXE_EIMC, 0xFFFF0000);

	SXE_REG_WRITE(hw, SXE_EIMC_EX(0), ~0);
	SXE_REG_WRITE(hw, SXE_EIMC_EX(1), ~0);

	SXE_WRITE_FLUSH(hw);
}

u32 sxe_hw_link_speed_get(struct sxe_hw *hw)
{
	u32 speed, value;
	struct sxe_adapter *adapter = hw->adapter;
	value = SXE_REG_READ(hw, SXE_COMCTRL);

	if ((value & SXE_COMCTRL_SPEED_10G) == SXE_COMCTRL_SPEED_10G)
		speed = SXE_LINK_SPEED_10GB_FULL;
	else if ((value & SXE_COMCTRL_SPEED_1G) == SXE_COMCTRL_SPEED_1G)
		speed = SXE_LINK_SPEED_1GB_FULL;
	else
		speed = SXE_LINK_SPEED_UNKNOWN;

	LOG_DEBUG_BDF("hw link speed=%x, (0x80=10G, 0x20=1G), reg=%x",
			speed, value);

	return speed;
}

bool sxe_hw_is_link_state_up(struct sxe_hw *hw)
{
	bool ret = false;
	u32 links_reg, link_speed;
	struct sxe_adapter *adapter = hw->adapter;

	links_reg  = SXE_REG_READ(hw, SXE_LINKS);

	LOG_DEBUG_BDF("nic link reg: 0x%x", links_reg);

	if (links_reg & SXE_LINKS_UP) {
		ret = true;

		link_speed = sxe_hw_link_speed_get(hw);
		if (link_speed == SXE_LINK_SPEED_10GB_FULL &&
			links_reg & SXE_10G_LINKS_DOWN)
			ret = false;
	}

	return ret;
}

void sxe_hw_mac_pad_enable(struct sxe_hw *hw)
{
	u32 ctl;

	ctl = SXE_REG_READ(hw, SXE_MACCFG);
	ctl |= SXE_MACCFG_PAD_EN;
	SXE_REG_WRITE(hw, SXE_MACCFG, ctl);
}

s32 sxe_hw_fc_enable(struct sxe_hw *hw)
{
	s32 ret = 0;
	u8  i;
	u32 reg;
	u32 flctrl_val;
	u32 fcrtl, fcrth;
	struct sxe_adapter *adapter = hw->adapter;

	flctrl_val = SXE_REG_READ(hw, SXE_FLCTRL);
	flctrl_val &= ~(SXE_FCTRL_TFCE_MASK | SXE_FCTRL_RFCE_MASK |
			   SXE_FCTRL_TFCE_FCEN_MASK | SXE_FCTRL_TFCE_XONE_MASK);

	switch (hw->fc.current_mode) {
	case SXE_FC_NONE:
		break;
	case SXE_FC_RX_PAUSE:
		flctrl_val |= SXE_FCTRL_RFCE_LFC_EN;
		break;
	case SXE_FC_TX_PAUSE:
		flctrl_val |= SXE_FCTRL_TFCE_LFC_EN;
		break;
	case SXE_FC_FULL:
		flctrl_val |= SXE_FCTRL_RFCE_LFC_EN;
		flctrl_val |= SXE_FCTRL_TFCE_LFC_EN;
		break;
	default:
		LOG_DEV_DEBUG("flow control param set incorrectly");
		ret = -SXE_ERR_CONFIG;
		goto l_ret;
	}

	for (i = 0; i < MAX_TRAFFIC_CLASS; i++) {
		if ((hw->fc.current_mode & SXE_FC_TX_PAUSE) &&
			hw->fc.high_water[i]) {
			fcrtl = (hw->fc.low_water[i] << 9) | SXE_FCRTL_XONE;
			SXE_REG_WRITE(hw, SXE_FCRTL(i), fcrtl);
			fcrth = (hw->fc.high_water[i] << 9) | SXE_FCRTH_FCEN;
		} else {
			SXE_REG_WRITE(hw, SXE_FCRTL(i), 0);
			fcrth = (SXE_REG_READ(hw, SXE_RXPBSIZE(i)) - 24576) >> 1;
		}

		SXE_REG_WRITE(hw, SXE_FCRTH(i), fcrth);
	}

	flctrl_val |= SXE_FCTRL_TFCE_DPF_EN;

	if ((hw->fc.current_mode & SXE_FC_TX_PAUSE))
		flctrl_val |= (SXE_FCTRL_TFCE_FCEN_MASK | SXE_FCTRL_TFCE_XONE_MASK);

	SXE_REG_WRITE(hw, SXE_FLCTRL, flctrl_val);

	reg = SXE_REG_READ(hw, SXE_PFCTOP);
	reg &= ~SXE_PFCTOP_FCOP_MASK;
	reg |= SXE_PFCTOP_FCT;
	reg |= SXE_PFCTOP_FCOP_LFC;
	SXE_REG_WRITE(hw, SXE_PFCTOP, reg);

	reg = hw->fc.pause_time * 0x00010001U;
	for (i = 0; i < (MAX_TRAFFIC_CLASS / 2); i++)
		SXE_REG_WRITE(hw, SXE_FCTTV(i), reg);

	SXE_REG_WRITE(hw, SXE_FCRTV, hw->fc.pause_time / 2);

l_ret:
	return ret;
}

void sxe_fc_autoneg_localcap_set(struct sxe_hw *hw)
{
	u32 reg = 0;

	if (hw->fc.requested_mode == SXE_FC_DEFAULT)
		hw->fc.requested_mode = SXE_FC_FULL;

	reg = SXE_REG_READ(hw, SXE_PCS1GANA);

	switch (hw->fc.requested_mode) {
	case SXE_FC_NONE:
		reg &= ~(SXE_PCS1GANA_SYM_PAUSE | SXE_PCS1GANA_ASM_PAUSE);
		break;
	case SXE_FC_TX_PAUSE:
		reg |= SXE_PCS1GANA_ASM_PAUSE;
		reg &= ~SXE_PCS1GANA_SYM_PAUSE;
		break;
	case SXE_FC_RX_PAUSE:
	case SXE_FC_FULL:
		reg |= SXE_PCS1GANA_SYM_PAUSE | SXE_PCS1GANA_ASM_PAUSE;
		break;
	default:
		LOG_ERROR("Flow control param set incorrectly.");
		break;
	}

	SXE_REG_WRITE(hw, SXE_PCS1GANA, reg);
}

s32 sxe_hw_pfc_enable(struct sxe_hw *hw, u8 tc_idx)
{
	s32 ret = 0;
	u8  i;
	u32 reg;
	u32 flctrl_val;
	u32 fcrtl, fcrth;
	struct sxe_adapter *adapter = hw->adapter;
	u8 rx_en_num;

	flctrl_val = SXE_REG_READ(hw, SXE_FLCTRL);
	flctrl_val &= ~(SXE_FCTRL_TFCE_MASK | SXE_FCTRL_RFCE_MASK |
			   SXE_FCTRL_TFCE_FCEN_MASK | SXE_FCTRL_TFCE_XONE_MASK);

	switch (hw->fc.current_mode) {
	case SXE_FC_NONE:
		rx_en_num = 0;
		for (i = 0; i < MAX_TRAFFIC_CLASS; i++) {
			reg = SXE_REG_READ(hw, SXE_FCRTH(i));
			if (reg & SXE_FCRTH_FCEN)
				rx_en_num++;
		}
		if (rx_en_num > 1)
			flctrl_val |= SXE_FCTRL_TFCE_PFC_EN;

		break;

	case SXE_FC_RX_PAUSE:
		flctrl_val |= SXE_FCTRL_RFCE_PFC_EN;

		rx_en_num = 0;
		for (i = 0; i < MAX_TRAFFIC_CLASS; i++) {
			reg = SXE_REG_READ(hw, SXE_FCRTH(i));
			if (reg & SXE_FCRTH_FCEN)
				rx_en_num++;
		}

		if (rx_en_num > 1)
			flctrl_val |= SXE_FCTRL_TFCE_PFC_EN;

		break;
	case SXE_FC_TX_PAUSE:
		flctrl_val |= SXE_FCTRL_TFCE_PFC_EN;
		break;
	case SXE_FC_FULL:
		flctrl_val |= SXE_FCTRL_RFCE_PFC_EN;
		flctrl_val |= SXE_FCTRL_TFCE_PFC_EN;
		break;
	default:
		LOG_DEV_DEBUG("flow control param set incorrectly");
		ret = -SXE_ERR_CONFIG;
		goto l_ret;
	}

	if ((hw->fc.current_mode & SXE_FC_TX_PAUSE) &&
		hw->fc.high_water[tc_idx]) {
		fcrtl = (hw->fc.low_water[tc_idx] << 9) | SXE_FCRTL_XONE;
		SXE_REG_WRITE(hw, SXE_FCRTL(tc_idx), fcrtl);
		fcrth = (hw->fc.high_water[tc_idx] << 9) | SXE_FCRTH_FCEN;
	} else {
		SXE_REG_WRITE(hw, SXE_FCRTL(tc_idx), 0);
		fcrth = (SXE_REG_READ(hw, SXE_RXPBSIZE(tc_idx)) - 24576) >> 1;
	}

	SXE_REG_WRITE(hw, SXE_FCRTH(tc_idx), fcrth);

	flctrl_val |= SXE_FCTRL_TFCE_DPF_EN;

	if ((hw->fc.current_mode & SXE_FC_TX_PAUSE)) {
		flctrl_val |= (BIT(tc_idx) << 16) & SXE_FCTRL_TFCE_FCEN_MASK;
		flctrl_val |= (BIT(tc_idx) << 24) & SXE_FCTRL_TFCE_XONE_MASK;
	}

	SXE_REG_WRITE(hw, SXE_FLCTRL, flctrl_val);

	reg = SXE_REG_READ(hw, SXE_PFCTOP);
	reg &= ~SXE_PFCTOP_FCOP_MASK;
	reg |= SXE_PFCTOP_FCT;
	reg |= SXE_PFCTOP_FCOP_PFC;
	SXE_REG_WRITE(hw, SXE_PFCTOP, reg);

	reg = hw->fc.pause_time * 0x00010001U;
	for (i = 0; i < (MAX_TRAFFIC_CLASS / 2); i++)
		SXE_REG_WRITE(hw, SXE_FCTTV(i), reg);

	SXE_REG_WRITE(hw, SXE_FCRTV, hw->fc.pause_time / 2);

l_ret:
	return ret;
}

void sxe_hw_loopback_switch(struct sxe_hw *hw, bool is_enable)
{
	u32 value;

	value = is_enable ? SXE_LPBK_EN : 0;

	SXE_REG_WRITE(hw, SXE_LPBKCTRL, value);
}

void sxe_hw_mac_txrx_enable(struct sxe_hw *hw)
{
	u32 ctl;

	ctl = SXE_REG_READ(hw, SXE_COMCTRL);
	ctl |= SXE_COMCTRL_TXEN | SXE_COMCTRL_RXEN | SXE_COMCTRL_EDSEL;
	SXE_REG_WRITE(hw, SXE_COMCTRL, ctl);
}

u32 sxe_hw_mac_max_frame_get(struct sxe_hw *hw)
{
	u32 maxfs = SXE_REG_READ(hw, SXE_MAXFS);

	maxfs &= SXE_MAXFS_MFS_MASK;
	maxfs >>= SXE_MAXFS_MFS_SHIFT;

	return maxfs;
}

void sxe_hw_fc_tc_high_water_mark_set(struct sxe_hw *hw, u8 tc_idx, u32 mark)
{
	hw->fc.high_water[tc_idx] = mark;
}

void sxe_hw_fc_tc_low_water_mark_set(struct sxe_hw *hw, u8 tc_idx, u32 mark)
{
	hw->fc.low_water[tc_idx] = mark;
}

bool sxe_hw_is_fc_autoneg_disabled(struct sxe_hw *hw)
{
	return hw->fc.disable_fc_autoneg;
}

void sxe_hw_fc_autoneg_disable_set(struct sxe_hw *hw, bool is_disabled)
{
	hw->fc.disable_fc_autoneg = is_disabled;
}

void sxe_hw_fc_requested_mode_set(struct sxe_hw *hw,
						enum sxe_fc_mode mode)
{
	hw->fc.requested_mode = mode;
}

u32 sxe_hw_rx_mode_get(struct sxe_hw *hw)
{
	return SXE_REG_READ(hw, SXE_FCTRL);
}

u32 sxe_hw_pool_rx_mode_get(struct sxe_hw *hw, u16 pool_idx)
{
	return SXE_REG_READ(hw, SXE_VMOLR(pool_idx));
}

void sxe_hw_rx_mode_set(struct sxe_hw *hw, u32 filter_ctrl)
{
	SXE_REG_WRITE(hw, SXE_FCTRL, filter_ctrl);
}

void sxe_hw_pool_rx_mode_set(struct sxe_hw *hw, u32 vmolr, u16 pool_idx)
{
	SXE_REG_WRITE(hw, SXE_VMOLR(pool_idx), vmolr);
}

void sxe_hw_rx_lro_enable(struct sxe_hw *hw, bool is_enable)
{
	u32 rfctl = SXE_REG_READ(hw, SXE_RFCTL);
	rfctl &= ~SXE_RFCTL_LRO_DIS;

	if (!is_enable)
		rfctl |= SXE_RFCTL_LRO_DIS;

	SXE_REG_WRITE(hw, SXE_RFCTL, rfctl);
}

void sxe_hw_rx_nfs_filter_disable(struct sxe_hw *hw)
{
	u32 rfctl = 0;

	rfctl |= (SXE_RFCTL_NFSW_DIS | SXE_RFCTL_NFSR_DIS);
	SXE_REG_WRITE(hw, SXE_RFCTL, rfctl);
}

void sxe_hw_rx_udp_frag_checksum_disable(struct sxe_hw *hw)
{
	u32 rxcsum;

	rxcsum = SXE_REG_READ(hw, SXE_RXCSUM);
	rxcsum |= SXE_RXCSUM_PCSD;
	SXE_REG_WRITE(hw, SXE_RXCSUM, rxcsum);
}

void sxe_hw_fc_mac_addr_set(struct sxe_hw *hw, u8 *mac_addr)
{
	u32 mac_addr_h, mac_addr_l;

	mac_addr_l = ((u32)mac_addr[5] |
			((u32)mac_addr[4] << 8) |
			((u32)mac_addr[3] << 16) |
			((u32)mac_addr[2] << 24));
	mac_addr_h = (((u32)mac_addr[1] << 16) |
			((u32)mac_addr[0] << 24));

	SXE_REG_WRITE(hw, SXE_SACONH, mac_addr_h);
	SXE_REG_WRITE(hw, SXE_SACONL, mac_addr_l);
}

s32 sxe_hw_uc_addr_add(struct sxe_hw *hw, u32 rar_idx,
					u8 *addr, u32 pool_idx)
{
	s32 ret = 0;
	u32 rar_low, rar_high;
	struct sxe_adapter *adapter = hw->adapter;

	if (rar_idx >= SXE_UC_ENTRY_NUM_MAX) {
		LOG_DEV_DEBUG("RAR rar_idx %d is out of range:%u.",
			rar_idx, SXE_UC_ENTRY_NUM_MAX);
		ret = -SXE_ERR_PARAM;
		goto l_end;
	}

	sxe_hw_uc_addr_pool_enable(hw, rar_idx, pool_idx);

	rar_low = ((u32)addr[0] |
		   ((u32)addr[1] << 8) |
		   ((u32)addr[2] << 16) |
		   ((u32)addr[3] << 24));

	rar_high = SXE_REG_READ(hw, SXE_RAH(rar_idx));
	rar_high &= ~(0x0000FFFF | SXE_RAH_AV);
	rar_high |= ((u32)addr[4] | ((u32)addr[5] << 8));

	rar_high |= SXE_RAH_AV;

	SXE_REG_WRITE(hw, SXE_RAL(rar_idx), rar_low);
	SXE_WRITE_FLUSH(hw);
	SXE_REG_WRITE(hw, SXE_RAH(rar_idx), rar_high);

	LOG_DEBUG_BDF("rar_idx:%d pool_idx:%u addr:%pM add to rar done",
		rar_idx, pool_idx, addr);

l_end:
	return ret;
}

s32 sxe_hw_uc_addr_del(struct sxe_hw *hw, u32 index)
{
	s32 ret = 0;
	u32 rar_high;
	struct sxe_adapter *adapter = hw->adapter;

	if (index >= SXE_UC_ENTRY_NUM_MAX) {
		ret = -SXE_ERR_PARAM;
		LOG_ERROR_BDF("uc_entry_num:%d index:%u invalid.(err:%d)",
			  SXE_UC_ENTRY_NUM_MAX, index, ret);
		goto l_end;
	}

	rar_high = SXE_REG_READ(hw, SXE_RAH(index));
	rar_high &= ~(0x0000FFFF | SXE_RAH_AV);

	SXE_REG_WRITE(hw, SXE_RAH(index), rar_high);
	SXE_WRITE_FLUSH(hw);
	SXE_REG_WRITE(hw, SXE_RAL(index), 0);

	sxe_hw_uc_addr_pool_disable(hw, index);

l_end:
	return ret;
}

void sxe_hw_mta_hash_table_set(struct sxe_hw *hw, u8 index, u32 value)
{
	SXE_REG_WRITE(hw, SXE_MTA(index), value);
}

void sxe_hw_mta_hash_table_update(struct sxe_hw *hw, u8 reg_idx, u8 bit_idx)
{
	u32 value = SXE_REG_READ(hw, SXE_MTA(reg_idx));

	value |= BIT(bit_idx);

	LOG_INFO("mta update value:0x%x.", value);
	SXE_REG_WRITE(hw, SXE_MTA(reg_idx), value);
}

u32 sxe_hw_mc_filter_get(struct sxe_hw *hw)
{
	return SXE_REG_READ(hw, SXE_MCSTCTRL);
}

void sxe_hw_mc_filter_enable(struct sxe_hw *hw)
{
	u32 value = SXE_MC_FILTER_TYPE0 | SXE_MCSTCTRL_MFE;

	SXE_REG_WRITE(hw, SXE_MCSTCTRL, value);
}

void sxe_hw_uc_addr_clear(struct sxe_hw *hw)
{
	u32 i;
	struct sxe_adapter *adapter = hw->adapter;

	sxe_hw_uc_addr_pool_disable(hw, 0);

	LOG_DEV_DEBUG("clear uc filter addr register:0-%d",
		   SXE_UC_ENTRY_NUM_MAX - 1);
	for (i = 0; i < SXE_UC_ENTRY_NUM_MAX; i++) {
		SXE_REG_WRITE(hw, SXE_RAL(i), 0);
		SXE_REG_WRITE(hw, SXE_RAH(i), 0);
	}

	LOG_DEV_DEBUG("clear %u uta filter addr register",
			SXE_UTA_ENTRY_NUM_MAX);
	for (i = 0; i < SXE_UTA_ENTRY_NUM_MAX; i++)
		SXE_REG_WRITE(hw, SXE_UTA(i), 0);

	SXE_REG_WRITE(hw, SXE_MCSTCTRL, SXE_MC_FILTER_TYPE0);

	LOG_DEV_DEBUG("clear %u mta filter addr register",
			SXE_MTA_ENTRY_NUM_MAX);
	for (i = 0; i < SXE_MTA_ENTRY_NUM_MAX; i++)
		SXE_REG_WRITE(hw, SXE_MTA(i), 0);
}

void sxe_hw_vt_ctrl_cfg(struct sxe_hw *hw, u8 default_pool)
{
	u32 ctrl;

	ctrl = SXE_REG_READ(hw, SXE_VT_CTL);

	ctrl |= SXE_VT_CTL_VT_ENABLE;
	ctrl &= ~SXE_VT_CTL_POOL_MASK;
	ctrl |= default_pool << SXE_VT_CTL_POOL_SHIFT;
	ctrl |= SXE_VT_CTL_REPLEN;

	SXE_REG_WRITE(hw, SXE_VT_CTL, ctrl);
}

void sxe_hw_vlan_filter_array_write(struct sxe_hw *hw,
					u16 reg_index, u32 value)
{
	SXE_REG_WRITE(hw, SXE_VFTA(reg_index), value);
}

u32 sxe_hw_vlan_filter_array_read(struct sxe_hw *hw, u16 reg_index)
{
	return SXE_REG_READ(hw, SXE_VFTA(reg_index));
}

void sxe_hw_vlan_filter_switch(struct sxe_hw *hw, bool is_enable)
{
	u32 vlnctrl;

	vlnctrl = SXE_REG_READ(hw, SXE_VLNCTRL);
	if (is_enable)
		vlnctrl |= SXE_VLNCTRL_VFE;
	else
		vlnctrl &= ~SXE_VLNCTRL_VFE;

	SXE_REG_WRITE(hw, SXE_VLNCTRL, vlnctrl);
}

s32 sxe_hw_vlvf_slot_find(struct sxe_hw *hw, u32 vlan, bool vlvf_bypass)
{
	s32 ret, regindex, first_empty_slot;
	u32 bits;
	struct sxe_adapter *adapter = hw->adapter;

	if (vlan == 0) {
		ret = 0;
		goto l_end;
	}

	first_empty_slot = vlvf_bypass ? -SXE_ERR_NO_SPACE : 0;

	vlan |= SXE_VLVF_VIEN;

	for (regindex = SXE_VLVF_ENTRIES; --regindex;) {
		bits = SXE_REG_READ(hw, SXE_VLVF(regindex));
		if (bits == vlan) {
			ret = regindex;
			goto l_end;
		}

		if (!first_empty_slot && !bits)
			first_empty_slot = regindex;
	}

	if (!first_empty_slot)
		LOG_DEV_WARN("no space in VLVF.");

	ret = first_empty_slot ? : -SXE_ERR_NO_SPACE;
l_end:
	return ret;
}

s32 sxe_hw_vlan_filter_configure(struct sxe_hw *hw, u32 vid, u32 pool,
				 bool vlan_on, bool vlvf_bypass)
{
	s32 ret = 0;
	u32 regidx, vfta_delta, vfta, bits;
	s32 vlvf_index;

	LOG_DEBUG("vid: %u, pool: %u, vlan_on: %d, vlvf_bypass: %d",
		vid, pool, vlan_on, vlvf_bypass);

	if (vid > 4095 || pool > 63) {
		ret = -SXE_ERR_PARAM;
		goto l_end;
	}

	regidx = vid / 32;
	vfta_delta = BIT(vid % 32);
	vfta = SXE_REG_READ(hw, SXE_VFTA(regidx));

	vfta_delta &= vlan_on ? ~vfta : vfta;
	vfta ^= vfta_delta;

	if (!(SXE_REG_READ(hw, SXE_VT_CTL) & SXE_VT_CTL_VT_ENABLE))
		goto vfta_update;

	vlvf_index = sxe_hw_vlvf_slot_find(hw, vid, vlvf_bypass);
	if (vlvf_index < 0) {
		if (vlvf_bypass)
			goto vfta_update;

		ret = vlvf_index;
		goto l_end;
	}

	bits = SXE_REG_READ(hw, SXE_VLVFB(vlvf_index * 2 + pool / 32));

	bits |= BIT(pool % 32);
	if (vlan_on)
		goto vlvf_update;

	bits ^= BIT(pool % 32);

	if (!bits &&
		!SXE_REG_READ(hw, SXE_VLVFB(vlvf_index * 2 + 1 - pool / 32))) {
		if (vfta_delta)
			SXE_REG_WRITE(hw, SXE_VFTA(regidx), vfta);

		SXE_REG_WRITE(hw, SXE_VLVF(vlvf_index), 0);
		SXE_REG_WRITE(hw, SXE_VLVFB(vlvf_index * 2 + pool / 32), 0);

		goto l_end;
	}

	vfta_delta = 0;

vlvf_update:
	SXE_REG_WRITE(hw, SXE_VLVFB(vlvf_index * 2 + pool / 32), bits);
	SXE_REG_WRITE(hw, SXE_VLVF(vlvf_index), SXE_VLVF_VIEN | vid);

vfta_update:
	if (vfta_delta)
		SXE_REG_WRITE(hw, SXE_VFTA(regidx), vfta);

l_end:
	return ret;
}

void sxe_hw_vlan_filter_array_clear(struct sxe_hw *hw)
{
	u32 offset;

	for (offset = 0; offset < SXE_VFT_TBL_SIZE; offset++)
		SXE_REG_WRITE(hw, SXE_VFTA(offset), 0);

	for (offset = 0; offset < SXE_VLVF_ENTRIES; offset++) {
		SXE_REG_WRITE(hw, SXE_VLVF(offset), 0);
		SXE_REG_WRITE(hw, SXE_VLVFB(offset * 2), 0);
		SXE_REG_WRITE(hw, SXE_VLVFB(offset * 2 + 1), 0);
	}
}

static void sxe_hw_rx_pkt_buf_switch(struct sxe_hw *hw, bool is_on)
{
	u32 dbucfg = SXE_REG_READ(hw, SXE_DRXCFG);

	if (is_on)
		dbucfg |= SXE_DRXCFG_DBURX_START;
	else
		dbucfg &= ~SXE_DRXCFG_DBURX_START;

	SXE_REG_WRITE(hw, SXE_DRXCFG, dbucfg);
}

u32 sxe_hw_rx_pkt_buf_size_get(struct sxe_hw *hw, u8 pb)
{
	return SXE_REG_READ(hw, SXE_RXPBSIZE(pb));
}

void sxe_hw_rx_multi_ring_configure(struct sxe_hw *hw, u8 tcs,
				    bool is_4q_per_pool, bool sriov_enable)
{
	u32 mrqc = SXE_REG_READ(hw, SXE_MRQC);

	mrqc &= ~SXE_MRQE_MASK;

	if (sriov_enable) {
		if (tcs > 4)
			mrqc |= SXE_MRQC_VMDQRT8TCEN;
		else if (tcs > 1)
			mrqc |= SXE_MRQC_VMDQRT4TCEN;
		else if (is_4q_per_pool)
			mrqc |= SXE_MRQC_VMDQRSS32EN;
		else
			mrqc |= SXE_MRQC_VMDQRSS64EN;

	} else {
		if (tcs > 4)
			mrqc |= SXE_MRQC_RTRSS8TCEN;
		else if (tcs > 1)
			mrqc |= SXE_MRQC_RTRSS4TCEN;
		else
			mrqc |= SXE_MRQC_RSSEN;
	}

	SXE_REG_WRITE(hw, SXE_MRQC, mrqc);
}

void sxe_hw_rss_key_set_all(struct sxe_hw *hw, u32 *rss_key)
{
	u32 i;

	for (i = 0; i < SXE_MAX_RSS_KEY_ENTRIES; i++)
		SXE_REG_WRITE(hw, SXE_RSSRK(i), rss_key[i]);
}

void sxe_hw_rss_redir_tbl_reg_write(struct sxe_hw *hw,
						u16 reg_idx, u32 value)
{
	SXE_REG_WRITE(hw, SXE_RETA(reg_idx >> 2), value);
}

void sxe_hw_rss_redir_tbl_set_all(struct sxe_hw *hw, u8 *redir_tbl)
{
	u32 i;
	u32 tbl = 0;
	u32 indices_multi = 0x1;


	for (i = 0; i < SXE_MAX_RETA_ENTRIES; i++) {
		tbl |= indices_multi * redir_tbl[i] << (i & 0x3) * 8;
		if ((i & 3) == 3) {
			sxe_hw_rss_redir_tbl_reg_write(hw, i, tbl);
			tbl = 0;
		}
	}
}

void sxe_hw_rx_cap_switch_on(struct sxe_hw *hw)
{
	u32 rxctrl;

	if (hw->mac.set_lben) {
		u32 pfdtxgswc = SXE_REG_READ(hw, SXE_PFDTXGSWC);
		pfdtxgswc |= SXE_PFDTXGSWC_VT_LBEN;
		SXE_REG_WRITE(hw, SXE_PFDTXGSWC, pfdtxgswc);
		hw->mac.set_lben = false;
	}

	rxctrl = SXE_REG_READ(hw, SXE_RXCTRL);
	rxctrl |= SXE_RXCTRL_RXEN;
	SXE_REG_WRITE(hw, SXE_RXCTRL, rxctrl);
}

void sxe_hw_rx_cap_switch_off(struct sxe_hw *hw)
{
	u32 rxctrl;

	rxctrl = SXE_REG_READ(hw, SXE_RXCTRL);
	if (rxctrl & SXE_RXCTRL_RXEN) {
		u32 pfdtxgswc = SXE_REG_READ(hw, SXE_PFDTXGSWC);
		if (pfdtxgswc & SXE_PFDTXGSWC_VT_LBEN) {
			pfdtxgswc &= ~SXE_PFDTXGSWC_VT_LBEN;
			SXE_REG_WRITE(hw, SXE_PFDTXGSWC, pfdtxgswc);
			hw->mac.set_lben = true;
		} else {
			hw->mac.set_lben = false;
		}
		rxctrl &= ~SXE_RXCTRL_RXEN;
		SXE_REG_WRITE(hw, SXE_RXCTRL, rxctrl);
	}
}

void sxe_hw_tx_pkt_buf_switch(struct sxe_hw *hw, bool is_on)
{
	u32 dbucfg;

	dbucfg = SXE_REG_READ(hw, SXE_DTXCFG);

	if (is_on) {
		dbucfg |= SXE_DTXCFG_DBUTX_START;
		dbucfg |= SXE_DTXCFG_DBUTX_BUF_ALFUL_CFG;
		SXE_REG_WRITE(hw, SXE_DTXCFG, dbucfg);
	} else {
		dbucfg &= ~SXE_DTXCFG_DBUTX_START;
		SXE_REG_WRITE(hw, SXE_DTXCFG, dbucfg);
	}
}

void sxe_hw_tx_pkt_buf_size_configure(struct sxe_hw *hw, u8 num_pb)
{
	u32 i, tx_pkt_size;

	if (!num_pb)
		num_pb = 1;

	tx_pkt_size = SXE_TX_PBSIZE_MAX / num_pb;
	for (i = 0; i < num_pb; i++)
		SXE_REG_WRITE(hw, SXE_TXPBSIZE(i), tx_pkt_size);

	for (; i < SXE_PKG_BUF_NUM_MAX; i++)
		SXE_REG_WRITE(hw, SXE_TXPBSIZE(i), 0);
}

void sxe_hw_rx_lro_ack_switch(struct sxe_hw *hw, bool is_on)
{
	u32 lro_dbu = SXE_REG_READ(hw, SXE_LRODBU);

	if (is_on)
		lro_dbu &= ~SXE_LRODBU_LROACKDIS;
	else
		lro_dbu |= SXE_LRODBU_LROACKDIS;

	SXE_REG_WRITE(hw, SXE_LRODBU, lro_dbu);
}

u64 sxe_hw_ptp_systime_get(struct sxe_hw *hw)
{
	struct sxe_adapter *adapter = hw->adapter;
	u32 systiml;
	u32 systimm;
	u64 ns;

	systiml = SXE_REG_READ(hw, SXE_SYSTIML);
	systimm = SXE_REG_READ(hw, SXE_SYSTIMM);
	ns = SXE_TIME_TO_NS(systiml, systimm);

	LOG_DEBUG_BDF("get ptp hw systime systiml=%u, systimm=%u, ns=%" SXE_PRIU64,
			systiml, systimm, ns);
	return ns;
}

void sxe_hw_ptp_systime_init(struct sxe_hw *hw)
{
	SXE_REG_WRITE(hw, SXE_SYSTIML, 0);
	SXE_REG_WRITE(hw, SXE_SYSTIMM, 0);
	SXE_REG_WRITE(hw, SXE_SYSTIMH, 0);

	SXE_WRITE_FLUSH(hw);
}

void sxe_hw_ptp_init(struct sxe_hw *hw)
{
	u32 regval;
	u32 tsctl = SXE_TSCTRL_TSEN |
	SXE_TSCTRL_VER_2 |
	SXE_TSCTRL_PTYP_ALL |
	SXE_TSCTRL_L4_UNICAST;

	regval = SXE_REG_READ(hw, SXE_TSCTRL);
	regval &= ~SXE_TSCTRL_ONESTEP;
	regval &= ~SXE_TSCTRL_CSEN;
	regval |= tsctl;
	SXE_REG_WRITE(hw, SXE_TSCTRL, regval);

	SXE_REG_WRITE(hw, SXE_TIMINC,
			SXE_TIMINC_SET(SXE_INCPD, SXE_IV_NS, SXE_IV_SNS));
}

void sxe_hw_ptp_rx_timestamp_clear(struct sxe_hw *hw)
{
	SXE_REG_READ(hw, SXE_RXSTMPH);
}

void sxe_hw_ptp_tx_timestamp_get(struct sxe_hw *hw, u32 *ts_sec, u32 *ts_ns)
{
	u32 reg_sec;
	u32 reg_ns;
	u32 sec_8bit;
	u32 sec_24bit;
	u32 systimm;
	u32 systimm_8bit;
	u32 systimm_24bit;

	SXE_REG64_WRITE(hw, SXE_TXSTMP_SEL, SXE_TXTS_MAGIC0);
	reg_ns = SXE_REG_READ(hw, SXE_TXSTMP_VAL);
	SXE_REG64_WRITE(hw, SXE_TXSTMP_SEL, SXE_TXTS_MAGIC1);
	reg_sec = SXE_REG_READ(hw, SXE_TXSTMP_VAL);
	systimm = SXE_REG_READ(hw, SXE_SYSTIMM);


	sec_8bit  = reg_sec & 0x000000FF;
	sec_24bit = (reg_sec >> 8) & 0x00FFFFFF;

	systimm_24bit = systimm & 0x00FFFFFF;
	systimm_8bit  = systimm & 0xFF000000;

	*ts_ns  = (sec_8bit << 24) | ((reg_ns & 0xFFFFFF00) >> 8);

	if (unlikely((sec_24bit - systimm_24bit) >= 0x00FFFFF0)) {
		if (systimm_8bit >= 1)
			systimm_8bit -= 1;
	}

	*ts_sec = systimm_8bit | sec_24bit;
}

u64 sxe_hw_ptp_rx_timestamp_get(struct sxe_hw *hw)
{
	struct sxe_adapter *adapter = hw->adapter;
	u32 rxtsl;
	u32 rxtsh;
	u64 ns;

	rxtsl = SXE_REG_READ(hw, SXE_RXSTMPL);
	rxtsh = SXE_REG_READ(hw, SXE_RXSTMPH);
	ns = SXE_TIME_TO_NS(rxtsl, rxtsh);

	LOG_DEBUG_BDF("ptp get rx ptp timestamp low=%u, high=%u, ns=%" SXE_PRIU64,
			rxtsl, rxtsh, ns);
	return ns;
}

bool sxe_hw_ptp_is_rx_timestamp_valid(struct sxe_hw *hw)
{
	bool rx_tmstamp_valid = false;
	u32 tsyncrxctl;

	tsyncrxctl = SXE_REG_READ(hw, SXE_TSYNCRXCTL);
	if (tsyncrxctl & SXE_TSYNCRXCTL_RXTT)
		rx_tmstamp_valid = true;

	return rx_tmstamp_valid;
}

void sxe_hw_ptp_timestamp_mode_set(struct sxe_hw *hw,
					bool is_l2, u32 tsctl, u32 tses)
{
	u32 regval;

	if (is_l2) {
		SXE_REG_WRITE(hw, SXE_ETQF(SXE_ETQF_FILTER_1588),
			(SXE_ETQF_FILTER_EN |
			 SXE_ETQF_1588 |
			 ETH_P_1588));
	} else {
		SXE_REG_WRITE(hw, SXE_ETQF(SXE_ETQF_FILTER_1588), 0);
	}

	if (tsctl) {
		regval = SXE_REG_READ(hw, SXE_TSCTRL);
		regval |= tsctl;
		SXE_REG_WRITE(hw, SXE_TSCTRL, regval);
	}

	SXE_REG_WRITE(hw, SXE_TSES, tses);

	SXE_WRITE_FLUSH(hw);
}

void sxe_hw_ptp_timestamp_enable(struct sxe_hw *hw)
{
	SXE_REG_WRITE(hw, SXE_TSYNCTXCTL,
			(SXE_REG_READ(hw, SXE_TSYNCTXCTL) |
			SXE_TSYNCTXCTL_TEN));

	SXE_REG_WRITE(hw, SXE_TSYNCRXCTL,
			(SXE_REG_READ(hw, SXE_TSYNCRXCTL) |
			SXE_TSYNCRXCTL_REN));
	SXE_WRITE_FLUSH(hw);
}

void sxe_hw_rx_dma_ctrl_init(struct sxe_hw *hw)
{
	u32 rx_dma_ctrl = SXE_REG_READ(hw, SXE_RDRXCTL);

	rx_dma_ctrl &= ~SXE_RDRXCTL_LROFRSTSIZE;
	SXE_REG_WRITE(hw, SXE_RDRXCTL, rx_dma_ctrl);
}

void sxe_hw_rx_dma_lro_ctrl_set(struct sxe_hw *hw)
{
	u32 rx_dma_ctrl = SXE_REG_READ(hw, SXE_RDRXCTL);

	rx_dma_ctrl |= SXE_RDRXCTL_LROACKC;
	SXE_REG_WRITE(hw, SXE_RDRXCTL, rx_dma_ctrl);
}

void sxe_hw_rx_desc_thresh_set(struct sxe_hw *hw, u8 reg_idx)
{
	u32 rxdctl;
	rxdctl = SXE_REG_READ(hw, SXE_RXDCTL(reg_idx));
	rxdctl |= 0x40 << SXE_RXDCTL_PREFETCH_NUM_CFG_SHIFT;
	rxdctl |= 0x2 << SXE_RXDCTL_DESC_FIFO_AE_TH_SHIFT;
	rxdctl |= 0x10;
	SXE_REG_WRITE(hw, SXE_RXDCTL(reg_idx), rxdctl);
}

void sxe_hw_rx_ring_switch(struct sxe_hw *hw, u8 reg_idx, bool is_on)
{
	u32 rxdctl;
	u32 wait_loop = SXE_RING_WAIT_LOOP;
	struct sxe_adapter *adapter = hw->adapter;

	rxdctl = SXE_REG_READ(hw, SXE_RXDCTL(reg_idx));
	if (is_on) {
		rxdctl |= SXE_RXDCTL_ENABLE;
		SXE_REG_WRITE(hw, SXE_RXDCTL(reg_idx), rxdctl);

		do {
			usleep_range(1000, 2000);
			rxdctl = SXE_REG_READ(hw, SXE_RXDCTL(reg_idx));
		} while (--wait_loop && !(rxdctl & SXE_RXDCTL_ENABLE));
	} else {
		rxdctl &= ~SXE_RXDCTL_ENABLE;
		SXE_REG_WRITE(hw, SXE_RXDCTL(reg_idx), rxdctl);

		do {
			usleep_range(1000, 2000);
			rxdctl = SXE_REG_READ(hw, SXE_RXDCTL(reg_idx));
		} while (--wait_loop && (rxdctl & SXE_RXDCTL_ENABLE));
	}

	SXE_WRITE_FLUSH(hw);

	if (!wait_loop) {
		LOG_MSG_ERR(drv, "rx ring %u switch %u failed within "
			  "the polling period", reg_idx, is_on);
	}
}

void sxe_hw_rx_queue_desc_reg_configure(struct sxe_hw *hw, u8 reg_idx,
					u32 rdh_value, u32 rdt_value)
{
	SXE_REG_WRITE(hw, SXE_RDH(reg_idx), rdh_value);
	SXE_REG_WRITE(hw, SXE_RDT(reg_idx), rdt_value);
}

static void sxe_hw_rx_ring_head_init(struct sxe_hw *hw, u8 reg_idx)
{
	SXE_REG_WRITE(hw, SXE_RDH(reg_idx), 0);
}

static void sxe_hw_rx_ring_tail_init(struct sxe_hw *hw, u8 reg_idx)
{
	SXE_REG_WRITE(hw, SXE_RDT(reg_idx), 0);
}

void sxe_hw_rx_ring_desc_configure(struct sxe_hw *hw, u32 desc_mem_len,
				   u64 desc_dma_addr, u8 reg_idx)
{
	SXE_REG_WRITE(hw, SXE_RDBAL(reg_idx),
			(desc_dma_addr & DMA_BIT_MASK(32)));
	SXE_REG_WRITE(hw, SXE_RDBAH(reg_idx), (desc_dma_addr >> 32));
	SXE_REG_WRITE(hw, SXE_RDLEN(reg_idx), desc_mem_len);

	SXE_WRITE_FLUSH(hw);

	sxe_hw_rx_ring_head_init(hw, reg_idx);
	sxe_hw_rx_ring_tail_init(hw, reg_idx);
}

void sxe_hw_rx_rcv_ctl_configure(struct sxe_hw *hw, u8 reg_idx,
				   u32 header_buf_len, u32 pkg_buf_len)
{
	u32 srrctl;

	srrctl = ((header_buf_len << SXE_SRRCTL_BSIZEHDRSIZE_SHIFT) &
			SXE_SRRCTL_BSIZEHDR_MASK);
	srrctl |= ((pkg_buf_len >> SXE_SRRCTL_BSIZEPKT_SHIFT) &
			SXE_SRRCTL_BSIZEPKT_MASK);

	SXE_REG_WRITE(hw, SXE_SRRCTL(reg_idx), srrctl);
}

void sxe_hw_rx_lro_ctl_configure(struct sxe_hw *hw, u8 reg_idx, u32 max_desc)
{
	u32 lroctrl;
	lroctrl = SXE_REG_READ(hw, SXE_LROCTL(reg_idx));
	lroctrl |= SXE_LROCTL_LROEN;
	lroctrl |= max_desc;
	SXE_REG_WRITE(hw, SXE_LROCTL(reg_idx), lroctrl);
}

static void sxe_hw_dcb_arbiter_set(struct sxe_hw *hw, bool is_enable)
{
	u32 rttdcs;

	rttdcs = SXE_REG_READ(hw, SXE_RTTDCS);

	if (is_enable) {
		rttdcs &= ~SXE_RTTDCS_ARBDIS;
		rttdcs &= ~SXE_RTTDCS_BPBFSM;

		SXE_REG_WRITE(hw, SXE_RTTDCS, rttdcs);
	} else {
		rttdcs |= SXE_RTTDCS_ARBDIS;
		SXE_REG_WRITE(hw, SXE_RTTDCS, rttdcs);
	}
}

void sxe_hw_tx_ring_head_init(struct sxe_hw *hw, u8 reg_idx)
{
	SXE_REG_WRITE(hw, SXE_TDH(reg_idx), 0);
}

void sxe_hw_tx_ring_tail_init(struct sxe_hw *hw, u8 reg_idx)
{
	SXE_REG_WRITE(hw, SXE_TDT(reg_idx), 0);
}

void sxe_hw_tx_ring_desc_configure(struct sxe_hw *hw, u32 desc_mem_len,
				   u64 desc_dma_addr, u8 reg_idx)
{
	SXE_REG_WRITE(hw, SXE_TXDCTL(reg_idx), 0);

	SXE_WRITE_FLUSH(hw);

	SXE_REG_WRITE(hw, SXE_TDBAL(reg_idx), (desc_dma_addr & DMA_BIT_MASK(32)));
	SXE_REG_WRITE(hw, SXE_TDBAH(reg_idx), (desc_dma_addr >> 32));
	SXE_REG_WRITE(hw, SXE_TDLEN(reg_idx), desc_mem_len);
	sxe_hw_tx_ring_head_init(hw, reg_idx);
	sxe_hw_tx_ring_tail_init(hw, reg_idx);
}

void sxe_hw_tx_desc_thresh_set(struct sxe_hw *hw, u8 reg_idx, u32 wb_thresh,
				u32 host_thresh, u32 prefech_thresh)
{
	u32 txdctl = 0;

	txdctl |= (wb_thresh << SXE_TXDCTL_WTHRESH_SHIFT);
	txdctl |= (host_thresh << SXE_TXDCTL_HTHRESH_SHIFT) | prefech_thresh;

	SXE_REG_WRITE(hw, SXE_TXDCTL(reg_idx), txdctl);
}

void sxe_hw_all_ring_disable(struct sxe_hw *hw, u32 ring_max)
{
	u32 i, value;

	for (i = 0; i < ring_max; i++) {
		value = SXE_REG_READ(hw, SXE_TXDCTL(i));
		value &= ~SXE_TXDCTL_ENABLE;
		SXE_REG_WRITE(hw, SXE_TXDCTL(i), value);

		value = SXE_REG_READ(hw, SXE_RXDCTL(i));
		value &= ~SXE_RXDCTL_ENABLE;
		SXE_REG_WRITE(hw, SXE_RXDCTL(i), value);
	}

	SXE_WRITE_FLUSH(hw);
	usleep_range(1000, 2000);
}

void sxe_hw_tx_ring_switch(struct sxe_hw *hw, u8 reg_idx, bool is_on)
{
	u32 wait_loop = SXE_RING_WAIT_LOOP;
	struct sxe_adapter *adapter = hw->adapter;

	u32 txdctl = SXE_REG_READ(hw, SXE_TXDCTL(reg_idx));
	if (is_on) {
		txdctl |= SXE_TXDCTL_ENABLE;
		SXE_REG_WRITE(hw, SXE_TXDCTL(reg_idx), txdctl);

		do {
			usleep_range(1000, 2000);
			txdctl = SXE_REG_READ(hw, SXE_TXDCTL(reg_idx));
		} while (--wait_loop && !(txdctl & SXE_TXDCTL_ENABLE));
	} else {
		txdctl &= ~SXE_TXDCTL_ENABLE;
		SXE_REG_WRITE(hw, SXE_TXDCTL(reg_idx), txdctl);

		do {
			usleep_range(1000, 2000);
			txdctl = SXE_REG_READ(hw, SXE_TXDCTL(reg_idx));
		} while (--wait_loop && (txdctl & SXE_TXDCTL_ENABLE));
	}

	if (!wait_loop) {
		LOG_DEV_ERR("tx ring %u switch %u failed within "
			  "the polling period", reg_idx, is_on);
	}
}

void sxe_hw_tx_pkt_buf_thresh_configure(struct sxe_hw *hw,
					u8 num_pb, bool dcb_enable)
{
	u32 i, tx_pkt_size, tx_pb_thresh;

	if (!num_pb)
		num_pb = 1;

	tx_pkt_size = SXE_TX_PBSIZE_MAX / num_pb;
	if (dcb_enable)
		tx_pb_thresh = (tx_pkt_size / 1024) - SXE_TX_PKT_SIZE_MAX;
	else
		tx_pb_thresh = (tx_pkt_size / 1024) - SXE_NODCB_TX_PKT_SIZE_MAX;

	for (i = 0; i < num_pb; i++)
		SXE_REG_WRITE(hw, SXE_TXPBTHRESH(i), tx_pb_thresh);

	for (; i < SXE_PKG_BUF_NUM_MAX; i++)
		SXE_REG_WRITE(hw, SXE_TXPBTHRESH(i), 0);
}

void sxe_hw_tx_enable(struct sxe_hw *hw)
{
	u32 ctl;

	ctl = SXE_REG_READ(hw, SXE_DMATXCTL);
	ctl |= SXE_DMATXCTL_TE;
	SXE_REG_WRITE(hw, SXE_DMATXCTL, ctl);
}

void sxe_hw_vlan_tag_strip_switch(struct sxe_hw *hw,
					u16 reg_index, bool is_enable)
{
	u32 rxdctl;

	rxdctl = SXE_REG_READ(hw, SXE_RXDCTL(reg_index));

	if (is_enable)
		rxdctl |= SXE_RXDCTL_VME;
	else
		rxdctl &= ~SXE_RXDCTL_VME;

	SXE_REG_WRITE(hw, SXE_RXDCTL(reg_index), rxdctl);
}

void sxe_hw_tx_vlan_tag_clear(struct sxe_hw *hw, u32 vf)
{
	SXE_REG_WRITE(hw, SXE_VMVIR(vf), 0);
}

u32 sxe_hw_tx_vlan_insert_get(struct sxe_hw *hw, u32 vf)
{
	return SXE_REG_READ(hw, SXE_VMVIR(vf));
}

void sxe_hw_tx_ring_info_get(struct sxe_hw *hw,
				u8 idx, u32 *head, u32 *tail)
{
	*head = SXE_REG_READ(hw, SXE_TDH(idx));
	*tail = SXE_REG_READ(hw, SXE_TDT(idx));
}

void sxe_hw_dcb_rx_bw_alloc_configure(struct sxe_hw *hw, u16 *refill,
				      u16 *max, u8 *bwg_id, u8 *prio_type,
				      u8 *prio_tc, u8 max_priority)
{
	u32	reg;
	u32	credit_refill;
	u32	credit_max;
	u8	 i;

	reg = SXE_RTRPCS_RRM | SXE_RTRPCS_RAC | SXE_RTRPCS_ARBDIS;
	SXE_REG_WRITE(hw, SXE_RTRPCS, reg);

	reg = 0;
	for (i = 0; i < max_priority; i++)
		reg |= (prio_tc[i] << (i * SXE_RTRUP2TC_UP_SHIFT));

	SXE_REG_WRITE(hw, SXE_RTRUP2TC, reg);

	for (i = 0; i < MAX_TRAFFIC_CLASS; i++) {
		credit_refill = refill[i];
		credit_max	= max[i];
		reg = credit_refill | (credit_max << SXE_RTRPT4C_MCL_SHIFT);

		reg |= (u32)(bwg_id[i]) << SXE_RTRPT4C_BWG_SHIFT;

		if (prio_type[i] == PRIO_LINK)
			reg |= SXE_RTRPT4C_LSP;

		SXE_REG_WRITE(hw, SXE_RTRPT4C(i), reg);
	}

	reg = SXE_RTRPCS_RRM | SXE_RTRPCS_RAC;
	SXE_REG_WRITE(hw, SXE_RTRPCS, reg);
}

void sxe_hw_dcb_tx_desc_bw_alloc_configure(struct sxe_hw *hw, u16 *refill,
					   u16 *max, u8 *bwg_id, u8 *prio_type)
{
	u32	reg, max_credits;
	u8	 i;

	for (i = 0; i < 128; i++) {
		SXE_REG_WRITE(hw, SXE_RTTDQSEL, i);
		SXE_REG_WRITE(hw, SXE_RTTDT1C, 0);
	}

	for (i = 0; i < MAX_TRAFFIC_CLASS; i++) {
		max_credits = max[i];
		reg = max_credits << SXE_RTTDT2C_MCL_SHIFT;
		reg |= refill[i];
		reg |= (u32)(bwg_id[i]) << SXE_RTTDT2C_BWG_SHIFT;

		if (prio_type[i] == PRIO_GROUP)
			reg |= SXE_RTTDT2C_GSP;

		if (prio_type[i] == PRIO_LINK)
			reg |= SXE_RTTDT2C_LSP;

		SXE_REG_WRITE(hw, SXE_RTTDT2C(i), reg);
	}

	reg = SXE_RTTDCS_TDPAC | SXE_RTTDCS_TDRM;
	SXE_REG_WRITE(hw, SXE_RTTDCS, reg);
}

void sxe_hw_dcb_tx_data_bw_alloc_configure(struct sxe_hw *hw, u16 *refill,
					   u16 *max, u8 *bwg_id, u8 *prio_type,
					   u8 *prio_tc, u8 max_priority)
{
	u32 reg;
	u8 i;

	reg = SXE_RTTPCS_TPPAC | SXE_RTTPCS_TPRM |
		  (SXE_RTTPCS_ARBD_DCB << SXE_RTTPCS_ARBD_SHIFT) |
		  SXE_RTTPCS_ARBDIS;
	SXE_REG_WRITE(hw, SXE_RTTPCS, reg);

	reg = 0;
	for (i = 0; i < max_priority; i++)
		reg |= (prio_tc[i] << (i * SXE_RTTUP2TC_UP_SHIFT));

	SXE_REG_WRITE(hw, SXE_RTTUP2TC, reg);

	for (i = 0; i < MAX_TRAFFIC_CLASS; i++) {
		reg = refill[i];
		reg |= (u32)(max[i]) << SXE_RTTPT2C_MCL_SHIFT;
		reg |= (u32)(bwg_id[i]) << SXE_RTTPT2C_BWG_SHIFT;

		if (prio_type[i] == PRIO_GROUP)
			reg |= SXE_RTTPT2C_GSP;

		if (prio_type[i] == PRIO_LINK)
			reg |= SXE_RTTPT2C_LSP;

		SXE_REG_WRITE(hw, SXE_RTTPT2C(i), reg);
	}

	reg = SXE_RTTPCS_TPPAC | SXE_RTTPCS_TPRM |
		  (SXE_RTTPCS_ARBD_DCB << SXE_RTTPCS_ARBD_SHIFT);
	SXE_REG_WRITE(hw, SXE_RTTPCS, reg);
}

void sxe_hw_dcb_pfc_configure(struct sxe_hw *hw, u8 pfc_en,
			      u8 *prio_tc, u8 max_priority)
{
	u32 i, j, fcrtl, reg;
	u8 max_tc = 0;
	u32 reg_val;

	reg_val = SXE_REG_READ(hw, SXE_FLCTRL);

	reg_val &= ~SXE_FCTRL_TFCE_MASK;
	reg_val |= SXE_FCTRL_TFCE_PFC_EN;
	reg_val |= SXE_FCTRL_TFCE_DPF_EN;

	reg_val &= ~(SXE_FCTRL_TFCE_FCEN_MASK | SXE_FCTRL_TFCE_XONE_MASK);
	reg_val |= (pfc_en << 16) & SXE_FCTRL_TFCE_FCEN_MASK;
	reg_val |= (pfc_en << 24) & SXE_FCTRL_TFCE_XONE_MASK;

	reg_val &= ~SXE_FCTRL_RFCE_MASK;
	reg_val |= SXE_FCTRL_RFCE_PFC_EN;
	SXE_REG_WRITE(hw, SXE_FLCTRL, reg_val);

	reg_val = SXE_REG_READ(hw, SXE_PFCTOP);
	reg_val &= ~SXE_PFCTOP_FCOP_MASK;
	reg_val |= SXE_PFCTOP_FCT;
	reg_val |= SXE_PFCTOP_FCOP_PFC;
	SXE_REG_WRITE(hw, SXE_PFCTOP, reg_val);

	for (i = 0; i < max_priority; i++) {
		if (prio_tc[i] > max_tc)
			max_tc = prio_tc[i];
	}

	for (i = 0; i <= max_tc; i++) {
		int enabled = 0;

		for (j = 0; j < max_priority; j++) {
			if (prio_tc[j] == i && (pfc_en & BIT(j))) {
				enabled = 1;
				break;
			}
		}

		if (enabled) {
			reg = (hw->fc.high_water[i] << 9) | SXE_FCRTH_FCEN;
			fcrtl = (hw->fc.low_water[i] << 9) | SXE_FCRTL_XONE;
			SXE_REG_WRITE(hw, SXE_FCRTL(i), fcrtl);
		} else {
			reg = (SXE_REG_READ(hw, SXE_RXPBSIZE(i)) - 24576) >> 1;
			SXE_REG_WRITE(hw, SXE_FCRTL(i), 0);
		}

		SXE_REG_WRITE(hw, SXE_FCRTH(i), reg);
	}

	for (; i < MAX_TRAFFIC_CLASS; i++) {
		SXE_REG_WRITE(hw, SXE_FCRTL(i), 0);
		SXE_REG_WRITE(hw, SXE_FCRTH(i), 0);
	}

	reg = hw->fc.pause_time * 0x00010001;
	for (i = 0; i < (MAX_TRAFFIC_CLASS / 2); i++)
		SXE_REG_WRITE(hw, SXE_FCTTV(i), reg);

	SXE_REG_WRITE(hw, SXE_FCRTV, hw->fc.pause_time / 2);
}

static void sxe_hw_dcb_8tc_vmdq_off_stats_configure(struct sxe_hw *hw)
{
	u32 reg;
	u8  i;

	for (i = 0; i < 32; i++) {
		reg = 0x01010101 * (i / 4);
		SXE_REG_WRITE(hw, SXE_RQSMR(i), reg);
	}

	for (i = 0; i < 32; i++) {
		if (i < 8)
			reg = 0x00000000;
		else if (i < 16)
			reg = 0x01010101;
		else if (i < 20)
			reg = 0x02020202;
		else if (i < 24)
			reg = 0x03030303;
		else if (i < 26)
			reg = 0x04040404;
		else if (i < 28)
			reg = 0x05050505;
		else if (i < 30)
			reg = 0x06060606;
		else
			reg = 0x07070707;

		SXE_REG_WRITE(hw, SXE_TQSM(i), reg);
	}
}

void sxe_hw_vt_pool_loopback_switch(struct sxe_hw *hw, bool is_enable)
{
	if (is_enable)
		SXE_REG_WRITE(hw, SXE_PFDTXGSWC, SXE_PFDTXGSWC_VT_LBEN);
	else
		SXE_REG_WRITE(hw, SXE_PFDTXGSWC, 0);
}

u32 sxe_hw_rx_pool_bitmap_get(struct sxe_hw *hw, u8 reg_idx)
{
	return SXE_REG_READ(hw, SXE_VFRE(reg_idx));
}

void sxe_hw_rx_pool_bitmap_set(struct sxe_hw *hw, u8 reg_idx, u32 bitmap)
{
	SXE_REG_WRITE(hw, SXE_VFRE(reg_idx), bitmap);
}

u32 sxe_hw_tx_pool_bitmap_get(struct sxe_hw *hw, u8 reg_idx)
{
	return SXE_REG_READ(hw, SXE_VFTE(reg_idx));
}

void sxe_hw_tx_pool_bitmap_set(struct sxe_hw *hw, u8 reg_idx, u32 bitmap)
{
	SXE_REG_WRITE(hw, SXE_VFTE(reg_idx), bitmap);
}

void sxe_hw_dcb_max_mem_window_set(struct sxe_hw *hw, u32 value)
{
	SXE_REG_WRITE(hw, SXE_RTTBCNRM, value);
}

void sxe_hw_dcb_tx_ring_rate_factor_set(struct sxe_hw *hw,
							u32 ring_idx, u32 rate)
{
	SXE_REG_WRITE(hw, SXE_RTTDQSEL, ring_idx);
	SXE_REG_WRITE(hw, SXE_RTTBCNRC, rate);
}

void sxe_hw_spoof_count_enable(struct sxe_hw *hw, u8 reg_idx, u8 bit_index)
{
	u32 value = SXE_REG_READ(hw, SXE_VMECM(reg_idx));

	value |= BIT(bit_index);

	SXE_REG_WRITE(hw, SXE_VMECM(reg_idx), value);
}

void sxe_hw_pool_mac_anti_spoof_set(struct sxe_hw *hw, u8 vf_idx, bool status)
{
	u8 reg_index = vf_idx >> 3;
	u8 bit_index = vf_idx % 8;
	u32 value;

	value = SXE_REG_READ(hw, SXE_SPOOF(reg_index));

	if (status)
		value |= BIT(bit_index);
	else
		value &= ~BIT(bit_index);

	SXE_REG_WRITE(hw, SXE_SPOOF(reg_index), value);
}

void sxe_hw_rx_drop_switch(struct sxe_hw *hw, u8 idx, bool is_enable)
{
	u32 srrctl = SXE_REG_READ(hw, SXE_SRRCTL(idx));

	if (is_enable)
		srrctl |= SXE_SRRCTL_DROP_EN;
	else
		srrctl &= ~SXE_SRRCTL_DROP_EN;

	SXE_REG_WRITE(hw, SXE_SRRCTL(idx), srrctl);
}

void sxe_hw_dcb_rate_limiter_clear(struct sxe_hw *hw, u8 ring_max)
{
	u32 i;

	for (i = 0; i < ring_max; i++) {
		SXE_REG_WRITE(hw, SXE_RTTDQSEL, i);
		SXE_REG_WRITE(hw, SXE_RTTBCNRC, 0);
	}
	SXE_WRITE_FLUSH(hw);
}

void sxe_hw_stats_regs_clean(struct sxe_hw *hw)
{
	u16 i;
	for (i = 0; i < 16; i++) {
		SXE_REG_READ(hw, SXE_QPTC(i));
		SXE_REG_READ(hw, SXE_QPRC(i));
		SXE_REG_READ(hw, SXE_QBTC_H(i));
		SXE_REG_READ(hw, SXE_QBTC_L(i));
		SXE_REG_READ(hw, SXE_QBRC_H(i));
		SXE_REG_READ(hw, SXE_QBRC_L(i));
		SXE_REG_READ(hw, SXE_QPRDC(i));
	}

	SXE_REG_READ(hw, SXE_RXDGBCH);
	SXE_REG_READ(hw, SXE_RXDGBCL);
	SXE_REG_READ(hw, SXE_RXDGPC);
	SXE_REG_READ(hw, SXE_TXDGPC);
	SXE_REG_READ(hw, SXE_TXDGBCH);
	SXE_REG_READ(hw, SXE_TXDGBCL);
	SXE_REG_READ(hw, SXE_RXDDGPC);
	SXE_REG_READ(hw, SXE_RXDDGBCH);
	SXE_REG_READ(hw, SXE_RXDDGBCL);
	SXE_REG_READ(hw, SXE_RXLPBKGPC);
	SXE_REG_READ(hw, SXE_RXLPBKGBCH);
	SXE_REG_READ(hw, SXE_RXLPBKGBCL);
	SXE_REG_READ(hw, SXE_RXDLPBKGPC);
	SXE_REG_READ(hw, SXE_RXDLPBKGBCH);
	SXE_REG_READ(hw, SXE_RXDLPBKGBCL);
	SXE_REG_READ(hw, SXE_RXTPCIN);
	SXE_REG_READ(hw, SXE_RXTPCOUT);
	SXE_REG_READ(hw, SXE_RXPRDDC);
	SXE_REG_READ(hw, SXE_TXSWERR);
	SXE_REG_READ(hw, SXE_TXSWITCH);
	SXE_REG_READ(hw, SXE_TXREPEAT);
	SXE_REG_READ(hw, SXE_TXDESCERR);

	SXE_REG_READ(hw, SXE_CRCERRS);
	SXE_REG_READ(hw, SXE_ERRBC);
	SXE_REG_READ(hw, SXE_RLEC);
	SXE_REG_READ(hw, SXE_PRC64);
	SXE_REG_READ(hw, SXE_PRC127);
	SXE_REG_READ(hw, SXE_PRC255);
	SXE_REG_READ(hw, SXE_PRC511);
	SXE_REG_READ(hw, SXE_PRC1023);
	SXE_REG_READ(hw, SXE_PRC1522);
	SXE_REG_READ(hw, SXE_GPRC);
	SXE_REG_READ(hw, SXE_BPRC);
	SXE_REG_READ(hw, SXE_MPRC);
	SXE_REG_READ(hw, SXE_GPTC);
	SXE_REG_READ(hw, SXE_GORCL);
	SXE_REG_READ(hw, SXE_GORCH);
	SXE_REG_READ(hw, SXE_GOTCL);
	SXE_REG_READ(hw, SXE_GOTCH);
	SXE_REG_READ(hw, SXE_RUC);
	SXE_REG_READ(hw, SXE_RFC);
	SXE_REG_READ(hw, SXE_ROC);
	SXE_REG_READ(hw, SXE_RJC);
	for (i = 0; i < 8; i++)
		SXE_REG_READ(hw, SXE_PRCPF(i));

	SXE_REG_READ(hw, SXE_TORL);
	SXE_REG_READ(hw, SXE_TORH);
	SXE_REG_READ(hw, SXE_TPR);
	SXE_REG_READ(hw, SXE_TPT);
	SXE_REG_READ(hw, SXE_PTC64);
	SXE_REG_READ(hw, SXE_PTC127);
	SXE_REG_READ(hw, SXE_PTC255);
	SXE_REG_READ(hw, SXE_PTC511);
	SXE_REG_READ(hw, SXE_PTC1023);
	SXE_REG_READ(hw, SXE_PTC1522);
	SXE_REG_READ(hw, SXE_MPTC);
	SXE_REG_READ(hw, SXE_BPTC);
	for (i = 0; i < 8; i++)
		SXE_REG_READ(hw, SXE_PFCT(i));
}

static void sxe_hw_stats_seq_get(struct sxe_hw *hw, struct sxe_mac_stats *stats)
{
	u8 i;
	u64 tx_pfc_num = 0;
#ifdef SXE_DPDK
	u64 gotch = 0;
	u32 rycle_cnt = 10;
#endif

	for (i = 0; i < 8; i++) {
		stats->prcpf[i] += SXE_REG_READ(hw, SXE_PRCPF(i));
		tx_pfc_num = SXE_REG_READ(hw, SXE_PFCT(i));
		stats->pfct[i] += tx_pfc_num;
		stats->total_tx_pause += tx_pfc_num;
	}

	stats->total_gptc += SXE_REG_READ(hw, SXE_GPTC);
	stats->total_gotc += (SXE_REG_READ(hw, SXE_GOTCL) |
			((u64)SXE_REG_READ(hw, SXE_GOTCH) << 32));
#ifdef SXE_DPDK
	do {
		gotch = SXE_REG_READ(hw, SXE_GOTCH);
		rycle_cnt--;
	} while (gotch != 0 && rycle_cnt != 0);
	if (gotch != 0)
		LOG_INFO("GOTCH is not clear!");
#endif
}

void sxe_hw_stats_seq_clean(struct sxe_hw *hw, struct sxe_mac_stats *stats)
{
	u8 i;
	u64 tx_pfc_num = 0;
	u64 gotch = 0;
	u32 rycle_cnt = 10;

	stats->total_gotc += (SXE_REG_READ(hw, SXE_GOTCL) |
			((u64)SXE_REG_READ(hw, SXE_GOTCH) << 32));
	stats->total_gptc += SXE_REG_READ(hw, SXE_GPTC);
	do {
		gotch = SXE_REG_READ(hw, SXE_GOTCH);
		rycle_cnt--;
	} while (gotch != 0 && rycle_cnt != 0);
	if (gotch != 0)
		LOG_INFO("GOTCH is not clear!");

	for (i = 0; i < 8; i++) {
		stats->prcpf[i] += SXE_REG_READ(hw, SXE_PRCPF(i));
		tx_pfc_num = SXE_REG_READ(hw, SXE_PFCT(i));
		stats->pfct[i] += tx_pfc_num;
		stats->total_tx_pause += tx_pfc_num;
	}
}

void sxe_hw_stats_get(struct sxe_hw *hw, struct sxe_mac_stats *stats)
{
	u64 rjc;
	u32 i, rx_dbu_drop, ring_drop = 0;
	u64 tpr = 0;
#ifdef SXE_DPDK
	u32 rycle_cnt = 10;
	u64 gorch, torh = 0;
#endif

	for (i = 0; i < 16; i++) {
		stats->qptc[i] += SXE_REG_READ(hw, SXE_QPTC(i));
		stats->qprc[i] += SXE_REG_READ(hw, SXE_QPRC(i));
		ring_drop = SXE_REG_READ(hw, SXE_QPRDC(i));
		stats->qprdc[i] += ring_drop;
		stats->hw_rx_no_dma_resources += ring_drop;

		stats->qbtc[i] += ((u64)SXE_REG_READ(hw, SXE_QBTC_H(i)) << 32);
		SXE_RMB();
		stats->qbtc[i] += SXE_REG_READ(hw, SXE_QBTC_L(i));

		stats->qbrc[i] += ((u64)SXE_REG_READ(hw, SXE_QBRC_H(i)) << 32);
		SXE_RMB();
		stats->qbrc[i] += SXE_REG_READ(hw, SXE_QBRC_L(i));
	}
	stats->rxdgbc += ((u64)SXE_REG_READ(hw, SXE_RXDGBCH) << 32) +
				(SXE_REG_READ(hw, SXE_RXDGBCL));

	stats->rxdgpc += SXE_REG_READ(hw, SXE_RXDGPC);
	stats->txdgpc += SXE_REG_READ(hw, SXE_TXDGPC);
	stats->txdgbc += (((u64)SXE_REG_READ(hw, SXE_TXDGBCH) << 32) +
				SXE_REG_READ(hw, SXE_TXDGBCL));

	stats->rxddpc += SXE_REG_READ(hw, SXE_RXDDGPC);
	stats->rxddbc += ((u64)SXE_REG_READ(hw, SXE_RXDDGBCH) << 32) +
				(SXE_REG_READ(hw, SXE_RXDDGBCL));

	stats->rxlpbkpc += SXE_REG_READ(hw, SXE_RXLPBKGPC);
	stats->rxlpbkbc += ((u64)SXE_REG_READ(hw, SXE_RXLPBKGBCH) << 32) +
			(SXE_REG_READ(hw, SXE_RXLPBKGBCL));

	stats->rxdlpbkpc += SXE_REG_READ(hw, SXE_RXDLPBKGPC);
	stats->rxdlpbkbc += ((u64)SXE_REG_READ(hw, SXE_RXDLPBKGBCH) << 32) +
				(SXE_REG_READ(hw, SXE_RXDLPBKGBCL));
	stats->rxtpcing += SXE_REG_READ(hw, SXE_RXTPCIN);
	stats->rxtpceng += SXE_REG_READ(hw, SXE_RXTPCOUT);
	stats->prddc += SXE_REG_READ(hw, SXE_RXPRDDC);
	stats->txswerr += SXE_REG_READ(hw, SXE_TXSWERR);
	stats->txswitch += SXE_REG_READ(hw, SXE_TXSWITCH);
	stats->txrepeat += SXE_REG_READ(hw, SXE_TXREPEAT);
	stats->txdescerr += SXE_REG_READ(hw, SXE_TXDESCERR);

	for (i = 0; i < 8; i++) {
		stats->dburxtcin[i] += SXE_REG_READ(hw, SXE_DBUDRTCICNT(i));
		stats->dburxtcout[i] += SXE_REG_READ(hw, SXE_DBUDRTCOCNT(i));
		stats->dburxgdreecnt[i] += SXE_REG_READ(hw, SXE_DBUDREECNT(i));
		rx_dbu_drop = SXE_REG_READ(hw, SXE_DBUDROFPCNT(i));
		stats->dburxdrofpcnt[i] += rx_dbu_drop;
		stats->dbutxtcin[i] += SXE_REG_READ(hw, SXE_DBUDTTCICNT(i));
		stats->dbutxtcout[i] += SXE_REG_READ(hw, SXE_DBUDTTCOCNT(i));
	}

	stats->fnavadd += (SXE_REG_READ(hw, SXE_FNAVUSTAT) & 0xFFFF);
	stats->fnavrmv += ((SXE_REG_READ(hw, SXE_FNAVUSTAT) >> 16) & 0xFFFF);
	stats->fnavadderr += (SXE_REG_READ(hw, SXE_FNAVFSTAT) & 0xFFFF);
	stats->fnavrmverr += ((SXE_REG_READ(hw, SXE_FNAVFSTAT) >> 16) & 0xFFFF);
	stats->fnavmatch += SXE_REG_READ(hw, SXE_FNAVMATCH);
	stats->fnavmiss += SXE_REG_READ(hw, SXE_FNAVMISS);

	sxe_hw_stats_seq_get(hw, stats);

	stats->crcerrs += SXE_REG_READ(hw, SXE_CRCERRS);
	stats->errbc   += SXE_REG_READ(hw, SXE_ERRBC);
	stats->bprc += SXE_REG_READ(hw, SXE_BPRC);
	stats->mprc += SXE_REG_READ(hw, SXE_MPRC);
	stats->roc += SXE_REG_READ(hw, SXE_ROC);
	stats->prc64 += SXE_REG_READ(hw, SXE_PRC64);
	stats->prc127 += SXE_REG_READ(hw, SXE_PRC127);
	stats->prc255 += SXE_REG_READ(hw, SXE_PRC255);
	stats->prc511 += SXE_REG_READ(hw, SXE_PRC511);
	stats->prc1023 += SXE_REG_READ(hw, SXE_PRC1023);
	stats->prc1522 += SXE_REG_READ(hw, SXE_PRC1522);
	stats->rlec += SXE_REG_READ(hw, SXE_RLEC);
	stats->mptc += SXE_REG_READ(hw, SXE_MPTC);
	stats->ruc += SXE_REG_READ(hw, SXE_RUC);
	stats->rfc += SXE_REG_READ(hw, SXE_RFC);

	rjc = SXE_REG_READ(hw, SXE_RJC);
	stats->rjc += rjc;
	stats->roc += rjc;

	tpr = SXE_REG_READ(hw, SXE_TPR);
	stats->tpr += tpr;
	stats->tpt += SXE_REG_READ(hw, SXE_TPT);
	stats->ptc64 += SXE_REG_READ(hw, SXE_PTC64);
	stats->ptc127 += SXE_REG_READ(hw, SXE_PTC127);
	stats->ptc255 += SXE_REG_READ(hw, SXE_PTC255);
	stats->ptc511 += SXE_REG_READ(hw, SXE_PTC511);
	stats->ptc1023 += SXE_REG_READ(hw, SXE_PTC1023);
	stats->ptc1522 += SXE_REG_READ(hw, SXE_PTC1522);
	stats->bptc += SXE_REG_READ(hw, SXE_BPTC);

	stats->gprc += SXE_REG_READ(hw, SXE_GPRC);
	stats->gorc += (SXE_REG_READ(hw, SXE_GORCL) |
			((u64)SXE_REG_READ(hw, SXE_GORCH) << 32));
#ifdef SXE_DPDK
	do {
		gorch = SXE_REG_READ(hw, SXE_GORCH);
		rycle_cnt--;
	} while (gorch != 0 && rycle_cnt != 0);
	if (gorch != 0)
		LOG_INFO("GORCH is not clear!");
#endif

	stats->tor += (SXE_REG_READ(hw, SXE_TORL) |
			((u64)SXE_REG_READ(hw, SXE_TORH) << 32));
#ifdef SXE_DPDK
	rycle_cnt = 10;
	do {
		torh = SXE_REG_READ(hw, SXE_TORH);
		rycle_cnt--;
	} while (torh != 0 && rycle_cnt != 0);
	if (torh != 0)
		LOG_INFO("TORH is not clear!");
#endif

#ifdef SXE_DPDK
	stats->tor -= tpr * RTE_ETHER_CRC_LEN;
	stats->gptc = stats->total_gptc - stats->total_tx_pause;
	stats->gotc = stats->total_gotc - stats->total_tx_pause * RTE_ETHER_MIN_LEN
			- stats->gptc * RTE_ETHER_CRC_LEN;
#else
	stats->gptc = stats->total_gptc;
	stats->gotc = stats->total_gotc;
#endif
}

void sxe_hw_mbx_init(struct sxe_hw *hw)
{
	hw->mbx.msg_len = SXE_MBX_MSG_NUM;
	hw->mbx.interval = SXE_MBX_RETRY_INTERVAL;
	hw->mbx.retry = SXE_MBX_RETRY_COUNT;

	hw->mbx.stats.rcv_msgs   = 0;
	hw->mbx.stats.send_msgs  = 0;
	hw->mbx.stats.acks	 = 0;
	hw->mbx.stats.reqs	 = 0;
	hw->mbx.stats.rsts	 = 0;
}

static bool sxe_hw_vf_irq_check(struct sxe_hw *hw, u32 mask, u32 index)
{
	u32 value = SXE_REG_READ(hw, SXE_PFMBICR(index));

	if (value & mask) {
		SXE_REG_WRITE(hw, SXE_PFMBICR(index), mask);
		return true;
	}

	return false;
}

bool sxe_hw_vf_rst_check(struct sxe_hw *hw, u8 vf_idx)
{
	u32 index = vf_idx >> 5;
	u32 bit = vf_idx % 32;
	u32 value;

	value = SXE_REG_READ(hw, SXE_VFLRE(index));
	if (value & BIT(bit)) {
		SXE_REG_WRITE(hw, SXE_VFLREC(index), BIT(bit));
		hw->mbx.stats.rsts++;
		return true;
	}

	return false;
}

bool sxe_hw_vf_req_check(struct sxe_hw *hw, u8 vf_idx)
{
	u8 index = vf_idx >> 4;
	u8 bit = vf_idx % 16;

	if (sxe_hw_vf_irq_check(hw, SXE_PFMBICR_VFREQ << bit, index)) {
		hw->mbx.stats.reqs++;
		return true;
	}

	return false;
}

bool sxe_hw_vf_ack_check(struct sxe_hw *hw, u8 vf_idx)
{
	u8 index = vf_idx >> 4;
	u8 bit = vf_idx % 16;

	if (sxe_hw_vf_irq_check(hw, SXE_PFMBICR_VFACK << bit, index)) {
		hw->mbx.stats.acks++;
		return true;
	}

	return false;
}

static bool sxe_hw_mbx_lock(struct sxe_hw *hw, u8 vf_idx)
{
	u32 value;
	bool ret = false;
	u32 retry = hw->mbx.retry;

	while (retry--) {
		SXE_REG_WRITE(hw, SXE_PFMAILBOX(vf_idx), SXE_PFMAILBOX_PFU);

		value = SXE_REG_READ(hw, SXE_PFMAILBOX(vf_idx));
		if (value & SXE_PFMAILBOX_PFU) {
			ret = true;
			break;
		}

		sxe_udelay(hw->mbx.interval);
	}

	return ret;
}

s32 sxe_hw_rcv_msg_from_vf(struct sxe_hw *hw, u32 *msg,
				u16 msg_len, u16 index)
{
	struct sxe_mbx_info *mbx = &hw->mbx;
	u8 i;
	s32 ret = 0;
	u16 msg_entry;
	struct sxe_adapter *adapter = hw->adapter;

	msg_entry = (msg_len > mbx->msg_len) ? mbx->msg_len : msg_len;

	if (!sxe_hw_mbx_lock(hw, index)) {
		ret = -SXE_ERR_MBX_LOCK_FAIL;
		LOG_ERROR_BDF("vf idx:%d msg_len:%d rcv lock mailbox fail.(err:%d)",
			   index, msg_len, ret);
		goto l_out;
	}

	for (i = 0; i < msg_entry; i++) {
		msg[i] = SXE_REG_READ(hw, (SXE_PFMBMEM(index) + (i << 2)));
		LOG_DEBUG_BDF("vf_idx:%u read mbx mem[%u]:0x%x.",
				  index, i, msg[i]);
	}

	SXE_REG_WRITE(hw, SXE_PFMAILBOX(index), SXE_PFMAILBOX_ACK);
	mbx->stats.rcv_msgs++;

l_out:
	return ret;
}

s32 sxe_hw_send_msg_to_vf(struct sxe_hw *hw, u32 *msg,
				u16 msg_len, u16 index)
{
	struct sxe_mbx_info *mbx = &hw->mbx;
	u8 i;
	s32 ret = 0;
	u32 old;
	struct sxe_adapter *adapter = hw->adapter;

	if (msg_len > mbx->msg_len) {
		ret = -EINVAL;
		LOG_ERROR_BDF("pf reply msg num:%d exceed limit:%d reply fail.(err:%d)",
			  msg_len, mbx->msg_len, ret);
		goto l_out;
	}

	if (!sxe_hw_mbx_lock(hw, index)) {
		ret = -SXE_ERR_MBX_LOCK_FAIL;
		LOG_ERROR_BDF("send msg len:%u to vf idx:%u msg[0]:0x%x "
			   "lock mailbox fail.(err:%d)",
			   msg_len, index, msg[0], ret);
		goto l_out;
	}

	old = SXE_REG_READ(hw, (SXE_PFMBMEM(index)));
	LOG_DEBUG_BDF("original send msg:0x%x. mbx mem[0]:0x%x", *msg, old);
	if (msg[0] & SXE_CTRL_MSG_MASK)
		msg[0] |= (old & SXE_MSGID_MASK);
	else
		msg[0] |= (old & SXE_PFMSG_MASK);

	for (i = 0; i < msg_len; i++) {
		SXE_REG_WRITE(hw, (SXE_PFMBMEM(index) + (i << 2)), msg[i]);
		LOG_DEBUG_BDF("vf_idx:%u write mbx mem[%u]:0x%x.",
				  index, i, msg[i]);
	}

	SXE_REG_WRITE(hw, SXE_PFMAILBOX(index), SXE_PFMAILBOX_STS);
	mbx->stats.send_msgs++;

l_out:
	return ret;
}

void sxe_hw_pcie_vt_mode_set(struct sxe_hw *hw, u32 value)
{
	SXE_REG_WRITE(hw, SXE_GCR_EXT, value);
}

s32 sxe_hw_hdc_lock_get(struct sxe_hw *hw, u32 trylock)
{
	u32 val;
	u16 i;
	s32 ret = 0;
	struct sxe_adapter *adapter = hw->adapter;

	SXE_REG_WRITE(hw, SXE_HDC_SW_LK, SXE_HDC_RELEASE_SW_LK);
	SXE_WRITE_FLUSH(hw);

	for (i = 0; i < trylock; i++) {
		val = SXE_REG_READ(hw, SXE_HDC_SW_LK) & SXE_HDC_SW_LK_BIT;
		if (!val)
			break;

		sxe_udelay(10);
	}

	if (i >= trylock) {
		LOG_ERROR_BDF("hdc is busy, reg: 0x%x", val);
		ret = -SXE_ERR_HDC_LOCK_BUSY;
		goto l_out;
	}

	val = SXE_REG_READ(hw, SXE_HDC_PF_LK) & SXE_HDC_PF_LK_BIT;
	if (!val) {
		SXE_REG_WRITE(hw, SXE_HDC_SW_LK, SXE_HDC_RELEASE_SW_LK);
		LOG_ERROR_BDF("get hdc lock fail, reg: 0x%x", val);
		ret = -SXE_ERR_HDC_LOCK_BUSY;
		goto l_out;
	}

	hw->hdc.pf_lock_val = val;
	LOG_DEBUG_BDF("hw[%p]'s port[%u] got pf lock", hw, val);

l_out:
	return ret;
}

void sxe_hw_hdc_lock_release(struct sxe_hw *hw, u32 retry_cnt)
{
	struct sxe_adapter *adapter = hw->adapter;

	do {
		SXE_REG_WRITE(hw, SXE_HDC_SW_LK, SXE_HDC_RELEASE_SW_LK);
		sxe_udelay(1);
		if (!(SXE_REG_READ(hw, SXE_HDC_PF_LK) & hw->hdc.pf_lock_val)) {
			LOG_DEBUG_BDF("hw[%p]'s port[%u] release pf lock", hw,
				hw->hdc.pf_lock_val);
			hw->hdc.pf_lock_val = 0;
			break;
		}
	} while ((retry_cnt--) > 0);
}

void sxe_hw_hdc_fw_ov_clear(struct sxe_hw *hw)
{
	SXE_REG_WRITE(hw, SXE_HDC_FW_OV, 0);
}

bool sxe_hw_hdc_is_fw_over_set(struct sxe_hw *hw)
{
	bool fw_ov = false;

	if (SXE_REG_READ(hw, SXE_HDC_FW_OV) & SXE_HDC_FW_OV_BIT)
		fw_ov = true;

	return fw_ov;
}

void sxe_hw_hdc_packet_send_done(struct sxe_hw *hw)
{
	SXE_REG_WRITE(hw, SXE_HDC_SW_OV, SXE_HDC_SW_OV_BIT);
	SXE_WRITE_FLUSH(hw);
}

void sxe_hw_hdc_packet_header_send(struct sxe_hw *hw, u32 value)
{
	SXE_REG_WRITE(hw, SXE_HDC_PACKET_HEAD0, value);
}

void sxe_hw_hdc_packet_data_dword_send(struct sxe_hw *hw,
						u16 dword_index, u32 value)
{
	SXE_WRITE_REG_ARRAY_32(hw, SXE_HDC_PACKET_DATA0, dword_index, value);
}

u32 sxe_hw_hdc_fw_ack_header_get(struct sxe_hw *hw)
{
	return SXE_REG_READ(hw, SXE_HDC_PACKET_HEAD0);
}

u32 sxe_hw_hdc_packet_data_dword_rcv(struct sxe_hw *hw, u16 dword_index)
{
	return SXE_READ_REG_ARRAY_32(hw, SXE_HDC_PACKET_DATA0, dword_index);
}

u32 sxe_hw_hdc_fw_status_get(struct sxe_hw *hw)
{
	struct sxe_adapter *adapter = hw->adapter;
	u32 status = SXE_REG_READ(hw, SXE_FW_STATUS_REG);

	LOG_DEBUG_BDF("fw status[0x%x]", status);

	return status;
}

void sxe_hw_hdc_drv_status_set(struct sxe_hw *hw, u32 value)
{
	SXE_REG_WRITE(hw, SXE_DRV_STATUS_REG, value);
}

u32 sxe_hw_hdc_channel_state_get(struct sxe_hw *hw)
{
	struct sxe_adapter *adapter = hw->adapter;

	u32 state = SXE_REG_READ(hw, SXE_FW_HDC_STATE_REG);

	LOG_DEBUG_BDF("hdc channel state[0x%x]", state);

	return state;
}

u32 sxe_hw_rss_key_get_by_idx(struct sxe_hw *hw, u8 reg_idx)
{
	u32 rss_key;

	if (reg_idx >= SXE_MAX_RSS_KEY_ENTRIES)
		rss_key = 0;
	else
		rss_key = SXE_REG_READ(hw, SXE_RSSRK(reg_idx));

	return rss_key;
}

bool sxe_hw_is_rss_enabled(struct sxe_hw *hw)
{
	bool rss_enable = false;
	u32 mrqc = SXE_REG_READ(hw, SXE_MRQC);
	u32 mrqe_val = mrqc & SXE_MRQC_MRQE_MASK;

	if (mrqe_val == SXE_MRQC_RSSEN ||
		mrqe_val == SXE_MRQC_RTRSS8TCEN ||
		mrqe_val == SXE_MRQC_RTRSS4TCEN ||
		mrqe_val == SXE_MRQC_VMDQRSS32EN ||
		mrqe_val == SXE_MRQC_VMDQRSS64EN)
		rss_enable = true;

	return rss_enable;
}

static u32 sxe_hw_mrqc_reg_get(struct sxe_hw *hw)
{
	return SXE_REG_READ(hw, SXE_MRQC);
}

u32 sxe_hw_rss_field_get(struct sxe_hw *hw)
{
	u32 mrqc = sxe_hw_mrqc_reg_get(hw);
	return (mrqc & SXE_RSS_FIELD_MASK);
}

#ifdef SXE_DPDK

#define SXE_TRAFFIC_CLASS_MAX			8
#define SXE_MR_VLAN_MSB_REG_OFFSET		4
#define SXE_MR_VIRTUAL_POOL_MSB_REG_OFFSET	4
#define SXE_MR_TYPE_MASK			0x0F
#define SXE_MR_DST_POOL_OFFSET			8

void sxe_hw_crc_strip_config(struct sxe_hw *hw, bool keep_crc)
{
	u32 crcflag = SXE_REG_READ(hw, SXE_CRC_STRIP_REG);

	if (keep_crc)
		crcflag |= SXE_KEEP_CRC_EN;
	else
		crcflag &= ~SXE_KEEP_CRC_EN;

	SXE_REG_WRITE(hw, SXE_CRC_STRIP_REG, crcflag);
}

void sxe_hw_rx_pkt_buf_size_set(struct sxe_hw *hw, u8 tc_idx, u16 pbsize)
{
	u32 rxpbsize = pbsize << SXE_RX_PKT_BUF_SIZE_SHIFT;

	sxe_hw_rx_pkt_buf_switch(hw, false);
	SXE_REG_WRITE(hw, SXE_RXPBSIZE(tc_idx), rxpbsize);
	sxe_hw_rx_pkt_buf_switch(hw, true);
}

void sxe_hw_dcb_vmdq_mq_configure(struct sxe_hw *hw, u8 num_pools)
{
	u16 pbsize;
	u8 i, nb_tcs;
	u32 mrqc;

	nb_tcs = SXE_VMDQ_DCB_NUM_QUEUES / num_pools;

	pbsize = (u8)(SXE_RX_PKT_BUF_SIZE / nb_tcs);

	for (i = 0; i < nb_tcs; i++)
		sxe_hw_rx_pkt_buf_size_set(hw, i, pbsize);

	for (i = nb_tcs; i < ETH_DCB_NUM_USER_PRIORITIES; i++)
		sxe_hw_rx_pkt_buf_size_set(hw, i, 0);

	mrqc = (num_pools == RTE_ETH_16_POOLS) ?
		SXE_MRQC_VMDQRT8TCEN : SXE_MRQC_VMDQRT4TCEN;
	SXE_REG_WRITE(hw, SXE_MRQC, mrqc);

	SXE_REG_WRITE(hw, SXE_RTRPCS, SXE_RTRPCS_RRM);
}

static const struct sxe_reg_info sxe_regs_general_group[] = {
	{SXE_CTRL, 1, 1, "SXE_CTRL"},
	{SXE_STATUS, 1, 1, "SXE_STATUS"},
	{SXE_CTRL_EXT, 1, 1, "SXE_CTRL_EXT"},
	{0, 0, 0, ""}
};

static const struct sxe_reg_info sxe_regs_interrupt_group[] = {
	{SXE_EICS, 1, 1, "SXE_EICS"},
	{SXE_EIMS, 1, 1, "SXE_EIMS"},
	{SXE_EIMC, 1, 1, "SXE_EIMC"},
	{SXE_EIAC, 1, 1, "SXE_EIAC"},
	{SXE_EIAM, 1, 1, "SXE_EIAM"},
	{SXE_EITR(0), 24, 4, "SXE_EITR"},
	{SXE_IVAR(0), 24, 4, "SXE_IVAR"},
	{SXE_GPIE, 1, 1, "SXE_GPIE"},
	{0, 0, 0, ""}
};

static const struct sxe_reg_info sxe_regs_fctl_group[] = {
	{SXE_PFCTOP, 1, 1, "SXE_PFCTOP"},
	{SXE_FCRTV, 1, 1, "SXE_FCRTV"},
	{SXE_TFCS, 1, 1, "SXE_TFCS"},
	{0, 0, 0, ""}
};

static const struct sxe_reg_info sxe_regs_rxdma_group[] = {
	{SXE_RDBAL(0), 64, 0x40, "SXE_RDBAL"},
	{SXE_RDBAH(0), 64, 0x40, "SXE_RDBAH"},
	{SXE_RDLEN(0), 64, 0x40, "SXE_RDLEN"},
	{SXE_RDH(0), 64, 0x40, "SXE_RDH"},
	{SXE_RDT(0), 64, 0x40, "SXE_RDT"},
	{SXE_RXDCTL(0), 64, 0x40, "SXE_RXDCTL"},
	{SXE_SRRCTL(0), 16, 0x4, "SXE_SRRCTL"},
	{SXE_TPH_RXCTRL(0), 16, 4, "SXE_TPH_RXCTRL"},
	{SXE_RDRXCTL, 1, 1, "SXE_RDRXCTL"},
	{SXE_RXPBSIZE(0), 8, 4, "SXE_RXPBSIZE"},
	{SXE_RXCTRL, 1, 1, "SXE_RXCTRL"},
	{0, 0, 0, ""}
};

static const struct sxe_reg_info sxe_regs_rx_group[] = {
	{SXE_RXCSUM, 1, 1, "SXE_RXCSUM"},
	{SXE_RFCTL, 1, 1, "SXE_RFCTL"},
	{SXE_RAL(0), 16, 8, "SXE_RAL"},
	{SXE_RAH(0), 16, 8, "SXE_RAH"},
	{SXE_PSRTYPE(0), 1, 4, "SXE_PSRTYPE"},
	{SXE_FCTRL, 1, 1, "SXE_FCTRL"},
	{SXE_VLNCTRL, 1, 1, "SXE_VLNCTRL"},
	{SXE_MCSTCTRL, 1, 1, "SXE_MCSTCTRL"},
	{SXE_MRQC, 1, 1, "SXE_MRQC"},
	{SXE_VMD_CTL, 1, 1, "SXE_VMD_CTL"},

	{0, 0, 0, ""}
};

static struct sxe_reg_info sxe_regs_tx_group[] = {
	{SXE_TDBAL(0), 32, 0x40, "SXE_TDBAL"},
	{SXE_TDBAH(0), 32, 0x40, "SXE_TDBAH"},
	{SXE_TDLEN(0), 32, 0x40, "SXE_TDLEN"},
	{SXE_TDH(0), 32, 0x40, "SXE_TDH"},
	{SXE_TDT(0), 32, 0x40, "SXE_TDT"},
	{SXE_TXDCTL(0), 32, 0x40, "SXE_TXDCTL"},
	{SXE_TPH_TXCTRL(0), 16, 4, "SXE_TPH_TXCTRL"},
	{SXE_TXPBSIZE(0), 8, 4, "SXE_TXPBSIZE"},
	{0, 0, 0, ""}
};

static const struct sxe_reg_info sxe_regs_wakeup_group[] = {
	{SXE_WUC, 1, 1, "SXE_WUC"},
	{SXE_WUFC, 1, 1, "SXE_WUFC"},
	{SXE_WUS, 1, 1, "SXE_WUS"},
	{0, 0, 0, ""}
};

static const struct sxe_reg_info sxe_regs_dcb_group[] = {
	{0, 0, 0, ""}
};

static const struct sxe_reg_info sxe_regs_diagnostic_group[] = {
	{SXE_MFLCN, 1, 1, "SXE_MFLCN"},
	{0, 0, 0, ""},
};

static const struct sxe_reg_info *sxe_regs_group[] = {
				sxe_regs_general_group,
				sxe_regs_interrupt_group,
				sxe_regs_fctl_group,
				sxe_regs_rxdma_group,
				sxe_regs_rx_group,
				sxe_regs_tx_group,
				sxe_regs_wakeup_group,
				sxe_regs_dcb_group,
				sxe_regs_diagnostic_group,
				NULL};

static u32 sxe_regs_group_count(const struct sxe_reg_info *regs)
{
	int i = 0;
	int count = 0;

	while (regs[i].count)
		count += regs[i++].count;

	return count;
};

static u32 sxe_hw_regs_group_read(struct sxe_hw *hw,
				const struct sxe_reg_info *regs,
				u32 *reg_buf)
{
	u32 j, i = 0;
	int count = 0;

	while (regs[i].count) {
		for (j = 0; j < regs[i].count; j++) {
			reg_buf[count + j] = SXE_REG_READ(hw,
					regs[i].addr + j * regs[i].stride);
			LOG_INFO("regs= %s, regs_addr=%x, regs_value=%04x",
				regs[i].name, regs[i].addr, reg_buf[count + j]);
		}

		i++;
		count += j;
	}

	return count;
};

u32 sxe_hw_all_regs_group_num_get(void)
{
	u32 i = 0;
	u32 count = 0;
	const struct sxe_reg_info *reg_group;
	const struct sxe_reg_info **reg_set = sxe_regs_group;

	while ((reg_group = reg_set[i++]))
		count += sxe_regs_group_count(reg_group);

	return count;
}

void sxe_hw_all_regs_group_read(struct sxe_hw *hw, u32 *data)
{
	u32 count = 0, i = 0;
	const struct sxe_reg_info *reg_group;
	const struct sxe_reg_info **reg_set = sxe_regs_group;

	while ((reg_group = reg_set[i++]))
		count += sxe_hw_regs_group_read(hw, reg_group, &data[count]);

	LOG_INFO("read regs cnt=%u, regs num=%u",
				count, sxe_hw_all_regs_group_num_get());
}

static void sxe_hw_default_pool_configure(struct sxe_hw *hw,
						u8 default_pool_enabled,
						u8 default_pool_idx)
{
	u32 vt_ctl;

	vt_ctl = SXE_VT_CTL_VT_ENABLE | SXE_VT_CTL_REPLEN;
	if (default_pool_enabled)
		vt_ctl |= (default_pool_idx << SXE_VT_CTL_POOL_SHIFT);
	else
		vt_ctl |= SXE_VT_CTL_DIS_DEFPL;

	SXE_REG_WRITE(hw, SXE_VT_CTL, vt_ctl);
}

void sxe_hw_dcb_vmdq_default_pool_configure(struct sxe_hw *hw,
						u8 default_pool_enabled,
						u8 default_pool_idx)
{
	sxe_hw_default_pool_configure(hw, default_pool_enabled, default_pool_idx);
}

u32 sxe_hw_ring_irq_switch_get(struct sxe_hw *hw, u8 idx)
{
	u32 mask;

	if (idx == 0)
		mask = SXE_REG_READ(hw, SXE_EIMS_EX(0));
	else
		mask = SXE_REG_READ(hw, SXE_EIMS_EX(1));

	return mask;
}

void sxe_hw_ring_irq_switch_set(struct sxe_hw *hw, u8 idx, u32 value)
{
	if (idx == 0)
		SXE_REG_WRITE(hw, SXE_EIMS_EX(0), value);
	else
		SXE_REG_WRITE(hw, SXE_EIMS_EX(1), value);
}

void sxe_hw_dcb_vmdq_up_2_tc_configure(struct sxe_hw *hw, u8 *tc_arr)
{
	u32 up2tc;
	u8 i;

	up2tc = 0;
	for (i = 0; i < 8; i++)
		up2tc |= ((tc_arr[i] & 0x07) << (i * 3));

	SXE_REG_WRITE(hw, SXE_RTRUP2TC, up2tc);
}

u32 sxe_hw_uta_hash_table_get(struct sxe_hw *hw, u8 reg_idx)
{
	return SXE_REG_READ(hw, SXE_UTA(reg_idx));
}

void sxe_hw_uta_hash_table_set(struct sxe_hw *hw, u8 reg_idx, u32 value)
{
	SXE_REG_WRITE(hw, SXE_UTA(reg_idx), value);
}

u32 sxe_hw_vlan_type_get(struct sxe_hw *hw)
{
	return SXE_REG_READ(hw, SXE_VLNCTRL);
}

void sxe_hw_vlan_type_set(struct sxe_hw *hw, u32 value)
{
	SXE_REG_WRITE(hw, SXE_VLNCTRL, value);
}

void sxe_hw_dcb_vmdq_vlan_configure(struct sxe_hw *hw, u8 num_pools)
{
	u32 vlanctrl;
	u8 i;

	vlanctrl = SXE_REG_READ(hw, SXE_VLNCTRL);
	vlanctrl |= SXE_VLNCTRL_VFE;
	SXE_REG_WRITE(hw, SXE_VLNCTRL, vlanctrl);

	for (i = 0; i < SXE_VFT_TBL_SIZE; i++)
		SXE_REG_WRITE(hw, SXE_VFTA(i), 0xFFFFFFFF);

	SXE_REG_WRITE(hw, SXE_VFRE(0),
			num_pools == RTE_ETH_16_POOLS ? 0xFFFF : 0xFFFFFFFF);

	SXE_REG_WRITE(hw, SXE_MPSAR_LOW(0), 0xFFFFFFFF);
	SXE_REG_WRITE(hw, SXE_MPSAR_HIGH(0), 0xFFFFFFFF);
}

void sxe_hw_vlan_ext_type_set(struct sxe_hw *hw, u32 value)
{
	SXE_REG_WRITE(hw, SXE_EXVET, value);
}

u32 sxe_hw_txctl_vlan_type_get(struct sxe_hw *hw)
{
	return SXE_REG_READ(hw, SXE_DMATXCTL);
}

void sxe_hw_txctl_vlan_type_set(struct sxe_hw *hw, u32 value)
{
	SXE_REG_WRITE(hw, SXE_DMATXCTL, value);
}

u32 sxe_hw_ext_vlan_get(struct sxe_hw *hw)
{
	return SXE_REG_READ(hw, SXE_CTRL_EXT);
}

void sxe_hw_ext_vlan_set(struct sxe_hw *hw, u32 value)
{
	SXE_REG_WRITE(hw, SXE_CTRL_EXT, value);
}

void sxe_hw_rxq_stat_map_set(struct sxe_hw *hw, u8 idx, u32 value)
{
	SXE_REG_WRITE(hw, SXE_RQSMR(idx), value);
}

void sxe_hw_dcb_vmdq_pool_configure(struct sxe_hw *hw,
						u8 pool_idx, u16 vlan_id,
						u64 pools_map)
{
	SXE_REG_WRITE(hw, SXE_VLVF(pool_idx), (SXE_VLVF_VIEN |
			(vlan_id & 0xFFF)));

	SXE_REG_WRITE(hw, SXE_VLVFB(pool_idx * 2), pools_map);
}

void sxe_hw_txq_stat_map_set(struct sxe_hw *hw, u8 idx, u32 value)
{
	SXE_REG_WRITE(hw, SXE_TQSM(idx), value);
}

void sxe_hw_dcb_rx_configure(struct sxe_hw *hw, bool is_vt_on,
					u8 sriov_active, u8 tc_num)
{
	u32 reg;
	u32 vlanctrl;
	u8 i;
	u32 q;

	reg = SXE_RTRPCS_RRM | SXE_RTRPCS_RAC | SXE_RTRPCS_ARBDIS;
	SXE_REG_WRITE(hw, SXE_RTRPCS, reg);

	reg = SXE_REG_READ(hw, SXE_MRQC);
	if (tc_num == 4) {
		if (is_vt_on) {
			reg = (reg & ~SXE_MRQC_MRQE_MASK) |
				SXE_MRQC_VMDQRT4TCEN;
		} else {
			SXE_REG_WRITE(hw, SXE_VT_CTL, 0);
			reg = (reg & ~SXE_MRQC_MRQE_MASK) |
				SXE_MRQC_RTRSS4TCEN;
		}
	}

	if (tc_num == 8) {
		if (is_vt_on) {
			reg = (reg & ~SXE_MRQC_MRQE_MASK) |
				SXE_MRQC_VMDQRT8TCEN;
		} else {
			SXE_REG_WRITE(hw, SXE_VT_CTL, 0);
			reg = (reg & ~SXE_MRQC_MRQE_MASK) |
				SXE_MRQC_RTRSS8TCEN;
		}
	}

	SXE_REG_WRITE(hw, SXE_MRQC, reg);

	if (sriov_active == 0) {
		for (q = 0; q < SXE_HW_TXRX_RING_NUM_MAX; q++) {
			SXE_REG_WRITE(hw, SXE_QDE,
				(SXE_QDE_WRITE |
				 (q << SXE_QDE_IDX_SHIFT)));
		}
	} else {
		for (q = 0; q < SXE_HW_TXRX_RING_NUM_MAX; q++) {
			SXE_REG_WRITE(hw, SXE_QDE,
				(SXE_QDE_WRITE |
				 (q << SXE_QDE_IDX_SHIFT) |
				 SXE_QDE_ENABLE));
		}
	}

	vlanctrl = SXE_REG_READ(hw, SXE_VLNCTRL);
	vlanctrl |= SXE_VLNCTRL_VFE;
	SXE_REG_WRITE(hw, SXE_VLNCTRL, vlanctrl);

	for (i = 0; i < SXE_VFT_TBL_SIZE; i++)
		SXE_REG_WRITE(hw, SXE_VFTA(i), 0xFFFFFFFF);

	reg = SXE_RTRPCS_RRM | SXE_RTRPCS_RAC;
	SXE_REG_WRITE(hw, SXE_RTRPCS, reg);
}

void sxe_hw_fc_status_get(struct sxe_hw *hw,
					bool *rx_pause_on, bool *tx_pause_on)
{
	u32 flctrl;

	flctrl = SXE_REG_READ(hw, SXE_FLCTRL);
	if (flctrl & (SXE_FCTRL_RFCE_PFC_EN | SXE_FCTRL_RFCE_LFC_EN))
		*rx_pause_on = true;
	else
		*rx_pause_on = false;

	if (flctrl & (SXE_FCTRL_TFCE_PFC_EN | SXE_FCTRL_TFCE_LFC_EN))
		*tx_pause_on = true;
	else
		*tx_pause_on = false;
}

void sxe_hw_fc_base_init(struct sxe_hw *hw)
{
	u8 i;

	hw->fc.requested_mode = SXE_FC_NONE;
	hw->fc.current_mode = SXE_FC_NONE;
	hw->fc.pause_time = SXE_DEFAULT_FCPAUSE;
	hw->fc.disable_fc_autoneg = false;

	for (i = 0; i < MAX_TRAFFIC_CLASS; i++) {
		hw->fc.low_water[i]  = SXE_FC_DEFAULT_LOW_WATER_MARK;
		hw->fc.high_water[i] = SXE_FC_DEFAULT_HIGH_WATER_MARK;
	}

	hw->fc.send_xon = 1;
}

u32 sxe_hw_fc_tc_high_water_mark_get(struct sxe_hw *hw, u8 tc_idx)
{
	return hw->fc.high_water[tc_idx];
}

u32 sxe_hw_fc_tc_low_water_mark_get(struct sxe_hw *hw, u8 tc_idx)
{
	return hw->fc.low_water[tc_idx];
}

u16 sxe_hw_fc_send_xon_get(struct sxe_hw *hw)
{
	return hw->fc.send_xon;
}

void sxe_hw_fc_send_xon_set(struct sxe_hw *hw, u16 send_xon)
{
	hw->fc.send_xon = send_xon;
}

u16 sxe_hw_fc_pause_time_get(struct sxe_hw *hw)
{
	return hw->fc.pause_time;
}

void sxe_hw_fc_pause_time_set(struct sxe_hw *hw, u16 pause_time)
{
	hw->fc.pause_time = pause_time;
}

void sxe_hw_dcb_tx_configure(struct sxe_hw *hw, bool is_vt_on, u8 tc_num)
{
	u32 reg;

	reg = SXE_REG_READ(hw, SXE_RTTDCS);
	reg |= SXE_RTTDCS_ARBDIS;
	SXE_REG_WRITE(hw, SXE_RTTDCS, reg);

	if (tc_num == 8)
		reg = SXE_MTQC_RT_ENA | SXE_MTQC_8TC_8TQ;
	else
		reg = SXE_MTQC_RT_ENA | SXE_MTQC_4TC_4TQ;

	if (is_vt_on)
		reg |= SXE_MTQC_VT_ENA;

	SXE_REG_WRITE(hw, SXE_MTQC, reg);

	reg = SXE_REG_READ(hw, SXE_RTTDCS);
	reg &= ~SXE_RTTDCS_ARBDIS;
	SXE_REG_WRITE(hw, SXE_RTTDCS, reg);
}

void sxe_hw_rx_ip_checksum_offload_switch(struct sxe_hw *hw, bool is_on)
{
	u32 rxcsum;

	rxcsum = SXE_REG_READ(hw, SXE_RXCSUM);
	if (is_on)
		rxcsum |= SXE_RXCSUM_IPPCSE;
	else
		rxcsum &= ~SXE_RXCSUM_IPPCSE;

	SXE_REG_WRITE(hw, SXE_RXCSUM, rxcsum);
}

void sxe_hw_rss_cap_switch(struct sxe_hw *hw, bool is_on)
{
	u32 mrqc = SXE_REG_READ(hw, SXE_MRQC);
	u32 mrqe_val;
	mrqe_val = mrqc & SXE_MRQC_MRQE_MASK;
	if (is_on) {
		mrqe_val = SXE_MRQC_RSSEN;
	} else {
		switch (mrqe_val) {
		case SXE_MRQC_RSSEN:
			mrqe_val = 0;
			break;
		case SXE_MRQC_RTRSS8TCEN:
			mrqe_val = SXE_MRQC_RT8TCEN;
			break;
		case SXE_MRQC_RTRSS4TCEN:
			mrqe_val = SXE_MRQC_RT4TCEN;
			break;
		case SXE_MRQC_VMDQRSS64EN:
			mrqe_val = SXE_MRQC_VMDQEN;
			break;
		case SXE_MRQC_VMDQRSS32EN:
			PMD_LOG_WARN(DRV, "Three is no regression for virtualizatic"
				" and RSS with 32 polls among the MRQE configuration"
				" after disable RSS and left it unchanged.");
			break;
		default:
			break;
		}
	}
	mrqc = (mrqc & ~SXE_MRQC_MRQE_MASK) | mrqe_val;

	SXE_REG_WRITE(hw, SXE_MRQC, mrqc);
}

void sxe_hw_pool_xmit_enable(struct sxe_hw *hw, u16 reg_idx, u8 pool_num)
{
	SXE_REG_WRITE(hw, SXE_VFTE(reg_idx),
		pool_num == RTE_ETH_16_POOLS ? 0xFFFF : 0xFFFFFFFF);
}

void sxe_hw_rss_field_set(struct sxe_hw *hw, u32 rss_field)
{
	u32 mrqc = SXE_REG_READ(hw, SXE_MRQC);

	mrqc &= ~SXE_RSS_FIELD_MASK;
	mrqc |= rss_field;
	SXE_REG_WRITE(hw, SXE_MRQC, mrqc);
}

static void sxe_hw_dcb_4tc_vmdq_off_stats_configure(struct sxe_hw *hw)
{
	u32 reg;
	u8  i;

	for (i = 0; i < 32; i++) {
		if (i % 8 > 3)
			continue;

		reg = 0x01010101 * (i / 8);
		SXE_REG_WRITE(hw, SXE_RQSMR(i), reg);
	}
	for (i = 0; i < 32; i++) {
		if (i < 16)
			reg = 0x00000000;
		else if (i < 24)
			reg = 0x01010101;
		else if (i < 28)
			reg = 0x02020202;
		else
			reg = 0x03030303;

		SXE_REG_WRITE(hw, SXE_TQSM(i), reg);
	}
}

static void sxe_hw_dcb_4tc_vmdq_on_stats_configure(struct sxe_hw *hw)
{
	u8  i;

	for (i = 0; i < 32; i++)
		SXE_REG_WRITE(hw, SXE_RQSMR(i), 0x03020100);


	for (i = 0; i < 32; i++)
		SXE_REG_WRITE(hw, SXE_TQSM(i), 0x03020100);
}

void sxe_hw_rss_redir_tbl_set_by_idx(struct sxe_hw *hw, u16 reg_idx, u32 value)
{
	return sxe_hw_rss_redir_tbl_reg_write(hw, reg_idx, value);
}

static u32 sxe_hw_rss_redir_tbl_reg_read(struct sxe_hw *hw, u16 reg_idx)
{
	return SXE_REG_READ(hw, SXE_RETA(reg_idx >> 2));
}

u32 sxe_hw_rss_redir_tbl_get_by_idx(struct sxe_hw *hw, u16 reg_idx)
{
	return sxe_hw_rss_redir_tbl_reg_read(hw, reg_idx);
}

void sxe_hw_ptp_time_inc_stop(struct sxe_hw *hw)
{
	SXE_REG_WRITE(hw, SXE_TIMINC, 0);
}

void sxe_hw_dcb_tc_stats_configure(struct sxe_hw *hw,
					u8 tc_num, bool vmdq_active)
{
	if (tc_num == 8 && !vmdq_active)
		sxe_hw_dcb_8tc_vmdq_off_stats_configure(hw);
	else if (tc_num == 4 && !vmdq_active)
		sxe_hw_dcb_4tc_vmdq_off_stats_configure(hw);
	else if (tc_num == 4 && vmdq_active)
		sxe_hw_dcb_4tc_vmdq_on_stats_configure(hw);
}

void sxe_hw_ptp_timestamp_disable(struct sxe_hw *hw)
{
	SXE_REG_WRITE(hw, SXE_TSYNCTXCTL,
			(SXE_REG_READ(hw, SXE_TSYNCTXCTL) &
			~SXE_TSYNCTXCTL_TEN));

	SXE_REG_WRITE(hw, SXE_TSYNCRXCTL,
			(SXE_REG_READ(hw, SXE_TSYNCRXCTL) &
			~SXE_TSYNCRXCTL_REN));
	SXE_WRITE_FLUSH(hw);
}

void sxe_hw_mac_pool_clear(struct sxe_hw *hw, u8 rar_idx)
{
	struct sxe_adapter *adapter = hw->adapter;

	if (rar_idx > SXE_UC_ENTRY_NUM_MAX) {
		LOG_ERROR_BDF("rar_idx:%d invalid.(err:%d)",
			  rar_idx, SXE_ERR_PARAM);
		return;
	}

	SXE_REG_WRITE(hw, SXE_MPSAR_LOW(rar_idx), 0);
	SXE_REG_WRITE(hw, SXE_MPSAR_HIGH(rar_idx), 0);
}

void sxe_hw_vmdq_mq_configure(struct sxe_hw *hw)
{
	u32 mrqc;

	mrqc = SXE_MRQC_VMDQEN;
	SXE_REG_WRITE(hw, SXE_MRQC, mrqc);
}

void sxe_hw_vmdq_default_pool_configure(struct sxe_hw *hw,
						u8 default_pool_enabled,
						u8 default_pool_idx)
{
	sxe_hw_default_pool_configure(hw, default_pool_enabled, default_pool_idx);
}

void sxe_hw_vmdq_vlan_configure(struct sxe_hw *hw, u8 num_pools, u32 rx_mode)
{
	u32 vlanctrl;
	u8 i;

	vlanctrl = SXE_REG_READ(hw, SXE_VLNCTRL);
	vlanctrl |= SXE_VLNCTRL_VFE;
	SXE_REG_WRITE(hw, SXE_VLNCTRL, vlanctrl);

	for (i = 0; i < SXE_VFT_TBL_SIZE; i++)
		SXE_REG_WRITE(hw, SXE_VFTA(i), 0xFFFFFFFF);

	SXE_REG_WRITE(hw, SXE_VFRE(0), 0xFFFFFFFF);
	if (num_pools == RTE_ETH_64_POOLS)
		SXE_REG_WRITE(hw, SXE_VFRE(1), 0xFFFFFFFF);

	for (i = 0; i < num_pools; i++)
		SXE_REG_WRITE(hw, SXE_VMOLR(i), rx_mode);

	SXE_REG_WRITE(hw, SXE_MPSAR_LOW(0), 0xFFFFFFFF);
	SXE_REG_WRITE(hw, SXE_MPSAR_HIGH(0), 0xFFFFFFFF);

	SXE_WRITE_FLUSH(hw);
}

u32 sxe_hw_pcie_vt_mode_get(struct sxe_hw *hw)
{
	return SXE_REG_READ(hw, SXE_GCR_EXT);
}

void sxe_rx_fc_threshold_set(struct sxe_hw *hw)
{
	u8 i;
	u32 high;

	for (i = 0; i < SXE_TRAFFIC_CLASS_MAX; i++) {
		SXE_REG_WRITE(hw, SXE_FCRTL(i), 0);
		high = SXE_REG_READ(hw, SXE_RXPBSIZE(i)) - 32;
		SXE_REG_WRITE(hw, SXE_FCRTH(i), high);
	}
}

void sxe_hw_vmdq_pool_configure(struct sxe_hw *hw, u8 pool_idx, u16 vlan_id,
				u64 pools_map)
{
	SXE_REG_WRITE(hw, SXE_VLVF(pool_idx), (SXE_VLVF_VIEN |
			(vlan_id & SXE_RXD_VLAN_ID_MASK)));

	if (((pools_map >> 32) & 0xFFFFFFFF) == 0) {
		SXE_REG_WRITE(hw, SXE_VLVFB(pool_idx * 2),
			(pools_map & 0xFFFFFFFF));
	} else {
		SXE_REG_WRITE(hw, SXE_VLVFB((pool_idx * 2 + 1)),
			((pools_map >> 32) & 0xFFFFFFFF));
	}

	SXE_WRITE_FLUSH(hw);
}

void sxe_hw_vmdq_loopback_configure(struct sxe_hw *hw)
{
	u8 i;
	SXE_REG_WRITE(hw, SXE_PFDTXGSWC, SXE_PFDTXGSWC_VT_LBEN);
	for (i = 0; i < SXE_VMTXSW_REGISTER_COUNT; i++)
		SXE_REG_WRITE(hw, SXE_VMTXSW(i), 0xFFFFFFFF);

	SXE_WRITE_FLUSH(hw);
}

void sxe_hw_tx_multi_queue_configure(struct sxe_hw *hw, bool vmdq_enable,
				     bool sriov_enable, u16 pools_num)
{
	u32 mtqc;

	sxe_hw_dcb_arbiter_set(hw, false);

	if (sriov_enable) {
		switch (pools_num) {
		case RTE_ETH_64_POOLS:
			mtqc = SXE_MTQC_VT_ENA | SXE_MTQC_64VF;
			break;
		case RTE_ETH_32_POOLS:
			mtqc = SXE_MTQC_VT_ENA | SXE_MTQC_32VF;
			break;
		case RTE_ETH_16_POOLS:
			mtqc = SXE_MTQC_VT_ENA | SXE_MTQC_RT_ENA |
				SXE_MTQC_8TC_8TQ;
			break;
		default:
			mtqc = SXE_MTQC_64Q_1PB;
		}
	} else {
		if (vmdq_enable) {
			u8 queue_idx;
			SXE_REG_WRITE(hw, SXE_VFTE(0), UINT32_MAX);
			SXE_REG_WRITE(hw, SXE_VFTE(1), UINT32_MAX);

			for (queue_idx = 0; queue_idx < SXE_HW_TXRX_RING_NUM_MAX;
				queue_idx++) {
				SXE_REG_WRITE(hw, SXE_QDE,
					(SXE_QDE_WRITE |
					(queue_idx << SXE_QDE_IDX_SHIFT)));
			}

			mtqc = SXE_MTQC_VT_ENA | SXE_MTQC_64VF;
		} else {
			mtqc = SXE_MTQC_64Q_1PB;
		}
	}

	SXE_REG_WRITE(hw, SXE_MTQC, mtqc);

	sxe_hw_dcb_arbiter_set(hw, true);
}

void sxe_hw_vf_queue_drop_enable(struct sxe_hw *hw, u8 vf_idx, u8 ring_per_pool)
{
	u32 value;
	u8 i;

	for (i = (vf_idx * ring_per_pool); i < ((vf_idx + 1) * ring_per_pool); i++) {
		value = SXE_QDE_ENABLE | SXE_QDE_WRITE;
		SXE_WRITE_FLUSH(hw);

		value |= i << SXE_QDE_IDX_SHIFT;

		SXE_REG_WRITE(hw, SXE_QDE, value);
	}
}

bool sxe_hw_vt_status(struct sxe_hw *hw)
{
	bool ret;
	u32 vt_ctl = SXE_REG_READ(hw, SXE_VT_CTL);

	if (vt_ctl & SXE_VMD_CTL_POOL_EN)
		ret = true;
	else
		ret = false;

	return ret;
}

void sxe_hw_mirror_ctl_set(struct sxe_hw *hw, u8 rule_id,
					u8 mirror_type, u8 dst_pool, bool on)
{
	u32 mr_ctl;

	mr_ctl = SXE_REG_READ(hw, SXE_MRCTL(rule_id));

	if (on) {
		mr_ctl |= mirror_type;
		mr_ctl &= SXE_MR_TYPE_MASK;
		mr_ctl |= dst_pool << SXE_MR_DST_POOL_OFFSET;
	} else {
		mr_ctl &= ~(mirror_type & SXE_MR_TYPE_MASK);
	}

	SXE_REG_WRITE(hw, SXE_MRCTL(rule_id), mr_ctl);
}

void sxe_hw_mirror_virtual_pool_set(struct sxe_hw *hw, u8 rule_id, u32 lsb, u32 msb)
{
	SXE_REG_WRITE(hw, SXE_VMRVM(rule_id), lsb);
	SXE_REG_WRITE(hw, SXE_VMRVM(rule_id  + SXE_MR_VIRTUAL_POOL_MSB_REG_OFFSET), msb);
}

void sxe_hw_mirror_vlan_set(struct sxe_hw *hw, u8 rule_id, u32 lsb, u32 msb)
{
	SXE_REG_WRITE(hw, SXE_VMRVLAN(rule_id), lsb);
	SXE_REG_WRITE(hw, SXE_VMRVLAN(rule_id  + SXE_MR_VLAN_MSB_REG_OFFSET), msb);
}

void sxe_hw_mirror_rule_clear(struct sxe_hw *hw, u8 rule_id)
{
	SXE_REG_WRITE(hw, SXE_MRCTL(rule_id), 0);

	SXE_REG_WRITE(hw, SXE_VMRVLAN(rule_id), 0);
	SXE_REG_WRITE(hw, SXE_VMRVLAN(rule_id  + SXE_MR_VLAN_MSB_REG_OFFSET), 0);

	SXE_REG_WRITE(hw, SXE_VMRVM(rule_id), 0);
	SXE_REG_WRITE(hw, SXE_VMRVM(rule_id  + SXE_MR_VIRTUAL_POOL_MSB_REG_OFFSET), 0);
}

void sxe_hw_mac_reuse_add(struct rte_eth_dev *dev, u8 *mac_addr, u8 rar_idx)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_uc_addr_table *uc_table = adapter->mac_filter_ctxt.uc_addr_table;
	struct sxe_hw *hw = &adapter->hw;
	s32 i;
	u32 value_low = SXE_REG_READ(hw, SXE_MPSAR_LOW(rar_idx));
	u32 value_high = SXE_REG_READ(hw, SXE_MPSAR_HIGH(rar_idx));

	for (i = 0; i < SXE_UC_ENTRY_NUM_MAX; i++) {
		if (memcmp(uc_table[i].addr, mac_addr, SXE_MAC_ADDR_LEN) == 0 &&
				uc_table[i].used && i != rar_idx) {
			value_low |= SXE_REG_READ(hw, SXE_MPSAR_LOW(i));
			value_high |= SXE_REG_READ(hw, SXE_MPSAR_HIGH(i));

			SXE_REG_WRITE(hw, SXE_MPSAR_LOW(i), value_low);
			SXE_REG_WRITE(hw, SXE_MPSAR_HIGH(i), value_high);
		}
	}

	SXE_REG_WRITE(hw, SXE_MPSAR_LOW(rar_idx), value_low);
	SXE_REG_WRITE(hw, SXE_MPSAR_HIGH(rar_idx), value_high);
}

void sxe_hw_mac_reuse_del(struct rte_eth_dev *dev,
				u8 *mac_addr, u8 pool_idx, u8 rar_idx)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_uc_addr_table *uc_table = adapter->mac_filter_ctxt.uc_addr_table;
	struct sxe_hw *hw = &adapter->hw;
	u32 value;
	s32 i;

	for (i = 0; i < SXE_UC_ENTRY_NUM_MAX; i++) {
		if (memcmp(uc_table[i].addr, mac_addr, SXE_MAC_ADDR_LEN) == 0 &&
				uc_table[i].used && i != rar_idx) {
			if (pool_idx < 32) {
				value = SXE_REG_READ(hw, SXE_MPSAR_LOW(i));
				value &= ~(BIT(pool_idx));
				SXE_REG_WRITE(hw, SXE_MPSAR_LOW(i), value);
			} else {
				value = SXE_REG_READ(hw, SXE_MPSAR_HIGH(i));
				value &= ~(BIT(pool_idx - 32));
				SXE_REG_WRITE(hw, SXE_MPSAR_HIGH(i), value);
			}
		}
	}
}

#endif

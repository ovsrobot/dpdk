/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2015-2025 Beijing WangXun Technology Co., Ltd.
 * Copyright(c) 2010-2017 Intel Corporation
 */

#include "txgbe_type.h"
#include "txgbe_mbx.h"
#include "txgbe_phy.h"
#include "txgbe_dcb.h"
#include "txgbe_vf.h"
#include "txgbe_eeprom.h"
#include "txgbe_mng.h"
#include "txgbe_hw.h"
#include "txgbe_aml.h"
#include "txgbe_aml40.h"
#include "txgbe_e56.h"
#include "txgbe_e56_bp.h"

void txgbe_init_ops_aml40(struct txgbe_hw *hw)
{
	struct txgbe_mac_info *mac = &hw->mac;
	struct txgbe_phy_info *phy = &hw->phy;
	struct txgbe_mbx_info *mbx = &hw->mbx;

	txgbe_init_ops_generic(hw);

	/* PHY */
	phy->get_media_type = txgbe_get_media_type_aml40;
	phy->setup_link_core = txgbe_setup_phy_link_aml40;

	/* LINK */
	mac->init_mac_link_ops = txgbe_init_mac_link_ops_aml40;
	mac->get_link_capabilities = txgbe_get_link_capabilities_aml40;
	mac->check_link = txgbe_check_mac_link_aml40;

	/* FW interaction */
	mbx->host_interface_command = txgbe_host_interface_command_aml;
}

s32 txgbe_check_mac_link_aml40(struct txgbe_hw *hw, u32 *speed,
				 bool *link_up, bool link_up_wait_to_complete)
{
	u32 links_reg, links_orig;
	u32 i;

	/* clear the old state */
	links_orig = rd32(hw, TXGBE_PORTSTAT);

	links_reg = rd32(hw, TXGBE_PORTSTAT);

	if (links_orig != links_reg) {
		DEBUGOUT("LINKS changed from %08X to %08X",
			  links_orig, links_reg);
	}

	if (link_up_wait_to_complete) {
		for (i = 0; i < hw->mac.max_link_up_time; i++) {
			if (!hw->link_valid) {
				*link_up = false;

				msleep(100);
				continue;
			}

			if (!(links_reg & TXGBE_PORTSTAT_UP)) {
				*link_up = false;
			} else {
				*link_up = true;
				break;
			}
			msec_delay(100);
			links_reg = rd32(hw, TXGBE_PORTSTAT);
		}
	} else {
		if (links_reg & TXGBE_PORTSTAT_UP)
			*link_up = true;
		else
			*link_up = false;
	}

	if (!hw->link_valid)
		*link_up = false;

	if (*link_up) {
		if ((links_reg & TXGBE_CFG_PORT_ST_AML_LINK_40G) ==
			TXGBE_CFG_PORT_ST_AML_LINK_40G)
			*speed = TXGBE_LINK_SPEED_40GB_FULL;
		else if ((links_reg & TXGBE_CFG_PORT_ST_AML_LINK_10G) ==
			TXGBE_CFG_PORT_ST_AML_LINK_10G)
			*speed = TXGBE_LINK_SPEED_10GB_FULL;
	} else {
		*speed = TXGBE_LINK_SPEED_UNKNOWN;
	}

	return 0;
}

static int txgbe_is_40g_fiber_qsfp(struct txgbe_hw *hw)
{
	if (hw->phy.sfp_type == txgbe_qsfp_type_40g_sr_core0 ||
	    hw->phy.sfp_type == txgbe_qsfp_type_40g_sr_core1 ||
	    hw->phy.sfp_type == txgbe_qsfp_type_40g_lr_core0 ||
	    hw->phy.sfp_type == txgbe_qsfp_type_40g_lr_core1 ||
	    hw->phy.sfp_type == txgbe_qsfp_type_40g_active_core0 ||
	    hw->phy.sfp_type == txgbe_qsfp_type_40g_active_core1)
		return true;

	return false;
}

static int txgbe_is_10g_fiber_sfp(struct txgbe_hw *hw)
{
	if (hw->phy.sfp_type == txgbe_sfp_type_srlr_core0 ||
	    hw->phy.sfp_type == txgbe_sfp_type_srlr_core1)
		return true;

	return false;
}

s32 txgbe_get_link_capabilities_aml40(struct txgbe_hw *hw,
				      u32 *speed,
				      bool *autoneg)
{
	PMD_DRV_LOG(DEBUG, "port[%d]hw->phy.sfp_type = %d",
		    hw->bus.lan_id, hw->phy.sfp_type);

	/* Backplane */
	if (txgbe_is_backplane(hw)) {
		*speed = TXGBE_LINK_SPEED_10GB_FULL |
			 TXGBE_LINK_SPEED_40GB_FULL;
		/* Backplane supports autonegotiation */
		*autoneg = hw->devarg.auto_neg;
		return 0;
	}

	/* Fiber or DAC cable */
	if (txgbe_is_dac_cable(hw)) {
		/*
		 * 10G-only DAC cable: legacy build-time AUTO=0/1 default
		 * mode forces AN off. DPDK equivalent: devarg.auto_neg == 0.
		 */
		if (hw->phy.fiber_suppport_speed ==
		    TXGBE_LINK_SPEED_10GB_FULL &&
		    hw->devarg.auto_neg == 0) {
			*autoneg = false;
		} else {
			*autoneg = hw->devarg.auto_neg;
		}
		*speed = hw->phy.fiber_suppport_speed;
	} else if (hw->phy.multispeed_fiber) {
		/* multispeed fiber must come before single-sfp/qsfp fiber */
		*speed = TXGBE_LINK_SPEED_10GB_FULL |
			 TXGBE_LINK_SPEED_40GB_FULL;
		*autoneg = true;
	} else if (txgbe_is_40g_fiber_qsfp(hw)) {
		*speed = TXGBE_LINK_SPEED_40GB_FULL;
		*autoneg = false;
	} else if (txgbe_is_10g_fiber_sfp(hw)) {
		*speed = TXGBE_LINK_SPEED_10GB_FULL;
		*autoneg = false;
	} else {
		/*
		 * Unknown / unsupported module: keep 40G default to avoid
		 * TXGBE_ERR_LINK_SETUP returned by setup_mac_link, mirroring
		 * the temporary workaround in the previous version.
		 */
		*speed = TXGBE_LINK_SPEED_40GB_FULL;
		*autoneg = false;
	}

	return 0;
}

u32 txgbe_get_media_type_aml40(struct txgbe_hw *hw)
{
	u8 device_type = hw->subsystem_device_id & 0xF0;
	enum txgbe_media_type media_type;

	switch (device_type) {
	case TXGBE_DEV_ID_KR_KX_KX4:
		media_type = txgbe_media_type_backplane;
		break;
	case TXGBE_DEV_ID_SFP:
		media_type = txgbe_media_type_fiber_qsfp;
		break;
	default:
		media_type = txgbe_media_type_unknown;
		break;
	}

	return media_type;
}

s32 txgbe_setup_phy_link_aml40(struct txgbe_hw *hw,
				      u32 speed,
				      bool autoneg_wait_to_complete,
				      bool *need_reset)
{
	bool autoneg = false;
	s32 status = 0;
	s32 ret_status = 0;
	u32 link_speed = TXGBE_LINK_SPEED_UNKNOWN;
	bool link_up = false;
	int i;
	u32 link_capabilities = TXGBE_LINK_SPEED_UNKNOWN;
	u32 value;

	*need_reset = false;

	if (hw->phy.sfp_type == txgbe_sfp_type_not_present && !txgbe_is_backplane(hw))
		hw->phy.identify_sfp(hw);

	/* Check to see if speed passed in is supported. */
	status = hw->mac.get_link_capabilities(hw,
			&link_capabilities, &autoneg);
	if (status)
		return status;

	speed &= link_capabilities;
	if (speed == TXGBE_LINK_SPEED_UNKNOWN)
		return TXGBE_ERR_LINK_SETUP;

	if (txgbe_xpcs_an_enabled(hw)) {
		txgbe_e56_check_phy_link(hw, &link_speed, &link_up);
		if (link_up && hw->an_done && !autoneg_wait_to_complete)
			return status;
		rte_spinlock_lock(&hw->phy_lock);
		txgbe_e56_set_phy_link_mode(hw, speed, autoneg_wait_to_complete);
		rte_spinlock_unlock(&hw->phy_lock);
		/* Restore link_valid, as the non-xpcs path below does. An
		 * earlier txgbe_set_link_to_amlite() timeout, for example when
		 * the port was started with no module plugged in, left it
		 * false, which keeps the check_phy_link and check_mac_link
		 * gates forcing the link down even after AN73 brings it up.
		 */
		hw->link_valid = true;
		return status;
	}

	/* setup the highest link when no autoneg */
	if (speed & TXGBE_LINK_SPEED_40GB_FULL)
		speed = TXGBE_LINK_SPEED_40GB_FULL;
	else if (speed & TXGBE_LINK_SPEED_10GB_FULL)
		speed = TXGBE_LINK_SPEED_10GB_FULL;

	if (txgbe_is_backplane(hw) || txgbe_is_dac_cable(hw) ||
	    hw->phy.ffe_set) {
		rte_spinlock_lock(&hw->phy_lock);
		txgbe_e56_tx_ffe_cfg(hw, speed);
		rte_spinlock_unlock(&hw->phy_lock);
	}

	for (i = 0; i < 4; i++) {
		txgbe_e56_check_phy_link(hw, &link_speed, &link_up);
		if (link_up)
			break;
		msleep(250);
	}

	if (link_speed == speed && link_up)
		goto out;

	rte_spinlock_lock(&hw->phy_lock);
	ret_status = txgbe_set_link_to_amlite(hw, speed);
	rte_spinlock_unlock(&hw->phy_lock);

	/* The PHY did not come out of reset; leave link_valid alone and
	 * let the retry in the alarm handler attempt the setup again.
	 */
	if (ret_status == TXGBE_ERR_PHY_INIT_NOT_DONE)
		goto out;

	if (ret_status == TXGBE_ERR_TIMEOUT)
		hw->link_valid = false;
	else
		hw->link_valid = true;

	for (i = 0; i < 4; i++) {
		txgbe_e56_check_phy_link(hw, &link_speed, &link_up);
		if (link_up)
			goto out;
		msleep(250);
	}

out:
	if (link_up) {
		value = rd32(hw, TXGBE_PORTSTAT);
		if (!(value & TXGBE_PORTSTAT_UP)) {
			DEBUGOUT("MAC link 0x14404: 0x%x", value);
			*need_reset = true;
			value = rd32(hw, 0x110b0);
			DEBUGOUT("MAC intr status 0x110b0: 0x%x", value);
		}
	} else {
		*need_reset = true;
		DEBUGOUT("Link reconfiguration required. Reset scheduled in 2000ms.");
	}

	return status;
}

void txgbe_init_mac_link_ops_aml40(struct txgbe_hw *hw)
{
	struct txgbe_mac_info *mac = &hw->mac;

	mac->disable_tx_laser =
		txgbe_disable_tx_laser_multispeed_fiber;
	mac->enable_tx_laser =
		txgbe_enable_tx_laser_multispeed_fiber;
	mac->flap_tx_laser =
		txgbe_flap_tx_laser_multispeed_fiber;

	mac->set_rate_select_speed = txgbe_set_hard_rate_select_speed;
}

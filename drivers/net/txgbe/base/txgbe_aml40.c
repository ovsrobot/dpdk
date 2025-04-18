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
#include "txgbe_e56.h"
#include "txgbe_e56_bp.h"

void txgbe_init_ops_aml40(struct txgbe_hw *hw);
s32 txgbe_check_mac_link_aml40(struct txgbe_hw *hw,
			       u32 *speed,
			       bool *link_up, bool link_up_wait_to_complete);
s32 txgbe_get_link_capabilities_aml40(struct txgbe_hw *hw,
				      u32 *speed, bool *autoneg);
u32 txgbe_get_media_type_aml40(struct txgbe_hw *hw);
s32 txgbe_setup_mac_link_aml40(struct txgbe_hw *hw, u32 speed,
			       bool autoneg_wait_to_complete);
void txgbe_init_mac_link_ops_aml40(struct txgbe_hw *hw);

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


	if (link_up) {
		if ((links_reg & TXGBE_CFG_PORT_ST_AML_LINK_40G) ==
			TXGBE_CFG_PORT_ST_AML_LINK_40G)
			*speed = TXGBE_LINK_SPEED_40GB_FULL;
	} else 
		*speed = TXGBE_LINK_SPEED_UNKNOWN;

	return 0;
}

s32 txgbe_get_link_capabilities_aml40(struct txgbe_hw *hw,
				      u32 *speed,
				      bool *autoneg)
{
	if (hw->phy.sfp_type == txgbe_sfp_type_40g_core0 ||
		   hw->phy.sfp_type == txgbe_sfp_type_40g_core1) {
		*speed = TXGBE_LINK_SPEED_40GB_FULL;
		*autoneg = false;
	} else if (hw->phy.sfp_type == txgbe_sfp_type_not_present) {
		/*
		 * Temporary workaround: set speed to 40G even if sfp not present
		 * to avoid TXGBE_ERR_LINK_SETUP returned by setup_mac_link, but
		 * a more reasonable solution is don't execute setup_mac_link when
		 * sfp module not present.
		 */
		*speed = TXGBE_LINK_SPEED_40GB_FULL;
		*autoneg = true;
	}

	return 0;
}

u32 txgbe_get_media_type_aml40(struct txgbe_hw *hw)
{
	UNREFERENCED_PARAMETER(hw);
	return txgbe_media_type_fiber_qsfp;
}

s32 txgbe_setup_mac_link_aml40(struct txgbe_hw *hw,
			       u32 speed,
			       bool autoneg_wait_to_complete)
{
	bool autoneg = false;
	s32 status = 0;
	s32 ret_status = 0;
	u32 link_speed = TXGBE_LINK_SPEED_UNKNOWN;
	bool link_up = false;
	int i;
	u32 link_capabilities = TXGBE_LINK_SPEED_UNKNOWN;

	UNREFERENCED_PARAMETER(autoneg_wait_to_complete);

	if (hw->phy.sfp_type == txgbe_sfp_type_not_present) {
		DEBUGOUT("SFP not detected, skip setup mac link");
		return 0;
	}

	/* Check to see if speed passed in is supported. */
	status = hw->mac.get_link_capabilities(hw,
			&link_capabilities, &autoneg);
	if (status)
		return status;

	speed &= link_capabilities;
	if (speed == TXGBE_LINK_SPEED_UNKNOWN)
		return TXGBE_ERR_LINK_SETUP;

	for (i = 0; i < 4; i++) {
		txgbe_e56_check_phy_link(hw, &link_speed, &link_up);
		if (link_up)
			break;
		msleep(250);
	}

	if (link_speed == speed && link_up)
		return status;

	rte_spinlock_lock(&hw->phy_lock);
	ret_status = txgbe_set_link_to_amlite(hw, speed);
	rte_spinlock_unlock(&hw->phy_lock);
	hw->tx_speed = speed;

	if (ret_status == TXGBE_ERR_TIMEOUT)
		hw->link_valid = false;

	for (i = 0; i < 4; i++) {
		txgbe_e56_check_phy_link(hw, &link_speed, &link_up);
		if (link_up)
			return status;
		msleep(250);
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

	mac->setup_link = txgbe_setup_mac_link_aml40;
	mac->set_rate_select_speed = txgbe_set_hard_rate_select_speed;
}

void txgbe_init_ops_aml40(struct txgbe_hw *hw)
{
	struct txgbe_mac_info *mac = &hw->mac;
	struct txgbe_phy_info *phy = &hw->phy;

	/* PHY */
	phy->get_media_type = txgbe_get_media_type_aml40;

	/* LINK */
	mac->init_mac_link_ops = txgbe_init_mac_link_ops_aml40;
	mac->get_link_capabilities = txgbe_get_link_capabilities_aml40;
	mac->check_link = txgbe_check_mac_link_aml40;
}

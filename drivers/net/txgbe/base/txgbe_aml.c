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

void txgbe_init_ops_aml(struct txgbe_hw *hw);
s32 txgbe_check_mac_link_aml(struct txgbe_hw *hw,
			       u32 *speed,
			       bool *link_up, bool link_up_wait_to_complete);
s32 txgbe_get_link_capabilities_aml(struct txgbe_hw *hw,
				      u32 *speed, bool *autoneg);
u32 txgbe_get_media_type_aml(struct txgbe_hw *hw);
s32 txgbe_setup_mac_link_aml(struct txgbe_hw *hw, u32 speed,
			       bool autoneg_wait_to_complete);
void txgbe_init_mac_link_ops_aml(struct txgbe_hw *hw);

s32 txgbe_check_mac_link_aml(struct txgbe_hw *hw, u32 *speed,
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

	if (link_up) {
		switch (links_reg & TXGBE_CFG_PORT_ST_AML_LINK_MASK) {
		case TXGBE_CFG_PORT_ST_AML_LINK_25G:
			*speed = TXGBE_LINK_SPEED_25GB_FULL;
			break;
		case TXGBE_CFG_PORT_ST_AML_LINK_10G:
			*speed = TXGBE_LINK_SPEED_10GB_FULL;
			break;
		default:
			*speed = TXGBE_LINK_SPEED_UNKNOWN;
		}
	} else
		*speed = TXGBE_LINK_SPEED_UNKNOWN;

	return 0;
}


s32 txgbe_get_link_capabilities_aml(struct txgbe_hw *hw,
				      u32 *speed,
				      bool *autoneg)
{
	if (hw->phy.multispeed_fiber) {
		*speed = TXGBE_LINK_SPEED_10GB_FULL |
			 TXGBE_LINK_SPEED_25GB_FULL;
		*autoneg = true;
	} else if (hw->phy.sfp_type == txgbe_sfp_type_25g_sr_core0 ||
		   hw->phy.sfp_type == txgbe_sfp_type_25g_sr_core1 ||
		   hw->phy.sfp_type == txgbe_sfp_type_25g_lr_core0 ||
		   hw->phy.sfp_type == txgbe_sfp_type_25g_lr_core1) {
		*speed = TXGBE_LINK_SPEED_25GB_FULL;
		*autoneg = false;
	} else if (hw->phy.sfp_type == txgbe_sfp_type_25g_da_cu_core0 ||
		   hw->phy.sfp_type == txgbe_sfp_type_25g_da_cu_core1 ||
		   hw->phy.sfp_type == txgbe_sfp_type_25g_5m_da_cu_core0 ||
		   hw->phy.sfp_type == txgbe_sfp_type_25g_5m_da_cu_core1 ||
		   hw->phy.sfp_type == txgbe_sfp_type_25g_fcpi4_lmt_core0 ||
		   hw->phy.sfp_type == txgbe_sfp_type_25g_fcpi4_lmt_core1) {
		*speed = TXGBE_LINK_SPEED_25GB_FULL;
		*autoneg = false;
	}

	return 0;
}

u32 txgbe_get_media_type_aml(struct txgbe_hw *hw)
{
	UNREFERENCED_PARAMETER(hw);
	return txgbe_media_type_fiber;
}

s32 txgbe_setup_mac_link_aml(struct txgbe_hw *hw,
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
	u32 value = 0;

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

	if (hw->phy.sfp_type == txgbe_sfp_type_25g_5m_da_cu_core0 ||
	    hw->phy.sfp_type == txgbe_sfp_type_25g_5m_da_cu_core1||
	    hw->phy.sfp_type == txgbe_sfp_type_25g_da_cu_core0 ||
	    hw->phy.sfp_type == txgbe_sfp_type_25g_da_cu_core1) {
		rte_spinlock_lock(&hw->phy_lock);
		txgbe_e56_set_link_to_kr(hw);
		rte_spinlock_unlock(&hw->phy_lock);
		return 0;
	}

	value = rd32(hw, TXGBE_GPIOEXT);
	if (value & (TXGBE_SFP1_MOD_ABS_LS | TXGBE_SFP1_RX_LOS_LS))
		return status;

	for (i = 0; i < 4; i++) {
		txgbe_e56_check_phy_link(hw, &link_speed, &link_up);
		if (link_up)
			break;
		msleep(250);
	}

	if (link_speed == speed && link_up &&
	   !(speed == TXGBE_LINK_SPEED_25GB_FULL &&
	   !(hw->fec_mode & hw->cur_fec_link))) {
		hw->tx_speed = speed;
		return status;
	}

	if (speed == TXGBE_LINK_SPEED_25GB_FULL &&
			link_speed == TXGBE_LINK_SPEED_25GB_FULL) {
		txgbe_e56_fec_polling(hw, &link_up);

		if (link_up)
			return status;
	}

	rte_spinlock_lock(&hw->phy_lock);
	ret_status = txgbe_set_link_to_amlite(hw, speed);
	rte_spinlock_unlock(&hw->phy_lock);
	hw->tx_speed = speed;

	if (ret_status == TXGBE_ERR_PHY_INIT_NOT_DONE)
		return status;

	if (speed == TXGBE_LINK_SPEED_25GB_FULL) {
		txgbe_e56_fec_polling(hw, &link_up);
	} else {
		for (i = 0; i < 4; i++) {
			txgbe_e56_check_phy_link(hw, &link_speed, &link_up);
			if (link_up)
				return status;;
			msleep(250);
		}
	}

	return status;
}

/**
 *  txgbe_setup_mac_link_multispeed_fiber_aml - Set MAC link speed
 *  @hw: pointer to hardware structure
 *  @speed: new link speed
 *  @autoneg_wait_to_complete: true when waiting for completion is needed
 *
 *  Set the link speed in the MAC and/or PHY register and restarts link.
 **/
static s32 txgbe_setup_mac_link_multispeed_fiber_aml(struct txgbe_hw *hw,
					  u32 speed,
					  bool autoneg_wait_to_complete)
{
	u32 link_speed = TXGBE_LINK_SPEED_UNKNOWN;
	u32 highest_link_speed = TXGBE_LINK_SPEED_UNKNOWN;
	s32 status = 0;
	u32 speedcnt = 0;
	bool autoneg, link_up = false;

	/* Mask off requested but non-supported speeds */
	status = hw->mac.get_link_capabilities(hw, &link_speed, &autoneg);
	if (status != 0)
		return status;

	speed &= link_speed;

	/* Try each speed one by one, highest priority first.  We do this in
	 * software because 10Gb fiber doesn't support speed autonegotiation.
	 */
	if (speed & TXGBE_LINK_SPEED_25GB_FULL) {
		speedcnt++;
		highest_link_speed = TXGBE_LINK_SPEED_25GB_FULL;

		/* If we already have link at this speed, just jump out */
		txgbe_e56_check_phy_link(hw, &link_speed, &link_up);

		if ((link_speed == TXGBE_LINK_SPEED_25GB_FULL) && link_up &&
		    hw->fec_mode & hw->cur_fec_link)
			goto out;

		/* Allow module to change analog characteristics (1G->10G) */
		msec_delay(40);

		status = hw->mac.setup_mac_link(hw,
				TXGBE_LINK_SPEED_25GB_FULL,
				autoneg_wait_to_complete);
		if (status != 0)
			return status;

		/*aml wait link in setup,no need to repeatly wait*/
		/* If we have link, just jump out */
		txgbe_e56_check_phy_link(hw, &link_speed, &link_up);

		if (link_up)
			goto out;

	}

	if (speed & TXGBE_LINK_SPEED_10GB_FULL) {
		speedcnt++;
		if (highest_link_speed == TXGBE_LINK_SPEED_UNKNOWN)
			highest_link_speed = TXGBE_LINK_SPEED_10GB_FULL;

		/* If we already have link at this speed, just jump out */
		txgbe_e56_check_phy_link(hw, &link_speed, &link_up);

		if ((link_speed == TXGBE_LINK_SPEED_10GB_FULL) && link_up)
			goto out;

		/* Allow module to change analog characteristics (25G->10G) */
		msec_delay(40);

		status = hw->mac.setup_mac_link(hw, TXGBE_LINK_SPEED_10GB_FULL,
				autoneg_wait_to_complete);
		if (status != 0)
			return status;

		/*aml wait link in setup,no need to repeatly wait*/
		/* If we have link, just jump out */
		txgbe_e56_check_phy_link(hw, &link_speed, &link_up);

		if (link_up)
			goto out;
	}

	/* We didn't get link.  Configure back to the highest speed we tried,
	 * (if there was more than one).  We call ourselves back with just the
	 * single highest speed that the user requested.
	 */
	if (speedcnt > 1)
		status = txgbe_setup_mac_link_multispeed_fiber_aml(hw,
						      highest_link_speed,
						      autoneg_wait_to_complete);

out:
	/* Set autoneg_advertised value based on input link speed */
	hw->phy.autoneg_advertised = 0;

	if (speed & TXGBE_LINK_SPEED_25GB_FULL)
		hw->phy.autoneg_advertised |= TXGBE_LINK_SPEED_25GB_FULL;

	if (speed & TXGBE_LINK_SPEED_10GB_FULL)
		hw->phy.autoneg_advertised |= TXGBE_LINK_SPEED_10GB_FULL;

	return status;
}

void txgbe_init_mac_link_ops_aml(struct txgbe_hw *hw)
{
	struct txgbe_mac_info *mac = &hw->mac;

	if (hw->phy.media_type == txgbe_media_type_fiber ||
	    hw->phy.media_type == txgbe_media_type_fiber_qsfp) {
		mac->disable_tx_laser =
			txgbe_disable_tx_laser_multispeed_fiber;
		mac->enable_tx_laser =
			txgbe_enable_tx_laser_multispeed_fiber;
		mac->flap_tx_laser =
			txgbe_flap_tx_laser_multispeed_fiber;

		if (hw->phy.multispeed_fiber) {
			/* Set up dual speed SFP+ support */
			mac->setup_link = txgbe_setup_mac_link_multispeed_fiber_aml;
			mac->setup_mac_link = txgbe_setup_mac_link_aml;
			mac->set_rate_select_speed = txgbe_set_hard_rate_select_speed;
		} else {
			mac->setup_link = txgbe_setup_mac_link_aml;
			mac->set_rate_select_speed = txgbe_set_hard_rate_select_speed;
		}
	}
}

void txgbe_init_ops_aml(struct txgbe_hw *hw)
{
	struct txgbe_mac_info *mac = &hw->mac;
	struct txgbe_phy_info *phy = &hw->phy;

	/* PHY */
	phy->get_media_type = txgbe_get_media_type_aml;

	/* LINK */
	mac->init_mac_link_ops = txgbe_init_mac_link_ops_aml;
	mac->get_link_capabilities = txgbe_get_link_capabilities_aml;
	mac->check_link = txgbe_check_mac_link_aml;
}
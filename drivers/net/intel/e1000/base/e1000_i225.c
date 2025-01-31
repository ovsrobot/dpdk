/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2001-2024 Intel Corporation
 */

#include "e1000_api.h"

STATIC s32 e1000_init_mac_params_i225(struct e1000_hw *hw);
STATIC s32 e1000_init_phy_params_i225(struct e1000_hw *hw);
STATIC s32 e1000_reset_hw_i225(struct e1000_hw *hw);

/**
 *  e1000_init_mac_params_i225 - Init MAC func ptrs.
 *  @hw: pointer to the HW structure
 **/
STATIC s32 e1000_init_mac_params_i225(struct e1000_hw *hw)
{
	struct e1000_mac_info *mac = &hw->mac;

	DEBUGFUNC("e1000_init_mac_params_i225");

	/* Initialize function pointer */
	e1000_init_mac_ops_generic(hw);

	/* Set media type */
	hw->phy.media_type = e1000_media_type_copper;
	/* Set mta register count */
	mac->mta_reg_count = 128;
	/* Set rar entry count */
	mac->rar_entry_count = E1000_RAR_ENTRIES_BASE;
	/* bus type/speed/width */
	mac->ops.get_bus_info = e1000_get_bus_info_pcie_generic;
	/* reset */
	mac->ops.reset_hw = e1000_reset_hw_i225;
	/* hw initialization */
	mac->ops.init_hw = e1000_init_hw_i225;
	/* link setup */
	mac->ops.setup_link = e1000_setup_link_generic;
	mac->ops.check_for_link = e1000_check_for_copper_link_generic;
	/* link info */
	mac->ops.get_link_up_info = e1000_get_speed_and_duplex_copper_generic;

	/* Allow a single clear of the SW semaphore on I225 */
	mac->ops.setup_physical_interface = e1000_setup_copper_link_i225;

	/* Set if part includes ASF firmware */
	mac->asf_firmware_present = true;

	/* multicast address update */
	mac->ops.update_mc_addr_list = e1000_update_mc_addr_list_generic;

	mac->ops.write_vfta = e1000_write_vfta_generic;

	/* LED */
	mac->ops.cleanup_led = e1000_cleanup_led_generic;
	mac->ops.id_led_init = e1000_id_led_init_i225;
	mac->ops.blink_led = e1000_blink_led_i225;

	return E1000_SUCCESS;
}

/**
 *  e1000_init_phy_params_i225 - Init PHY func ptrs.
 *  @hw: pointer to the HW structure
 **/
STATIC s32 e1000_init_phy_params_i225(struct e1000_hw *hw)
{
	struct e1000_phy_info *phy = &hw->phy;
	s32 ret_val = E1000_SUCCESS;
	u32 ctrl_ext;

	DEBUGFUNC("e1000_init_phy_params_i225");

	phy->ops.read_i2c_byte = e1000_read_i2c_byte_generic;
	phy->ops.write_i2c_byte = e1000_write_i2c_byte_generic;

	if (hw->phy.media_type != e1000_media_type_copper) {
		phy->type = e1000_phy_none;
		goto out;
	}

	phy->ops.power_up   = e1000_power_up_phy_copper;
	phy->ops.power_down = e1000_power_down_phy_copper_base;

	phy->autoneg_mask = AUTONEG_ADVERTISE_SPEED_DEFAULT_2500;

	phy->reset_delay_us	= 100;

	phy->ops.acquire	= e1000_acquire_phy_base;
	phy->ops.check_reset_block = e1000_check_reset_block_generic;
	phy->ops.commit		= e1000_phy_sw_reset_generic;
	phy->ops.release	= e1000_release_phy_base;
	phy->ops.reset		= e1000_phy_hw_reset_generic;

	ctrl_ext = E1000_READ_REG(hw, E1000_CTRL_EXT);

	/* Make sure the PHY is in a good state. Several people have reported
	 * firmware leaving the PHY's page select register set to something
	 * other than the default of zero, which causes the PHY ID read to
	 * access something other than the intended register.
	 */
	ret_val = hw->phy.ops.reset(hw);
	if (ret_val)
		goto out;

	E1000_WRITE_REG(hw, E1000_CTRL_EXT, ctrl_ext);

	ret_val = e1000_get_phy_id(hw);

	/*
	 * IGC/IGB merge note: in base code, there was a PHY ID check for I225
	 * at this point. However, in DPDK version of IGC this check was
	 * removed because it interfered with some i225-based NICs, and it was
	 * deemed unnecessary because only the i225 NIC would've called this
	 * code anyway because it was in the IGC driver.
	 *
	 * In merged IGB/IGC, this code is still only called by i225-based NICs,
	 * so the previous fix is applicable.
	 */
	phy->type = e1000_phy_i225;

out:
	return ret_val;
}

/**
 *  e1000_reset_hw_i225 - Reset hardware
 *  @hw: pointer to the HW structure
 *
 *  This resets the hardware into a known state.
 **/
STATIC s32 e1000_reset_hw_i225(struct e1000_hw *hw)
{
	u32 ctrl;
	s32 ret_val;

	DEBUGFUNC("e1000_reset_hw_i225");

	/*
	 * Prevent the PCI-E bus from sticking if there is no TLP connection
	 * on the last TLP read/write transaction when MAC is reset.
	 */
	ret_val = e1000_disable_pcie_master_generic(hw);
	if (ret_val)
		DEBUGOUT("PCI-E Master disable polling has failed.\n");

	DEBUGOUT("Masking off all interrupts\n");
	E1000_WRITE_REG(hw, E1000_IMC, 0xffffffff);

	E1000_WRITE_REG(hw, E1000_RCTL, 0);
	E1000_WRITE_REG(hw, E1000_TCTL, E1000_TCTL_PSP);
	E1000_WRITE_FLUSH(hw);

	msec_delay(10);

	ctrl = E1000_READ_REG(hw, E1000_CTRL);

	DEBUGOUT("Issuing a global reset to MAC\n");
	E1000_WRITE_REG(hw, E1000_CTRL, ctrl | E1000_CTRL_RST);

	ret_val = e1000_get_auto_rd_done_generic(hw);
	if (ret_val) {
		/*
		 * When auto config read does not complete, do not
		 * return with an error. This can happen in situations
		 * where there is no eeprom and prevents getting link.
		 */
		DEBUGOUT("Auto Read Done did not complete\n");
	}

	/* Clear any pending interrupt events. */
	E1000_WRITE_REG(hw, E1000_IMC, 0xffffffff);
	E1000_READ_REG(hw, E1000_ICR);

	/* Install any alternate MAC address into RAR0 */
	ret_val = e1000_check_alt_mac_addr_generic(hw);

	return ret_val;
}

/*
 * e1000_setup_copper_link_i225 - Configure copper link settings
 * @hw: pointer to the HW structure
 *
 * Configures the link for auto-neg or forced speed and duplex.  Then we check
 * for link, once link is established calls to configure collision distance
 * and flow control are called.
 */
s32 e1000_setup_copper_link_i225(struct e1000_hw *hw)
{
	u32 phpm_reg;
	s32 ret_val;
	u32 ctrl;

	DEBUGFUNC("e1000_setup_copper_link_i225");

	ctrl = E1000_READ_REG(hw, E1000_CTRL);
	ctrl |= E1000_CTRL_SLU;
	ctrl &= ~(E1000_CTRL_FRCSPD | E1000_CTRL_FRCDPX);
	E1000_WRITE_REG(hw, E1000_CTRL, ctrl);

	phpm_reg = E1000_READ_REG(hw, E1000_I225_PHPM);
	phpm_reg &= ~E1000_I225_PHPM_GO_LINKD;
	E1000_WRITE_REG(hw, E1000_I225_PHPM, phpm_reg);

	ret_val = e1000_setup_copper_link_generic(hw);

	return ret_val;
}

/* e1000_init_function_pointers_i225 - Init func ptrs.
 * @hw: pointer to the HW structure
 *
 * Called to initialize all function pointers and parameters.
 */
void e1000_init_function_pointers_i225(struct e1000_hw *hw)
{
	e1000_init_mac_ops_generic(hw);
	e1000_init_phy_ops_generic(hw);
	hw->mac.ops.init_params = e1000_init_mac_params_i225;
	hw->phy.ops.init_params = e1000_init_phy_params_i225;
}

/* e1000_get_cfg_done_i225 - Read config done bit
 * @hw: pointer to the HW structure
 *
 * Read the management control register for the config done bit for
 * completion status.  NOTE: silicon which is EEPROM-less will fail trying
 * to read the config done bit, so an error is *ONLY* logged and returns
 * E1000_SUCCESS.  If we were to return with error, EEPROM-less silicon
 * would not be able to be reset or change link.
 */
STATIC s32 e1000_get_cfg_done_i225(struct e1000_hw *hw)
{
	s32 timeout = PHY_CFG_TIMEOUT;
	u32 mask = E1000_NVM_CFG_DONE_PORT_0;

	DEBUGFUNC("e1000_get_cfg_done_i225");

	while (timeout) {
		if (E1000_READ_REG(hw, E1000_EEMNGCTL_I225) & mask)
			break;
		msec_delay(1);
		timeout--;
	}
	if (!timeout)
		DEBUGOUT("MNG configuration cycle has not completed.\n");

	return E1000_SUCCESS;
}

/* e1000_init_hw_i225 - Init hw for I225
 * @hw: pointer to the HW structure
 *
 * Called to initialize hw for i225 hw family.
 */
s32 e1000_init_hw_i225(struct e1000_hw *hw)
{
	s32 ret_val;

	DEBUGFUNC("e1000_init_hw_i225");

	hw->phy.ops.get_cfg_done = e1000_get_cfg_done_i225;
	ret_val = e1000_init_hw_base(hw);
	return ret_val;
}

/*
 * e1000_set_d0_lplu_state_i225 - Set Low-Power-Link-Up (LPLU) D0 state
 * @hw: pointer to the HW structure
 * @active: true to enable LPLU, false to disable
 *
 * Note: since I225 does not actually support LPLU, this function
 * simply enables/disables 1G and 2.5G speeds in D0.
 */
s32 e1000_set_d0_lplu_state_i225(struct e1000_hw *hw, bool active)
{
	u32 data;

	DEBUGFUNC("e1000_set_d0_lplu_state_i225");

	data = E1000_READ_REG(hw, E1000_I225_PHPM);

	if (active) {
		data |= E1000_I225_PHPM_DIS_1000;
		data |= E1000_I225_PHPM_DIS_2500;
	} else {
		data &= ~E1000_I225_PHPM_DIS_1000;
		data &= ~E1000_I225_PHPM_DIS_2500;
	}

	E1000_WRITE_REG(hw, E1000_I225_PHPM, data);
	return E1000_SUCCESS;
}

/*
 * e1000_set_d3_lplu_state_i225 - Set Low-Power-Link-Up (LPLU) D3 state
 * @hw: pointer to the HW structure
 * @active: true to enable LPLU, false to disable
 *
 * Note: since I225 does not actually support LPLU, this function
 * simply enables/disables 100M, 1G and 2.5G speeds in D3.
 */
s32 e1000_set_d3_lplu_state_i225(struct e1000_hw *hw, bool active)
{
	u32 data;

	DEBUGFUNC("e1000_set_d3_lplu_state_i225");

	data = E1000_READ_REG(hw, E1000_I225_PHPM);

	if (active) {
		data |= E1000_I225_PHPM_DIS_100_D3;
		data |= E1000_I225_PHPM_DIS_1000_D3;
		data |= E1000_I225_PHPM_DIS_2500_D3;
	} else {
		data &= ~E1000_I225_PHPM_DIS_100_D3;
		data &= ~E1000_I225_PHPM_DIS_1000_D3;
		data &= ~E1000_I225_PHPM_DIS_2500_D3;
	}

	E1000_WRITE_REG(hw, E1000_I225_PHPM, data);
	return E1000_SUCCESS;
}

/**
 *  e1000_blink_led_i225 - Blink SW controllable LED
 *  @hw: pointer to the HW structure
 *
 *  This starts the adapter LED blinking.
 *  Request the LED to be setup first.
 **/
s32 e1000_blink_led_i225(struct e1000_hw *hw)
{
	u32 blink = 0;

	DEBUGFUNC("e1000_blink_led_i225");

	e1000_id_led_init_i225(hw);

	blink = hw->mac.ledctl_default;
	blink &= ~(E1000_GLOBAL_BLINK_MODE | E1000_LED1_MODE_MASK | E1000_LED2_MODE_MASK);
	blink |= E1000_LED1_BLINK;

	E1000_WRITE_REG(hw, E1000_LEDCTL, blink);

	return E1000_SUCCESS;
}

/**
 *  e1000_id_led_init_i225 - store LED configurations in SW
 *  @hw: pointer to the HW structure
 *
 *  Initializes the LED config in SW.
 **/
s32 e1000_id_led_init_i225(struct e1000_hw *hw)
{
	DEBUGFUNC("e1000_id_led_init_i225");

	hw->mac.ledctl_default = E1000_READ_REG(hw, E1000_LEDCTL);

	return E1000_SUCCESS;
}

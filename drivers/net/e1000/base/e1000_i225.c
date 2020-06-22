#include "e1000_api.h"

STATIC s32 e1000_init_nvm_params_i225(struct e1000_hw *hw);
STATIC s32 e1000_init_mac_params_i225(struct e1000_hw *hw);
STATIC s32 e1000_init_phy_params_i225(struct e1000_hw *hw);
STATIC s32 e1000_reset_hw_i225(struct e1000_hw *hw);
STATIC s32 e1000_acquire_nvm_i225(struct e1000_hw *hw);
STATIC void e1000_release_nvm_i225(struct e1000_hw *hw);
STATIC s32 e1000_get_hw_semaphore_i225(struct e1000_hw *hw);
#ifndef QV_RELEASE
STATIC s32 __e1000_write_nvm_srwr(struct e1000_hw *hw, u16 offset, u16 words,
				  u16 *data);
#endif /* QV_RELEASE */
STATIC s32 e1000_pool_flash_update_done_i225(struct e1000_hw *hw);
STATIC s32 e1000_valid_led_default_i225(struct e1000_hw *hw, u16 *data);

/**
 *  e1000_init_nvm_params_i225 - Init NVM func ptrs.
 *  @hw: pointer to the HW structure
 **/
STATIC s32 e1000_init_nvm_params_i225(struct e1000_hw *hw)
{
	struct e1000_nvm_info *nvm = &hw->nvm;
	u32 eecd = E1000_READ_REG(hw, E1000_EECD);
	u16 size;

	DEBUGFUNC("e1000_init_nvm_params_i225");

	size = (u16)((eecd & E1000_EECD_SIZE_EX_MASK) >>
		     E1000_EECD_SIZE_EX_SHIFT);
	/*
	 * Added to a constant, "size" becomes the left-shift value
	 * for setting word_size.
	 */
	size += NVM_WORD_SIZE_BASE_SHIFT;

	/* Just in case size is out of range, cap it to the largest
	 * EEPROM size supported
	 */
	if (size > 15)
		size = 15;

	nvm->word_size = 1 << size;
	nvm->opcode_bits = 8;
	nvm->delay_usec = 1;
	nvm->type = e1000_nvm_eeprom_spi;


	nvm->page_size = eecd & E1000_EECD_ADDR_BITS ? 32 : 8;
	nvm->address_bits = eecd & E1000_EECD_ADDR_BITS ?
			    16 : 8;

	if (nvm->word_size == (1 << 15))
		nvm->page_size = 128;

	nvm->ops.acquire = e1000_acquire_nvm_i225;
	nvm->ops.release = e1000_release_nvm_i225;
	nvm->ops.valid_led_default = e1000_valid_led_default_i225;
	if (e1000_get_flash_presence_i225(hw)) {
		hw->nvm.type = e1000_nvm_flash_hw;
		nvm->ops.read    = e1000_read_nvm_srrd_i225;
		nvm->ops.write   = e1000_write_nvm_srwr_i225;
		nvm->ops.validate = e1000_validate_nvm_checksum_i225;
		nvm->ops.update   = e1000_update_nvm_checksum_i225;
	} else {
		hw->nvm.type = e1000_nvm_invm;
		nvm->ops.write    = e1000_null_write_nvm;
		nvm->ops.validate = e1000_null_ops_generic;
		nvm->ops.update   = e1000_null_ops_generic;
	}

	return E1000_SUCCESS;
}

/**
 *  e1000_init_mac_params_i225 - Init MAC func ptrs.
 *  @hw: pointer to the HW structure
 **/
STATIC s32 e1000_init_mac_params_i225(struct e1000_hw *hw)
{
	struct e1000_mac_info *mac = &hw->mac;
	struct e1000_dev_spec_i225 *dev_spec = &hw->dev_spec._i225;

	DEBUGFUNC("e1000_init_mac_params_i225");

	/* Initialize function pointer */
	e1000_init_mac_ops_generic(hw);

	/* Set media type */
	hw->phy.media_type = e1000_media_type_copper;
	/* Set mta register count */
	mac->mta_reg_count = 128;
	/* Set rar entry count */
	mac->rar_entry_count = E1000_RAR_ENTRIES_BASE;
	/* Set EEE */
	mac->ops.set_eee = e1000_set_eee_i225;
	/* reset */
	mac->ops.reset_hw = e1000_reset_hw_i225;
	/* hw initialization */
	mac->ops.init_hw = e1000_init_hw_i225;
	/* link setup */
	mac->ops.setup_link = e1000_setup_link_generic;
	mac->ops.check_for_link = e1000_check_for_copper_link_generic;
	/* link info */
	mac->ops.get_link_up_info = e1000_get_speed_and_duplex_copper_generic;
	/* acquire SW_FW sync */
	mac->ops.acquire_swfw_sync = e1000_acquire_swfw_sync_i225;
	/* release SW_FW sync */
	mac->ops.release_swfw_sync = e1000_release_swfw_sync_i225;

	/* Allow a single clear of the SW semaphore on I225 */
	dev_spec->clear_semaphore_once = true;
	mac->ops.setup_physical_interface = e1000_setup_copper_link_i225;

	/* Set if part includes ASF firmware */
	mac->asf_firmware_present = true;

	/* multicast address update */
	mac->ops.update_mc_addr_list = e1000_update_mc_addr_list_generic;

	mac->ops.write_vfta = e1000_write_vfta_generic;

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
	phy->ops.read_reg = e1000_read_phy_reg_gpy;
	phy->ops.write_reg = e1000_write_phy_reg_gpy;

	ret_val = e1000_get_phy_id(hw);
	/* Verify phy id and set remaining function pointers */
	switch (phy->id) {
	case I225_I_PHY_ID:
		phy->type		= e1000_phy_i225;
		phy->ops.set_d0_lplu_state = e1000_set_d0_lplu_state_i225;
		phy->ops.set_d3_lplu_state = e1000_set_d3_lplu_state_i225;
		/* TODO - complete with GPY PHY information */
		break;
	default:
		ret_val = -E1000_ERR_PHY;
		goto out;
	}

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
	E1000_WRITE_REG(hw, E1000_CTRL, ctrl | E1000_CTRL_DEV_RST);

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

/* e1000_acquire_nvm_i225 - Request for access to EEPROM
 * @hw: pointer to the HW structure
 *
 * Acquire the necessary semaphores for exclusive access to the EEPROM.
 * Set the EEPROM access request bit and wait for EEPROM access grant bit.
 * Return successful if access grant bit set, else clear the request for
 * EEPROM access and return -E1000_ERR_NVM (-1).
 */
STATIC s32 e1000_acquire_nvm_i225(struct e1000_hw *hw)
{
	s32 ret_val;

	DEBUGFUNC("e1000_acquire_nvm_i225");

	ret_val = e1000_acquire_swfw_sync_i225(hw, E1000_SWFW_EEP_SM);

	return ret_val;
}

/* e1000_release_nvm_i225 - Release exclusive access to EEPROM
 * @hw: pointer to the HW structure
 *
 * Stop any current commands to the EEPROM and clear the EEPROM request bit,
 * then release the semaphores acquired.
 */
STATIC void e1000_release_nvm_i225(struct e1000_hw *hw)
{
	DEBUGFUNC("e1000_release_nvm_i225");

	e1000_release_swfw_sync_i225(hw, E1000_SWFW_EEP_SM);
}

/* e1000_acquire_swfw_sync_i225 - Acquire SW/FW semaphore
 * @hw: pointer to the HW structure
 * @mask: specifies which semaphore to acquire
 *
 * Acquire the SW/FW semaphore to access the PHY or NVM.  The mask
 * will also specify which port we're acquiring the lock for.
 */
s32 e1000_acquire_swfw_sync_i225(struct e1000_hw *hw, u16 mask)
{
	u32 swfw_sync;
	u32 swmask = mask;
	u32 fwmask = mask << 16;
	s32 ret_val = E1000_SUCCESS;
	s32 i = 0, timeout = 200; /* FIXME: find real value to use here */

	DEBUGFUNC("e1000_acquire_swfw_sync_i225");

	while (i < timeout) {
		if (e1000_get_hw_semaphore_i225(hw)) {
			ret_val = -E1000_ERR_SWFW_SYNC;
			goto out;
		}

		swfw_sync = E1000_READ_REG(hw, E1000_SW_FW_SYNC);
		if (!(swfw_sync & (fwmask | swmask)))
			break;

		/* Firmware currently using resource (fwmask)
		 * or other software thread using resource (swmask)
		 */
		e1000_put_hw_semaphore_generic(hw);
		msec_delay_irq(5);
		i++;
	}

	if (i == timeout) {
		DEBUGOUT("Driver can't access resource, SW_FW_SYNC timeout.\n");
		ret_val = -E1000_ERR_SWFW_SYNC;
		goto out;
	}

	swfw_sync |= swmask;
	E1000_WRITE_REG(hw, E1000_SW_FW_SYNC, swfw_sync);

	e1000_put_hw_semaphore_generic(hw);

out:
	return ret_val;
}

/* e1000_release_swfw_sync_i225 - Release SW/FW semaphore
 * @hw: pointer to the HW structure
 * @mask: specifies which semaphore to acquire
 *
 * Release the SW/FW semaphore used to access the PHY or NVM.  The mask
 * will also specify which port we're releasing the lock for.
 */
void e1000_release_swfw_sync_i225(struct e1000_hw *hw, u16 mask)
{
	u32 swfw_sync;

	DEBUGFUNC("e1000_release_swfw_sync_i225");

	while (e1000_get_hw_semaphore_i225(hw) != E1000_SUCCESS)
		; /* Empty */

	swfw_sync = E1000_READ_REG(hw, E1000_SW_FW_SYNC);
	swfw_sync &= ~mask;
	E1000_WRITE_REG(hw, E1000_SW_FW_SYNC, swfw_sync);

	e1000_put_hw_semaphore_generic(hw);
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

/* e1000_get_hw_semaphore_i225 - Acquire hardware semaphore
 * @hw: pointer to the HW structure
 *
 * Acquire the HW semaphore to access the PHY or NVM
 */
STATIC s32 e1000_get_hw_semaphore_i225(struct e1000_hw *hw)
{
	u32 swsm;
	s32 timeout = hw->nvm.word_size + 1;
	s32 i = 0;

	DEBUGFUNC("e1000_get_hw_semaphore_i225");

	/* Get the SW semaphore */
	while (i < timeout) {
		swsm = E1000_READ_REG(hw, E1000_SWSM);
		if (!(swsm & E1000_SWSM_SMBI))
			break;

		usec_delay(50);
		i++;
	}

	if (i == timeout) {
		/* In rare circumstances, the SW semaphore may already be held
		 * unintentionally. Clear the semaphore once before giving up.
		 */
		if (hw->dev_spec._82575.clear_semaphore_once) {
			hw->dev_spec._82575.clear_semaphore_once = false;
			e1000_put_hw_semaphore_generic(hw);
			for (i = 0; i < timeout; i++) {
				swsm = E1000_READ_REG(hw, E1000_SWSM);
				if (!(swsm & E1000_SWSM_SMBI))
					break;

				usec_delay(50);
			}
		}

		/* If we do not have the semaphore here, we have to give up. */
		if (i == timeout) {
			DEBUGOUT("Driver can't access device -\n");
			DEBUGOUT("SMBI bit is set.\n");
			return -E1000_ERR_NVM;
		}
	}

	/* Get the FW semaphore. */
	for (i = 0; i < timeout; i++) {
		swsm = E1000_READ_REG(hw, E1000_SWSM);
		E1000_WRITE_REG(hw, E1000_SWSM, swsm | E1000_SWSM_SWESMBI);

		/* Semaphore acquired if bit latched */
		if (E1000_READ_REG(hw, E1000_SWSM) & E1000_SWSM_SWESMBI)
			break;

		usec_delay(50);
	}

	if (i == timeout) {
		/* Release semaphores */
		e1000_put_hw_semaphore_generic(hw);
		DEBUGOUT("Driver can't access the NVM\n");
		return -E1000_ERR_NVM;
	}

	return E1000_SUCCESS;
}

/* e1000_read_nvm_srrd_i225 - Reads Shadow Ram using EERD register
 * @hw: pointer to the HW structure
 * @offset: offset of word in the Shadow Ram to read
 * @words: number of words to read
 * @data: word read from the Shadow Ram
 *
 * Reads a 16 bit word from the Shadow Ram using the EERD register.
 * Uses necessary synchronization semaphores.
 */
s32 e1000_read_nvm_srrd_i225(struct e1000_hw *hw, u16 offset, u16 words,
			     u16 *data)
{
	s32 status = E1000_SUCCESS;
	u16 i, count;

	DEBUGFUNC("e1000_read_nvm_srrd_i225");

	/* We cannot hold synchronization semaphores for too long,
	 * because of forceful takeover procedure. However it is more efficient
	 * to read in bursts than synchronizing access for each word.
	 */
	for (i = 0; i < words; i += E1000_EERD_EEWR_MAX_COUNT) {
		count = (words - i) / E1000_EERD_EEWR_MAX_COUNT > 0 ?
			E1000_EERD_EEWR_MAX_COUNT : (words - i);
		if (hw->nvm.ops.acquire(hw) == E1000_SUCCESS) {
			status = e1000_read_nvm_eerd(hw, offset, count,
						     data + i);
			hw->nvm.ops.release(hw);
		} else {
			status = E1000_ERR_SWFW_SYNC;
		}

		if (status != E1000_SUCCESS)
			break;
	}

	return status;
}

/* e1000_write_nvm_srwr_i225 - Write to Shadow RAM using EEWR
 * @hw: pointer to the HW structure
 * @offset: offset within the Shadow RAM to be written to
 * @words: number of words to write
 * @data: 16 bit word(s) to be written to the Shadow RAM
 *
 * Writes data to Shadow RAM at offset using EEWR register.
 *
 * If e1000_update_nvm_checksum is not called after this function , the
 * data will not be committed to FLASH and also Shadow RAM will most likely
 * contain an invalid checksum.
 *
 * If error code is returned, data and Shadow RAM may be inconsistent - buffer
 * partially written.
 */
s32 e1000_write_nvm_srwr_i225(struct e1000_hw *hw, u16 offset, u16 words,
			      u16 *data)
{
	s32 status = E1000_SUCCESS;
	u16 i, count;

	DEBUGFUNC("e1000_write_nvm_srwr_i225");

	/* We cannot hold synchronization semaphores for too long,
	 * because of forceful takeover procedure. However it is more efficient
	 * to write in bursts than synchronizing access for each word.
	 */
	for (i = 0; i < words; i += E1000_EERD_EEWR_MAX_COUNT) {
		count = (words - i) / E1000_EERD_EEWR_MAX_COUNT > 0 ?
			E1000_EERD_EEWR_MAX_COUNT : (words - i);
		if (hw->nvm.ops.acquire(hw) == E1000_SUCCESS) {
			status = __e1000_write_nvm_srwr(hw, offset, count,
							data + i);
			hw->nvm.ops.release(hw);
		} else {
			status = E1000_ERR_SWFW_SYNC;
		}

		if (status != E1000_SUCCESS)
			break;
	}

	return status;
}

/* __e1000_write_nvm_srwr - Write to Shadow Ram using EEWR
 * @hw: pointer to the HW structure
 * @offset: offset within the Shadow Ram to be written to
 * @words: number of words to write
 * @data: 16 bit word(s) to be written to the Shadow Ram
 *
 * Writes data to Shadow Ram at offset using EEWR register.
 *
 * If e1000_update_nvm_checksum is not called after this function , the
 * Shadow Ram will most likely contain an invalid checksum.
 */
STATIC s32 __e1000_write_nvm_srwr(struct e1000_hw *hw, u16 offset, u16 words,
				  u16 *data)
{
	struct e1000_nvm_info *nvm = &hw->nvm;
	u32 i, k, eewr = 0;
	u32 attempts = 100000;
	s32 ret_val = E1000_SUCCESS;

	DEBUGFUNC("__e1000_write_nvm_srwr");

	/* A check for invalid values:  offset too large, too many words,
	 * too many words for the offset, and not enough words.
	 */
	if ((offset >= nvm->word_size) || (words > (nvm->word_size - offset)) ||
	    (words == 0)) {
		DEBUGOUT("nvm parameter(s) out of bounds\n");
		ret_val = -E1000_ERR_NVM;
		goto out;
	}

	for (i = 0; i < words; i++) {
		eewr = ((offset + i) << E1000_NVM_RW_ADDR_SHIFT) |
			(data[i] << E1000_NVM_RW_REG_DATA) |
			E1000_NVM_RW_REG_START;

		E1000_WRITE_REG(hw, E1000_SRWR, eewr);

		for (k = 0; k < attempts; k++) {
			if (E1000_NVM_RW_REG_DONE &
			    E1000_READ_REG(hw, E1000_SRWR)) {
				ret_val = E1000_SUCCESS;
				break;
			}
			usec_delay(5);
		}

		if (ret_val != E1000_SUCCESS) {
			DEBUGOUT("Shadow RAM write EEWR timed out\n");
			break;
		}
	}

out:
	return ret_val;
}

/* e1000_read_invm_word_i225 - Reads OTP
 * @hw: pointer to the HW structure
 * @address: the word address (aka eeprom offset) to read
 * @data: pointer to the data read
 *
 * Reads 16-bit words from the OTP. Return error when the word is not
 * stored in OTP.
 */
STATIC s32 e1000_read_invm_word_i225(struct e1000_hw *hw, u8 address, u16 *data)
{
	s32 status = -E1000_ERR_INVM_VALUE_NOT_FOUND;
	u32 invm_dword;
	u16 i;
	u8 record_type, word_address;

	DEBUGFUNC("e1000_read_invm_word_i225");

	for (i = 0; i < E1000_INVM_SIZE; i++) {
		invm_dword = E1000_READ_REG(hw, E1000_INVM_DATA_REG(i));
		/* Get record type */
		record_type = INVM_DWORD_TO_RECORD_TYPE(invm_dword);
		if (record_type == e1000_invm_unitialized_structure)
			break;
		if (record_type == e1000_invm_csr_autoload_structure)
			i += E1000_INVM_CSR_AUTOLOAD_DATA_SIZE_IN_DWORDS;
		if (record_type == e1000_invm_rsa_key_sha256_structure)
			i += E1000_INVM_RSA_KEY_SHA256_DATA_SIZE_IN_DWORDS;
		if (record_type == e1000_invm_word_autoload_structure) {
			word_address = INVM_DWORD_TO_WORD_ADDRESS(invm_dword);
			if (word_address == address) {
				*data = INVM_DWORD_TO_WORD_DATA(invm_dword);
				DEBUGOUT2("Read INVM Word 0x%02x = %x",
					  address, *data);
				status = E1000_SUCCESS;
				break;
			}
		}
	}
	if (status != E1000_SUCCESS)
		DEBUGOUT1("Requested word 0x%02x not found in OTP\n", address);
	return status;
}

#if defined(NVM_VERSION_SUPPORT) || defined(QV_RELEASE)
/* e1000_read_invm_version_i225 - Reads iNVM version and image type
 * @hw: pointer to the HW structure
 * @invm_ver: version structure for the version read
 *
 * Reads iNVM version and image type.
 */
s32 e1000_read_invm_version_i225(struct e1000_hw *hw,
				 struct e1000_fw_version *invm_ver)
{
	u32 *record = NULL;
	u32 *next_record = NULL;
	u32 i = 0;
	u32 invm_dword = 0;
	u32 invm_blocks = E1000_INVM_SIZE - (E1000_INVM_ULT_BYTES_SIZE /
					     E1000_INVM_RECORD_SIZE_IN_BYTES);
	u32 buffer[E1000_INVM_SIZE];
	s32 status = -E1000_ERR_INVM_VALUE_NOT_FOUND;
	u16 version = 0;

	DEBUGFUNC("e1000_read_invm_version_i225");

	/* Read iNVM memory */
	for (i = 0; i < E1000_INVM_SIZE; i++) {
		invm_dword = E1000_READ_REG(hw, E1000_INVM_DATA_REG(i));
		buffer[i] = invm_dword;
	}

	/* Read version number */
	for (i = 1; i < invm_blocks; i++) {
		record = &buffer[invm_blocks - i];
		next_record = &buffer[invm_blocks - i + 1];

		/* Check if we have first version location used */
		if ((i == 1) && ((*record & E1000_INVM_VER_FIELD_ONE) == 0)) {
			version = 0;
			status = E1000_SUCCESS;
			break;
		}
		/* Check if we have second version location used */
		else if ((i == 1) &&
			 ((*record & E1000_INVM_VER_FIELD_TWO) == 0)) {
			version = (*record & E1000_INVM_VER_FIELD_ONE) >> 3;
			status = E1000_SUCCESS;
			break;
		}
		/* Check if we have odd version location
		 * used and it is the last one used
		 */
		else if ((((*record & E1000_INVM_VER_FIELD_ONE) == 0) &&
			  ((*record & 0x3) == 0)) || (((*record & 0x3) != 0) &&
			   (i != 1))) {
			version = (*next_record & E1000_INVM_VER_FIELD_TWO)
				  >> 13;
			status = E1000_SUCCESS;
			break;
		}
		/* Check if we have even version location
		 * used and it is the last one used
		 */
		else if (((*record & E1000_INVM_VER_FIELD_TWO) == 0) &&
			 ((*record & 0x3) == 0)) {
			version = (*record & E1000_INVM_VER_FIELD_ONE) >> 3;
			status = E1000_SUCCESS;
			break;
		}
	}

	if (status == E1000_SUCCESS) {
		invm_ver->invm_major = (version & E1000_INVM_MAJOR_MASK)
					>> E1000_INVM_MAJOR_SHIFT;
		invm_ver->invm_minor = version & E1000_INVM_MINOR_MASK;
	}
	/* Read Image Type */
	for (i = 1; i < invm_blocks; i++) {
		record = &buffer[invm_blocks - i];
		next_record = &buffer[invm_blocks - i + 1];

		/* Check if we have image type in first location used */
		if ((i == 1) && ((*record & E1000_INVM_IMGTYPE_FIELD) == 0)) {
			invm_ver->invm_img_type = 0;
			status = E1000_SUCCESS;
			break;
		}
		/* Check if we have image type in first location used */
		else if ((((*record & 0x3) == 0) &&
			  ((*record & E1000_INVM_IMGTYPE_FIELD) == 0)) ||
			    ((((*record & 0x3) != 0) && (i != 1)))) {
			invm_ver->invm_img_type =
				(*next_record & E1000_INVM_IMGTYPE_FIELD) >> 23;
			status = E1000_SUCCESS;
			break;
		}
	}
	return status;
}

#endif /* NVM_VERSION_SUPPORT or QV_RELEASE */
/* e1000_validate_nvm_checksum_i225 - Validate EEPROM checksum
 * @hw: pointer to the HW structure
 *
 * Calculates the EEPROM checksum by reading/adding each word of the EEPROM
 * and then verifies that the sum of the EEPROM is equal to 0xBABA.
 */
s32 e1000_validate_nvm_checksum_i225(struct e1000_hw *hw)
{
	s32 status = E1000_SUCCESS;
	s32 (*read_op_ptr)(struct e1000_hw *, u16, u16, u16 *);

	DEBUGFUNC("e1000_validate_nvm_checksum_i225");

	if (hw->nvm.ops.acquire(hw) == E1000_SUCCESS) {
		/* Replace the read function with semaphore grabbing with
		 * the one that skips this for a while.
		 * We have semaphore taken already here.
		 */
		read_op_ptr = hw->nvm.ops.read;
		hw->nvm.ops.read = e1000_read_nvm_eerd;

		status = e1000_validate_nvm_checksum_generic(hw);

		/* Revert original read operation. */
		hw->nvm.ops.read = read_op_ptr;

		hw->nvm.ops.release(hw);
	} else {
		status = E1000_ERR_SWFW_SYNC;
	}

	return status;
}

/* e1000_update_nvm_checksum_i225 - Update EEPROM checksum
 * @hw: pointer to the HW structure
 *
 * Updates the EEPROM checksum by reading/adding each word of the EEPROM
 * up to the checksum.  Then calculates the EEPROM checksum and writes the
 * value to the EEPROM. Next commit EEPROM data onto the Flash.
 */
s32 e1000_update_nvm_checksum_i225(struct e1000_hw *hw)
{
	s32 ret_val;
	u16 checksum = 0;
	u16 i, nvm_data;

	DEBUGFUNC("e1000_update_nvm_checksum_i225");

	/* Read the first word from the EEPROM. If this times out or fails, do
	 * not continue or we could be in for a very long wait while every
	 * EEPROM read fails
	 */
	ret_val = e1000_read_nvm_eerd(hw, 0, 1, &nvm_data);
	if (ret_val != E1000_SUCCESS) {
		DEBUGOUT("EEPROM read failed\n");
		goto out;
	}

	if (hw->nvm.ops.acquire(hw) == E1000_SUCCESS) {
		/* Do not use hw->nvm.ops.write, hw->nvm.ops.read
		 * because we do not want to take the synchronization
		 * semaphores twice here.
		 */

		for (i = 0; i < NVM_CHECKSUM_REG; i++) {
			ret_val = e1000_read_nvm_eerd(hw, i, 1, &nvm_data);
			if (ret_val) {
				hw->nvm.ops.release(hw);
				DEBUGOUT("NVM Read Error while updating\n");
				DEBUGOUT("checksum.\n");
				goto out;
			}
			checksum += nvm_data;
		}
		checksum = (u16)NVM_SUM - checksum;
		ret_val = __e1000_write_nvm_srwr(hw, NVM_CHECKSUM_REG, 1,
						 &checksum);
		if (ret_val != E1000_SUCCESS) {
			hw->nvm.ops.release(hw);
			DEBUGOUT("NVM Write Error while updating checksum.\n");
			goto out;
		}

		hw->nvm.ops.release(hw);

		ret_val = e1000_update_flash_i225(hw);
	} else {
		ret_val = E1000_ERR_SWFW_SYNC;
	}
out:
	return ret_val;
}

/* e1000_get_flash_presence_i225 - Check if flash device is detected.
 * @hw: pointer to the HW structure
 */
bool e1000_get_flash_presence_i225(struct e1000_hw *hw)
{
	u32 eec = 0;
	bool ret_val = false;

	DEBUGFUNC("e1000_get_flash_presence_i225");

	eec = E1000_READ_REG(hw, E1000_EECD);

	if (eec & E1000_EECD_FLASH_DETECTED_I225)
		ret_val = true;

	return ret_val;
}

/* e1000_update_flash_i225 - Commit EEPROM to the flash
 * @hw: pointer to the HW structure
 */
s32 e1000_update_flash_i225(struct e1000_hw *hw)
{
	s32 ret_val;
	u32 flup;

	DEBUGFUNC("e1000_update_flash_i225");

	ret_val = e1000_pool_flash_update_done_i225(hw);
	if (ret_val == -E1000_ERR_NVM) {
		DEBUGOUT("Flash update time out\n");
		goto out;
	}

	flup = E1000_READ_REG(hw, E1000_EECD) | E1000_EECD_FLUPD_I225;
	E1000_WRITE_REG(hw, E1000_EECD, flup);

	ret_val = e1000_pool_flash_update_done_i225(hw);
	if (ret_val == E1000_SUCCESS)
		DEBUGOUT("Flash update complete\n");
	else
		DEBUGOUT("Flash update time out\n");

out:
	return ret_val;
}

/* e1000_pool_flash_update_done_i225 - Pool FLUDONE status.
 * @hw: pointer to the HW structure
 */
s32 e1000_pool_flash_update_done_i225(struct e1000_hw *hw)
{
	s32 ret_val = -E1000_ERR_NVM;
	u32 i, reg;

	DEBUGFUNC("e1000_pool_flash_update_done_i225");

	for (i = 0; i < E1000_FLUDONE_ATTEMPTS; i++) {
		reg = E1000_READ_REG(hw, E1000_EECD);
		if (reg & E1000_EECD_FLUDONE_I225) {
			ret_val = E1000_SUCCESS;
			break;
		}
		usec_delay(5);
	}

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
	e1000_init_nvm_ops_generic(hw);
	hw->mac.ops.init_params = e1000_init_mac_params_i225;
	hw->nvm.ops.init_params = e1000_init_nvm_params_i225;
	hw->phy.ops.init_params = e1000_init_phy_params_i225;
}

/* e1000_valid_led_default_i225 - Verify a valid default LED config
 * @hw: pointer to the HW structure
 * @data: pointer to the NVM (EEPROM)
 *
 * Read the EEPROM for the current default LED configuration.  If the
 * LED configuration is not valid, set to a valid LED configuration.
 */
STATIC s32 e1000_valid_led_default_i225(struct e1000_hw *hw, u16 *data)
{
	s32 ret_val;

	DEBUGFUNC("e1000_valid_led_default_i225");

	ret_val = hw->nvm.ops.read(hw, NVM_ID_LED_SETTINGS, 1, data);
	if (ret_val) {
		DEBUGOUT("NVM Read Error\n");
		goto out;
	}

	if (*data == ID_LED_RESERVED_0000 || *data == ID_LED_RESERVED_FFFF) {
		switch (hw->phy.media_type) {
		case e1000_media_type_internal_serdes:
			*data = ID_LED_DEFAULT_I225_SERDES;
			break;
		case e1000_media_type_copper:
		default:
			*data = ID_LED_DEFAULT_I225;
			break;
		}
	}
#ifndef QV_RELEASE
out:
#endif /* QV_RELEASE */
	return ret_val;
}

/* e1000_pll_workaround_i225
 * @hw: pointer to the HW structure
 *
 * Works around an errata in the PLL circuit where it occasionally
 * provides the wrong clock frequency after power up.
 */
STATIC s32 e1000_pll_workaround_i225(struct e1000_hw *hw)
{
	s32 ret_val;
	u32 wuc, mdicnfg, ctrl, ctrl_ext, reg_val;
	u16 nvm_word, phy_word, pci_word, tmp_nvm;
	int i;

	/* Get PHY semaphore */
	hw->phy.ops.acquire(hw);
	/* Get and set needed register values */
	wuc = E1000_READ_REG(hw, E1000_WUC);
	mdicnfg = E1000_READ_REG(hw, E1000_MDICNFG);
	reg_val = mdicnfg & ~E1000_MDICNFG_EXT_MDIO;
	E1000_WRITE_REG(hw, E1000_MDICNFG, reg_val);

	/* Get data from NVM, or set default */
	ret_val = e1000_read_invm_word_i225(hw, E1000_INVM_AUTOLOAD,
					    &nvm_word);
	if (ret_val != E1000_SUCCESS)
		nvm_word = E1000_INVM_DEFAULT_AL;
	tmp_nvm = nvm_word | E1000_INVM_PLL_WO_VAL;
	for (i = 0; i < E1000_MAX_PLL_TRIES; i++) {
		/* check current state directly from internal PHY */
		e1000_write_phy_reg_mdic(hw, GS40G_PAGE_SELECT, 0xFC);
		usec_delay(20);
		e1000_read_phy_reg_mdic(hw, E1000_PHY_PLL_FREQ_REG, &phy_word);
		usec_delay(20);
		e1000_write_phy_reg_mdic(hw, GS40G_PAGE_SELECT, 0);
		if ((phy_word & E1000_PHY_PLL_UNCONF)
		    != E1000_PHY_PLL_UNCONF) {
			ret_val = E1000_SUCCESS;
		} else {
			ret_val = -E1000_ERR_PHY;
		}
		/* directly reset the internal PHY */
		ctrl = E1000_READ_REG(hw, E1000_CTRL);
		E1000_WRITE_REG(hw, E1000_CTRL, ctrl | E1000_CTRL_PHY_RST);

		ctrl_ext = E1000_READ_REG(hw, E1000_CTRL_EXT);
		ctrl_ext |= (E1000_CTRL_EXT_PHYPDEN | E1000_CTRL_EXT_SDLPE);
		E1000_WRITE_REG(hw, E1000_CTRL_EXT, ctrl_ext);

		E1000_WRITE_REG(hw, E1000_WUC, 0);
		reg_val = (E1000_INVM_AUTOLOAD << 4) | (tmp_nvm << 16);
		E1000_WRITE_REG(hw, E1000_EEARBC_I225, reg_val);

		e1000_read_pci_cfg(hw, E1000_PCI_PMCSR, &pci_word);
		pci_word |= E1000_PCI_PMCSR_D3;
		e1000_write_pci_cfg(hw, E1000_PCI_PMCSR, &pci_word);
		msec_delay(1);
		pci_word &= ~E1000_PCI_PMCSR_D3;
		e1000_write_pci_cfg(hw, E1000_PCI_PMCSR, &pci_word);
		reg_val = (E1000_INVM_AUTOLOAD << 4) | (nvm_word << 16);
		E1000_WRITE_REG(hw, E1000_EEARBC_I225, reg_val);

		/* restore WUC register */
		E1000_WRITE_REG(hw, E1000_WUC, wuc);
	}
	/* restore MDICNFG setting */
	E1000_WRITE_REG(hw, E1000_MDICNFG, mdicnfg);
	/* Release PHY semaphore */
	hw->phy.ops.release(hw);
	return ret_val;
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
	if ((hw->mac.type >= e1000_i225) &&
	    !(e1000_get_flash_presence_i225(hw))) {
		ret_val = e1000_pll_workaround_i225(hw);
		if (ret_val != E1000_SUCCESS)
			return ret_val;
	}
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
 *  e1000_set_eee_i225 - Enable/disable EEE support
 *  @hw: pointer to the HW structure
 *  @adv2p5G: boolean flag enabling 2.5G EEE advertisement
 *  @adv1G: boolean flag enabling 1G EEE advertisement
 *  @adv100M: boolean flag enabling 100M EEE advertisement
 *
 *  Enable/disable EEE based on setting in dev_spec structure.
 *
 **/
s32 e1000_set_eee_i225(struct e1000_hw *hw, bool adv2p5G, bool adv1G,
		       bool adv100M)
{
	u32 ipcnfg, eeer;

	DEBUGFUNC("e1000_set_eee_i225");

	if (hw->mac.type != e1000_i225 ||
	    hw->phy.media_type != e1000_media_type_copper)
		goto out;
	ipcnfg = E1000_READ_REG(hw, E1000_IPCNFG);
	eeer = E1000_READ_REG(hw, E1000_EEER);

	/* enable or disable per user setting */
	if (!(hw->dev_spec._82575.eee_disable)) {
		u32 eee_su = E1000_READ_REG(hw, E1000_EEE_SU);

		if (adv100M)
			ipcnfg |= E1000_IPCNFG_EEE_100M_AN;
		else
			ipcnfg &= ~E1000_IPCNFG_EEE_100M_AN;

		if (adv1G)
			ipcnfg |= E1000_IPCNFG_EEE_1G_AN;
		else
			ipcnfg &= ~E1000_IPCNFG_EEE_1G_AN;

		if (adv2p5G)
			ipcnfg |= E1000_IPCNFG_EEE_2_5G_AN;
		else
			ipcnfg &= ~E1000_IPCNFG_EEE_2_5G_AN;

		eeer |= (E1000_EEER_TX_LPI_EN | E1000_EEER_RX_LPI_EN |
			E1000_EEER_LPI_FC);

#ifndef EXTERNAL_RELEASE
		/*
		 * This bit is supposed to be cleared by the NVM. However, older
		 * NVMs may not have done this (Springville HW HSD #359296).
		 */
#endif /* EXTERNAL_RELEASE */
		/* This bit should not be set in normal operation. */
		if (eee_su & E1000_EEE_SU_LPI_CLK_STP)
			DEBUGOUT("LPI Clock Stop Bit should not be set!\n");
	} else {
		ipcnfg &= ~(E1000_IPCNFG_EEE_2_5G_AN | E1000_IPCNFG_EEE_1G_AN |
			E1000_IPCNFG_EEE_100M_AN);
		eeer &= ~(E1000_EEER_TX_LPI_EN | E1000_EEER_RX_LPI_EN |
			E1000_EEER_LPI_FC);
	}
	E1000_WRITE_REG(hw, E1000_IPCNFG, ipcnfg);
	E1000_WRITE_REG(hw, E1000_EEER, eeer);
	E1000_READ_REG(hw, E1000_IPCNFG);
	E1000_READ_REG(hw, E1000_EEER);
out:

	return E1000_SUCCESS;
}

#ifndef NO_API_SUPPORT
#include "e1000_api.h"
#else
#include "e1000_hw.h"
#endif /* NO_API_SUPPORT */
#ifndef EXTERNAL_RELEASE
#ifdef WPP_TRACING_ENABLED
#include <e1000_i225.tmh>
#endif /* WPP_TRACING_ENABLED */
#endif /* EXTERNAL_RELEASE */

STATIC s32 e1000_acquire_nvm_i225(struct e1000_hw *hw);
STATIC void e1000_release_nvm_i225(struct e1000_hw *hw);
STATIC s32 e1000_get_hw_semaphore_i225(struct e1000_hw *hw);
#ifndef QV_RELEASE
STATIC s32 __e1000_write_nvm_srwr(struct e1000_hw *hw, u16 offset, u16 words,
				  u16 *data);
#endif /* QV_RELEASE */
STATIC s32 e1000_pool_flash_update_done_i225(struct e1000_hw *hw);
STATIC s32 e1000_valid_led_default_i225(struct e1000_hw *hw, u16 *data);

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

/* e1000_read_invm_i225 - Read invm wrapper function for I225
 * @hw: pointer to the HW structure
 * @address: the word address (aka eeprom offset) to read
 * @data: pointer to the data read
 *
 * Wrapper function to return data formerly found in the NVM.
 */
STATIC s32 e1000_read_invm_i225(struct e1000_hw *hw, u16 offset,
				u16 E1000_UNUSEDARG words, u16 *data)
{
	s32 ret_val = E1000_SUCCESS;

	UNREFERENCED_1PARAMETER(words);

	DEBUGFUNC("e1000_read_invm_i225");

	/* Only the MAC addr is required to be present in the iNVM */
	switch (offset) {
	case NVM_MAC_ADDR:
		ret_val = e1000_read_invm_word_i225(hw, (u8)offset, &data[0]);
		ret_val |= e1000_read_invm_word_i225(hw, (u8)offset + 1,
						     &data[1]);
		ret_val |= e1000_read_invm_word_i225(hw, (u8)offset + 2,
						     &data[2]);
		if (ret_val != E1000_SUCCESS)
			DEBUGOUT("MAC Addr not found in iNVM\n");
		break;
	case NVM_INIT_CTRL_2:
		ret_val = e1000_read_invm_word_i225(hw, (u8)offset, data);
		if (ret_val != E1000_SUCCESS) {
			*data = NVM_INIT_CTRL_2_DEFAULT_I225;
			ret_val = E1000_SUCCESS;
		}
		break;
	case NVM_INIT_CTRL_4:
		ret_val = e1000_read_invm_word_i225(hw, (u8)offset, data);
		if (ret_val != E1000_SUCCESS) {
			*data = NVM_INIT_CTRL_4_DEFAULT_I225;
			ret_val = E1000_SUCCESS;
		}
		break;
	case NVM_LED_1_CFG:
		ret_val = e1000_read_invm_word_i225(hw, (u8)offset, data);
		if (ret_val != E1000_SUCCESS) {
			*data = NVM_LED_1_CFG_DEFAULT_I225;
			ret_val = E1000_SUCCESS;
		}
		break;
	case NVM_LED_0_2_CFG:
		ret_val = e1000_read_invm_word_i225(hw, (u8)offset, data);
		if (ret_val != E1000_SUCCESS) {
			*data = NVM_LED_0_2_CFG_DEFAULT_I225;
			ret_val = E1000_SUCCESS;
		}
		break;
	case NVM_ID_LED_SETTINGS:
		ret_val = e1000_read_invm_word_i225(hw, (u8)offset, data);
		if (ret_val != E1000_SUCCESS) {
			*data = ID_LED_RESERVED_FFFF;
			ret_val = E1000_SUCCESS;
		}
		break;
	case NVM_SUB_DEV_ID:
		*data = hw->subsystem_device_id;
		break;
	case NVM_SUB_VEN_ID:
		*data = hw->subsystem_vendor_id;
		break;
	case NVM_DEV_ID:
		*data = hw->device_id;
		break;
	case NVM_VEN_ID:
		*data = hw->vendor_id;
		break;
	default:
		DEBUGOUT1("NVM word 0x%02x is not mapped.\n", offset);
		*data = NVM_RESERVED_WORD;
		break;
	}
	return ret_val;
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

/* e1000_init_nvm_params_i225 - Initialize i225 NVM function pointers
 * @hw: pointer to the HW structure
 *
 * Initialize the i225/i211 NVM parameters and function pointers.
 */
STATIC s32 e1000_init_nvm_params_i225(struct e1000_hw *hw)
{
	s32 ret_val;
	struct e1000_nvm_info *nvm = &hw->nvm;

	DEBUGFUNC("e1000_init_nvm_params_i225");

	ret_val = e1000_init_nvm_params_82575(hw);
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
		nvm->ops.read     = e1000_read_invm_i225;
#ifndef NO_NULL_OPS_SUPPORT
		nvm->ops.write    = e1000_null_write_nvm;
		nvm->ops.validate = e1000_null_ops_generic;
		nvm->ops.update   = e1000_null_ops_generic;
#else
		nvm->ops.write    = NULL;
		nvm->ops.validate = NULL;
		nvm->ops.update   = NULL;
#endif /* NO_NULL_OPS_SUPPORT */
	}
	return ret_val;
}

#ifdef I225_LTR_SUPPORT
/* e1000_set_ltr_i225 - Set Latency Tolerance Reporting thresholds.
 * @hw: pointer to the HW structure
 * @link: bool indicating link status
 *
 * Set the LTR thresholds based on the link speed (Mbps), EEE, and DMAC
 * settings, otherwise specify that there is no LTR requirement.
 */
STATIC s32 e1000_set_ltr_i225(struct e1000_hw *hw, bool link)
{
	u16 speed, duplex;
	u32 tw_system, ltrc, ltrv, ltr_min, ltr_max, scale_min, scale_max;
	s32 size;

	DEBUGFUNC("e1000_set_ltr_i225");

	/* If we do not have link, LTR thresholds are zero. */
	if (link) {
		hw->mac.ops.get_link_up_info(hw, &speed, &duplex);

		/* Check if using copper interface with EEE enabled or if the
		 * link speed is 10 Mbps.
		 */
		if ((hw->phy.media_type == e1000_media_type_copper) &&
		    !(hw->dev_spec._82575.eee_disable) &&
		     (speed != SPEED_10)) {
			/* EEE enabled, so send LTRMAX threshold. */
			ltrc = E1000_READ_REG(hw, E1000_LTRC) |
				E1000_LTRC_EEEMS_EN;
			E1000_WRITE_REG(hw, E1000_LTRC, ltrc);

			/* Calculate tw_system (nsec). */
			if (speed == SPEED_100) {
				tw_system = ((E1000_READ_REG(hw, E1000_EEE_SU) &
					     E1000_TW_SYSTEM_100_MASK) >>
					     E1000_TW_SYSTEM_100_SHIFT) * 500;
			} else {
				tw_system = (E1000_READ_REG(hw, E1000_EEE_SU) &
					     E1000_TW_SYSTEM_1000_MASK) * 500;
				}
		} else {
			tw_system = 0;
			}

		/* Get the Rx packet buffer size. */
		size = E1000_READ_REG(hw, E1000_RXPBS) &
			E1000_RXPBS_SIZE_I225_MASK;

		/* Calculations vary based on DMAC settings. */
		if (E1000_READ_REG(hw, E1000_DMACR) & E1000_DMACR_DMAC_EN) {
			size -= (E1000_READ_REG(hw, E1000_DMACR) &
				 E1000_DMACR_DMACTHR_MASK) >>
				 E1000_DMACR_DMACTHR_SHIFT;
			/* Convert size to bits. */
			size *= 1024 * 8;
		} else {
			/* Convert size to bytes, subtract the MTU, and then
			 * convert the size to bits.
			 */
			size *= 1024;
			size -= hw->dev_spec._82575.mtu;
			size *= 8;
		}

		if (size < 0) {
			DEBUGOUT1("Invalid effective Rx buffer size %d\n",
				  size);
			return -E1000_ERR_CONFIG;
		}

		/* Calculate the thresholds. Since speed is in Mbps, simplify
		 * the calculation by multiplying size/speed by 1000 for result
		 * to be in nsec before dividing by the scale in nsec. Set the
		 * scale such that the LTR threshold fits in the register.
		 */
		ltr_min = (1000 * size) / speed;
		ltr_max = ltr_min + tw_system;
		scale_min = (ltr_min / 1024) < 1024 ? E1000_LTRMINV_SCALE_1024 :
			    E1000_LTRMINV_SCALE_32768;
		scale_max = (ltr_max / 1024) < 1024 ? E1000_LTRMAXV_SCALE_1024 :
			    E1000_LTRMAXV_SCALE_32768;
		ltr_min /= scale_min == E1000_LTRMINV_SCALE_1024 ? 1024 : 32768;
		ltr_max /= scale_max == E1000_LTRMAXV_SCALE_1024 ? 1024 : 32768;

		/* Only write the LTR thresholds if they differ from before. */
		ltrv = E1000_READ_REG(hw, E1000_LTRMINV);
		if (ltr_min != (ltrv & E1000_LTRMINV_LTRV_MASK)) {
			ltrv = E1000_LTRMINV_LSNP_REQ | ltr_min |
			      (scale_min << E1000_LTRMINV_SCALE_SHIFT);
			E1000_WRITE_REG(hw, E1000_LTRMINV, ltrv);
		}

		ltrv = E1000_READ_REG(hw, E1000_LTRMAXV);
		if (ltr_max != (ltrv & E1000_LTRMAXV_LTRV_MASK)) {
			ltrv = E1000_LTRMAXV_LSNP_REQ | ltr_max |
			      (scale_min << E1000_LTRMAXV_SCALE_SHIFT);
			E1000_WRITE_REG(hw, E1000_LTRMAXV, ltrv);
		}
	}

	return E1000_SUCCESS;
}

/* e1000_check_for_link_i225 - Check for link
 * @hw: pointer to the HW structure
 *
 * Checks to see of the link status of the hardware has changed.  If a
 * change in link status has been detected, then we read the PHY registers
 * to get the current speed/duplex if link exists.
 */
s32 e1000_check_for_link_i225(struct e1000_hw *hw)
{
	struct e1000_mac_info *mac = &hw->mac;
	s32 ret_val;
	bool link = false;

	DEBUGFUNC("e1000_check_for_link_i225");

	if (hw->phy.media_type != e1000_media_type_copper) {
		u16 speed, duplex;

		ret_val = e1000_get_pcs_speed_and_duplex_82575(hw, &speed,
							       &duplex);
		/* Use this flag to determine if link needs to be checked or
		 * not.  If we have link clear the flag so that we do not
		 * continue to check for link.
		 */
		hw->mac.get_link_status = !hw->mac.serdes_has_link;

		link = hw->mac.serdes_has_link;
	} else {
		/* We only want to go out to the PHY registers to see if
		 * Auto-Neg has completed and/or if our link status has
		 * changed.  The get_link_status flag is set upon receiving
		 * a Link Status Change or Rx Sequence Error interrupt.
		 */
		if (!mac->get_link_status) {
			ret_val = E1000_SUCCESS;
			goto out;
		}

		/* First we want to see if the MII Status Register reports
		 * link.  If so, then we want to get the current speed/duplex
		 * of the PHY.
		 */
		ret_val = e1000_phy_has_link_generic(hw, 1, 0, &link);
		if (ret_val)
			goto out;

		if (!link)
			goto out; /* No link detected */

		mac->get_link_status = false;

		/* Check if there was DownShift, must be checked
		 * immediately after link-up
		 */
		e1000_check_downshift_generic(hw);

		/* If we are forcing speed/duplex, then we simply return since
		 * we have already determined whether we have link or not.
		 */
		if (!mac->autoneg) {
			ret_val = -E1000_ERR_CONFIG;
			goto out;
		}

		/* Auto-Neg is enabled.  Auto Speed Detection takes care
		 * of MAC speed/duplex configuration.  So we only need to
		 * configure Collision Distance in the MAC.
		 */
		mac->ops.config_collision_dist(hw);

		/* Configure Flow Control now that Auto-Neg has completed.
		 * First, we need to restore the desired flow control
		 * settings because we may have had to re-autoneg with a
		 * different link partner.
		 */
		ret_val = e1000_config_fc_after_link_up_generic(hw);
		if (ret_val)
			DEBUGOUT("Error configuring flow control\n");
	}

out:
	/* Now that we are aware of our link settings, we can set the LTR
	 * thresholds.
	 */
	ret_val = e1000_set_ltr_i225(hw, link);

	return ret_val;
}

#endif /* I225_LTR_SUPPORT */
/* e1000_init_function_pointers_i225 - Init func ptrs.
 * @hw: pointer to the HW structure
 *
 * Called to initialize all function pointers and parameters.
 */
void e1000_init_function_pointers_i225(struct e1000_hw *hw)
{
	e1000_init_function_pointers_82575(hw);
	hw->nvm.ops.init_params = e1000_init_nvm_params_i225;
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
	ret_val = e1000_init_hw_82575(hw);
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

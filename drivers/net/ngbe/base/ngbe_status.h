/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2020 Beijing WangXun Technology Co., Ltd.
 * Copyright(c) 2010-2017 Intel Corporation
 */

#ifndef _NGBE_STATUS_H_
#define _NGBE_STATUS_H_

/* Error Codes:
 * common error
 * module error(simple)
 * module error(detailed)
 *
 * (-256, 256): reserved for non-ngbe defined error code
 */
#define TERR_BASE (0x100)
enum ngbe_error {
	TERR_NULL = TERR_BASE,
	TERR_ANY,
	TERR_NOSUPP,
	TERR_NOIMPL,
	TERR_NOMEM,
	TERR_NOSPACE,
	TERR_NOENTRY,
	TERR_CONFIG,
	TERR_ARGS,
	TERR_PARAM,
	TERR_INVALID,
	TERR_TIMEOUT,
	TERR_VERSION,
	TERR_REGISTER,
	TERR_FEATURE,
	TERR_RESET,
	TERR_AUTONEG,
	TERR_MBX,
	TERR_I2C,
	TERR_FC,
	TERR_FLASH,
	TERR_DEVICE,
	TERR_HOSTIF,
	TERR_SRAM,
	TERR_EEPROM,
	TERR_EEPROM_CHECKSUM,
	TERR_EEPROM_PROTECT,
	TERR_EEPROM_VERSION,
	TERR_MAC,
	TERR_MAC_ADDR,
	TERR_SFP,
	TERR_SFP_INITSEQ,
	TERR_SFP_PRESENT,
	TERR_SFP_SUPPORT,
	TERR_SFP_SETUP,
	TERR_PHY,
	TERR_PHY_ADDR,
	TERR_PHY_INIT,
	TERR_FDIR_CMD,
	TERR_FDIR_REINIT,
	TERR_SWFW_SYNC,
	TERR_SWFW_COMMAND,
	TERR_FC_CFG,
	TERR_FC_NEGO,
	TERR_LINK_SETUP,
	TERR_PCIE_PENDING,
	TERR_PBA_SECTION,
	TERR_OVERTEMP,
	TERR_UNDERTEMP,
	TERR_XPCS_POWERUP,
};

/* WARNING: just for legacy compatibility */
#define NGBE_NOT_IMPLEMENTED 0x7FFFFFFF
#define NGBE_ERR_OPS_DUMMY   0x3FFFFFFF

/* Error Codes */
#define NGBE_ERR_EEPROM				-(TERR_BASE + 1)
#define NGBE_ERR_EEPROM_CHECKSUM		-(TERR_BASE + 2)
#define NGBE_ERR_PHY				-(TERR_BASE + 3)
#define NGBE_ERR_CONFIG				-(TERR_BASE + 4)
#define NGBE_ERR_PARAM				-(TERR_BASE + 5)
#define NGBE_ERR_MAC_TYPE			-(TERR_BASE + 6)
#define NGBE_ERR_UNKNOWN_PHY			-(TERR_BASE + 7)
#define NGBE_ERR_LINK_SETUP			-(TERR_BASE + 8)
#define NGBE_ERR_ADAPTER_STOPPED		-(TERR_BASE + 9)
#define NGBE_ERR_INVALID_MAC_ADDR		-(TERR_BASE + 10)
#define NGBE_ERR_DEVICE_NOT_SUPPORTED		-(TERR_BASE + 11)
#define NGBE_ERR_MASTER_REQUESTS_PENDING	-(TERR_BASE + 12)
#define NGBE_ERR_INVALID_LINK_SETTINGS		-(TERR_BASE + 13)
#define NGBE_ERR_AUTONEG_NOT_COMPLETE		-(TERR_BASE + 14)
#define NGBE_ERR_RESET_FAILED			-(TERR_BASE + 15)
#define NGBE_ERR_SWFW_SYNC			-(TERR_BASE + 16)
#define NGBE_ERR_PHY_ADDR_INVALID		-(TERR_BASE + 17)
#define NGBE_ERR_I2C				-(TERR_BASE + 18)
#define NGBE_ERR_SFP_NOT_SUPPORTED		-(TERR_BASE + 19)
#define NGBE_ERR_SFP_NOT_PRESENT		-(TERR_BASE + 20)
#define NGBE_ERR_SFP_NO_INIT_SEQ_PRESENT	-(TERR_BASE + 21)
#define NGBE_ERR_NO_SAN_ADDR_PTR		-(TERR_BASE + 22)
#define NGBE_ERR_FDIR_REINIT_FAILED		-(TERR_BASE + 23)
#define NGBE_ERR_EEPROM_VERSION			-(TERR_BASE + 24)
#define NGBE_ERR_NO_SPACE			-(TERR_BASE + 25)
#define NGBE_ERR_OVERTEMP			-(TERR_BASE + 26)
#define NGBE_ERR_FC_NOT_NEGOTIATED		-(TERR_BASE + 27)
#define NGBE_ERR_FC_NOT_SUPPORTED		-(TERR_BASE + 28)
#define NGBE_ERR_SFP_SETUP_NOT_COMPLETE		-(TERR_BASE + 30)
#define NGBE_ERR_PBA_SECTION			-(TERR_BASE + 31)
#define NGBE_ERR_INVALID_ARGUMENT		-(TERR_BASE + 32)
#define NGBE_ERR_HOST_INTERFACE_COMMAND		-(TERR_BASE + 33)
#define NGBE_ERR_OUT_OF_MEM			-(TERR_BASE + 34)
#define NGBE_ERR_FEATURE_NOT_SUPPORTED		-(TERR_BASE + 36)
#define NGBE_ERR_EEPROM_PROTECTED_REGION	-(TERR_BASE + 37)
#define NGBE_ERR_FDIR_CMD_INCOMPLETE		-(TERR_BASE + 38)
#define NGBE_ERR_FW_RESP_INVALID		-(TERR_BASE + 39)
#define NGBE_ERR_TOKEN_RETRY			-(TERR_BASE + 40)
#define NGBE_ERR_FLASH_LOADING_FAILED		-(TERR_BASE + 41)

#define NGBE_ERR_NOSUPP                        -(TERR_BASE + 42)
#define NGBE_ERR_UNDERTEMP                     -(TERR_BASE + 43)
#define NGBE_ERR_XPCS_POWER_UP_FAILED          -(TERR_BASE + 44)
#define NGBE_ERR_PHY_INIT_NOT_DONE             -(TERR_BASE + 45)
#define NGBE_ERR_TIMEOUT                       -(TERR_BASE + 46)
#define NGBE_ERR_REGISTER                      -(TERR_BASE + 47)
#define NGBE_ERR_MNG_ACCESS_FAILED             -(TERR_BASE + 49)
#define NGBE_ERR_PHY_TYPE                      -(TERR_BASE + 50)
#define NGBE_ERR_PHY_TIMEOUT                   -(TERR_BASE + 51)

#endif /* _NGBE_STATUS_H_ */

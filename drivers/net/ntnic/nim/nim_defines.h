/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef NIM_DEFINES_H_
#define NIM_DEFINES_H_

#define NIM_IDENTIFIER_ADDR 0	/* 1 byte */

#define SFP_BIT_RATE_ADDR 12	/* 1 byte */
#define SFP_VENDOR_NAME_ADDR 20	/* 16bytes */
#define SFP_VENDOR_PN_ADDR 40	/* 16bytes */
#define SFP_VENDOR_REV_ADDR 56	/* 4bytes */
#define SFP_VENDOR_SN_ADDR 68	/* 16bytes */
#define SFP_VENDOR_DATE_ADDR 84	/* 8bytes */

#define SFP_CONTROL_STATUS_LIN_ADDR (110U + 256U)	/* 0xA2 */
#define SFP_SOFT_TX_DISABLE_BIT (1U << 6)

#define QSFP_EXTENDED_IDENTIFIER 129
#define QSFP_SUP_LEN_INFO_ADDR 142	/* 5bytes */
#define QSFP_TRANSMITTER_TYPE_ADDR 147	/* 1byte */
#define QSFP_VENDOR_NAME_ADDR 148	/* 16bytes */
#define QSFP_VENDOR_PN_ADDR 168	/* 16bytes */
#define QSFP_VENDOR_REV_ADDR 184/* 2bytes */
#define QSFP_VENDOR_SN_ADDR 196	/* 16bytes */
#define QSFP_VENDOR_DATE_ADDR 212	/* 8bytes */

/* I2C addresses */
#define NIM_I2C_0XA0 0xA0	/* Basic I2C address */
#define NIM_I2C_0XA2 0xA2	/* Diagnostic monitoring */
#define NIM_I2C_0XAC 0xAC	/* Address of integrated PHY */

typedef enum {
	NIM_OPTION_TEMP = 0,
	NIM_OPTION_SUPPLY,
	NIM_OPTION_RX_POWER,
	NIM_OPTION_TX_BIAS,
	NIM_OPTION_TX_POWER,
	NIM_OPTION_TX_DISABLE,
	/* Indicates that the module should be checked for the two next FEC types */
	NIM_OPTION_FEC,
	NIM_OPTION_MEDIA_SIDE_FEC,
	NIM_OPTION_HOST_SIDE_FEC,
	NIM_OPTION_RX_ONLY
} nim_option_t;

enum nt_nim_identifier_e {
	NT_NIM_UNKNOWN = 0x00,	/* Nim type is unknown */
	NT_NIM_GBIC = 0x01,	/* Nim type = GBIC */
	NT_NIM_FIXED = 0x02,	/* Nim type = FIXED */
	NT_NIM_SFP_SFP_PLUS = 0x03,	/* Nim type = SFP/SFP+ */
	NT_NIM_300_PIN_XBI = 0x04,	/* Nim type = 300 pin XBI */
	NT_NIM_XEN_PAK = 0x05,	/* Nim type = XEN-PAK */
	NT_NIM_XFP = 0x06,	/* Nim type = XFP */
	NT_NIM_XFF = 0x07,	/* Nim type = XFF */
	NT_NIM_XFP_E = 0x08,	/* Nim type = XFP-E */
	NT_NIM_XPAK = 0x09,	/* Nim type = XPAK */
	NT_NIM_X2 = 0x0A,	/* Nim type = X2 */
	NT_NIM_DWDM = 0x0B,	/* Nim type = DWDM */
	NT_NIM_QSFP = 0x0C,	/* Nim type = QSFP */
	NT_NIM_QSFP_PLUS = 0x0D,/* Nim type = QSFP+ */
	NT_NIM_QSFP28 = 0x11,	/* Nim type = QSFP28 */
	NT_NIM_CFP4 = 0x12,	/* Nim type = CFP4 */
};
typedef enum nt_nim_identifier_e nt_nim_identifier_t;

#endif	/* NIM_DEFINES_H_ */

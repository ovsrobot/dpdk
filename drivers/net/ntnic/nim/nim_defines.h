/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef NIM_DEFINES_H_
#define NIM_DEFINES_H_

#define NIM_IDENTIFIER_ADDR 0 /* 1 byte */

#define SFP_BIT_RATE_ADDR 12 /* 1 byte */
#define SFP_VENDOR_NAME_ADDR 20 /* 16bytes */
#define SFP_VENDOR_PN_ADDR 40 /* 16bytes */
#define SFP_VENDOR_REV_ADDR 56 /* 4bytes */
#define SFP_VENDOR_SN_ADDR 68 /* 16bytes */
#define SFP_VENDOR_DATE_ADDR 84 /* 8bytes */

#define SFP_CONTROL_STATUS_LIN_ADDR (110U + 256U) /* 0xA2 */
#define SFP_SOFT_TX_DISABLE_BIT (1U << 6)

#define QSFP_EXTENDED_IDENTIFIER 129
#define QSFP_SUP_LEN_INFO_ADDR 142 /* 5bytes */
#define QSFP_TRANSMITTER_TYPE_ADDR 147 /* 1byte */
#define QSFP_VENDOR_NAME_ADDR 148 /* 16bytes */
#define QSFP_VENDOR_PN_ADDR 168 /* 16bytes */
#define QSFP_VENDOR_REV_ADDR 184 /* 2bytes */
#define QSFP_VENDOR_SN_ADDR 196 /* 16bytes */
#define QSFP_VENDOR_DATE_ADDR 212 /* 8bytes */

/* I2C addresses */
#define nim_i2c_0xa0 0xA0 /* Basic I2C address */
#define nim_i2c_0xa2 0xA2 /* Diagnostic monitoring */
#define nim_i2c_0xac 0xAC /* Address of integrated PHY */

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
	NT_NIM_UNKNOWN = 0x00, /* Nim type is unknown */
	NT_NIM_GBIC = 0x01, /* Nim type = GBIC */
	NT_NIM_FIXED = 0x02, /* Nim type = FIXED */
	NT_NIM_SFP_SFP_PLUS = 0x03, /* Nim type = SFP/SFP+ */
	NT_NIM_300_PIN_XBI = 0x04, /* Nim type = 300 pin XBI */
	NT_NIM_XEN_PAK = 0x05, /* Nim type = XEN-PAK */
	NT_NIM_XFP = 0x06, /* Nim type = XFP */
	NT_NIM_XFF = 0x07, /* Nim type = XFF */
	NT_NIM_XFP_E = 0x08, /* Nim type = XFP-E */
	NT_NIM_XPAK = 0x09, /* Nim type = XPAK */
	NT_NIM_X2 = 0x0A, /* Nim type = X2 */
	NT_NIM_DWDM = 0x0B, /* Nim type = DWDM */
	NT_NIM_QSFP = 0x0C, /* Nim type = QSFP */
	NT_NIM_QSFP_PLUS = 0x0D, /* Nim type = QSFP+ */
	NT_NIM_QSFP28 = 0x11, /* Nim type = QSFP28 */
	NT_NIM_CFP4 = 0x12, /* Nim type = CFP4 */
};

typedef enum nt_nim_identifier_e nt_nim_identifier_t;

/*
 * Port types
 * The use of all non-generic XX_NOT_PRESENT is deprecated - use
 * NT_PORT_TYPE_NIM_NOT_PRESENT instead
 */
enum nt_port_type_e {
	NT_PORT_TYPE_NOT_AVAILABLE =
		0, /* The NIM/port type is not available (unknown) */
	NT_PORT_TYPE_NOT_RECOGNISED, /* The NIM/port type not recognized */
	NT_PORT_TYPE_RJ45, /* RJ45 type */
	NT_PORT_TYPE_SFP_NOT_PRESENT, /* SFP type but slot is empty */
	NT_PORT_TYPE_SFP_SX, /* SFP SX */
	NT_PORT_TYPE_SFP_SX_DD, /* SFP SX digital diagnostic */
	NT_PORT_TYPE_SFP_LX, /* SFP LX */
	NT_PORT_TYPE_SFP_LX_DD, /* SFP LX digital diagnostic */
	NT_PORT_TYPE_SFP_ZX, /* SFP ZX */
	NT_PORT_TYPE_SFP_ZX_DD, /* SFP ZX digital diagnostic */
	NT_PORT_TYPE_SFP_CU, /* SFP copper */
	NT_PORT_TYPE_SFP_CU_DD, /* SFP copper digital diagnostic */
	NT_PORT_TYPE_SFP_NOT_RECOGNISED, /* SFP unknown */
	NT_PORT_TYPE_XFP, /* XFP */
	NT_PORT_TYPE_XPAK, /* XPAK */
	NT_PORT_TYPE_SFP_CU_TRI_SPEED, /* SFP copper tri-speed */
	NT_PORT_TYPE_SFP_CU_TRI_SPEED_DD, /* SFP copper tri-speed digital diagnostic */
	NT_PORT_TYPE_SFP_PLUS, /* SFP+ type */
	NT_PORT_TYPE_SFP_PLUS_NOT_PRESENT, /* SFP+ type but slot is empty */
	NT_PORT_TYPE_XFP_NOT_PRESENT, /* XFP type but slot is empty */
	NT_PORT_TYPE_QSFP_PLUS_NOT_PRESENT, /* QSFP type but slot is empty */
	NT_PORT_TYPE_QSFP_PLUS, /* QSFP type */
	NT_PORT_TYPE_SFP_PLUS_PASSIVE_DAC, /* SFP+ Passive DAC */
	NT_PORT_TYPE_SFP_PLUS_ACTIVE_DAC, /* SFP+ Active DAC */
	NT_PORT_TYPE_CFP4, /* CFP4 type */
	NT_PORT_TYPE_CFP4_LR4 = NT_PORT_TYPE_CFP4, /* CFP4 100G, LR4 type */
	NT_PORT_TYPE_CFP4_NOT_PRESENT, /* CFP4 type but slot is empty */
	NT_PORT_TYPE_INITIALIZE, /* The port type is not fully established yet */
	NT_PORT_TYPE_NIM_NOT_PRESENT, /* Generic "Not present" */
	NT_PORT_TYPE_HCB, /* Test mode: Host Compliance Board */
	NT_PORT_TYPE_NOT_SUPPORTED, /* The NIM type is not supported in this context */
	NT_PORT_TYPE_SFP_PLUS_DUAL_RATE, /* SFP+ supports 1G/10G */
	NT_PORT_TYPE_CFP4_SR4, /* CFP4 100G, SR4 type */
	NT_PORT_TYPE_QSFP28_NOT_PRESENT, /* QSFP28 type but slot is empty */
	NT_PORT_TYPE_QSFP28, /* QSFP28 type */
	NT_PORT_TYPE_QSFP28_SR4, /* QSFP28-SR4 type */
	NT_PORT_TYPE_QSFP28_LR4, /* QSFP28-LR4 type */
	/* Deprecated. The port type should not mention speed eg 4x10 or 1x40 */
	NT_PORT_TYPE_QSFP_PLUS_4X10,
	/* Deprecated. The port type should not mention speed eg 4x10 or 1x40 */
	NT_PORT_TYPE_QSFP_PASSIVE_DAC_4X10,
	NT_PORT_TYPE_QSFP_PASSIVE_DAC =
		NT_PORT_TYPE_QSFP_PASSIVE_DAC_4X10, /* QSFP passive DAC type */
	/* Deprecated. The port type should not mention speed eg 4x10 or 1x40 */
	NT_PORT_TYPE_QSFP_ACTIVE_DAC_4X10,
	NT_PORT_TYPE_QSFP_ACTIVE_DAC =
		NT_PORT_TYPE_QSFP_ACTIVE_DAC_4X10, /* QSFP active DAC type */
	NT_PORT_TYPE_SFP_28, /* SFP28 type */
	NT_PORT_TYPE_SFP_28_SR, /* SFP28-SR type */
	NT_PORT_TYPE_SFP_28_LR, /* SFP28-LR type */
	NT_PORT_TYPE_SFP_28_CR_CA_L, /* SFP28-CR-CA-L type */
	NT_PORT_TYPE_SFP_28_CR_CA_S, /* SFP28-CR-CA-S type */
	NT_PORT_TYPE_SFP_28_CR_CA_N, /* SFP28-CR-CA-N type */
	NT_PORT_TYPE_QSFP28_CR_CA_L, /* QSFP28-CR-CA-L type */
	NT_PORT_TYPE_QSFP28_CR_CA_S, /* QSFP28-CR-CA-S type */
	NT_PORT_TYPE_QSFP28_CR_CA_N, /* QSFP28-CR-CA-N type */
	NT_PORT_TYPE_SFP_28_SR_DR, /* SFP28-SR-DR type */
	NT_PORT_TYPE_SFP_28_LR_DR, /* SFP28-LR-DR type */
	NT_PORT_TYPE_SFP_FX, /* SFP FX */
	NT_PORT_TYPE_SFP_PLUS_CU, /* SFP+ CU type */
	/* QSFP28-FR type. Uses PAM4 modulation on one lane only */
	NT_PORT_TYPE_QSFP28_FR,
	/* QSFP28-DR type. Uses PAM4 modulation on one lane only */
	NT_PORT_TYPE_QSFP28_DR,
	/* QSFP28-LR type. Uses PAM4 modulation on one lane only */
	NT_PORT_TYPE_QSFP28_LR,
};

typedef enum nt_port_type_e nt_port_type_t, *nt_port_type_p;

#endif /* NIM_DEFINES_H_ */

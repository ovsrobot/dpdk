/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Napatech A/S
 */

#ifndef _NTNIC_NIM_H_
#define _NTNIC_NIM_H_

#include <stdint.h>

typedef enum i2c_type {
	I2C_HWIIC,
	I2C_HWAGX
} i2c_type_e;

/*
 * Port types
 * The use of all non-generic XX_NOT_PRESENT is deprecated - use
 * NT_PORT_TYPE_NIM_NOT_PRESENT instead
 */
enum nt_port_type_e {
	NT_PORT_TYPE_NOT_AVAILABLE = 0,	/* The NIM/port type is not available (unknown) */
	NT_PORT_TYPE_NOT_RECOGNISED,	/* The NIM/port type not recognized */
	NT_PORT_TYPE_RJ45,	/* RJ45 type */
	NT_PORT_TYPE_SFP_NOT_PRESENT,	/* SFP type but slot is empty */
	NT_PORT_TYPE_SFP_SX,	/* SFP SX */
	NT_PORT_TYPE_SFP_SX_DD,	/* SFP SX digital diagnostic */
	NT_PORT_TYPE_SFP_LX,	/* SFP LX */
	NT_PORT_TYPE_SFP_LX_DD,	/* SFP LX digital diagnostic */
	NT_PORT_TYPE_SFP_ZX,	/* SFP ZX */
	NT_PORT_TYPE_SFP_ZX_DD,	/* SFP ZX digital diagnostic */
	NT_PORT_TYPE_SFP_CU,	/* SFP copper */
	NT_PORT_TYPE_SFP_CU_DD,	/* SFP copper digital diagnostic */
	NT_PORT_TYPE_SFP_NOT_RECOGNISED,/* SFP unknown */
	NT_PORT_TYPE_XFP,	/* XFP */
	NT_PORT_TYPE_XPAK,	/* XPAK */
	NT_PORT_TYPE_SFP_CU_TRI_SPEED,	/* SFP copper tri-speed */
	NT_PORT_TYPE_SFP_CU_TRI_SPEED_DD,	/* SFP copper tri-speed digital diagnostic */
	NT_PORT_TYPE_SFP_PLUS,	/* SFP+ type */
	NT_PORT_TYPE_SFP_PLUS_NOT_PRESENT,	/* SFP+ type but slot is empty */
	NT_PORT_TYPE_XFP_NOT_PRESENT,	/* XFP type but slot is empty */
	NT_PORT_TYPE_QSFP_PLUS_NOT_PRESENT,	/* QSFP type but slot is empty */
	NT_PORT_TYPE_QSFP_PLUS,	/* QSFP type */
	NT_PORT_TYPE_SFP_PLUS_PASSIVE_DAC,	/* SFP+ Passive DAC */
	NT_PORT_TYPE_SFP_PLUS_ACTIVE_DAC,	/* SFP+ Active DAC */
	NT_PORT_TYPE_CFP4,	/* CFP4 type */
	NT_PORT_TYPE_CFP4_LR4 = NT_PORT_TYPE_CFP4,	/* CFP4 100G, LR4 type */
	NT_PORT_TYPE_CFP4_NOT_PRESENT,	/* CFP4 type but slot is empty */
	NT_PORT_TYPE_INITIALIZE,/* The port type is not fully established yet */
	NT_PORT_TYPE_NIM_NOT_PRESENT,	/* Generic "Not present" */
	NT_PORT_TYPE_HCB,	/* Test mode: Host Compliance Board */
	NT_PORT_TYPE_NOT_SUPPORTED,	/* The NIM type is not supported in this context */
	NT_PORT_TYPE_SFP_PLUS_DUAL_RATE,/* SFP+ supports 1G/10G */
	NT_PORT_TYPE_CFP4_SR4,	/* CFP4 100G, SR4 type */
	NT_PORT_TYPE_QSFP28_NOT_PRESENT,/* QSFP28 type but slot is empty */
	NT_PORT_TYPE_QSFP28,	/* QSFP28 type */
	NT_PORT_TYPE_QSFP28_SR4,/* QSFP28-SR4 type */
	NT_PORT_TYPE_QSFP28_LR4,/* QSFP28-LR4 type */
	/* Deprecated. The port type should not mention speed eg 4x10 or 1x40 */
	NT_PORT_TYPE_QSFP_PLUS_4X10,
	/* Deprecated. The port type should not mention speed eg 4x10 or 1x40 */
	NT_PORT_TYPE_QSFP_PASSIVE_DAC_4X10,
	/* QSFP passive DAC type */
	NT_PORT_TYPE_QSFP_PASSIVE_DAC = NT_PORT_TYPE_QSFP_PASSIVE_DAC_4X10,
	/* Deprecated. The port type should not mention speed eg 4x10 or 1x40 */
	NT_PORT_TYPE_QSFP_ACTIVE_DAC_4X10,
	/* QSFP active DAC type */
	NT_PORT_TYPE_QSFP_ACTIVE_DAC = NT_PORT_TYPE_QSFP_ACTIVE_DAC_4X10,
	NT_PORT_TYPE_SFP_28,	/* SFP28 type */
	NT_PORT_TYPE_SFP_28_SR,	/* SFP28-SR type */
	NT_PORT_TYPE_SFP_28_LR,	/* SFP28-LR type */
	NT_PORT_TYPE_SFP_28_CR_CA_L,	/* SFP28-CR-CA-L type */
	NT_PORT_TYPE_SFP_28_CR_CA_S,	/* SFP28-CR-CA-S type */
	NT_PORT_TYPE_SFP_28_CR_CA_N,	/* SFP28-CR-CA-N type */
	NT_PORT_TYPE_QSFP28_CR_CA_L,	/* QSFP28-CR-CA-L type */
	NT_PORT_TYPE_QSFP28_CR_CA_S,	/* QSFP28-CR-CA-S type */
	NT_PORT_TYPE_QSFP28_CR_CA_N,	/* QSFP28-CR-CA-N type */
	NT_PORT_TYPE_SFP_28_SR_DR,	/* SFP28-SR-DR type */
	NT_PORT_TYPE_SFP_28_LR_DR,	/* SFP28-LR-DR type */
	NT_PORT_TYPE_SFP_FX,	/* SFP FX */
	NT_PORT_TYPE_SFP_PLUS_CU,	/* SFP+ CU type */
	/* QSFP28-FR type. Uses PAM4 modulation on one lane only */
	NT_PORT_TYPE_QSFP28_FR,
	/* QSFP28-DR type. Uses PAM4 modulation on one lane only */
	NT_PORT_TYPE_QSFP28_DR,
	/* QSFP28-LR type. Uses PAM4 modulation on one lane only */
	NT_PORT_TYPE_QSFP28_LR,
};

typedef enum nt_port_type_e nt_port_type_t, *nt_port_type_p;

typedef struct nim_i2c_ctx {
	union {
		nthw_iic_t hwiic;	/* depends on *Fpga_t, instance number, and cycle time */
		struct {
			nthw_i2cm_t *p_nt_i2cm;
			int mux_channel;
		} hwagx;
	};
	i2c_type_e type;/* 0 = hwiic (xilinx) - 1 =  hwagx (agilex) */
	uint8_t instance;
	uint8_t devaddr;
	uint8_t regaddr;
	uint8_t nim_id;
	nt_port_type_t port_type;

	char vendor_name[17];
	char prod_no[17];
	char serial_no[17];
	char date[9];
	char rev[5];
	bool avg_pwr;
	bool content_valid;
	uint8_t pwr_level_req;
	uint8_t pwr_level_cur;
	uint16_t len_info[5];
	uint32_t speed_mask;	/* Speeds supported by the NIM */
	int8_t lane_idx;/* Is this associated with a single lane or all lanes (-1) */
	uint8_t lane_count;
	uint32_t options;
	bool tx_disable;
	bool dmi_supp;

	union {
		struct {
			bool sfp28;
			bool sfpplus;
			bool dual_rate;
			bool hw_rate_sel;
			bool sw_rate_sel;
			bool cu_type;
			bool tri_speed;
			bool ext_cal;
			bool addr_chg;
		} sfp;

		struct {
			bool rx_only;
			bool qsfp28;
			union {
				struct {
					uint8_t rev_compliance;
					bool media_side_fec_ctrl;
					bool host_side_fec_ctrl;
					bool media_side_fec_ena;
					bool host_side_fec_ena;
				} qsfp28;
			} specific_u;
		} qsfp;

	} specific_u;
} nim_i2c_ctx_t, *nim_i2c_ctx_p;

struct nim_sensor_group {
	struct nt_adapter_sensor *sensor;
	void (*read)(struct nim_sensor_group *sg, nthw_spis_t *t_spi);
	struct nim_i2c_ctx *ctx;
	struct nim_sensor_group *next;
};

#endif	/* _NTNIC_NIM_H_ */

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef I2C_NIM_H_
#define I2C_NIM_H_

#include "nthw_drv.h"
#include "nim_defines.h"
#include "nt_link_speed.h"

#include "sensors.h"

typedef struct sfp_nim_state {
	uint8_t br; /* bit rate, units of 100 MBits/sec */
} sfp_nim_state_t, *sfp_nim_state_p;

typedef struct nim_i2c_ctx {
	nthw_iic_t hwiic; /* depends on *Fpga_t, instance number, and cycle time */
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
	uint32_t speed_mask; /* Speeds supported by the NIM */
	int8_t lane_idx; /* Is this associated with a single lane or all lanes (-1) */
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

struct nim_sensor_group *
allocate_nim_sensor_group(uint8_t port, struct nim_i2c_ctx *ctx,
			  enum nt_sensor_source_e ssrc,
			  struct nt_adapter_sensor_description *sd);

/*
 * Utility functions
 */

nt_nim_identifier_t translate_nimid(const nim_i2c_ctx_t *ctx);

/*
 * Builds an nim state for the port implied by `ctx`, returns zero
 * if successful, and non-zero otherwise. SFP and QSFP nims are supported
 */
int nim_state_build(nim_i2c_ctx_t *ctx, sfp_nim_state_t *state);

/*
 * Returns a type name such as "SFP/SFP+" for a given NIM type identifier,
 * or the string "ILLEGAL!".
 */
const char *nim_id_to_text(uint8_t nim_id);

int nim_sfp_nim_set_tx_laser_disable(nim_i2c_ctx_p ctx, bool disable);

int nim_qsfp_plus_nim_set_tx_laser_disable(nim_i2c_ctx_t *ctx, bool disable,
				       int lane_idx);

int nim_set_link_speed(nim_i2c_ctx_p ctx, nt_link_speed_t speed);

/*
 * This function tries to classify NIM based on it's ID and some register reads
 * and collects information into ctx structure. The @extra parameter could contain
 * the initialization argument for specific type of NIMS.
 */
int construct_and_preinit_nim(nim_i2c_ctx_p ctx, void *extra, uint8_t port,
			      struct nim_sensor_group **nim_sensors_ptr,
			      uint16_t *nim_sensors_cnt);

int read_data_lin(nim_i2c_ctx_p ctx, uint16_t lin_addr, uint16_t length,
		void *data);

#endif /* I2C_NIM_H_ */

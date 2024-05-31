/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef I2C_NIM_H_
#define I2C_NIM_H_

#include "nthw_drv.h"
#include "nim_defines.h"
#include "nt_link_speed.h"
#include "ntnic_nim.h"

#include "ntnic_sensor.h"

typedef struct sfp_nim_state {
	uint8_t br;	/* bit rate, units of 100 MBits/sec */
} sfp_nim_state_t, *sfp_nim_state_p;

struct nim_sensor_group *allocate_nim_sensor_group(uint8_t port, struct nim_i2c_ctx *ctx,
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

int nim_qsfp_plus_nim_set_tx_laser_disable(nim_i2c_ctx_t *ctx, bool disable, int lane_idx);

/*
 * This function tries to classify NIM based on it's ID and some register reads
 * and collects information into ctx structure. The @extra parameter could contain
 * the initialization argument for specific type of NIMS.
 */
int construct_and_preinit_nim(nim_i2c_ctx_p ctx, void *extra, uint8_t port,
	struct nim_sensor_group **nim_sensors_ptr,
	uint16_t *nim_sensors_cnt);

int read_data_lin(nim_i2c_ctx_p ctx, uint16_t lin_addr, uint16_t length, void *data);

struct sfp_ops {
	void (*nim_read_sfp_temp)(struct nim_sensor_group *sg, nthw_spis_t *t_spi);
	void (*nim_read_sfp_voltage)(struct nim_sensor_group *sg, nthw_spis_t *t_spi);
	void (*nim_read_sfp_bias_current)(struct nim_sensor_group *sg, nthw_spis_t *t_spi);
	void (*nim_read_sfp_tx_power)(struct nim_sensor_group *sg, nthw_spis_t *t_spi);
	void (*nim_read_sfp_rx_power)(struct nim_sensor_group *sg, nthw_spis_t *t_spi);
};

struct qsfp_ops {
	void (*nim_read_qsfp_temp)(struct nim_sensor_group *sg, nthw_spis_t *t_spi);
	void (*nim_read_qsfp_voltage)(struct nim_sensor_group *sg, nthw_spis_t *t_spi);
	void (*nim_read_qsfp_bias_current)(struct nim_sensor_group *sg, nthw_spis_t *t_spi);
	void (*nim_read_qsfp_tx_power)(struct nim_sensor_group *sg, nthw_spis_t *t_spi);
	void (*nim_read_qsfp_rx_power)(struct nim_sensor_group *sg, nthw_spis_t *t_spi);
};

void register_qsfp_ops(struct qsfp_ops *ops);
struct qsfp_ops *get_qsfp_ops(void);

void register_sfp_ops(struct sfp_ops *ops);
struct sfp_ops *get_sfp_ops(void);

#endif	/* I2C_NIM_H_ */

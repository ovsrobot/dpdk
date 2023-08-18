/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _SFP_H
#define _SFP_H

#include "sensors.h"
#include "i2c_nim.h"

/* Read functions */
void nim_read_sfp_temp(struct nim_sensor_group *sg, nthw_spis_t *t_spi);
void nim_read_sfp_voltage(struct nim_sensor_group *sg, nthw_spis_t *t_spi);
void nim_read_sfp_bias_current(struct nim_sensor_group *sg, nthw_spis_t *t_spi);
void nim_read_sfp_tx_power(struct nim_sensor_group *sg, nthw_spis_t *t_spi);
void nim_read_sfp_rx_power(struct nim_sensor_group *sg, nthw_spis_t *t_spi);

#endif /* _SFP_H */

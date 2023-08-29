/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _QSFP_H
#define _QSFP_H

#include "sensors.h"
#include "i2c_nim.h"

/* Read functions */
void nim_read_qsfp_temp(struct nim_sensor_group *sg, nthw_spis_t *t_spi);
void nim_read_qsfp_voltage(struct nim_sensor_group *sg, nthw_spis_t *t_spi);
void nim_read_qsfp_bias_current(struct nim_sensor_group *sg, nthw_spis_t *t_spi);
void nim_read_qsfp_tx_power(struct nim_sensor_group *sg, nthw_spis_t *t_spi);
void nim_read_qsfp_rx_power(struct nim_sensor_group *sg, nthw_spis_t *t_spi);

#endif /* _QSFP_H */

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _NTAVR_H
#define _NTAVR_H

#include <stdint.h>
#include <stdlib.h>

#include "avr_intf.h"
#include "nthw_drv.h"
#include "nthw_spi_v3.h"

/*
 * @internal
 * @brief AVR Device Enum
 *
 * Global names for identifying an AVR device for Generation2 adapters
 */
enum ntavr_device {
	NTAVR_MAINBOARD, /* Mainboard AVR device */
	NTAVR_FRONTBOARD /* Frontboard AVR device */
};

int nt_avr_sensor_mon_setup(struct sensor_mon_setup16 *p_setup,
			nthw_spi_v3_t *s_spi);
int nt_avr_sensor_mon_ctrl(nthw_spi_v3_t *s_spi, enum sensor_mon_control ctrl);
uint32_t sensor_read(nthw_spis_t *t_spi, uint8_t fpga_idx,
		     uint32_t *p_sensor_result);

#endif /* _NTAVR_H */

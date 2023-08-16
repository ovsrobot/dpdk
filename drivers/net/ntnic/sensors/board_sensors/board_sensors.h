/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _BOARD_SENSORS_H
#define _BOARD_SENSORS_H

#include <stdint.h>

#include "sensors.h"

#include "nthw_fpga_model.h"

struct nt_sensor_group *fpga_temperature_sensor_init(uint8_t adapter_no,
		unsigned int sensor_idx,
		nt_fpga_t *p_fpga);

#endif /* _BOARD_SENSORS_H */

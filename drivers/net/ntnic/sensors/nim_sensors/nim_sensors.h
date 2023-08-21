/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _NIM_SENSORS_H
#define _NIM_SENSORS_H

#include <stdint.h>
#include <string.h>
#include "sensors.h"

#define XFP_TEMP_LIN_ADDR 96

extern struct nt_adapter_sensor_description sfp_sensors_level0[1];
extern struct nt_adapter_sensor_description sfp_sensors_level1[4];
extern struct nt_adapter_sensor_description qsfp_sensor_level0[1];
extern struct nt_adapter_sensor_description qsfp_sensor_level1[13];

#endif /* _NIM_SENSORS_H */

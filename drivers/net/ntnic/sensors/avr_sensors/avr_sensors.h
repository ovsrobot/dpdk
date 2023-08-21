/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _AVR_SENSORS_H
#define _AVR_SENSORS_H

#include <stdint.h>

#include "sensors.h"
#include "avr_intf.h"
#include "ntavr.h"

struct nt_sensor_group *
avr_sensor_init(nthw_spi_v3_t *s_spi, uint8_t m_adapter_no, const char *p_name,
		enum nt_sensor_source_e ssrc, enum nt_sensor_type_e type,
		unsigned int index, enum sensor_mon_device avr_dev,
		uint8_t avr_dev_reg, enum sensor_mon_endian end,
		enum sensor_mon_sign si, int (*conv_func)(uint32_t),
		uint16_t mask);

#endif /* _AVR_SENSORS_H */

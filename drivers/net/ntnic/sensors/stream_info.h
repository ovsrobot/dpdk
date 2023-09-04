/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _STREAM_INFO_H
#define _STREAM_INFO_H

#include "sensor_types.h"

#include <stdint.h>

/*
 * This structure will return the sensor specific information
 *
 * The units used for the fields: value, value_lowest, value_highest, limit_low and
 * limit_high depend on the type field. See @ref nt_sensor_type_e.
 *
 * For the limit_low and limit_high fields the following applies:\n
 * If the sensor is located in a NIM (Network Interface Module), the limits are read
 * from the NIM module via the DMI (Diagnostic Monitoring Interface) from the alarm
 * and warning thresholds section, and the units are changed to internal representation.
 * Only the alarm thresholds are used and are read only once during initialization.
 * The limits cannot be changed.
 *
 * The value field is updated internally on a regular basis and is also based on a
 * value read from the NIM which is also changed to internal representation.
 *
 * Not all NIM types support DMI data, and its presence must be determined by reading an
 * option flag. In general, a NIM can read out: temperature, supply voltage,
 * TX bias, TX optical power and RX optical power but not all NIM types support all
 * 5 values.
 *
 * If external calibration is used (most NIM use internal calibration), both the
 * current value and the threshold values are subjected to the specified calibration
 * along with the change to internal calibration.
 */
#define NT_INFO_SENSOR_NAME 50
struct nt_info_sensor_s {
	enum nt_sensor_source_e
	source; /* The source of the sensor (port or adapter on which the sensor resides) */
	/*
	 * The source index - the adapter number for adapter sensors and port number for port
	 * sensors
	 */
	uint32_t source_index;
	/*
	 * The sensor index within the source index (sensor number on the adapter or sensor number
	 * on the port)
	 */
	uint32_t sensor_index;
	enum nt_sensor_type_e type; /* The sensor type */
	enum nt_sensor_sub_type_e sub_type; /* The sensor subtype (if applicable) */
	enum nt_sensor_state_e state; /* The current state (normal or alarm) */
	int32_t value; /* The current value */
	int32_t value_lowest; /* The lowest value registered */
	int32_t value_highest; /* The highest value registered */
	char name[NT_INFO_SENSOR_NAME + 1]; /* The sensor name */
	enum nt_adapter_type_e
	adapter_type; /* The adapter type where the sensor resides */
};

/* The NT200A02 adapter sensor id's */
enum nt_sensors_adapter_nt200a02_e {
	/* Public sensors (Level 0) */
	NT_SENSOR_NT200A02_FPGA_TEMP, /* FPGA temperature sensor */
	NT_SENSOR_NT200A02_FAN_SPEED, /* FAN speed sensor */

	NT_SENSOR_NT200A02_MCU_TEMP,
	NT_SENSOR_NT200A02_PSU0_TEMP, /* Power supply 0 temperature sensor */
	NT_SENSOR_NT200A02_PSU1_TEMP, /* Power supply 1 temperature sensor */
	NT_SENSOR_NT200A02_PCB_TEMP, /* PCB temperature sensor */

	/* Diagnostic sensors (Level 1) */
	/* Total power consumption (calculated value) - does not generate alarms */
	NT_SENSOR_NT200A02_NT200A02_POWER,
	/* FPGA power consumption (calculated value) - does not generate alarms */
	NT_SENSOR_NT200A02_FPGA_POWER,
	/* DDR4 RAM power consumption (calculated value) - does not generate alarms */
	NT_SENSOR_NT200A02_DDR4_POWER,
	/* NIM power consumption (calculated value) - does not generate alarms */
	NT_SENSOR_NT200A02_NIM_POWER,

	NT_SENSOR_NT200A02_L1_MAX, /* Number of NT200A01 level 0,1 board sensors */
};

#endif

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <arpa/inet.h>

#include "nim_sensors.h"
#include "ntlog.h"

#define TEMP NT_SENSOR_TYPE_TEMPERATURE
#define VOLT NT_SENSOR_TYPE_VOLTAGE
#define CURR NT_SENSOR_TYPE_CURRENT
#define PWR NT_SENSOR_TYPE_POWER

#define SNA NT_SENSOR_SUBTYPE_NA
#define AVG NT_SENSOR_SUBTYPE_POWER_AVERAGE

#define ENA NT_SENSOR_ENABLE_ALARM
#define DIA NT_SENSOR_DISABLE_ALARM

/*
 * Sensors for SFP/SFP+/SFP28. The name of the level 0 temperature sensor is
 * empty and will then be set automatically
 */
struct nt_adapter_sensor_description sfp_sensors_level0[1] = {
	{ TEMP, SNA, NT_SENSOR_SFP_TEMP, DIA, "" },
};

struct nt_adapter_sensor_description sfp_sensors_level1[4] = {
	{ VOLT, SNA, NT_SENSOR_SFP_SUPPLY, DIA, "Supply" },
	{ CURR, SNA, NT_SENSOR_SFP_TX_BIAS, DIA, "Tx Bias" },
	{ PWR, AVG, NT_SENSOR_SFP_TX_POWER, DIA, "Tx" },
	{ PWR, AVG, NT_SENSOR_SFP_RX_POWER, DIA, "Rx" }
};

struct nt_adapter_sensor_description qsfp_sensor_level0[1] = {
	{ TEMP, SNA, NT_SENSOR_QSFP_TEMP, DIA, "" },
};

struct nt_adapter_sensor_description qsfp_sensor_level1[13] = {
	{ VOLT, SNA, NT_SENSOR_QSFP_SUPPLY, DIA, "Supply" },
	{ CURR, SNA, NT_SENSOR_QSFP_TX_BIAS1, DIA, "Tx Bias 1" },
	{ CURR, SNA, NT_SENSOR_QSFP_TX_BIAS2, DIA, "Tx Bias 2" },
	{ CURR, SNA, NT_SENSOR_QSFP_TX_BIAS3, DIA, "Tx Bias 3" },
	{ CURR, SNA, NT_SENSOR_QSFP_TX_BIAS4, DIA, "Tx Bias 4" },
	{ PWR, AVG, NT_SENSOR_QSFP_TX_POWER1, DIA, "Tx 1" },
	{ PWR, AVG, NT_SENSOR_QSFP_TX_POWER2, DIA, "Tx 2" },
	{ PWR, AVG, NT_SENSOR_QSFP_TX_POWER3, DIA, "Tx 3" },
	{ PWR, AVG, NT_SENSOR_QSFP_TX_POWER4, DIA, "Tx 4" },
	{ PWR, AVG, NT_SENSOR_QSFP_RX_POWER1, DIA, "Rx 1" },
	{ PWR, AVG, NT_SENSOR_QSFP_RX_POWER2, DIA, "Rx 2" },
	{ PWR, AVG, NT_SENSOR_QSFP_RX_POWER3, DIA, "Rx 3" },
	{ PWR, AVG, NT_SENSOR_QSFP_RX_POWER4, DIA, "Rx 4" }
};

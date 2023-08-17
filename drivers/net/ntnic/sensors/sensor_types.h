/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _SENSOR_TYPES_H
#define _SENSOR_TYPES_H

/*
 * Sensor types
 */
enum nt_sensor_type_e {
	NT_SENSOR_TYPE_UNKNOWN = 0,
	NT_SENSOR_TYPE_TEMPERATURE = 1, /* Unit: 0.1 degree Celsius */
	NT_SENSOR_TYPE_VOLTAGE = 2, /* Unit: 1 mV */
	NT_SENSOR_TYPE_CURRENT = 3, /* Unit: 1 uA */
	NT_SENSOR_TYPE_POWER = 4, /* Unit: 0.1 uW */
	NT_SENSOR_TYPE_FAN = 5, /* Unit: 1 RPM (Revolutions Per Minute) */
	NT_SENSOR_TYPE_HIGH_POWER = 6, /* Unit: 1 mW */
	NT_SENSOR_TYPE_NUMBER = 7,
};

/*
 * Generic SFP/SFP+/SFP28 sensors
 *
 * These sensors should be used instead of all adapter specific SFP sensors
 * that have been deprecated..
 */
enum nt_sensors_sfp {
	NT_SENSOR_SFP_TEMP,
	NT_SENSOR_SFP_SUPPLY,
	NT_SENSOR_SFP_TX_BIAS,
	NT_SENSOR_SFP_TX_POWER,
	NT_SENSOR_SFP_RX_POWER,
};

/*
 * Generic QSFP/QSFP+/QSFP28 sensors
 *
 * These sensors should be used instead of all adapter specific QSFP sensors
 * that have been deprecated..
 */
enum nt_sensors_qsfp {
	NT_SENSOR_QSFP_TEMP,
	NT_SENSOR_QSFP_SUPPLY,
	NT_SENSOR_QSFP_TX_BIAS1,
	NT_SENSOR_QSFP_TX_BIAS2,
	NT_SENSOR_QSFP_TX_BIAS3,
	NT_SENSOR_QSFP_TX_BIAS4,
	NT_SENSOR_QSFP_TX_POWER1,
	NT_SENSOR_QSFP_TX_POWER2,
	NT_SENSOR_QSFP_TX_POWER3,
	NT_SENSOR_QSFP_TX_POWER4,
	NT_SENSOR_QSFP_RX_POWER1,
	NT_SENSOR_QSFP_RX_POWER2,
	NT_SENSOR_QSFP_RX_POWER3,
	NT_SENSOR_QSFP_RX_POWER4,
};

typedef enum nt_sensor_type_e nt_sensor_type_t;

/*
 * Sensor subtypes
 */
enum nt_sensor_sub_type_e {
	NT_SENSOR_SUBTYPE_NA = 0,
	/*
	 * Subtype for NT_SENSOR_TYPE_POWER type on optical modules (optical modulation
	 * amplitude measured)
	 */
	NT_SENSOR_SUBTYPE_POWER_OMA,
	/* Subtype for NT_SENSOR_TYPE_POWER type on optical modules (average power measured) */
	NT_SENSOR_SUBTYPE_POWER_AVERAGE,
	/* Subtype for NT_SENSOR_TYPE_HIGH_POWER type on adapters (total power consumption) */
	NT_SENSOR_SUBTYPE_POWER_TOTAL
};

typedef enum nt_sensor_sub_type_e nt_sensor_sub_type_t;

/*
 * Sensor source
 */
enum nt_sensor_source_e {
	NT_SENSOR_SOURCE_UNKNOWN = 0x00, /* Unknown source */
	/*
	 * Sensors located in a port. These are primary sensors - usually NIM temperature. Presence
	 * depends on adapter and NIM type.
	 */
	NT_SENSOR_SOURCE_PORT =
		0x01,
	/*
	 * Level 1 sensors located in a port. These are secondary sensors - usually NIM supply
	 * voltage, Tx bias and Rx/Tx optical power. Presence depends on adapter and NIM type.
	 */
	NT_SENSOR_SOURCE_LEVEL1_PORT =
		0x02,
#ifndef DOXYGEN_INTERNAL_ONLY
	NT_SENSOR_SOURCE_LEVEL2_PORT =
		0x04, /* Level 2 sensors located in a port */
#endif
	NT_SENSOR_SOURCE_ADAPTER = 0x08, /* Sensors mounted on the adapter */
	NT_SENSOR_SOURCE_LEVEL1_ADAPTER =
		0x10, /* Level 1 sensors mounted on the adapter */
#ifndef DOXYGEN_INTERNAL_ONLY
	NT_SENSOR_SOURCE_LEVEL2_ADAPTER =
		0x20, /* Level 2 sensors mounted on the adapter */
#endif
};

/*
 * Sensor state
 */
enum nt_sensor_state_e {
	NT_SENSOR_STATE_UNKNOWN = 0, /* Unknown state */
	NT_SENSOR_STATE_INITIALIZING = 1, /* The sensor is initializing */
	NT_SENSOR_STATE_NORMAL = 2, /* Sensor values are within range */
	NT_SENSOR_STATE_ALARM = 3, /* Sensor values are out of range */
	NT_SENSOR_STATE_NOT_PRESENT =
		4 /* The sensor is not present, for example, SFP without diagnostics */
};

typedef enum nt_sensor_state_e nt_sensor_state_t;

/*
 * Sensor value
 */
#define NT_SENSOR_NAN \
	(0x80000000) /* Indicates that sensor value or sensor limit is not valid (Not a Number) */

/*
 * Master/Slave
 */
enum nt_bonding_type_e {
	NT_BONDING_UNKNOWN, /* Unknown bonding type */
	NT_BONDING_MASTER, /* Adapter is master in the bonding */
	NT_BONDING_SLAVE, /* Adapter is slave in the bonding */
	NT_BONDING_PEER /* Adapter is bonded, but relationship is symmetric */
};

enum nt_sensors_e {
	/* Public sensors (Level 0) */
	NT_SENSOR_FPGA_TEMP, /* FPGA temperature sensor */
};

/*
 * Adapter types
 */
enum nt_adapter_type_e {
	NT_ADAPTER_TYPE_UNKNOWN = 0, /* Unknown adapter type */
	NT_ADAPTER_TYPE_NT4E, /* NT4E network adapter */
	NT_ADAPTER_TYPE_NT20E, /* NT20E network adapter */
	NT_ADAPTER_TYPE_NT4E_STD, /* NT4E-STD network adapter */
	NT_ADAPTER_TYPE_NT4E_PORT, /* NTPORT4E expansion adapter */
	NT_ADAPTER_TYPE_NTBPE, /* NTBPE bypass adapter */
	NT_ADAPTER_TYPE_NT20E2, /* NT20E2 network adapter */
	NT_ADAPTER_TYPE_RESERVED1, /* Reserved */
	NT_ADAPTER_TYPE_RESERVED2, /* Reserved */
	NT_ADAPTER_TYPE_NT40E2_1, /* NT40E2-1 network adapter */
	NT_ADAPTER_TYPE_NT40E2_4, /* NT40E2-4 network adapter */
	NT_ADAPTER_TYPE_NT4E2_4T_BP, /* NT4E2-4T-BP bypass network adapter */
	NT_ADAPTER_TYPE_NT4E2_4_PTP, /* NT4E2-4 PTP network adapter with IEEE1588 */
	NT_ADAPTER_TYPE_NT20E2_PTP, /* NT20E2 PTP network adapter with IEEE1588 */
	NT_ADAPTER_TYPE_NT40E3_4_PTP, /* NT40E3 network adapter with IEEE1588 */
	NT_ADAPTER_TYPE_NT100E3_1_PTP, /* NT100E3 network adapter with IEEE1588 */
	NT_ADAPTER_TYPE_NT20E3_2_PTP, /* NT20E3 network adapter with IEEE1588 */
	NT_ADAPTER_TYPE_NT80E3_2_PTP, /* NT80E3 network adapter with IEEE1588 */
	NT_ADAPTER_TYPE_NT200E3_2, /* NT200E3 network adapter */
	NT_ADAPTER_TYPE_NT200A01, /* NT200A01 network adapter */
	NT_ADAPTER_TYPE_NT200A01_2X100 =
		NT_ADAPTER_TYPE_NT200A01, /* NT200A01 2 x 100 Gbps network adapter */
	NT_ADAPTER_TYPE_NT40A01_4X1, /* NT40A01_4X1 network adapter with IEEE1588 */
	NT_ADAPTER_TYPE_NT200A01_2X40, /* NT200A01 2 x 40 Gbps network adapter */
	NT_ADAPTER_TYPE_NT80E3_2_PTP_8X10, /* NT80E3 8 x 10 Gbps network adapter with IEEE1588 */
	/*  */
	NT_ADAPTER_TYPE_INTEL_A10_4X10, /* Intel PAC A10 GX 4 x 10 Gbps network adapter */
	NT_ADAPTER_TYPE_INTEL_A10_1X40, /* Intel PAC A10 GX 1 x 40 Gbps network adapter */
	/*  */
	NT_ADAPTER_TYPE_NT200A01_8X10, /* NT200A01 8 x 10 Gbps network adapter */
	NT_ADAPTER_TYPE_NT200A02_2X100, /* NT200A02 2 x 100 Gbps network adapter */
	NT_ADAPTER_TYPE_NT200A02_2X40, /* NT200A02 2 x 40 Gbps network adapter */
	NT_ADAPTER_TYPE_NT200A01_2X25, /* Deprecated */
	NT_ADAPTER_TYPE_NT200A01_2X10_25 =
		NT_ADAPTER_TYPE_NT200A01_2X25, /* NT200A01 2 x 10/25 Gbps network adapter */
	NT_ADAPTER_TYPE_NT200A02_2X25, /* Deprecated */
	NT_ADAPTER_TYPE_NT200A02_2X10_25 =
		NT_ADAPTER_TYPE_NT200A02_2X25, /* NT200A02 2 x 10/25 Gbps network adapter */
	NT_ADAPTER_TYPE_NT200A02_4X25, /* Deprecated */
	NT_ADAPTER_TYPE_NT200A02_4X10_25 =
		NT_ADAPTER_TYPE_NT200A02_4X25, /* NT200A02 4 x 10/25 Gbps network adapter */
	NT_ADAPTER_TYPE_NT200A02_8X10, /* NT200A02 8 x 10 Gbps network adapter */
	NT_ADAPTER_TYPE_NT50B01_2X25, /* Deprecated */
	NT_ADAPTER_TYPE_NT50B01_2X10_25 =
		NT_ADAPTER_TYPE_NT50B01_2X25, /* NT50B01 2 x 10/25 Gbps network adapter */
	NT_ADAPTER_TYPE_NT200A02_2X1_10, /* NT200A02 2 x 1/10 Gbps network adapter */
	NT_ADAPTER_TYPE_NT100A01_4X1_10, /* NT100A01 4 x 1/10 Gbps network adapter */
	NT_ADAPTER_TYPE_NT100A01_4X10_25, /* NT100A01 4 x 10/25 Gbps network adapter */
	NT_ADAPTER_TYPE_NT50B01_2X1_10, /* NT50B01 2 x 1/10 Gbps network adapter */
	NT_ADAPTER_TYPE_NT40A11_4X1_10, /* NT40A11 4 x 1/10 Gbps network adapter */
#ifndef DOXYGEN_INTERNAL_ONLY
	NT_ADAPTER_TYPE_ML605 = 10000, /* NT20E2 eval board */
#endif
	NT_ADAPTER_TYPE_4GARCH_HAMOA =
		(1U
		 << 29), /* Bit to mark to adapters as a 4GArch Hamoa adapter */
	NT_ADAPTER_TYPE_4GARCH =
		(1U << 30), /* Bit to mark to adapters as a 4GArch adapter */
	/* NOTE: do *NOT* add normal adapters after the group bit mark enums */
};

/* The NT200E3 adapter sensor id's */
typedef enum nt_sensors_adapter_nt200_e3_e {
	/* Public sensors (Level 0) */
	NT_SENSOR_NT200E3_FPGA_TEMP, /* FPGA temperature sensor */
	NT_SENSOR_NT200E3_FAN_SPEED, /* FAN speed sensor */
	/* MCU (Micro Controller Unit) temperature sensor located inside enclosure below FAN */
	NT_SENSOR_NT200E3_MCU_TEMP,
	NT_SENSOR_NT200E3_PSU0_TEMP, /* Power supply 0 temperature sensor */
	NT_SENSOR_NT200E3_PSU1_TEMP, /* Power supply 1 temperature sensor */
	NT_SENSOR_NT200E3_PCB_TEMP, /* PCB temperature sensor */

	/* Diagnostic sensors (Level 1) */
	/* Total power consumption (calculated value) - does not generate alarms */
	NT_SENSOR_NT200E3_NT200E3_POWER,
	/* FPGA power consumption (calculated value) - does not generate alarms */
	NT_SENSOR_NT200E3_FPGA_POWER,
	/* DDR4 RAM power consumption (calculated value) - does not generate alarms */
	NT_SENSOR_NT200E3_DDR4_POWER,
	/* NIM power consumption (calculated value) - does not generate alarms */
	NT_SENSOR_NT200E3_NIM_POWER,

	NT_SENSOR_NT200E3_L1_MAX, /* Number of NT200E3 level 0,1 board sensors */
} nt_sensors_adapter_nt200_e3_t;

/*
 * The following sensors are deprecated - generic types should be used instead
 * The NIM temperature sensor must be the one with the lowest sensor_index
 * (enum value) in order to be shown by the monitoring tool in port mode
 */
enum nt_sensors_port_nt200_e3_2_e {
	/* Public sensors */
	NT_SENSOR_NT200E3_NIM, /* QSFP28 temperature sensor */

	/* Diagnostic sensors (Level 1) */
	NT_SENSOR_NT200E3_SUPPLY, /* QSFP28 supply voltage sensor */
	NT_SENSOR_NT200E3_TX_BIAS1, /* QSFP28 TX bias line 0 current sensor */
	NT_SENSOR_NT200E3_TX_BIAS2, /* QSFP28 TX bias line 1 current sensor */
	NT_SENSOR_NT200E3_TX_BIAS3, /* QSFP28 TX bias line 2 current sensor */
	NT_SENSOR_NT200E3_TX_BIAS4, /* QSFP28 TX bias line 3 current sensor */
	NT_SENSOR_NT200E3_RX1, /* QSFP28 RX line 0 power sensor */
	NT_SENSOR_NT200E3_RX2, /* QSFP28 RX line 1 power sensor */
	NT_SENSOR_NT200E3_RX3, /* QSFP28 RX line 2 power sensor */
	NT_SENSOR_NT200E3_RX4, /* QSFP28 RX line 3 power sensor */
	NT_SENSOR_NT200E3_TX1, /* QSFP28 TX line 0 power sensor */
	NT_SENSOR_NT200E3_TX2, /* QSFP28 TX line 1 power sensor */
	NT_SENSOR_NT200E3_TX3, /* QSFP28 TX line 2 power sensor */
	NT_SENSOR_NT200E3_TX4, /* QSFP28 TX line 3 power sensor */
	NT_SENSOR_NT200E3_PORT_MAX, /* Number of NT200E3 port sensors */
};

#endif

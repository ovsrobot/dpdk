/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _NTNIC_SENSOR_H_
#define _NTNIC_SENSOR_H_

#include "nthw_fpga_model.h"
#include "nthw_spis.h"

#define SENSOR_MON_UINT16_NAN 0xFFFF	/* Most positive number used as NaN */
#define SENSOR_MON_INT16_NAN ((int16_t)0x8000)	/* Most negative number used as NaN */

/*
 * Sensor types
 */

#pragma pack(1)
struct sensor_mon_setup_data16 {
	uint8_t fpga_idx;	/* Destination of results */
	uint8_t device;	/* Device to monitor */
	uint8_t device_register;/* Sensor within device */
	uint16_t mask;	/* Indicates active bits */
	uint8_t pos;	/* Position of first active bit */
	uint16_t format;/* b0,1:sensor_mon_endian_t endian */
	/* b2,3:sensor_mon_sign_t   sign */
	union {
		struct {
			int16_t limit_low;	/* Signed alarm limit low */
			int16_t limit_high;	/* Signed alarm limit high */
		} int16;

		struct {
			uint16_t limit_low;	/* Unsigned alarm limit low */
			uint16_t limit_high;	/* Unsigned alarm limit high */
		} uint16;
	};
};
#pragma pack()
struct sensor_mon_setup16 {
	uint8_t setup_cnt;	/* Number of entries in setup_data */
	struct sensor_mon_setup_data16 setup_data[40];
};

enum nt_sensor_type_e {
	NT_SENSOR_TYPE_UNKNOWN = 0,
	NT_SENSOR_TYPE_TEMPERATURE = 1,	/* Unit: 0.1 degree Celsius */
	NT_SENSOR_TYPE_VOLTAGE = 2,	/* Unit: 1 mV */
	NT_SENSOR_TYPE_CURRENT = 3,	/* Unit: 1 uA */
	NT_SENSOR_TYPE_POWER = 4,	/* Unit: 0.1 uW */
	NT_SENSOR_TYPE_FAN = 5,	/* Unit: 1 RPM (Revolutions Per Minute) */
	NT_SENSOR_TYPE_HIGH_POWER = 6,	/* Unit: 1 mW */
	NT_SENSOR_TYPE_NUMBER = 7,
};

typedef enum nt_sensor_type_e nt_sensor_type_t;

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

/*
 * Sensor subtypes
 */
enum nt_sensor_sub_type_e {
	NT_SENSOR_SUBTYPE_NA = 0,
	/*
	 * Subtype for NT_SENSOR_TYPE_POWER type on optical modules
	 * (optical modulation amplitude measured)
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
	NT_SENSOR_SOURCE_UNKNOWN = 0x00,/* Unknown source */
	/* Sensors located in a port. These are primary sensors - usually NIM temperature.
	 * Presence depends on adapter and NIM type.
	 */
	NT_SENSOR_SOURCE_PORT = 0x01,
	/*
	 * Level 1 sensors located in a port.
	 * These are secondary sensors - usually NIM supply voltage,
	 * Tx bias and Rx/Tx optical power. Presence depends on adapter and NIM type.
	 */
	NT_SENSOR_SOURCE_LEVEL1_PORT = 0x02,
#ifndef DOXYGEN_INTERNAL_ONLY
	NT_SENSOR_SOURCE_LEVEL2_PORT = 0x04,	/* Level 2 sensors located in a port */
#endif
	NT_SENSOR_SOURCE_ADAPTER = 0x08,/* Sensors mounted on the adapter */
	NT_SENSOR_SOURCE_LEVEL1_ADAPTER = 0x10,	/* Level 1 sensors mounted on the adapter */
#ifndef DOXYGEN_INTERNAL_ONLY
	NT_SENSOR_SOURCE_LEVEL2_ADAPTER = 0x20,	/* Level 2 sensors mounted on the adapter */
#endif
};

/*
 * Sensor state
 */
enum nt_sensor_state_e {
	NT_SENSOR_STATE_UNKNOWN = 0,	/* Unknown state */
	NT_SENSOR_STATE_INITIALIZING = 1,	/* The sensor is initializing */
	NT_SENSOR_STATE_NORMAL = 2,	/* Sensor values are within range */
	NT_SENSOR_STATE_ALARM = 3,	/* Sensor values are out of range */
	/* The sensor is not present, for example, SFP without diagnostics */
	NT_SENSOR_STATE_NOT_PRESENT = 4
};

typedef enum nt_sensor_state_e nt_sensor_state_t;

/*
 * Sensor value
 */

/* Indicates that sensor value or sensor limit is not valid (Not a Number) */
#define NT_SENSOR_NAN 0x80000000

enum nt_sensors_e {
	/* Public sensors (Level 0) */
	NT_SENSOR_FPGA_TEMP,	/* FPGA temperature sensor */
};

/*
 * Adapter types
 */
enum nt_adapter_type_e {
	NT_ADAPTER_TYPE_UNKNOWN = 0,	/* Unknown adapter type */
	NT_ADAPTER_TYPE_NT4E,	/* NT4E network adapter */
	NT_ADAPTER_TYPE_NT20E,	/* NT20E network adapter */
	NT_ADAPTER_TYPE_NT4E_STD,	/* NT4E-STD network adapter */
	NT_ADAPTER_TYPE_NT4E_PORT,	/* NTPORT4E expansion adapter */
	NT_ADAPTER_TYPE_NTBPE,	/* NTBPE bypass adapter */
	NT_ADAPTER_TYPE_NT20E2,	/* NT20E2 network adapter */
	NT_ADAPTER_TYPE_RESERVED1,	/* Reserved */
	NT_ADAPTER_TYPE_RESERVED2,	/* Reserved */
	NT_ADAPTER_TYPE_NT40E2_1,	/* NT40E2-1 network adapter */
	NT_ADAPTER_TYPE_NT40E2_4,	/* NT40E2-4 network adapter */
	NT_ADAPTER_TYPE_NT4E2_4T_BP,	/* NT4E2-4T-BP bypass network adapter */
	NT_ADAPTER_TYPE_NT4E2_4_PTP,	/* NT4E2-4 PTP network adapter with IEEE1588 */
	NT_ADAPTER_TYPE_NT20E2_PTP,	/* NT20E2 PTP network adapter with IEEE1588 */
	NT_ADAPTER_TYPE_NT40E3_4_PTP,	/* NT40E3 network adapter with IEEE1588 */
	NT_ADAPTER_TYPE_NT100E3_1_PTP,	/* NT100E3 network adapter with IEEE1588 */
	NT_ADAPTER_TYPE_NT20E3_2_PTP,	/* NT20E3 network adapter with IEEE1588 */
	NT_ADAPTER_TYPE_NT80E3_2_PTP,	/* NT80E3 network adapter with IEEE1588 */
	NT_ADAPTER_TYPE_NT200E3_2,	/* NT200E3 network adapter */
	NT_ADAPTER_TYPE_NT200A01,	/* NT200A01 network adapter */
	/* NT200A01 2 x 100 Gbps network adapter */
	NT_ADAPTER_TYPE_NT200A01_2X100 = NT_ADAPTER_TYPE_NT200A01,
	NT_ADAPTER_TYPE_NT40A01_4X1,	/* NT40A01_4X1 network adapter with IEEE1588 */
	NT_ADAPTER_TYPE_NT200A01_2X40,	/* NT200A01 2 x 40 Gbps network adapter */
	/* NT80E3 8 x 10 Gbps network adapter with IEEE1588 */
	NT_ADAPTER_TYPE_NT80E3_2_PTP_8X10,
	/*  */
	NT_ADAPTER_TYPE_INTEL_A10_4X10,	/* Intel PAC A10 GX 4 x 10 Gbps network adapter */
	NT_ADAPTER_TYPE_INTEL_A10_1X40,	/* Intel PAC A10 GX 1 x 40 Gbps network adapter */
	/*  */
	NT_ADAPTER_TYPE_NT200A01_8X10,	/* NT200A01 8 x 10 Gbps network adapter */
	NT_ADAPTER_TYPE_NT200A02_2X100,	/* NT200A02 2 x 100 Gbps network adapter */
	NT_ADAPTER_TYPE_NT200A02_2X40,	/* NT200A02 2 x 40 Gbps network adapter */
	NT_ADAPTER_TYPE_NT200A01_2X25,	/* Deprecated */
	/* NT200A01 2 x 10/25 Gbps network adapter */
	NT_ADAPTER_TYPE_NT200A01_2X10_25 = NT_ADAPTER_TYPE_NT200A01_2X25,
	NT_ADAPTER_TYPE_NT200A02_2X25,	/* Deprecated */
	/* NT200A02 2 x 10/25 Gbps network adapter */
	NT_ADAPTER_TYPE_NT200A02_2X10_25 = NT_ADAPTER_TYPE_NT200A02_2X25,
	NT_ADAPTER_TYPE_NT200A02_4X25,	/* Deprecated */
	/* NT200A02 4 x 10/25 Gbps network adapter */
	NT_ADAPTER_TYPE_NT200A02_4X10_25 = NT_ADAPTER_TYPE_NT200A02_4X25,
	NT_ADAPTER_TYPE_NT200A02_8X10,	/* NT200A02 8 x 10 Gbps network adapter */
	NT_ADAPTER_TYPE_NT50B01_2X25,	/* Deprecated */
	/* NT50B01 2 x 10/25 Gbps network adapter */
	NT_ADAPTER_TYPE_NT50B01_2X10_25 = NT_ADAPTER_TYPE_NT50B01_2X25,
	NT_ADAPTER_TYPE_NT200A02_2X1_10,/* NT200A02 2 x 1/10 Gbps network adapter */
	NT_ADAPTER_TYPE_NT100A01_4X1_10,/* NT100A01 4 x 1/10 Gbps network adapter */
	NT_ADAPTER_TYPE_NT100A01_4X10_25,	/* NT100A01 4 x 10/25 Gbps network adapter */
	NT_ADAPTER_TYPE_NT50B01_2X1_10,	/* NT50B01 2 x 1/10 Gbps network adapter */
	NT_ADAPTER_TYPE_NT40A11_4X1_10,	/* NT40A11 4 x 1/10 Gbps network adapter */
	NT_ADAPTER_TYPE_NT400D11_2X100,	/*!< NT400D11 2 x 100 Gbps network adapter */
#ifndef DOXYGEN_INTERNAL_ONLY
	NT_ADAPTER_TYPE_ML605 = 10000,	/* NT20E2 eval board */
#endif
	NT_ADAPTER_TYPE_4GARCH_HAMOA =
		(1U << 29),	/* Bit to mark to adapters as a 4GArch Hamoa adapter */
	NT_ADAPTER_TYPE_4GARCH = (1U << 30),	/* Bit to mark to adapters as a 4GArch adapter */
	/* NOTE: do *NOT* add normal adapters after the group bit mark enums */
};

/* The NT200E3 adapter sensor id's */
typedef enum nt_sensors_adapter_nt200_e3_e {
	/* Public sensors (Level 0) */
	NT_SENSOR_NT200E3_FPGA_TEMP,	/* FPGA temperature sensor */
	NT_SENSOR_NT200E3_FAN_SPEED,	/* FAN speed sensor */
	/* MCU (Micro Controller Unit) temperature sensor located inside enclosure below FAN */
	NT_SENSOR_NT200E3_MCU_TEMP,
	NT_SENSOR_NT200E3_PSU0_TEMP,	/* Power supply 0 temperature sensor */
	NT_SENSOR_NT200E3_PSU1_TEMP,	/* Power supply 1 temperature sensor */
	NT_SENSOR_NT200E3_PCB_TEMP,	/* PCB temperature sensor */

	/* Diagnostic sensors (Level 1) */
	/* Total power consumption (calculated value) - does not generate alarms */
	NT_SENSOR_NT200E3_NT200E3_POWER,
	/* FPGA power consumption (calculated value) - does not generate alarms */
	NT_SENSOR_NT200E3_FPGA_POWER,
	/* DDR4 RAM power consumption (calculated value) - does not generate alarms */
	NT_SENSOR_NT200E3_DDR4_POWER,
	/* NIM power consumption (calculated value) - does not generate alarms */
	NT_SENSOR_NT200E3_NIM_POWER,

	NT_SENSOR_NT200E3_L1_MAX,	/* Number of NT200E3 level 0,1 board sensors */
} nt_sensors_adapter_nt200_e3_t;

/* The following sensors are deprecated - generic types should be used instead */
/* The NIM temperature sensor must be the one with the lowest sensor_index */
/* (enum value) in order to be shown by the monitoring tool in port mode */
enum nt_sensors_port_nt200_e3_2_e {
	/* Public sensors */
	NT_SENSOR_NT200E3_NIM,	/* QSFP28 temperature sensor */

	/* Diagnostic sensors (Level 1) */
	NT_SENSOR_NT200E3_SUPPLY,	/* QSFP28 supply voltage sensor */
	NT_SENSOR_NT200E3_TX_BIAS1,	/* QSFP28 TX bias line 0 current sensor */
	NT_SENSOR_NT200E3_TX_BIAS2,	/* QSFP28 TX bias line 1 current sensor */
	NT_SENSOR_NT200E3_TX_BIAS3,	/* QSFP28 TX bias line 2 current sensor */
	NT_SENSOR_NT200E3_TX_BIAS4,	/* QSFP28 TX bias line 3 current sensor */
	NT_SENSOR_NT200E3_RX1,	/* QSFP28 RX line 0 power sensor */
	NT_SENSOR_NT200E3_RX2,	/* QSFP28 RX line 1 power sensor */
	NT_SENSOR_NT200E3_RX3,	/* QSFP28 RX line 2 power sensor */
	NT_SENSOR_NT200E3_RX4,	/* QSFP28 RX line 3 power sensor */
	NT_SENSOR_NT200E3_TX1,	/* QSFP28 TX line 0 power sensor */
	NT_SENSOR_NT200E3_TX2,	/* QSFP28 TX line 1 power sensor */
	NT_SENSOR_NT200E3_TX3,	/* QSFP28 TX line 2 power sensor */
	NT_SENSOR_NT200E3_TX4,	/* QSFP28 TX line 3 power sensor */
	NT_SENSOR_NT200E3_PORT_MAX,	/* Number of NT200E3 port sensors */
};

typedef enum nt_sensors_adapter_nt400d11_e {
	/*
	 * Public sensors (Level 0)
	 * NT_SENSOR_NT400D11_FPGA_TEMP,               //!< FPGA temperature sensor
	 */
	/* !< FPGA temperature sensor 2 = NT_SENSOR_NT400D11_FPGA_TEMP */
	NT_SENSOR_NT400D11_TEMP2_TEMP_CORE_FABRIC,
	NT_SENSOR_NT400D11_FAN_SPEED,	/* !< FAN speed sensor */
	/* !< MCU (Micro Controller Unit) temperature sensor located inside enclosure below FAN */
	NT_SENSOR_NT400D11_MCU_TEMP,
	NT_SENSOR_NT400D11_PSU1_TEMP,	/* !< Power supply 1 temperature sensor */
	NT_SENSOR_NT400D11_PSU2_TEMP,	/* !< Power supply 2 temperature sensor */
	NT_SENSOR_NT400D11_PSU3_TEMP,	/* !< Power supply 3 temperature sensor */
	NT_SENSOR_NT400D11_PSU5_TEMP,	/* !< Power supply 5 temperature sensor */
	NT_SENSOR_NT400D11_L1_MAX,	/* !< Number of NT400D11 level 0,1 board sensors */
} nt_sensors_adapter_nt400_d11_t;

typedef enum nt_sensors_adapter_nt400_d11_level2_t {
	/* Supportinfo sensors (Level 2) */
	/* !< FPGA temperature sensor 1 */
	NT_SENSOR_NT400D11_TEMP3_TEMP_INLET = NT_SENSOR_NT400D11_L1_MAX,
	NT_SENSOR_NT400D11_L2_MAX
} nt_sensors_adapter_nt400_d11_level2_t;

enum nt_sensor_event_alarm_e {
	NT_SENSOR_ENABLE_ALARM,
	NT_SENSOR_LOG_ALARM,
	NT_SENSOR_DISABLE_ALARM,
};

/*
 * Specify the nature of the raw data. AVR and ntservice must use this
 * information when comparing or converting to native format which is little endian
 */
enum sensor_mon_endian {
	SENSOR_MON_LITTLE_ENDIAN,
	SENSOR_MON_BIG_ENDIAN
};

enum sensor_mon_sign {
	SENSOR_MON_UNSIGNED,
	SENSOR_MON_SIGNED,	/* 2's complement */
};

/* Define sensor devices */
enum sensor_mon_device {
	SENSOR_MON_PSU_EXAR_7724_0 = 0,	/* NT40E3, NT100E3 */
	SENSOR_MON_PSU_EXAR_7724_1,	/* NT40E3, NT100E3 */
	SENSOR_MON_PSU_LTM_4676_0,	/* na      NT100E3, page-0 */
	SENSOR_MON_PSU_LTM_4676_1,	/* na      NT100E3, page-0 */
	SENSOR_MON_INA219_1,	/* NT40E3, NT100E3 */
	SENSOR_MON_INA219_2,	/* NT40E3, NT100E3 */
	SENSOR_MON_MAX6642,	/* NT40E3, NT100E3 */
	SENSOR_MON_DS1775,	/* NT40E3, NT100E3 */
	SENSOR_MON_FAN,	/* NT40E3, NT100E3 */
	SENSOR_MON_AVR,	/* NT40E3, NT100E3 */
	SENSOR_MON_PEX8734,	/* na      NT100E3 */
	SENSOR_MON_RATE_COUNT,	/* NT40E3, NT100E3 */
	SENSOR_MON_PSU_LTM_4676_0_1,	/* na      NT100E3, page-1 */
	SENSOR_MON_PSU_LTM_4676_1_1,	/* na      NT100E3, page-1 */
	SENSOR_MON_MP2886A,	/* na,     na,      NT200A02, */
	SENSOR_MON_PSU_EM2260_1,/*     na,      na,      na,       na, NT200D01^M */
	SENSOR_MON_PSU_EM2120_2,/*     na,      na,      na,       na, NT200D01^M */
	/*     na,      na,      na, NT200A02,        na,   NT50B01, */
	SENSOR_MON_MP2886A_PSU_1,
	/*     na,      na,      na, NT200A02,        na,   NT50B01, */
	SENSOR_MON_MP8869S_PSU_2,
	/*     na,      na,      na, NT200A02,        na,   NT50B01, */
	SENSOR_MON_MP8645PGVT_PSU_3,
	/*     na,      na,      na, NT200A02,        na,   NT50B01, */
	SENSOR_MON_MP8645PGVT_PSU_4,
	/*     na,      na,      na, NT200A02,        na,   NT50B01, */
	SENSOR_MON_MP8869S_PSU_5,
	/*     na,      na,      na, NT200A02,        na,   NT50B01, */
	SENSOR_MON_MP8869S_PSU_6,
	/* NT40E3,      na,      na,      na,         na,        na,       na */
	SENSOR_MON_NT40E3_MP8869S_PSU_1,
	/* NT40E3,      na,      na,      na,         na,        na,       na */
	SENSOR_MON_NT40E3_MP8645PGVT_PSU_2,
	/* NT40E3,      na,      na,      na,         na,        na,       na */
	SENSOR_MON_NT40E3_MP8869S_PSU_4,
	/* NT40E3,      na,      na,      na,         na,        na,       na */
	SENSOR_MON_NT40E3_MP8869S_PSU_6,
	/* NT40E3,      na,      na,      na,         na,        na,       na */
	SENSOR_MON_NT40E3_MP8869S_PSU_7,
	/* NT40E3,      na,      na,      na,         na,        na,       na */
	SENSOR_MON_NT40E3_MP8869S_PSU_8,
	/*     na,      na,      na,      na,         na,        na,       na,  NT400D11 */
	SENSOR_MON_MPS_PSU_1,
	/*     na,      na,      na,      na,         na,        na,       na,  NT400D11 */
	SENSOR_MON_MPS_PSU_2_PAGE_0,
	/*     na,      na,      na,      na,         na,        na,       na,  NT400D11 */
	SENSOR_MON_MPS_PSU_3,
	/*     na,      na,      na,      na,         na,        na,       na,  NT400D11 */
	SENSOR_MON_MPS_PSU_4,
	/*     na,      na,      na,      na,         na,        na,       na,  NT400D11 */
	SENSOR_MON_MPS_PSU_5,
	/*     na,      na,      na,      na,         na,        na,       na,  NT400D11 */
	SENSOR_MON_MPS_PSU_6,
	/*     na,      na,      na,      na,         na,        na,       na,  NT400D11 */
	SENSOR_MON_TMP464_1,
	/*     na,      na,      na,      na,         na,        na,       na,  NT400D11 */
	SENSOR_MON_TMP464_2,
	/*     na,      na,      na,      na,         na,        na,       na,  NT400D11 */
	SENSOR_MON_INA3221,
	/*     na,      na,      na,      na,         na,        na,       na,  NT400D11 */
	SENSOR_MON_MPS_PSU_2_PAGE_1,
	/*     na,      na,      na,      na,         na,        na,       na,  NT400D11 */
	SENSOR_MON_DEVICE_COUNT
};

/* Define sensor monitoring control */
enum sensor_mon_control {
	SENSOR_MON_CTRL_STOP = 0,	/* Stop sensor monitoring */
	SENSOR_MON_CTRL_RUN = 1,/* Start sensor monitoring */
	SENSOR_MON_CTRL_REM_ALL_SENSORS = 2,	/* Stop and remove all sensor monitoring setup */
};

/*
 * This structure will return the sensor specific information
 *
 * The units used for the fields: value, value_lowest, value_highest, limit_low and
 * limit_high depend on the type field. See @ref NtSensorType_e.
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
	/* The source of the sensor (port or adapter on which the sensor resides) */
	enum nt_sensor_source_e source;
	/*
	 * The source index - the adapter number for
	 * adapter sensors and port number for port sensors
	 */
	uint32_t source_index;
	/*
	 * The sensor index within the source index
	 * (sensor number on the adapter or sensor number on the port)
	 */
	uint32_t sensor_index;
	enum nt_sensor_type_e type;	/* The sensor type */
	enum nt_sensor_sub_type_e subtype;	/* The sensor subtype (if applicable) */
	enum nt_sensor_state_e state;	/* The current state (normal or alarm) */
	int32_t value;	/* The current value */
	int32_t value_lowest;	/* The lowest value registered */
	int32_t value_highest;	/* The highest value registered */
	char name[NT_INFO_SENSOR_NAME + 1];	/* The sensor name */
	enum nt_adapter_type_e adaptertype;	/* The adapter type where the sensor resides */
};

/*
 * Port of the sensor class
 */
struct nt_adapter_sensor {
	uint8_t m_adapter_no;
	uint8_t m_intf_no;
	uint8_t fpga_idx;	/* for AVR sensors */
	enum sensor_mon_sign si;
	struct nt_info_sensor_s info;
	enum nt_sensor_event_alarm_e alarm;
	bool m_enable_alarm;
};

struct nt_fpga_sensor_monitor {
	nthw_fpga_t *FPGA;
	nthw_module_t *mod;

	nthw_register_t *reg;
	nthw_field_t **fields;
	uint8_t fields_num;
};

/*
 * Sensor description.
 * Describe the static behavior of the sensor.
 */
struct nt_adapter_sensor_description {
	enum nt_sensor_type_e type;	/* Sensor type. */
	enum nt_sensor_sub_type_e subtype;	/* Sensor subtype (if any applicable) */
	unsigned int index;	/* Sensor group index. */
	enum nt_sensor_event_alarm_e event_alarm;	/* Enable/Disable event alarm */
	char name[20];	/* Sensor name. */
};

struct nt_sensor_group {
	struct nt_adapter_sensor *sensor;
	struct nt_fpga_sensor_monitor *monitor;
	void (*read)(struct nt_sensor_group *sg, nthw_spis_t *t_spi);

	/* conv params are needed to call current conversion functions */
	int (*conv_func)(uint32_t p_sensor_result);
	/* i2c interface for NIM sensors */

	struct nt_sensor_group *next;
};

/* The NT200A02 adapter sensor id's */
enum nt_sensors_adapter_nt200a02_e {
	/* Public sensors (Level 0) */
	NT_SENSOR_NT200A02_FPGA_TEMP,	/* FPGA temperature sensor */
	NT_SENSOR_NT200A02_FAN_SPEED,	/* FAN speed sensor */
	/* MCU (Micro Controller Unit) temperature sensor located inside enclosure below FAN */
	NT_SENSOR_NT200A02_MCU_TEMP,
	NT_SENSOR_NT200A02_PSU0_TEMP,	/* Power supply 0 temperature sensor */
	NT_SENSOR_NT200A02_PSU1_TEMP,	/* Power supply 1 temperature sensor */
	NT_SENSOR_NT200A02_PCB_TEMP,	/* PCB temperature sensor */

	/* Diagnostic sensors (Level 1) */
	/* Total power consumption (calculated value) - does not generate alarms */
	NT_SENSOR_NT200A02_NT200A02_POWER,
	/* FPGA power consumption (calculated value) - does not generate alarms */
	NT_SENSOR_NT200A02_FPGA_POWER,
	/* DDR4 RAM power consumption (calculated value) - does not generate alarms */
	NT_SENSOR_NT200A02_DDR4_POWER,
	/* NIM power consumption (calculated value) - does not generate alarms */
	NT_SENSOR_NT200A02_NIM_POWER,
	/* Number of NT200A01 level 0,1 board sensors */
	NT_SENSOR_NT200A02_L1_MAX,
};

#endif	/* _NTNIC_SENSOR_H_ */

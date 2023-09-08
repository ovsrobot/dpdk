/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _AVR_INTF
#define _AVR_INTF

#include <stdint.h>

#define SENSOR_MON_UINT16_NAN 0xFFFF /* Most positive number used as NaN */
#define SENSOR_MON_INT16_NAN \
	((int16_t)0x8000) /* Most negative number used as NaN */

/*
 * Specify the nature of the raw data. AVR and ntservice must use this
 * information when comparing or converting to native format which is little endian
 */
enum sensor_mon_endian { SENSOR_MON_LITTLE_ENDIAN, SENSOR_MON_BIG_ENDIAN };

enum sensor_mon_sign {
	SENSOR_MON_UNSIGNED,
	SENSOR_MON_SIGNED, /* 2's complement */
};

/* Define sensor devices */
enum sensor_mon_device {
	SENSOR_MON_PSU_EXAR_7724_0 = 0, /* NT40E3, NT100E3 */
	SENSOR_MON_PSU_EXAR_7724_1, /* NT40E3, NT100E3 */
	SENSOR_MON_PSU_LTM_4676_0, /* na      NT100E3, page-0 */
	SENSOR_MON_PSU_LTM_4676_1, /* na      NT100E3, page-0 */
	SENSOR_MON_INA219_1, /* NT40E3, NT100E3 */
	SENSOR_MON_INA219_2, /* NT40E3, NT100E3 */
	SENSOR_MON_MAX6642, /* NT40E3, NT100E3 */
	SENSOR_MON_DS1775, /* NT40E3, NT100E3 */
	SENSOR_MON_FAN, /* NT40E3, NT100E3 */
	SENSOR_MON_AVR, /* NT40E3, NT100E3 */
	SENSOR_MON_PEX8734, /* na      NT100E3 */
	SENSOR_MON_RATE_COUNT, /* NT40E3, NT100E3 */
	SENSOR_MON_PSU_LTM_4676_0_1, /* na      NT100E3, page-1 */
	SENSOR_MON_PSU_LTM_4676_1_1, /* na      NT100E3, page-1 */
	SENSOR_MON_MP2886A, /* na,     na,      NT200A02, */
	SENSOR_MON_PSU_EM2260_1, /*     na,      na,      na,       na, NT200D01^M */
	SENSOR_MON_PSU_EM2120_2, /*     na,      na,      na,       na, NT200D01^M */
	SENSOR_MON_MP2886A_PSU_1, /*     na,      na,      na, NT200A02,        na,   NT50B01, */
	SENSOR_MON_MP8869S_PSU_2, /*     na,      na,      na, NT200A02,        na,   NT50B01, */
	SENSOR_MON_MP8645PGVT_PSU_3, /*     na,      na,      na, NT200A02,        na,   NT50B01, */
	SENSOR_MON_MP8645PGVT_PSU_4, /*     na,      na,      na, NT200A02,        na,   NT50B01, */
	SENSOR_MON_MP8869S_PSU_5, /*     na,      na,      na, NT200A02,        na,   NT50B01, */
	SENSOR_MON_MP8869S_PSU_6, /*     na,      na,      na, NT200A02,        na,   NT50B01, */
	SENSOR_MON_DEVICE_COUNT
};

#pragma pack(1)
struct sensor_mon_setup_data16 {
	uint8_t fpga_idx; /* Destination of results */
	uint8_t device; /* Device to monitor */
	uint8_t device_register; /* Sensor within device */
	uint16_t mask; /* Indicates active bits */
	uint8_t pos; /* Position of first active bit */
	uint16_t format; /* b0,1:sensor_mon_endian_t endian */
	/* b2,3:sensor_mon_sign_t   sign */
	union {
		struct {
			int16_t limit_low; /* Signed alarm limit low */
			int16_t limit_high; /* Signed alarm limit high */
		} int16;

		struct {
			uint16_t limit_low; /* Unsigned alarm limit low */
			uint16_t limit_high; /* Unsigned alarm limit high */
		} uint16;
	};
};

#pragma pack()
struct sensor_mon_setup16 {
	uint8_t setup_cnt; /* Number of entries in setup_data */
	struct sensor_mon_setup_data16 setup_data[40];
};

/* Define sensor monitoring control */
enum sensor_mon_control {
	SENSOR_MON_CTRL_STOP = 0, /* Stop sensor monitoring */
	SENSOR_MON_CTRL_RUN = 1, /* Start sensor monitoring */
	SENSOR_MON_CTRL_REM_ALL_SENSORS =
		2, /* Stop and remove all sensor monitoring setup */
};

#endif /* _AVR_INTF */

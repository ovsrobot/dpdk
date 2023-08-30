/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _SENSORS_H
#define _SENSORS_H

#include "sensor_types.h"
#include "stream_info.h"
#include "nthw_platform_drv.h"
#include "nthw_drv.h"
#include "nthw_spi_v3.h"
#include "nthw_fpga_model.h"

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <limits.h>
#include "avr_intf.h"

enum nt_sensor_event_alarm_e {
	NT_SENSOR_ENABLE_ALARM,
	NT_SENSOR_LOG_ALARM,
	NT_SENSOR_DISABLE_ALARM,
};

/*
 * Sensor Class types
 */
enum nt_sensor_class_e {
	NT_SENSOR_CLASS_FPGA =
		0, /* Class for FPGA based sensors e.g FPGA temperature */
	NT_SENSOR_CLASS_MCU =
		1, /* Class for MCU based sensors e.g MCU temperature */
	NT_SENSOR_CLASS_PSU =
		2, /* Class for PSU based sensors e.g PSU temperature */
	NT_SENSOR_CLASS_PCB =
		3, /* Class for PCB based sensors e.g PCB temperature */
	NT_SENSOR_CLASS_NIM =
		4, /* Class for NIM based sensors e.g NIM temperature */
	NT_SENSOR_CLASS_ANY = 5, /* Class for ANY sensors e.g any sensors */
};

typedef enum nt_sensor_class_e nt_sensor_class_t;

/*
 * Port of the sensor class
 */
struct nt_adapter_sensor {
	uint8_t m_adapter_no;
	uint8_t m_intf_no;
	uint8_t fpga_idx; /* for AVR sensors */
	enum sensor_mon_sign si;
	struct nt_info_sensor_s info;
	enum nt_sensor_event_alarm_e alarm;
	bool m_enable_alarm;
};

struct nt_fpga_sensor_monitor {
	nt_fpga_t *fpga;
	nt_module_t *mod;

	nt_register_t *reg;
	nt_field_t **fields;
	uint8_t fields_num;
};

/*
 * Sensor description.
 * Describe the static behavior of the sensor.
 */
struct nt_adapter_sensor_description {
	enum nt_sensor_type_e type; /* Sensor type. */
	enum nt_sensor_sub_type_e sub_type; /* Sensor subtype (if any applicable) */
	unsigned int index; /* Sensor group index. */
	enum nt_sensor_event_alarm_e event_alarm; /* Enable/Disable event alarm */
	char name[20]; /* Sensor name. */
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

void init_sensor_group(struct nt_sensor_group *sg);

void update_sensor_value(struct nt_adapter_sensor *sensor, int32_t value);

void sensor_deinit(struct nt_sensor_group *sg);

/* getters */
int32_t get_value(struct nt_sensor_group *sg);
int32_t get_lowest(struct nt_sensor_group *sg);
int32_t get_highest(struct nt_sensor_group *sg);
char *get_name(struct nt_sensor_group *sg);

struct nt_adapter_sensor *
allocate_sensor(uint8_t adapter_or_port_index, const char *p_name,
		enum nt_sensor_source_e ssrc, enum nt_sensor_type_e type,
		unsigned int index, enum nt_sensor_event_alarm_e event_alarm,
		enum sensor_mon_sign si);
struct nt_adapter_sensor *
allocate_sensor_by_description(uint8_t adapter_or_port_index,
			       enum nt_sensor_source_e ssrc,
			       struct nt_adapter_sensor_description *descr);

/* conversion functions */
int null_signed(uint32_t p_sensor_result);
int null_unsigned(uint32_t p_sensor_result);
int exar7724_tj(uint32_t p_sensor_result);
int max6642_t(uint32_t p_sensor_result);
int ds1775_t(uint32_t p_sensor_result);
int ltm4676_tj(uint32_t p_sensor_result);
int exar7724_vch(uint32_t p_sensor_result);
int exar7724_vin(uint32_t p_sensor_result);
int mp2886a_tj(uint32_t p_sensor_result);
int fan(uint32_t p_sensor_result);

#endif /* _SENSORS_H */

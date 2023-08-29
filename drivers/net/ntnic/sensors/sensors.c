/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "sensors.h"
#include "ntlog.h"

void sensor_deinit(struct nt_sensor_group *sg)
{
	if (sg) {
		if (sg->sensor)
			free(sg->sensor);
		if (sg->monitor)
			free(sg->monitor);
		free(sg);
	}
}

struct nt_adapter_sensor *
allocate_sensor(uint8_t adapter_or_port_index, const char *p_name,
		enum nt_sensor_source_e ssrc, enum nt_sensor_type_e type,
		unsigned int index, enum nt_sensor_event_alarm_e event_alarm,
		enum sensor_mon_sign si)
{
	struct nt_adapter_sensor *sensor =
		(struct nt_adapter_sensor *)malloc(sizeof(struct nt_adapter_sensor));
	if (sensor == NULL) {
		NT_LOG(ERR, ETHDEV, "%s: sensor is NULL", __func__);
		return NULL;
	}

	sensor->alarm = event_alarm;
	sensor->m_enable_alarm = true;
	sensor->m_intf_no = 0xFF;
	sensor->m_adapter_no = 0xFF;
	sensor->si = si;

	sensor->info.source = ssrc;
	sensor->info.source_index = adapter_or_port_index;
	sensor->info.sensor_index = index;
	sensor->info.type = type;
	sensor->info.sub_type = NT_SENSOR_SUBTYPE_NA;
	sensor->info.state = NT_SENSOR_STATE_INITIALIZING;
	sensor->info.value = NT_SENSOR_NAN;
	sensor->info.value_lowest = NT_SENSOR_NAN;
	sensor->info.value_highest = NT_SENSOR_NAN;
	memset(sensor->info.name, 0, NT_INFO_SENSOR_NAME);
	memcpy(sensor->info.name, p_name,
	       (strlen(p_name) > NT_INFO_SENSOR_NAME) ? NT_INFO_SENSOR_NAME :
	       strlen(p_name));
	sensor->info.name[NT_INFO_SENSOR_NAME] = '\0';

	return sensor;
}

void update_sensor_value(struct nt_adapter_sensor *sensor, int32_t value)
{
	if (sensor == NULL)
		return;
	sensor->info.value = value;
	if (sensor->info.value_highest < value ||
			(unsigned int)sensor->info.value_highest == NT_SENSOR_NAN)
		sensor->info.value_highest = value;
	if (sensor->info.value_lowest > value ||
			(unsigned int)sensor->info.value_lowest == NT_SENSOR_NAN)
		sensor->info.value_lowest = value;
}

struct nt_adapter_sensor *
allocate_sensor_by_description(uint8_t adapter_or_port_index,
			       enum nt_sensor_source_e ssrc,
			       struct nt_adapter_sensor_description *descr)
{
	struct nt_adapter_sensor *sensor =
		(struct nt_adapter_sensor *)malloc(sizeof(struct nt_adapter_sensor));
	if (sensor == NULL) {
		NT_LOG(ERR, ETHDEV, "%s: sensor is NULL", __func__);
		return NULL;
	}

	sensor->alarm = descr->event_alarm;
	sensor->m_enable_alarm = true;
	sensor->m_intf_no = 0xFF;
	sensor->m_adapter_no = 0xFF;
	sensor->si = SENSOR_MON_UNSIGNED;

	sensor->info.source_index = adapter_or_port_index;
	sensor->info.source = ssrc;
	sensor->info.type = descr->type;
	sensor->info.sensor_index = descr->index;
	memset(sensor->info.name, 0, NT_INFO_SENSOR_NAME);
	memcpy(sensor->info.name, descr->name,
	       (strlen(descr->name) > NT_INFO_SENSOR_NAME) ?
	       NT_INFO_SENSOR_NAME :
	       strlen(descr->name));
	sensor->info.name[NT_INFO_SENSOR_NAME] = '\0';

	return sensor;
}

void init_sensor_group(struct nt_sensor_group *sg)
{
	/* Set all pointers to NULL */
	sg->sensor = NULL;
	sg->monitor = NULL;
	sg->next = NULL;
	sg->read = NULL;
	sg->conv_func = NULL;
}

/* Getters */
int32_t get_value(struct nt_sensor_group *sg)
{
	return sg->sensor->info.value;
};

int32_t get_lowest(struct nt_sensor_group *sg)
{
	return sg->sensor->info.value_lowest;
};

int32_t get_highest(struct nt_sensor_group *sg)
{
	return sg->sensor->info.value_highest;
};

char *get_name(struct nt_sensor_group *sg)
{
	return sg->sensor->info.name;
};

/* Conversion functions */
int null_signed(uint32_t p_sensor_result)
{
	return (int16_t)p_sensor_result;
}

int null_unsigned(uint32_t p_sensor_result)
{
	return (uint16_t)p_sensor_result;
}

/*
 * ******************************************************************************
 * For EXAR7724: Convert a read Vch value to Napatech internal representation
 * Doc: Vout = ReadVal * 0.015 (PRESCALE is accounted for)
 * ******************************************************************************
 */
int exar7724_vch(uint32_t p_sensor_result)
{
	return p_sensor_result * 15; /* NT unit: 1mV */
}

/*
 * ******************************************************************************
 * For EXAR7724: Convert a read Vin value to Napatech internal representation
 * Doc: Vout = ReadVal * 0.0125
 * ******************************************************************************
 */
int exar7724_vin(uint32_t p_sensor_result)
{
	return (p_sensor_result * 25) / 2; /* NT unit: 1mV */
}

/*
 * ******************************************************************************
 * For EXAR7724: Convert a read Tj value to Napatech internal representation
 * Doc: Temp (in Kelvin) = (((ReadVal * 10mV) - 600mV) / (2mV/K)) + 300K =
 *                      = ReadVal * 5K
 * ******************************************************************************
 */
int exar7724_tj(uint32_t p_sensor_result)
{
	/*
	 * A value of 2730 is used instead of 2732 which is more correct but since
	 * the temperature step is 5 degrees it is more natural to show these steps
	 */
	return p_sensor_result * 50 - 2730; /* NT unit: 0.1C */
}

/*
 * ******************************************************************************
 * Conversion function for Linear Tecnology Linear_5s_11s format.
 * The functions returns Y * 2**N, where N = b[15:11] is a 5-bit two's complement
 * integer and Y = b[10:0] is an 11-bit two's complement integer.
 * The multiplier value is used for scaling to Napatech units.
 * ******************************************************************************
 */
static int conv5s_11s(uint16_t value, int multiplier)
{
	int n, y;

	y = value & 0x07FF;

	if (value & 0x0400)
		y -= 0x0800; /* The MSBit is a sign bit */

	n = (value >> 11) & 0x1F;

	if (n & 0x10)
		n -= 0x20; /* The MSBit is a sign bit */

	y *= multiplier;

	if (n > 0)
		y *= (1 << n);

	else if (n < 0)
		y /= (1 << (-n));

	return y;
}

/*
 * ******************************************************************************
 * Temperature conversion from Linear_5s_11s format.
 * ******************************************************************************
 */
int ltm4676_tj(uint32_t p_sensor_result)
{
	return (uint16_t)conv5s_11s(p_sensor_result, 10); /* NT unit: 0.1C */
}

/*
 * ******************************************************************************
 * For MP2886a: Convert a read Tj value to Napatech internal representation
 * ******************************************************************************
 */
int mp2886a_tj(uint32_t p_sensor_result)
{
	/*
	 * MPS-2886p: READ_TEMPERATURE (register 0x8Dh)
	 * READ_TEMPERATURE is a 2-byte, unsigned integer.
	 */
	return (uint16_t)p_sensor_result; /* NT unit: 0.1C */
}

/*
 * ******************************************************************************
 * For MAX6642: Convert a read temperature value to Napatech internal representation
 * ******************************************************************************
 */
int max6642_t(uint32_t p_sensor_result)
{
	if ((p_sensor_result >> 8) == 0xFF)
		return NT_SENSOR_NAN;

	/* The six lower bits are not used */
	return (int)(((p_sensor_result >> 6) * 5) /
		     2); /* NT unit: 0.25 deg, Native unit: 0.1C */
}

/*
 * ******************************************************************************
 * For DS1775: Convert a read temperature value to Napatech internal representation
 * ******************************************************************************
 */
int ds1775_t(uint32_t p_sensor_result)
{
	return (p_sensor_result * 10) /
	       256; /* NT unit: 0.1 deg, Native unit: 1/256 C */
}

/*
 * ******************************************************************************
 * For FAN: Convert a tick count to RPM
 * NT unit: RPM, Native unit: 2 ticks/revolution
 * ******************************************************************************
 */
int fan(uint32_t p_sensor_result)
{
	return (p_sensor_result * 60U / 4);
}

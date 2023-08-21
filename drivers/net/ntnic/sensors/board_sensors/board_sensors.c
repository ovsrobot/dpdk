/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <stddef.h>
#include <math.h>

#include "tempmon.h"
#include "board_sensors.h"
#include "ntlog.h"

static void fpga_temperature_sensor_read(struct nt_sensor_group *sg,
		nthw_spis_t *t_spi)
{
	int temp = 0;
	(void)t_spi;
	if (sg == NULL || sg->sensor == NULL) {
		NT_LOG(ERR, ETHDEV, "failed to read FPGA temperature\n");
		return;
	}
	struct nt_fpga_sensor_monitor *temp_monitor = sg->monitor;
	uint32_t val = field_get_updated(temp_monitor->fields[0]);

	temp = (val * 20159 - 44752896) / 16384;

	update_sensor_value(sg->sensor, temp);
}

struct nt_sensor_group *fpga_temperature_sensor_init(uint8_t adapter_no,
		unsigned int sensor_idx,
		nt_fpga_t *p_fpga)
{
	struct nt_sensor_group *sg = malloc(sizeof(struct nt_sensor_group));

	if (sg == NULL) {
		NT_LOG(ERR, ETHDEV, "%s: sensor group is NULL", __func__);
		return NULL;
	}
	init_sensor_group(sg);
	sg->monitor = tempmon_new();
	tempmon_init(sg->monitor, p_fpga);
	sg->sensor =
		allocate_sensor(adapter_no, "FPGA", NT_SENSOR_SOURCE_ADAPTER,
				NT_SENSOR_TYPE_TEMPERATURE, sensor_idx,
				NT_SENSOR_DISABLE_ALARM, SENSOR_MON_UNSIGNED);
	sg->read = &fpga_temperature_sensor_read;
	return sg;
}

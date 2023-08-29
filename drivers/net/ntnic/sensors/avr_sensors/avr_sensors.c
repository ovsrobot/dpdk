/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "avr_sensors.h"
#include "ntlog.h"

#define MAX_ADAPTERS 2

uint8_t s_fpga_indexes[MAX_ADAPTERS] = { 0 }; /* _NTSD_MAX_NUM_ADAPTERS_ */
static uint8_t get_fpga_idx(unsigned int adapter_no);

/*
 * This function setups monitoring of AVR sensors
 */
static uint8_t _avr_sensor_init(nthw_spi_v3_t *s_spi, uint8_t m_adapter_no,
				const char *p_name,
				enum sensor_mon_device avr_dev,
				uint8_t avr_dev_reg, enum sensor_mon_endian end,
				enum sensor_mon_sign si, uint16_t mask)
{
	uint8_t fpga_idx = get_fpga_idx(m_adapter_no);
	struct sensor_mon_setup16 avr_sensor_setup;

	/* Setup monitoring in AVR placing results in FPGA */
	avr_sensor_setup.setup_cnt = 1;
	avr_sensor_setup.setup_data[0].fpga_idx = fpga_idx;
	avr_sensor_setup.setup_data[0].device = avr_dev;
	avr_sensor_setup.setup_data[0].device_register = avr_dev_reg;
	avr_sensor_setup.setup_data[0].format = (uint16_t)(end | si << 2);

	avr_sensor_setup.setup_data[0].mask = mask;
	avr_sensor_setup.setup_data[0].pos =
		0; /* So far for all sensors in table */

	/*
	 * At first it is the task of ntservice to test limit_low and limit_high on all
	 * board sensors. Later the test is going to be carried out by the AVR
	 */
	if (si == SENSOR_MON_SIGNED) {
		avr_sensor_setup.setup_data[0].int16.limit_low =
			SENSOR_MON_INT16_NAN;
		avr_sensor_setup.setup_data[0].int16.limit_high =
			SENSOR_MON_INT16_NAN;
	} else {
		avr_sensor_setup.setup_data[0].uint16.limit_low =
			SENSOR_MON_UINT16_NAN;
		avr_sensor_setup.setup_data[0].uint16.limit_high =
			SENSOR_MON_UINT16_NAN;
	}

	int result = nt_avr_sensor_mon_setup(&avr_sensor_setup, s_spi);

	if (result)
		NT_LOG(ERR, ETHDEV, "%s: sensor initialization error\n", p_name);

	return fpga_idx;
}

static void avr_read(struct nt_sensor_group *sg, nthw_spis_t *t_spi)
{
	uint32_t p_sensor_result;

	if (sg == NULL || sg->sensor == NULL)
		return;

	sensor_read(t_spi, sg->sensor->fpga_idx, &p_sensor_result);
	update_sensor_value(sg->sensor, sg->conv_func(p_sensor_result));
}

struct nt_sensor_group *
avr_sensor_init(nthw_spi_v3_t *s_spi, uint8_t m_adapter_no, const char *p_name,
		enum nt_sensor_source_e ssrc, enum nt_sensor_type_e type,
		unsigned int index, enum sensor_mon_device avr_dev,
		uint8_t avr_dev_reg, enum sensor_mon_endian end,
		enum sensor_mon_sign si, int (*conv_func)(uint32_t),
		uint16_t mask)
{
	struct nt_sensor_group *sg = malloc(sizeof(struct nt_sensor_group));

	if (sg == NULL) {
		NT_LOG(ERR, ETHDEV, "%s: sensor group is NULL", __func__);
		return NULL;
	}
	init_sensor_group(sg);
	sg->sensor = allocate_sensor(m_adapter_no, p_name, ssrc, type, index,
				     NT_SENSOR_DISABLE_ALARM, si);
	sg->sensor->fpga_idx = _avr_sensor_init(s_spi, m_adapter_no, p_name, avr_dev,
					       avr_dev_reg, end, si, mask);
	sg->read = &avr_read;
	sg->conv_func = conv_func;
	sg->monitor = NULL;
	sg->next = NULL;
	return sg;
}

static uint8_t get_fpga_idx(unsigned int adapter_no)
{
	uint8_t tmp = s_fpga_indexes[adapter_no];

	s_fpga_indexes[adapter_no] = (uint8_t)(tmp + 1);

	return tmp;
}

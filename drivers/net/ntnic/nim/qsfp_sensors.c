/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <stdbool.h>

#include "qsfp_sensors.h"

#include "ntlog.h"
#include "qsfp_registers.h"

static bool qsfp_plus_nim_get_sensor(nim_i2c_ctx_p ctx, uint16_t addr,
				   nim_option_t nim_option, uint8_t count,
				   uint16_t *p_lane_values)
{
	(void)nim_option;

	read_data_lin(ctx, addr, (uint16_t)(sizeof(uint16_t) * count),
		    p_lane_values);

	for (int i = 0; i < count; i++) {
		*p_lane_values = (*p_lane_values); /* Swap to little endian */

#ifdef NIM_DMI_TEST_VALUE
		if (nim_option == NIM_OPTION_RX_POWER)
			*p_lane_values = (uint16_t)NIM_DMI_RX_PWR_TEST_VALUE;
		else
			*p_lane_values = (uint16_t)NIM_DMI_TEST_VALUE;
#endif

		p_lane_values++;
	}

	return true;
}

/*
 * Read NIM temperature
 */
static bool qsfp_plus_nim_get_temperature(nim_i2c_ctx_p ctx, int16_t *p_value)
{
	return qsfp_plus_nim_get_sensor(ctx, QSFP_TEMP_LIN_ADDR, NIM_OPTION_TEMP,
				      1, (uint16_t *)p_value);
}

/*
 * Read NIM supply voltage
 */
static bool qsfp_plus_nim_get_supply_voltage(nim_i2c_ctx_p ctx, uint16_t *p_value)
{
	return qsfp_plus_nim_get_sensor(ctx, QSFP_VOLT_LIN_ADDR,
				      NIM_OPTION_SUPPLY, 1, p_value);
}

/*
 * Read NIM bias current for four lanes
 */
static bool qsfp_plus_nim_get_tx_bias_current(nim_i2c_ctx_p ctx, uint16_t *p_value)
{
	return qsfp_plus_nim_get_sensor(ctx, QSFP_TX_BIAS_LIN_ADDR,
				      NIM_OPTION_TX_BIAS, 4, p_value);
}

/*
 * Read NIM TX optical power for four lanes
 */
static bool qsfp_plus_nim_get_tx_power(nim_i2c_ctx_p ctx, uint16_t *p_value)
{
	return qsfp_plus_nim_get_sensor(ctx, QSFP_TX_PWR_LIN_ADDR,
				      NIM_OPTION_TX_POWER, 4, p_value);
}

/*
 * Read NIM RX optical power for four lanes
 */
static bool qsfp_plus_nim_get_rx_power(nim_i2c_ctx_p ctx, uint16_t *p_value)
{
	return qsfp_plus_nim_get_sensor(ctx, QSFP_TX_PWR_LIN_ADDR,
				      NIM_OPTION_RX_POWER, 4, p_value);
}

void nim_read_qsfp_temp(struct nim_sensor_group *sg, nthw_spis_t *t_spi)
{
	int16_t res;
	(void)t_spi;

	if (sg == NULL || sg->ctx == NULL) {
		NT_LOG(ERR, ETHDEV, "%s: bad argument(s)\n", __func__);
		return;
	}

	if (qsfp_plus_nim_get_temperature(sg->ctx, &res))
		update_sensor_value(sg->sensor, (int)(res * 10 / 256));

	else
		update_sensor_value(sg->sensor, -1);
}

void nim_read_qsfp_voltage(struct nim_sensor_group *sg, nthw_spis_t *t_spi)
{
	uint16_t res;
	(void)t_spi;

	if (sg == NULL || sg->ctx == NULL) {
		NT_LOG(ERR, ETHDEV, "%s: bad argument(s)\n", __func__);
		return;
	}

	if (qsfp_plus_nim_get_supply_voltage(sg->ctx, &res))
		update_sensor_value(sg->sensor, (int)((res) / 10));

	else
		update_sensor_value(sg->sensor, -1);
}

void nim_read_qsfp_bias_current(struct nim_sensor_group *sg, nthw_spis_t *t_spi)
{
	uint16_t temp[4] = { 0 };
	(void)t_spi;

	if (sg == NULL || sg->ctx == NULL) {
		NT_LOG(ERR, ETHDEV, "%s: bad argument(s)\n", __func__);
		return;
	}

	bool res = qsfp_plus_nim_get_tx_bias_current(sg->ctx, temp);

	if (res) {
		for (uint8_t i = 0; i < sg->ctx->lane_count; i++)
			update_sensor_value(sg->sensor, (int)temp[i] * 2);
	} else {
		update_sensor_value(sg->sensor, -1);
	}
}

void nim_read_qsfp_tx_power(struct nim_sensor_group *sg, nthw_spis_t *t_spi)
{
	uint16_t temp[4] = { 0 };
	(void)t_spi;

	if (sg == NULL || sg->ctx == NULL) {
		NT_LOG(ERR, ETHDEV, "%s: bad argument(s)\n", __func__);
		return;
	}

	bool res = qsfp_plus_nim_get_tx_power(sg->ctx, temp);

	if (res) {
		for (uint8_t i = 0; i < sg->ctx->lane_count; i++)
			update_sensor_value(sg->sensor, (int)temp[i]);
	} else {
		update_sensor_value(sg->sensor, -1);
	}
}

void nim_read_qsfp_rx_power(struct nim_sensor_group *sg, nthw_spis_t *t_spi)
{
	uint16_t temp[4] = { 0 };
	(void)t_spi;

	if (sg == NULL || sg->ctx == NULL) {
		NT_LOG(ERR, ETHDEV, "%s: bad argument(s)\n", __func__);
		return;
	}

	bool res = qsfp_plus_nim_get_rx_power(sg->ctx, temp);

	if (res) {
		for (uint8_t i = 0; i < sg->ctx->lane_count; i++)
			update_sensor_value(sg->sensor, (int)temp[i]);
	} else {
		update_sensor_value(sg->sensor, -1);
	}
}

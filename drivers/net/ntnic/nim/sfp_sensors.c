/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <arpa/inet.h>
#include <stdbool.h>

#include "ntlog.h"
#include "sfp_sensors.h"

#include "sfp_p_registers.h"

/*
 * Return calibrated data from an SFP module.
 * It is first investigated if external calibration is to be used and if it is
 * calibration data is retrieved. The function can only be used when calibration
 * consists of a slope and offset factor. After function return p_data will point
 * to 16bit data that can be either signed or unsigned.
 */
static bool sfp_nim_get_dmi_data(uint16_t data_addr, uint16_t slope_addr,
			       uint16_t offset_addr, void *p_value,
			       bool signed_data, nim_i2c_ctx_p ctx)
{
	int32_t value;
	uint16_t slope = 1;
	int16_t offset = 0;

	if (!ctx->dmi_supp)
		return false;

	/* Read data in big endian format */
	read_data_lin(ctx, data_addr, 2, p_value);
	*(uint16_t *)p_value =
		htons(*(uint16_t *)p_value); /* Swap to little endian */

	/*
	 * Inject test value which can be both signed and unsigned but handle
	 * here as unsigned
	 */
#ifdef NIM_DMI_TEST_VALUE
	*(uint16_t *)p_value = (uint16_t)NIM_DMI_TEST_VALUE;
#endif

#if defined(NIM_DMI_TEST_SLOPE) || defined(NIM_DMI_TEST_OFFSET)
	ctx->specific_u.sfp.ext_cal = true;
#endif

	if (ctx->specific_u.sfp.ext_cal) {
		/* External calibration is needed */
		read_data_lin(ctx, slope_addr, sizeof(slope), &slope);
		read_data_lin(ctx, offset_addr, sizeof(offset), &offset);

		/* Swap calibration to little endian */
		slope = htons(slope);
		offset = htons(offset);

#ifdef NIM_DMI_TEST_SLOPE
		slope = NIM_DMI_TEST_SLOPE;
#endif

#ifdef NIM_DMI_TEST_OFFSET
		offset = NIM_DMI_TEST_OFFSET; /* 0x0140 equals 1.25 */
#endif

		if (signed_data) {
			value = *(int16_t *)p_value * slope / 256 + offset;

			if (value > INT16_MAX)
				value = INT16_MAX;
			else if (value < INT16_MIN)
				value = INT16_MIN;

			*(int16_t *)p_value = (int16_t)value;
		} else {
			value = *(uint16_t *)p_value * slope / 256 + offset;

			if (value > UINT16_MAX)
				value = UINT16_MAX;
			else if (value < 0)
				value = 0;

			*(uint16_t *)p_value = (uint16_t)value;
		}
	}

	return true;
}

/*
 * Read NIM temperature
 */
static bool sfp_nim_get_temperature(nim_i2c_ctx_p ctx, int16_t *p_value)
{
	return sfp_nim_get_dmi_data(SFP_TEMP_LIN_ADDR, SFP_TEMP_SLOPE_LIN_ADDR,
				  SFP_TEMP_OFFSET_LIN_ADDR, p_value, true, ctx);
}

/*
 * Read NIM supply voltage
 */
static bool sfp_nim_get_supply_voltage(nim_i2c_ctx_p ctx, uint16_t *p_value)
{
	return sfp_nim_get_dmi_data(SFP_VOLT_LIN_ADDR, SFP_VOLT_SLOPE_LIN_ADDR,
				  SFP_VOLT_OFFSET_LIN_ADDR, p_value, false, ctx);
}

/*
 * Read NIM bias current
 */
static bool sfp_nim_get_tx_bias_current(nim_i2c_ctx_p ctx, uint16_t *p_value)
{
	return sfp_nim_get_dmi_data(SFP_TX_BIAS_LIN_ADDR,
				  SFP_TX_BIAS_SLOPE_LIN_ADDR,
				  SFP_TX_BIAS_OFFSET_LIN_ADDR, p_value, false,
				  ctx);
}

/*
 * Read NIM TX optical power
 */
static bool sfp_nim_get_tx_power(nim_i2c_ctx_p ctx, uint16_t *p_value)
{
	return sfp_nim_get_dmi_data(SFP_TX_PWR_LIN_ADDR,
				  SFP_TX_PWR_SLOPE_LIN_ADDR,
				  SFP_TX_PWR_OFFSET_LIN_ADDR, p_value, false,
				  ctx);
}

/*
 * Return the SFP received power in units of 0.1uW from DMI data.
 * If external calibration is necessary, the calibration data is retrieved and
 * the calibration is carried out.
 */
static bool sfp_nim_get_calibrated_rx_power(nim_i2c_ctx_p ctx, uint16_t addr,
		uint16_t *p_value)
{
	float rx_pwr_cal[5];
	float power_raised;
	float rx_power;

	/* Read data in big endian format */
	read_data_lin(ctx, addr, sizeof(*p_value), p_value);
	*(uint16_t *)p_value =
		htons(*(uint16_t *)p_value); /* Swap to little endian */

#ifdef NIM_DMI_RX_PWR_TEST_VALUE
	*p_value = NIM_DMI_RX_PWR_TEST_VALUE;
#endif

#ifdef NIM_DMI_RX_PWR_CAL_DATA
	ctx->specific_u.sfp.ext_cal = true;
#endif

	if (ctx->specific_u.sfp.ext_cal) {
		/* Read calibration data in big endian format */
		read_data_lin(ctx, SFP_RX_PWR_COEFF_LIN_ADDR, sizeof(rx_pwr_cal),
			    rx_pwr_cal);

		for (int i = 0; i < 5; i++) {
			uint32_t *p_val = (uint32_t *)&rx_pwr_cal[i];
			*p_val = ntohl(*p_val); /* 32 bit swap */
		}

#ifdef NIM_DMI_RX_PWR_CAL_DATA
		/* Testdata for verification */
		NIM_DMI_RX_PWR_CAL_DATA
#endif

		/*
		 * If SFP module specifies external calibration - use calibration data
		 * according to the polynomial correction formula
		 * RxPwrCal = Coeff0 + Coeff1 * RxPwr   + Coeff2 * RxPwr^2 +
		 *                     Coeff3 * RxPwr^3 + Coeff4 * RxPwr^4
		 */
		power_raised = 1.0;
		rx_power = rx_pwr_cal[4]; /* Coeff0 */

		for (int i = 3; i >= 0; i--) {
			power_raised *= (float)*p_value;
			rx_power += rx_pwr_cal[i] * power_raised;
		}

		/* Check out for out of range */
		if (rx_power > 65535)
			return false;

		if (rx_power < 0)
			*p_value = 0;
		else
			*p_value = (uint16_t)rx_power;
	}

	return true;
}

/*
 * Read RX optical power if it exists
 */
static bool sfp_nim_get_rx_power(nim_i2c_ctx_p ctx, uint16_t *p_value)
{
	return sfp_nim_get_calibrated_rx_power(ctx, SFP_RX_PWR_LIN_ADDR, p_value);
}

void nim_read_sfp_temp(struct nim_sensor_group *sg, nthw_spis_t *t_spi)
{
	int16_t temp;
	(void)t_spi;

	if (sg == NULL || sg->ctx == NULL) {
		NT_LOG(ERR, ETHDEV, "%s: bad argument(s)\n", __func__);
		return;
	}

	if (sfp_nim_get_temperature(sg->ctx, &temp))
		update_sensor_value(sg->sensor, (int)(temp * 10 / 256));

	else
		update_sensor_value(sg->sensor, -1);
}

void nim_read_sfp_voltage(struct nim_sensor_group *sg, nthw_spis_t *t_spi)
{
	uint16_t temp;
	(void)t_spi;

	if (sg == NULL || sg->ctx == NULL) {
		NT_LOG(ERR, ETHDEV, "%s: bad argument(s)\n", __func__);
		return;
	}

	if (sfp_nim_get_supply_voltage(sg->ctx, &temp)) {
		update_sensor_value(sg->sensor,
				    (int)(temp / 10)); /* Unit: 100uV -> 1mV */
	} else {
		update_sensor_value(sg->sensor, -1);
	}
}

void nim_read_sfp_bias_current(struct nim_sensor_group *sg, nthw_spis_t *t_spi)
{
	uint16_t temp;
	(void)t_spi;

	if (sg == NULL || sg->ctx == NULL) {
		NT_LOG(ERR, ETHDEV, "%s: bad argument(s)\n", __func__);
		return;
	}

	if (sfp_nim_get_tx_bias_current(sg->ctx, &temp))
		update_sensor_value(sg->sensor, (int)(temp * 2));

	else
		update_sensor_value(sg->sensor, -1);
}

void nim_read_sfp_tx_power(struct nim_sensor_group *sg, nthw_spis_t *t_spi)
{
	uint16_t temp;
	(void)t_spi;

	if (sg == NULL || sg->ctx == NULL) {
		NT_LOG(ERR, ETHDEV, "%s: bad argument(s)\n", __func__);
		return;
	}

	if (sfp_nim_get_tx_power(sg->ctx, &temp))
		update_sensor_value(sg->sensor, (int)temp);

	else
		update_sensor_value(sg->sensor, -1);
}

void nim_read_sfp_rx_power(struct nim_sensor_group *sg, nthw_spis_t *t_spi)
{
	uint16_t temp;
	(void)t_spi;

	if (sg == NULL || sg->ctx == NULL) {
		NT_LOG(ERR, ETHDEV, "%s: bad argument(s)\n", __func__);
		return;
	}

	if (sfp_nim_get_rx_power(sg->ctx, &temp))
		update_sensor_value(sg->sensor, (int)temp);

	else
		update_sensor_value(sg->sensor, -1);
}

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "ntavr.h"
#include "ntlog.h"

static int txrx(nthw_spi_v3_t *s_spi, enum avr_opcodes opcode, size_t txsz,
		uint16_t *tx, size_t *rxsz, uint16_t *rx)
{
	int res = 1;
	struct tx_rx_buf m_tx = { .size = (uint16_t)txsz, .p_buf = tx };
	struct tx_rx_buf m_rx = { .size = (uint16_t)*rxsz, .p_buf = rx };

	res = nthw_spi_v3_transfer(s_spi, opcode, &m_tx, &m_rx);
	if (res) {
		NT_LOG(ERR, ETHDEV, "%s transfer failed - %i", __func__, res);
		return res;
	}

	if (rxsz != NULL)
		*rxsz = m_rx.size;

	return res;
}

uint32_t sensor_read(nthw_spis_t *t_spi, uint8_t fpga_idx,
		     uint32_t *p_sensor_result)
{
	return nthw_spis_read_sensor(t_spi, fpga_idx, p_sensor_result);
}

int nt_avr_sensor_mon_setup(struct sensor_mon_setup16 *p_setup, nthw_spi_v3_t *s_spi)
{
	int error;
	size_t tx_size;
	size_t rx_size = 0;

	tx_size = sizeof(struct sensor_mon_setup16) - sizeof(p_setup->setup_data);
	tx_size += sizeof(p_setup->setup_data[0]) * p_setup->setup_cnt;

	error = txrx(s_spi, AVR_OP_SENSOR_MON_SETUP, tx_size, (uint16_t *)p_setup,
		     &rx_size, NULL);

	if (error) {
		NT_LOG(ERR, ETHDEV, "%s failed\n", __func__);
		return error;
	}

	if (rx_size != 0) {
		NT_LOG(ERR, ETHDEV,
		       "%s: Returned data: Expected size = 0, Actual = %zu",
		       __func__, rx_size);
		return 1;
	}
	return 0;
}

int nt_avr_sensor_mon_ctrl(nthw_spi_v3_t *s_spi, enum sensor_mon_control ctrl)
{
	int error;
	size_t rx_size = 0;

	error = txrx(s_spi, AVR_OP_SENSOR_MON_CONTROL, sizeof(ctrl),
		     (uint16_t *)(&ctrl), &rx_size, NULL);

	if (error != 0)
		return error;

	if (rx_size != 0) {
		NT_LOG(ERR, ETHDEV,
		       "%s: Returned data: Expected size = 0, Actual = %zu",
		       __func__, rx_size);
		return 1;
	}

	return 0;
}

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "nt_util.h"
#include "ntlog.h"

#include "nthw_drv.h"
#include "nthw_register.h"

#include "nthw_iic.h"

#define I2C_TRANSMIT_WR (0x00)
#define I2C_TRANSMIT_RD (0x01)

#define I2C_WAIT_US(x) NT_OS_WAIT_USEC(x)

/*
 * Minimum timing values for I2C for a Marvel 88E11111 Phy.
 * This Phy is used in many Trispeed NIMs.
 * In order to access this Phy, the I2C clock speed is needed to be set to 100KHz.
 */
static const uint32_t susta = 4700; /* ns */
static const uint32_t susto = 4000; /* ns */
static const uint32_t hdsta = 4000; /* ns */
static const uint32_t sudat = 250; /* ns */
static const uint32_t buf = 4700; /* ns */
static const uint32_t high = 4000; /* ns */
static const uint32_t low = 4700; /* ns */
static const uint32_t hddat = 300; /* ns */

static int nthw_iic_reg_control_txfifo_reset(nthw_iic_t *p)
{
	field_update_register(p->mp_fld_cr_txfifo_reset);

	field_set_all(p->mp_fld_cr_txfifo_reset);
	field_flush_register(p->mp_fld_cr_txfifo_reset);

	field_clr_all(p->mp_fld_cr_txfifo_reset);
	field_flush_register(p->mp_fld_cr_txfifo_reset);

	return 0;
}

static int nthw_iic_reg_tx_fifo_write(nthw_iic_t *p, uint32_t data, bool start,
				     bool stop)
{
	if (start)
		field_set_all(p->mp_fld_tx_fifo_start);

	else
		field_clr_all(p->mp_fld_tx_fifo_start);

	if (stop)
		field_set_all(p->mp_fld_tx_fifo_stop);

	else
		field_clr_all(p->mp_fld_tx_fifo_stop);

	field_set_val32(p->mp_fld_tx_fifo_txdata, data);

	register_flush(p->mp_reg_tx_fifo, 1);

	return 0;
}

static int nthw_iic_reg_read_i2c_rx_fifo(nthw_iic_t *p, uint8_t *p_data)
{
	assert(p_data);

	*p_data = (uint8_t)field_get_updated(p->mp_fld_rx_fifo_rxdata);

	return 0;
}

static int nthw_iic_reg_softr(nthw_iic_t *p)
{
	field_update_register(p->mp_fld_cr_en);
	field_set_val_flush32(p->mp_fld_softr_rkey, 0x0A);

	return 0;
}

static int nthw_iic_reg_enable(nthw_iic_t *p)
{
	field_update_register(p->mp_fld_cr_en);
	field_set_flush(p->mp_fld_cr_en);

	return 0;
}

static int nthw_iic_reg_busbusy(nthw_iic_t *p, bool *pb_flag)
{
	assert(pb_flag);

	*pb_flag = field_get_updated(p->mp_fld_sr_bb) ? true : false;

	return 0;
}

static int nthw_iic_reg_rxfifo_empty(nthw_iic_t *p, bool *pb_flag)
{
	assert(pb_flag);

	*pb_flag = field_get_updated(p->mp_fld_sr_rxfifo_empty) ? true : false;

	return 0;
}

/*
 * nIicCycleTime is the I2C clock cycle time in ns ie 125MHz = 8ns
 */
static int nthw_iic_reg_set_timing(nthw_iic_t *p, uint32_t n_iic_cycle_time)
{
	uint32_t val;

	val = susta / n_iic_cycle_time;
	field_set_val_flush(p->mp_fld_tsusta, &val, 1);

	val = susto / n_iic_cycle_time;
	field_set_val_flush(p->mp_fld_tsusto, &val, 1);

	val = hdsta / n_iic_cycle_time;
	field_set_val_flush(p->mp_fld_thdsta, &val, 1);

	val = sudat / n_iic_cycle_time;
	field_set_val_flush(p->mp_fld_tsudat, &val, 1);

	val = buf / n_iic_cycle_time;
	field_set_val_flush(p->mp_fld_tbuf, &val, 1);

	val = high / n_iic_cycle_time;
	field_set_val_flush(p->mp_fld_thigh, &val, 1);

	val = low / n_iic_cycle_time;
	field_set_val_flush(p->mp_fld_tlow, &val, 1);

	val = hddat / n_iic_cycle_time;
	field_set_val_flush(p->mp_fld_thddat, &val, 1);

	return 0;
}

nthw_iic_t *nthw_iic_new(void)
{
	nthw_iic_t *p = malloc(sizeof(nthw_iic_t));

	if (p)
		memset(p, 0, sizeof(nthw_iic_t));
	return p;
}

int nthw_iic_init(nthw_iic_t *p, nt_fpga_t *p_fpga, int n_iic_instance,
		 uint32_t n_iic_cycle_time)
{
	const char *const p_adapter_id_str = p_fpga->p_fpga_info->mp_adapter_id_str;
	nt_module_t *mod = fpga_query_module(p_fpga, MOD_IIC, n_iic_instance);

	if (p == NULL)
		return mod == NULL ? -1 : 0;

	if (mod == NULL) {
		NT_LOG(ERR, NTHW, "%s: I2C %d: no such instance\n",
		       p_adapter_id_str, n_iic_instance);
		return -1;
	}

	p->mp_fpga = p_fpga;
	p->mn_iic_instance = n_iic_instance;

	p->mn_iic_cycle_time = n_iic_cycle_time;

	nthw_iic_set_retry_params(p, -1, -1, -1, -1, -1);

	p->mp_mod_iic = mod;

	/* I2C is a primary communication channel - turn off debug by default */
	module_set_debug_mode(p->mp_mod_iic, 0x00);

	p->mp_reg_tsusta = module_get_register(p->mp_mod_iic, IIC_TSUSTA);
	p->mp_fld_tsusta =
		register_get_field(p->mp_reg_tsusta, IIC_TSUSTA_TSUSTA_VAL);

	p->mp_reg_tsusto = module_get_register(p->mp_mod_iic, IIC_TSUSTO);
	p->mp_fld_tsusto =
		register_get_field(p->mp_reg_tsusto, IIC_TSUSTO_TSUSTO_VAL);

	p->mp_reg_thdsta = module_get_register(p->mp_mod_iic, IIC_THDSTA);
	p->mp_fld_thdsta =
		register_get_field(p->mp_reg_thdsta, IIC_THDSTA_THDSTA_VAL);

	p->mp_reg_tsudat = module_get_register(p->mp_mod_iic, IIC_TSUDAT);
	p->mp_fld_tsudat =
		register_get_field(p->mp_reg_tsudat, IIC_TSUDAT_TSUDAT_VAL);

	p->mp_reg_tbuf = module_get_register(p->mp_mod_iic, IIC_TBUF);
	p->mp_fld_tbuf = register_get_field(p->mp_reg_tbuf, IIC_TBUF_TBUF_VAL);

	p->mp_reg_thigh = module_get_register(p->mp_mod_iic, IIC_THIGH);
	p->mp_fld_thigh = register_get_field(p->mp_reg_thigh, IIC_THIGH_THIGH_VAL);

	p->mp_reg_tlow = module_get_register(p->mp_mod_iic, IIC_TLOW);
	p->mp_fld_tlow = register_get_field(p->mp_reg_tlow, IIC_TLOW_TLOW_VAL);

	p->mp_reg_thddat = module_get_register(p->mp_mod_iic, IIC_THDDAT);
	p->mp_fld_thddat =
		register_get_field(p->mp_reg_thddat, IIC_THDDAT_THDDAT_VAL);

	p->mp_reg_cr = module_get_register(p->mp_mod_iic, IIC_CR);
	p->mp_fld_cr_en = register_get_field(p->mp_reg_cr, IIC_CR_EN);
	p->mp_fld_cr_msms = register_get_field(p->mp_reg_cr, IIC_CR_MSMS);
	p->mp_fld_cr_txfifo_reset =
		register_get_field(p->mp_reg_cr, IIC_CR_TXFIFO_RESET);
	p->mp_fld_cr_txak = register_get_field(p->mp_reg_cr, IIC_CR_TXAK);

	p->mp_reg_sr = module_get_register(p->mp_mod_iic, IIC_SR);
	p->mp_fld_sr_bb = register_get_field(p->mp_reg_sr, IIC_SR_BB);
	p->mp_fld_sr_rxfifo_full =
		register_get_field(p->mp_reg_sr, IIC_SR_RXFIFO_FULL);
	p->mp_fld_sr_rxfifo_empty =
		register_get_field(p->mp_reg_sr, IIC_SR_RXFIFO_EMPTY);
	p->mp_fld_sr_txfifo_full =
		register_get_field(p->mp_reg_sr, IIC_SR_TXFIFO_FULL);
	p->mp_fld_sr_txfifo_empty =
		register_get_field(p->mp_reg_sr, IIC_SR_TXFIFO_EMPTY);

	p->mp_reg_tx_fifo = module_get_register(p->mp_mod_iic, IIC_TX_FIFO);
	p->mp_fld_tx_fifo_txdata =
		register_get_field(p->mp_reg_tx_fifo, IIC_TX_FIFO_TXDATA);
	p->mp_fld_tx_fifo_start =
		register_get_field(p->mp_reg_tx_fifo, IIC_TX_FIFO_START);
	p->mp_fld_tx_fifo_stop =
		register_get_field(p->mp_reg_tx_fifo, IIC_TX_FIFO_STOP);

	p->mp_reg_rx_fifo_pirq =
		module_get_register(p->mp_mod_iic, IIC_RX_FIFO_PIRQ);
	p->mp_fld_rx_fifo_pirq_cmp_val =
		register_get_field(p->mp_reg_rx_fifo_pirq, IIC_RX_FIFO_PIRQ_CMP_VAL);

	p->mp_reg_rx_fifo = module_get_register(p->mp_mod_iic, IIC_RX_FIFO);
	p->mp_fld_rx_fifo_rxdata =
		register_get_field(p->mp_reg_rx_fifo, IIC_RX_FIFO_RXDATA);

	p->mp_reg_softr = module_get_register(p->mp_mod_iic, IIC_SOFTR);
	p->mp_fld_softr_rkey = register_get_field(p->mp_reg_softr, IIC_SOFTR_RKEY);

	/*
	 * Initialize I2C controller by applying soft reset and enable the controller
	 */
	nthw_iic_reg_softr(p);
	/* Enable the controller */
	nthw_iic_reg_enable(p);

	/* Setup controller timing */
	if (p->mn_iic_cycle_time) {
		NT_LOG(DBG, NTHW, "%s: I2C%d: cycletime=%d\n", p_adapter_id_str,
		       p->mn_iic_instance, p->mn_iic_cycle_time);
		nthw_iic_reg_set_timing(p, p->mn_iic_cycle_time);
	}

	/* Reset TX fifo - must be after enable */
	nthw_iic_reg_control_txfifo_reset(p);
	nthw_iic_reg_tx_fifo_write(p, 0, 0, 0);

	return 0;
}

void nthw_iic_delete(nthw_iic_t *p)
{
	if (p) {
		memset(p, 0, sizeof(nthw_iic_t));
		free(p);
	}
}

int nthw_iic_set_retry_params(nthw_iic_t *p, const int n_poll_delay,
			   const int n_bus_ready_retry, const int n_data_ready_retry,
			   const int n_read_data_retry, const int n_write_data_retry)
{
	p->mn_poll_delay = n_poll_delay >= 0 ? n_poll_delay : 10;

	p->mn_bus_ready_retry = n_bus_ready_retry >= 0 ? n_bus_ready_retry : 1000;
	p->mn_data_ready_retry = n_data_ready_retry >= 0 ? n_data_ready_retry : 1000;

	p->mn_read_data_retry = n_read_data_retry >= 0 ? n_read_data_retry : 10;
	p->mn_write_data_retry = n_write_data_retry >= 0 ? n_write_data_retry : 10;

	return 0;
}

int nthw_iic_read_data(nthw_iic_t *p, uint8_t dev_addr, uint8_t reg_addr,
		     uint8_t data_len, void *p_void)
{
	const char *const p_adapter_id_str = p->mp_fpga->p_fpga_info->mp_adapter_id_str;
	const int n_debug_mode = module_get_debug_mode(p->mp_mod_iic);

	uint8_t *pb = (uint8_t *)p_void;
	int retry = (p->mn_read_data_retry >= 0 ? p->mn_read_data_retry : 10);

	if (n_debug_mode == 0xff) {
		NT_LOG(DBG, NTHW, "%s: adr=0x%2.2x, reg=%d, len=%d\n",
		       p_adapter_id_str, dev_addr, reg_addr, data_len);
	}

	while (nthw_iic_readbyte(p, dev_addr, reg_addr, data_len, pb) != 0) {
		retry--;
		if (retry <= 0) {
			NT_LOG(ERR, NTHW,
			       "%s: I2C%d: Read retry exhausted (dev_addr=%d reg_addr=%d)\n",
			       p_adapter_id_str, p->mn_iic_instance, dev_addr,
			       reg_addr);
			return -1;
		}
#if defined(DEBUG)
		NT_LOG(DBG, NTHW,
		       "%s: I2C%d: Read retry=%d (dev_addr=%d reg_addr=%d)\n",
		       p_adapter_id_str, p->mn_iic_instance, retry, dev_addr,
		       reg_addr);
#endif
	}

	if (n_debug_mode == 0xff) {
		NT_LOG(DBG, NTHW,
		       "%s: adr=0x%2.2x, reg=%d, len=%d, retries remaining: %d\n",
		       p_adapter_id_str, dev_addr, reg_addr, data_len, retry);
	}

	return 0;
}

int nthw_iic_readbyte(nthw_iic_t *p, uint8_t dev_addr, uint8_t reg_addr,
		     uint8_t data_len, uint8_t *p_byte)
{
	const char *const p_adapter_id_str = p->mp_fpga->p_fpga_info->mp_adapter_id_str;

	uint32_t value;
	uint32_t i;

	if (nthw_iic_bus_ready(p)) {
		/* Reset TX fifo */
		nthw_iic_reg_control_txfifo_reset(p);

		/* Write device address to TX_FIFO and set start bit!! */
		value = (dev_addr << 1) | I2C_TRANSMIT_WR;
		nthw_iic_reg_tx_fifo_write(p, value, 1, 0);

		/* Write reg_addr to TX FIFO */
		nthw_iic_reg_tx_fifo_write(p, reg_addr, 0, 1);

		if (!nthw_iic_bus_ready(p)) {
			NT_LOG(ERR, NTHW, "%s: error: (%s:%u)\n", p_adapter_id_str,
			       __func__, __LINE__);
			return -1;
		}

		/* Write device address + RD bit to TX_FIFO and set start bit!! */
		value = (dev_addr << 1) | I2C_TRANSMIT_RD;
		nthw_iic_reg_tx_fifo_write(p, value, 1, 0);

		/* Write DataLen to TX_FIFO and set stop bit!! */
		nthw_iic_reg_tx_fifo_write(p, data_len, 0, 1);

		for (i = 0; i < data_len; i++) {
			/* Wait for RX FIFO not empty */
			if (!nthw_iic_data_ready(p))
				return -1;

			/* Read DataLen bytes from RX_FIFO */
			nthw_iic_reg_read_i2c_rx_fifo(p, p_byte);
			p_byte++;
		}

		return 0;

	} else {
		NT_LOG(ERR, NTHW, "%s: error: (%s:%u)\n", p_adapter_id_str,
		       __func__, __LINE__);
		return -1;
	}
	return 0;
}

int nthw_iic_write_data(nthw_iic_t *p, uint8_t dev_addr, uint8_t reg_addr,
		      uint8_t data_len, void *p_void)
{
	const char *const p_adapter_id_str = p->mp_fpga->p_fpga_info->mp_adapter_id_str;
	int retry = (p->mn_write_data_retry >= 0 ? p->mn_write_data_retry : 10);
	uint8_t *pb = (uint8_t *)p_void;

	while (nthw_iic_writebyte(p, dev_addr, reg_addr, data_len, pb) != 0) {
		retry--;
		if (retry <= 0) {
			NT_LOG(ERR, NTHW,
			       "%s: I2C%d: Write retry exhausted (dev_addr=%d reg_addr=%d)\n",
			       p_adapter_id_str, p->mn_iic_instance, dev_addr,
			       reg_addr);
			return -1;
		}
#if defined(DEBUG)
		NT_LOG(DBG, NTHW,
		       "%s: I2C%d: Write retry=%d (dev_addr=%d reg_addr=%d)\n",
		       p_adapter_id_str, p->mn_iic_instance, retry, dev_addr,
		       reg_addr);
#endif
	}

	return 0;
}

int nthw_iic_writebyte(nthw_iic_t *p, uint8_t dev_addr, uint8_t reg_addr,
		      uint8_t data_len, uint8_t *p_byte)
{
	const char *const p_adapter_id_str = p->mp_fpga->p_fpga_info->mp_adapter_id_str;
	uint32_t value;
	int count;
	int i;

	if (data_len == 0)
		return -1;

	count = data_len - 1;
	if (nthw_iic_bus_ready(p)) {
		/* Reset TX fifo */
		nthw_iic_reg_control_txfifo_reset(p);

		/* Write device address to TX_FIFO and set start bit!! */
		value = (dev_addr << 1) | I2C_TRANSMIT_WR;
		nthw_iic_reg_tx_fifo_write(p, value, 1, 0);

		/* Write reg_addr to TX FIFO */
		nthw_iic_reg_tx_fifo_write(p, reg_addr, 0, 0);

		for (i = 0; i < count; i++) {
			/* Write data byte to TX fifo and set stop bit */
			nthw_iic_reg_tx_fifo_write(p, *p_byte, 0, 0);
			p_byte++;
		}

		/* Write data byte to TX fifo and set stop bit */
		nthw_iic_reg_tx_fifo_write(p, *p_byte, 0, 1);

		if (!nthw_iic_bus_ready(p)) {
			NT_LOG(WRN, NTHW, "%s: warn: !busReady (%s:%u)\n",
			       p_adapter_id_str, __func__, __LINE__);
			while (true) {
				if (nthw_iic_bus_ready(p)) {
					NT_LOG(DBG, NTHW,
					       "%s: info: busReady (%s:%u)\n",
					       p_adapter_id_str, __func__,
					       __LINE__);
					break;
				}
			}
		}

		return 0;

	} else {
		NT_LOG(WRN, NTHW, "%s: (%s:%u)\n", p_adapter_id_str, __func__,
		       __LINE__);
		return -1;
	}
}

/*
 * Support function for read/write functions below. Waits for bus ready.
 */
bool nthw_iic_bus_ready(nthw_iic_t *p)
{
	int count = (p->mn_bus_ready_retry >= 0 ? p->mn_bus_ready_retry : 1000);
	bool b_bus_busy = true;

	while (true) {
		nthw_iic_reg_busbusy(p, &b_bus_busy);
		if (!b_bus_busy)
			break;

		count--;
		if (count <= 0)   /* Test for timeout */
			break;

		if (p->mn_poll_delay != 0)
			I2C_WAIT_US(p->mn_poll_delay);
	}

	if (count == 0)
		return false;

	return true;
}

/*
 * Support function for read function. Waits for data ready.
 */
bool nthw_iic_data_ready(nthw_iic_t *p)
{
	int count = (p->mn_data_ready_retry >= 0 ? p->mn_data_ready_retry : 1000);
	bool b_rx_fifo_empty = true;

	while (true) {
		nthw_iic_reg_rxfifo_empty(p, &b_rx_fifo_empty);
		if (!b_rx_fifo_empty)
			break;

		count--;
		if (count <= 0)   /* Test for timeout */
			break;

		if (p->mn_poll_delay != 0)
			I2C_WAIT_US(p->mn_poll_delay);
	}

	if (count == 0)
		return false;

	return true;
}

int nthw_iic_scan_dev_addr(nthw_iic_t *p, int n_dev_addr, int n_reg_addr)
{
	const char *const p_adapter_id_str _unused =
		p->mp_fpga->p_fpga_info->mp_adapter_id_str;
	int res;
	uint8_t data_val = -1;

	res = nthw_iic_readbyte(p, (uint8_t)n_dev_addr, (uint8_t)n_reg_addr, 1,
			       &data_val);
	if (res == 0) {
		NT_LOG(DBG, NTHW,
		       "%s: I2C%d: devaddr=0x%02X (%03d) regaddr=%02X val=%02X (%03d) res=%d\n",
		       p_adapter_id_str, p->mn_iic_instance, n_dev_addr, n_dev_addr,
		       n_reg_addr, data_val, data_val, res);
	}
	return res;
}

int nthw_iic_scan_find_dev(nthw_iic_t *p, int n_dev_addr_start, bool b_increate)
{
	const char *const p_adapter_id_str _unused =
		p->mp_fpga->p_fpga_info->mp_adapter_id_str;

	int res = 0;
	int i = 0;

	if (b_increate) {
		for (i = n_dev_addr_start; i < 128; i++) {
			res = nthw_iic_scan_dev_addr(p, i, 0x00);
			if (res == 0)
				break;
		}
	} else {
		for (i = n_dev_addr_start; i >= 0; i--) {
			res = nthw_iic_scan_dev_addr(p, i, 0x00);
			if (res == 0)
				break;
		}
	}
	NT_LOG(DBG, NTHW, "%s: I2C%d: FOUND: %d\n", p_adapter_id_str,
	       p->mn_iic_instance, i);
	return (res == 0 ? i : -1);
}

int nthw_iic_scan(nthw_iic_t *p)
{
	int i;

	for (i = 0; i < 128; i++)
		(void)nthw_iic_scan_dev_addr(p, i, 0x00);
	return 0;
}

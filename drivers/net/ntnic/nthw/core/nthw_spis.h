/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __NTHW_SPIS_H__
#define __NTHW_SPIS_H__

struct nthw_spis {
	nt_fpga_t *mp_fpga;
	nt_module_t *mp_mod_spis;
	int mn_instance;

	nt_register_t *mp_reg_srr;
	nt_field_t *mp_fld_srr_rst;

	nt_register_t *mp_reg_cr;
	nt_field_t *mp_fld_cr_loop;
	nt_field_t *mp_fld_cr_en;
	nt_field_t *mp_fld_cr_txrst;
	nt_field_t *mp_fld_cr_rxrst;
	nt_field_t *mp_fld_cr_debug;

	nt_register_t *mp_reg_sr;
	nt_field_t *mp_fld_sr_done;
	nt_field_t *mp_fld_sr_txempty;
	nt_field_t *mp_fld_sr_rxempty;
	nt_field_t *mp_fld_sr_txfull;
	nt_field_t *mp_fld_sr_rxfull;
	nt_field_t *mp_fld_sr_txlvl;
	nt_field_t *mp_fld_sr_rxlvl;
	nt_field_t *mp_fld_sr_frame_err;
	nt_field_t *mp_fld_sr_read_err;
	nt_field_t *mp_fld_sr_write_err;

	nt_register_t *mp_reg_dtr;
	nt_field_t *mp_fld_dtr_dtr;

	nt_register_t *mp_reg_drr;
	nt_field_t *mp_fld_drr_drr;

	nt_register_t *mp_reg_ram_ctrl;
	nt_field_t *mp_fld_ram_ctrl_adr;
	nt_field_t *mp_fld_ram_ctrl_cnt;

	nt_register_t *mp_reg_ram_data;
	nt_field_t *mp_fld_ram_data_data;
};

typedef struct nthw_spis nthw_spis_t;
typedef struct nthw_spis nthw_spis;

nthw_spis_t *nthw_spis_new(void);
int nthw_spis_init(nthw_spis_t *p, nt_fpga_t *p_fpga, int n_instance);
void nthw_spis_delete(nthw_spis_t *p);

uint32_t nthw_spis_reset(nthw_spis_t *p);
uint32_t nthw_spis_enable(nthw_spis_t *p, bool b_enable);
uint32_t nthw_spis_get_rx_fifo_empty(nthw_spis_t *p, bool *pb_empty);
uint32_t nthw_spis_read_rx_fifo(nthw_spis_t *p, uint32_t *p_data);
uint32_t nthw_spis_read_sensor(nthw_spis_t *p, uint8_t n_result_idx,
			      uint32_t *p_sensor_result);

#endif /* __NTHW_SPIS_H__ */

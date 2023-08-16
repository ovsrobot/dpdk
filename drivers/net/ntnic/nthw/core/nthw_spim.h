/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __NTHW_SPIM_H__
#define __NTHW_SPIM_H__

struct nthw_spim {
	nt_fpga_t *mp_fpga;
	nt_module_t *mp_mod_spim;
	int mn_instance;

	nt_register_t *mp_reg_srr;
	nt_field_t *mp_fld_srr_rst;

	nt_register_t *mp_reg_cr;
	nt_field_t *mp_fld_cr_loop;
	nt_field_t *mp_fld_cr_en;
	nt_field_t *mp_fld_cr_txrst;
	nt_field_t *mp_fld_cr_rxrst;

	nt_register_t *mp_reg_sr;
	nt_field_t *mp_fld_sr_done;
	nt_field_t *mp_fld_sr_txempty;
	nt_field_t *mp_fld_sr_rxempty;
	nt_field_t *mp_fld_sr_txfull;
	nt_field_t *mp_fld_sr_rxfull;
	nt_field_t *mp_fld_sr_txlvl;
	nt_field_t *mp_fld_sr_rxlvl;

	nt_register_t *mp_reg_dtr;
	nt_field_t *mp_fld_dtr_dtr;

	nt_register_t *mp_reg_drr;
	nt_field_t *mp_fld_drr_drr;
	nt_register_t *mp_reg_cfg;
	nt_field_t *mp_fld_cfg_pre;
};

typedef struct nthw_spim nthw_spim_t;
typedef struct nthw_spim nthw_spim;

nthw_spim_t *nthw_spim_new(void);
int nthw_spim_init(nthw_spim_t *p, nt_fpga_t *p_fpga, int n_instance);
void nthw_spim_delete(nthw_spim_t *p);

uint32_t nthw_spim_reset(nthw_spim_t *p);
uint32_t nthw_spim_enable(nthw_spim_t *p, bool b_enable);
uint32_t nthw_spim_get_tx_fifo_empty(nthw_spim_t *p, bool *pb_empty);
uint32_t nthw_spim_write_tx_fifo(nthw_spim_t *p, uint32_t n_data);

#endif /* __NTHW_SPIM_H__ */

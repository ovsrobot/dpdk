/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "ntlog.h"

#include "nthw_drv.h"
#include "nthw_register.h"

#include "nthw_spim.h"

nthw_spim_t *nthw_spim_new(void)
{
	nthw_spim_t *p = malloc(sizeof(nthw_spim_t));

	if (p)
		memset(p, 0, sizeof(nthw_spim_t));
	return p;
}

int nthw_spim_init(nthw_spim_t *p, nt_fpga_t *p_fpga, int n_instance)
{
	const char *const p_adapter_id_str = p_fpga->p_fpga_info->mp_adapter_id_str;
	nt_module_t *mod = fpga_query_module(p_fpga, MOD_SPIM, n_instance);

	if (p == NULL)
		return mod == NULL ? -1 : 0;

	if (mod == NULL) {
		NT_LOG(ERR, NTHW, "%s: SPIM %d: no such instance\n",
		       p_adapter_id_str, n_instance);
		return -1;
	}

	p->mp_fpga = p_fpga;
	p->mn_instance = n_instance;
	p->mp_mod_spim = mod;

	/* SPIM is a primary communication channel - turn off debug by default */
	module_set_debug_mode(p->mp_mod_spim, 0x00);

	p->mp_reg_srr = module_get_register(p->mp_mod_spim, SPIM_SRR);
	p->mp_fld_srr_rst = register_get_field(p->mp_reg_srr, SPIM_SRR_RST);

	p->mp_reg_cr = module_get_register(p->mp_mod_spim, SPIM_CR);
	p->mp_fld_cr_loop = register_get_field(p->mp_reg_cr, SPIM_CR_LOOP);
	p->mp_fld_cr_en = register_get_field(p->mp_reg_cr, SPIM_CR_EN);
	p->mp_fld_cr_txrst = register_get_field(p->mp_reg_cr, SPIM_CR_TXRST);
	p->mp_fld_cr_rxrst = register_get_field(p->mp_reg_cr, SPIM_CR_RXRST);

	p->mp_reg_sr = module_get_register(p->mp_mod_spim, SPIM_SR);
	p->mp_fld_sr_done = register_get_field(p->mp_reg_sr, SPIM_SR_DONE);
	p->mp_fld_sr_txempty = register_get_field(p->mp_reg_sr, SPIM_SR_TXEMPTY);
	p->mp_fld_sr_rxempty = register_get_field(p->mp_reg_sr, SPIM_SR_RXEMPTY);
	p->mp_fld_sr_txfull = register_get_field(p->mp_reg_sr, SPIM_SR_TXFULL);
	p->mp_fld_sr_rxfull = register_get_field(p->mp_reg_sr, SPIM_SR_RXFULL);
	p->mp_fld_sr_txlvl = register_get_field(p->mp_reg_sr, SPIM_SR_TXLVL);
	p->mp_fld_sr_rxlvl = register_get_field(p->mp_reg_sr, SPIM_SR_RXLVL);

	p->mp_reg_dtr = module_get_register(p->mp_mod_spim, SPIM_DTR);
	p->mp_fld_dtr_dtr = register_get_field(p->mp_reg_dtr, SPIM_DTR_DTR);

	p->mp_reg_drr = module_get_register(p->mp_mod_spim, SPIM_DRR);
	p->mp_fld_drr_drr = register_get_field(p->mp_reg_drr, SPIM_DRR_DRR);

	p->mp_reg_cfg = module_get_register(p->mp_mod_spim, SPIM_CFG);
	p->mp_fld_cfg_pre = register_get_field(p->mp_reg_cfg, SPIM_CFG_PRE);

	return 0;
}

void nthw_spim_delete(nthw_spim_t *p)
{
	if (p) {
		memset(p, 0, sizeof(nthw_spim_t));
		free(p);
	}
}

uint32_t nthw_spim_reset(nthw_spim_t *p)
{
	register_update(p->mp_reg_srr);
	field_set_val32(p->mp_fld_srr_rst,
		       0x0A); /* 0x0A hardcoded value - see doc */
	register_flush(p->mp_reg_srr, 1);

	return 0;
}

uint32_t nthw_spim_enable(nthw_spim_t *p, bool b_enable)
{
	field_update_register(p->mp_fld_cr_en);

	if (b_enable)
		field_set_all(p->mp_fld_cr_en);

	else
		field_clr_all(p->mp_fld_cr_en);
	field_flush_register(p->mp_fld_cr_en);

	return 0;
}

uint32_t nthw_spim_write_tx_fifo(nthw_spim_t *p, uint32_t n_data)
{
	field_set_val_flush32(p->mp_fld_dtr_dtr, n_data);
	return 0;
}

uint32_t nthw_spim_get_tx_fifo_empty(nthw_spim_t *p, bool *pb_empty)
{
	assert(pb_empty);

	*pb_empty = field_get_updated(p->mp_fld_sr_txempty) ? true : false;

	return 0;
}

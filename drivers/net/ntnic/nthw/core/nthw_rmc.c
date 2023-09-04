/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "ntlog.h"

#include "nthw_drv.h"
#include "nthw_register.h"

#include "nthw_rmc.h"

nthw_rmc_t *nthw_rmc_new(void)
{
	nthw_rmc_t *p = malloc(sizeof(nthw_rmc_t));

	if (p)
		memset(p, 0, sizeof(nthw_rmc_t));
	return p;
}

void nthw_rmc_delete(nthw_rmc_t *p)
{
	if (p) {
		memset(p, 0, sizeof(nthw_rmc_t));
		free(p);
	}
}

int nthw_rmc_init(nthw_rmc_t *p, nt_fpga_t *p_fpga, int n_instance)
{
	const char *const p_adapter_id_str = p_fpga->p_fpga_info->mp_adapter_id_str;
	nt_module_t *p_mod = fpga_query_module(p_fpga, MOD_RMC, n_instance);

	if (p == NULL)
		return p_mod == NULL ? -1 : 0;

	if (p_mod == NULL) {
		NT_LOG(ERR, NTHW, "%s: RMC %d: no such instance\n",
		       p_adapter_id_str, n_instance);
		return -1;
	}

	p->mp_fpga = p_fpga;
	p->mn_instance = n_instance;
	p->mp_mod_rmc = p_mod;

	/* Params */
	p->mb_is_vswitch = p_fpga->p_fpga_info->profile == FPGA_INFO_PROFILE_VSWITCH;
	p->mn_ports = fpga_get_product_param(p_fpga, NT_RX_PORTS,
					     fpga_get_product_param(p_fpga, NT_PORTS, 0));
	p->mn_nims = fpga_get_product_param(p_fpga, NT_NIMS, 0);
	p->mb_administrative_block = false;

	NT_LOG(DBG, NTHW, "%s: RMC %d: vswitch=%d\n", p_adapter_id_str,
	       p->mn_instance, p->mb_is_vswitch);

	p->mp_reg_ctrl = module_get_register(p->mp_mod_rmc, RMC_CTRL);

	p->mp_fld_ctrl_block_stat_drop =
		register_get_field(p->mp_reg_ctrl, RMC_CTRL_BLOCK_STATT);
	p->mp_fld_ctrl_block_keep_alive =
		register_get_field(p->mp_reg_ctrl, RMC_CTRL_BLOCK_KEEPA);
	p->mp_fld_ctrl_block_mac_port =
		register_get_field(p->mp_reg_ctrl, RMC_CTRL_BLOCK_MAC_PORT);

	p->mp_reg_status = module_query_register(p->mp_mod_rmc, RMC_STATUS);
	if (p->mp_reg_status) {
		p->mp_fld_sf_ram_of =
			register_get_field(p->mp_reg_status, RMC_STATUS_SF_RAM_OF);
		p->mp_fld_descr_fifo_of =
			register_get_field(p->mp_reg_status, RMC_STATUS_DESCR_FIFO_OF);
	}

	p->mp_reg_dbg = module_query_register(p->mp_mod_rmc, RMC_DBG);
	if (p->mp_reg_dbg) {
		p->mp_fld_dbg_merge =
			register_get_field(p->mp_reg_dbg, RMC_DBG_MERGE);
	}

	p->mp_reg_mac_if = module_query_register(p->mp_mod_rmc, RMC_MAC_IF);
	if (p->mp_reg_mac_if) {
		p->mp_fld_mac_if_err =
			register_get_field(p->mp_reg_mac_if, RMC_MAC_IF_ERR);
	}
	return 0;
}

uint32_t nthw_rmc_get_mac_block(nthw_rmc_t *p)
{
	return field_get_updated(p->mp_fld_ctrl_block_mac_port);
}

uint32_t nthw_rmc_get_status_sf_ram_of(nthw_rmc_t *p)
{
	return (p->mp_reg_status) ? field_get_updated(p->mp_fld_sf_ram_of) :
	       0xffffffff;
}

uint32_t nthw_rmc_get_status_descr_fifo_of(nthw_rmc_t *p)
{
	return (p->mp_reg_status) ? field_get_updated(p->mp_fld_descr_fifo_of) :
	       0xffffffff;
}

uint32_t nthw_rmc_get_dbg_merge(nthw_rmc_t *p)
{
	return (p->mp_reg_dbg) ? field_get_updated(p->mp_fld_dbg_merge) : 0xffffffff;
}

uint32_t nthw_rmc_get_mac_if_err(nthw_rmc_t *p)
{
	return (p->mp_reg_mac_if) ? field_get_updated(p->mp_fld_mac_if_err) :
	       0xffffffff;
}

void nthw_rmc_set_mac_block(nthw_rmc_t *p, uint32_t mask)
{
	field_set_val_flush32(p->mp_fld_ctrl_block_mac_port, mask);
}

void nthw_rmc_block(nthw_rmc_t *p)
{
	/* BLOCK_STATT(0)=1 BLOCK_KEEPA(1)=1 BLOCK_MAC_PORT(8:11)=~0 */
	if (!p->mb_administrative_block) {
		field_set_flush(p->mp_fld_ctrl_block_stat_drop);
		field_set_flush(p->mp_fld_ctrl_block_keep_alive);
		field_set_flush(p->mp_fld_ctrl_block_mac_port);
	}
}

void nthw_rmc_unblock(nthw_rmc_t *p, bool b_is_secondary)
{
	uint32_t n_block_mask = ~0U << (b_is_secondary ? p->mn_nims : p->mn_ports);

	if (p->mb_is_vswitch) {
		/*
		 * VSWITCH: NFV: block bits: phy_nim_ports(2) + rtd_ports(4) +
		 * roa_recirculate_port(1)
		 */
		n_block_mask = 1 << (2 + 4); /* block only ROA recirculate */
	}

	/* BLOCK_STATT(0)=0 BLOCK_KEEPA(1)=0 BLOCK_MAC_PORT(8:11)=0 */
	if (!p->mb_administrative_block) {
		field_clr_flush(p->mp_fld_ctrl_block_stat_drop);
		field_clr_flush(p->mp_fld_ctrl_block_keep_alive);
		field_set_val_flush32(p->mp_fld_ctrl_block_mac_port, n_block_mask);
	}
}

void nthw_rmc_administrative_block(nthw_rmc_t *p)
{
	/* block all MAC ports */
	field_set_flush(p->mp_fld_ctrl_block_mac_port);
	p->mb_administrative_block = true;
}

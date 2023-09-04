/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef NTHW_RMC_H_
#define NTHW_RMC_H_

struct nthw_rmc {
	nt_fpga_t *mp_fpga;
	nt_module_t *mp_mod_rmc;
	int mn_instance;

	int mn_ports;
	int mn_nims;
	bool mb_is_vswitch;

	bool mb_administrative_block;

	/* RMC CTRL register */
	nt_register_t *mp_reg_ctrl;
	nt_field_t *mp_fld_ctrl_block_stat_drop;
	nt_field_t *mp_fld_ctrl_block_keep_alive;
	nt_field_t *mp_fld_ctrl_block_mac_port;

	/* RMC Status register */
	nt_register_t *mp_reg_status;
	nt_field_t *mp_fld_sf_ram_of;
	nt_field_t *mp_fld_descr_fifo_of;

	/* RMC DBG register */
	nt_register_t *mp_reg_dbg;
	nt_field_t *mp_fld_dbg_merge;

	/* RMC MAC_IF register */
	nt_register_t *mp_reg_mac_if;
	nt_field_t *mp_fld_mac_if_err;
};

typedef struct nthw_rmc nthw_rmc_t;
typedef struct nthw_rmc nthw_rmc;

nthw_rmc_t *nthw_rmc_new(void);
void nthw_rmc_delete(nthw_rmc_t *p);
int nthw_rmc_init(nthw_rmc_t *p, nt_fpga_t *p_fpga, int n_instance);

uint32_t nthw_rmc_get_mac_block(nthw_rmc_t *p);
void nthw_rmc_set_mac_block(nthw_rmc_t *p, uint32_t mask);
void nthw_rmc_block(nthw_rmc_t *p);
void nthw_rmc_unblock(nthw_rmc_t *p, bool b_is_secondary);
void nthw_rmc_administrative_block(nthw_rmc_t *p);

uint32_t nthw_rmc_get_status_sf_ram_of(nthw_rmc_t *p);
uint32_t nthw_rmc_get_status_descr_fifo_of(nthw_rmc_t *p);
uint32_t nthw_rmc_get_dbg_merge(nthw_rmc_t *p);
uint32_t nthw_rmc_get_mac_if_err(nthw_rmc_t *p);

#endif /* NTHW_RMC_H_ */

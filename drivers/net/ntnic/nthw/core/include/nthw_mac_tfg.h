/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef NTHW_MAC_TFG_H_
#define NTHW_MAC_TFG_H_

struct nthw_mac_tfg {
	nthw_fpga_t *mp_fpga;
	nthw_module_t *mp_mod_mac_tfg;
	int mn_instance;

	/* Params */
	int mn_ifg_speed_mul;
	int mn_ifg_speed_div;

	/* TFG */
	nthw_register_t *mp_reg_tfg_data;
	nthw_register_t *mp_reg_tfg_addr;
	nthw_register_t *mp_reg_tfg_ctrl;
	nthw_register_t *mp_reg_tfg_repetition;

	/* TFG ADDR */
	nthw_field_t *mp_fld_tfg_addr_write_ram_adr;
	nthw_field_t *mp_fld_tfg_addr_read_enable;
	nthw_field_t *mp_fld_tfg_addr_read_done;

	/* TFG DATA */
	nthw_field_t *mp_fld_tfg_data_length;
	nthw_field_t *mp_fld_tfg_data_gap;
	nthw_field_t *mp_fld_tfg_data_id;

	/* TFG CTRL */
	nthw_field_t *mp_fld_tfg_wrap;
	nthw_field_t *mp_fld_tfg_restart;
	nthw_field_t *mp_fld_tfg_enable;
	nthw_field_t *mp_fld_tfg_time_mode;
	nthw_field_t *mp_fld_tfg_id_pos;
	nthw_field_t *mp_fld_tfg_id_ena;
	nthw_field_t *mp_fld_tfg_tx_active;

	/* TFG REPETITION */
	nthw_field_t *mp_fld_tfg_repetition_count;
};

typedef struct nthw_mac_tfg nthw_mac_tfg_t;
typedef struct nthw_mac_tfg nthw_mac_tfg;

nthw_mac_tfg_t *nthw_mac_tfg_new(void);
void nthw_mac_tfg_delete(nthw_mac_tfg_t *p);
int nthw_mac_tfg_init(nthw_mac_tfg_t *p, nthw_fpga_t *p_fpga, int n_instance);

void nthw_mac_tfg_tfg_tx_start(nthw_mac_tfg_t *p, uint32_t repetition, uint32_t size,
	uint32_t pkt_gap);
void nthw_mac_tfg_tfg_tx_stop(nthw_mac_tfg_t *p);

#endif	/* NTHW_MAC_TFG_H_ */

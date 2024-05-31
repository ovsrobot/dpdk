/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef NTHW_GFG_H_
#define NTHW_GFG_H_

struct nthw_gfg {
	nthw_fpga_t *mp_fpga;
	nthw_module_t *mp_mod_gfg;
	int mn_instance;

	int mn_param_gfg_present;

	nthw_field_t *mpa_fld_ctrl_enable[8];
	nthw_field_t *mpa_fld_ctrl_mode[8];
	nthw_field_t *mpa_fld_ctrl_prbs_en[8];
	nthw_field_t *mpa_fld_ctrl_size[8];
	nthw_field_t *mpa_fld_stream_id_val[8];
	nthw_field_t *mpa_fld_run_run[8];
	nthw_field_t *mpa_fld_size_mask[8];
	nthw_field_t *mpa_fld_burst_size_val[8];
};

typedef struct nthw_gfg nthw_gfg_t;
typedef struct nthw_gfg nthw_gfg;

nthw_gfg_t *nthw_gfg_new(void);
int nthw_gfg_init(nthw_gfg_t *p, nthw_fpga_t *p_fpga, int n_instance);

int nthw_gfg_start(nthw_gfg_t *p, const int n_intf_no, const int n_frame_count,
	const int n_frame_size, const int n_frame_fill_mode,
	const int n_frame_stream_id);
int nthw_gfg_stop(nthw_gfg_t *p, const int n_intf_no);
int nthw_gfg_setup(nthw_gfg_t *p, const size_t n_intf_no, const int n_enable,
	const int n_frame_count, const int n_frame_size, const int n_frame_fill_mode,
	const int n_frame_stream_id);

#endif	/* NTHW_GFG_H_ */

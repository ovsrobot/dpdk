/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __NTHW_SDC_H__
#define __NTHW_SDC_H__

struct nthw_sdc {
	nt_fpga_t *mp_fpga;
	nt_module_t *mp_mod_sdc;
	int mn_instance;

	nt_field_t *mp_fld_ctrl_init;
	nt_field_t *mp_fld_ctrl_run_test;
	nt_field_t *mp_fld_ctrl_stop_client;
	nt_field_t *mp_fld_ctrl_test_enable;

	nt_field_t *mp_fld_stat_calib;
	nt_field_t *mp_fld_stat_cell_cnt_stopped;
	nt_field_t *mp_fld_stat_err_found;
	nt_field_t *mp_fld_stat_init_done;
	nt_field_t *mp_fld_stat_mmcm_lock;
	nt_field_t *mp_fld_stat_pll_lock;
	nt_field_t *mp_fld_stat_resetting;

	nt_field_t *mp_fld_cell_cnt;
	nt_field_t *mp_fld_cell_cnt_period;
	nt_field_t *mp_fld_fill_level;
	nt_field_t *mp_fld_max_fill_level;
};

typedef struct nthw_sdc nthw_sdc_t;
typedef struct nthw_sdc nthw_sdc;

nthw_sdc_t *nthw_sdc_new(void);
int nthw_sdc_init(nthw_sdc_t *p, nt_fpga_t *p_fpga, int n_instance);
void nthw_sdc_delete(nthw_sdc_t *p);

int nthw_sdc_wait_states(nthw_sdc_t *p, const int n_poll_iterations,
		       const int n_poll_interval);
int nthw_sdc_get_states(nthw_sdc_t *p, uint64_t *pn_result_mask);

#endif /* __NTHW_SDC_H__ */

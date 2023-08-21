/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __NTHW_TSM_H__
#define __NTHW_TSM_H__

struct nthw_tsm {
	nt_fpga_t *mp_fpga;
	nt_module_t *mp_mod_tsm;
	int mn_instance;

	nt_field_t *mp_fld_config_ts_format;

	nt_field_t *mp_fld_timer_ctrl_timer_en_t0;
	nt_field_t *mp_fld_timer_ctrl_timer_en_t1;

	nt_field_t *mp_fld_timer_timer_t0_max_count;

	nt_field_t *mp_fld_timer_timer_t1_max_count;

	nt_register_t *mp_reg_ts_lo;
	nt_field_t *mp_fld_ts_lo;

	nt_register_t *mp_reg_ts_hi;
	nt_field_t *mp_fld_ts_hi;

	nt_register_t *mp_reg_time_lo;
	nt_field_t *mp_fld_time_lo;

	nt_register_t *mp_reg_time_hi;
	nt_field_t *mp_fld_time_hi;
};

typedef struct nthw_tsm nthw_tsm_t;
typedef struct nthw_tsm nthw_tsm;

nthw_tsm_t *nthw_tsm_new(void);
void nthw_tsm_delete(nthw_tsm_t *p);
int nthw_tsm_init(nthw_tsm_t *p, nt_fpga_t *p_fpga, int n_instance);

int nthw_tsm_get_ts(nthw_tsm_t *p, uint64_t *p_ts);
int nthw_tsm_get_time(nthw_tsm_t *p, uint64_t *p_time);
int nthw_tsm_set_time(nthw_tsm_t *p, uint64_t n_time);

int nthw_tsm_set_timer_t0_enable(nthw_tsm_t *p, bool b_enable);
int nthw_tsm_set_timer_t0_max_count(nthw_tsm_t *p, uint32_t n_timer_val);
int nthw_tsm_set_timer_t1_enable(nthw_tsm_t *p, bool b_enable);
int nthw_tsm_set_timer_t1_max_count(nthw_tsm_t *p, uint32_t n_timer_val);

int nthw_tsm_set_config_ts_format(nthw_tsm_t *p, uint32_t n_val);

#endif /* __NTHW_TSM_H__ */

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __FLOW_NTHW_FLM_H__
#define __FLOW_NTHW_FLM_H__

#include <stdint.h> /* uint32_t */
#include "nthw_fpga_model.h"

struct flm_nthw;

typedef struct flm_nthw flm_nthw_t;

struct flm_nthw *flm_nthw_new(void);
void flm_nthw_delete(struct flm_nthw *p);
int flm_nthw_init(struct flm_nthw *p, nt_fpga_t *p_fpga, int n_instance);
void flm_nthw_set_debug_mode(struct flm_nthw *p, unsigned int n_debug_mode);

/* Control */
void flm_nthw_control_enable(const struct flm_nthw *p, uint32_t val);
void flm_nthw_control_init(const struct flm_nthw *p, uint32_t val);
void flm_nthw_control_lds(const struct flm_nthw *p, uint32_t val);
void flm_nthw_control_lfs(const struct flm_nthw *p, uint32_t val);
void flm_nthw_control_lis(const struct flm_nthw *p, uint32_t val);
void flm_nthw_control_uds(const struct flm_nthw *p, uint32_t val);
void flm_nthw_control_uis(const struct flm_nthw *p, uint32_t val);
void flm_nthw_control_rds(const struct flm_nthw *p, uint32_t val);
void flm_nthw_control_ris(const struct flm_nthw *p, uint32_t val);
void flm_nthw_control_pds(const struct flm_nthw *p, uint32_t val);
void flm_nthw_control_pis(const struct flm_nthw *p, uint32_t val);
void flm_nthw_control_crcwr(const struct flm_nthw *p, uint32_t val);
void flm_nthw_control_crcrd(const struct flm_nthw *p, uint32_t val);
void flm_nthw_control_rbl(const struct flm_nthw *p, uint32_t val);
void flm_nthw_control_eab(const struct flm_nthw *p, uint32_t val);
void flm_nthw_control_split_sdram_usage(const struct flm_nthw *p, uint32_t val);
void flm_nthw_control_flush(const struct flm_nthw *p);

/* Status */
void flm_nthw_status_calibdone(const struct flm_nthw *p, uint32_t *val, int get);
void flm_nthw_status_initdone(const struct flm_nthw *p, uint32_t *val, int get);
void flm_nthw_status_idle(const struct flm_nthw *p, uint32_t *val, int get);
void flm_nthw_status_critical(const struct flm_nthw *p, uint32_t *val, int get);
void flm_nthw_status_panic(const struct flm_nthw *p, uint32_t *val, int get);
void flm_nthw_status_crcerr(const struct flm_nthw *p, uint32_t *val, int get);
void flm_nthw_status_eft_bp(const struct flm_nthw *p, uint32_t *val, int get);
void flm_nthw_status_flush(const struct flm_nthw *p);
void flm_nthw_status_update(const struct flm_nthw *p);

/* Timeout */
void flm_nthw_timeout_t(const struct flm_nthw *p, uint32_t val);
void flm_nthw_timeout_flush(const struct flm_nthw *p);

/* Scrub */
void flm_nthw_scrub_i(const struct flm_nthw *p, uint32_t val);
void flm_nthw_scrub_flush(const struct flm_nthw *p);

/* Load BIN */
void flm_nthw_load_bin(const struct flm_nthw *p, uint32_t val);
void flm_nthw_load_bin_flush(const struct flm_nthw *p);

/* Load PPS */
void flm_nthw_load_pps(const struct flm_nthw *p, uint32_t val);
void flm_nthw_load_pps_flush(const struct flm_nthw *p);

/* Load LPS */
void flm_nthw_load_lps(const struct flm_nthw *p, uint32_t val);
void flm_nthw_load_lps_flush(const struct flm_nthw *p);

/* Load APS */
void flm_nthw_load_aps(const struct flm_nthw *p, uint32_t val);
void flm_nthw_load_aps_flush(const struct flm_nthw *p);

/* Prio */
void flm_nthw_prio_limit0(const struct flm_nthw *p, uint32_t val);
void flm_nthw_prio_ft0(const struct flm_nthw *p, uint32_t val);
void flm_nthw_prio_limit1(const struct flm_nthw *p, uint32_t val);
void flm_nthw_prio_ft1(const struct flm_nthw *p, uint32_t val);
void flm_nthw_prio_limit2(const struct flm_nthw *p, uint32_t val);
void flm_nthw_prio_ft2(const struct flm_nthw *p, uint32_t val);
void flm_nthw_prio_limit3(const struct flm_nthw *p, uint32_t val);
void flm_nthw_prio_ft3(const struct flm_nthw *p, uint32_t val);
void flm_nthw_prio_flush(const struct flm_nthw *p);

/* PST */
void flm_nthw_pst_select(const struct flm_nthw *p, uint32_t val);
void flm_nthw_pst_cnt(const struct flm_nthw *p, uint32_t val);
void flm_nthw_pst_bp(const struct flm_nthw *p, uint32_t val);
void flm_nthw_pst_pp(const struct flm_nthw *p, uint32_t val);
void flm_nthw_pst_tp(const struct flm_nthw *p, uint32_t val);
void flm_nthw_pst_flush(const struct flm_nthw *p);

/* RCP */
void flm_nthw_rcp_select(const struct flm_nthw *p, uint32_t val);
void flm_nthw_rcp_cnt(const struct flm_nthw *p, uint32_t val);
void flm_nthw_rcp_lookup(const struct flm_nthw *p, uint32_t val);
void flm_nthw_rcp_qw0_dyn(const struct flm_nthw *p, uint32_t val);
void flm_nthw_rcp_qw0_ofs(const struct flm_nthw *p, uint32_t val);
void flm_nthw_rcp_qw0_sel(const struct flm_nthw *p, uint32_t val);
void flm_nthw_rcp_qw4_dyn(const struct flm_nthw *p, uint32_t val);
void flm_nthw_rcp_qw4_ofs(const struct flm_nthw *p, uint32_t val);
void flm_nthw_rcp_sw8_dyn(const struct flm_nthw *p, uint32_t val);
void flm_nthw_rcp_sw8_ofs(const struct flm_nthw *p, uint32_t val);
void flm_nthw_rcp_sw8_sel(const struct flm_nthw *p, uint32_t val);
void flm_nthw_rcp_sw9_dyn(const struct flm_nthw *p, uint32_t val);
void flm_nthw_rcp_sw9_ofs(const struct flm_nthw *p, uint32_t val);
void flm_nthw_rcp_mask(const struct flm_nthw *p, const uint32_t *val);
void flm_nthw_rcp_kid(const struct flm_nthw *p, uint32_t val);
void flm_nthw_rcp_opn(const struct flm_nthw *p, uint32_t val);
void flm_nthw_rcp_ipn(const struct flm_nthw *p, uint32_t val);
void flm_nthw_rcp_byt_dyn(const struct flm_nthw *p, uint32_t val);
void flm_nthw_rcp_byt_ofs(const struct flm_nthw *p, uint32_t val);
void flm_nthw_rcp_txplm(const struct flm_nthw *p, uint32_t val);
void flm_nthw_rcp_auto_ipv4_mask(const struct flm_nthw *p, uint32_t val);
void flm_nthw_rcp_flush(const struct flm_nthw *p);

/* Buf Ctrl */
int flm_nthw_buf_ctrl_update(const struct flm_nthw *p, uint32_t *lrn_free,
			  uint32_t *inf_avail, uint32_t *sta_avail);

/* Lrn Data */
int flm_nthw_lrn_data_flush(const struct flm_nthw *p, const uint32_t *data,
			 uint32_t word_count, uint32_t *lrn_free,
			 uint32_t *inf_avail, uint32_t *sta_avail);

/* Inf Data */
int flm_nthw_inf_data_update(const struct flm_nthw *p, uint32_t *data,
			  uint32_t word_count, uint32_t *lrn_free,
			  uint32_t *inf_avail, uint32_t *sta_avail);

/* Sta Data */
int flm_nthw_sta_data_update(const struct flm_nthw *p, uint32_t *data,
			  uint32_t word_count, uint32_t *lrn_free,
			  uint32_t *inf_avail, uint32_t *sta_avail);

/* Stat Lrn _done */
void flm_nthw_stat_lrn_done_cnt(const struct flm_nthw *p, uint32_t *val, int get);
void flm_nthw_stat_lrn_done_update(const struct flm_nthw *p);

/* Stat Lrn Ignore */
void flm_nthw_stat_lrn_ignore_cnt(const struct flm_nthw *p, uint32_t *val, int get);
void flm_nthw_stat_lrn_ignore_update(const struct flm_nthw *p);

/* Stat Lrn Fail */
void flm_nthw_stat_lrn_fail_cnt(const struct flm_nthw *p, uint32_t *val, int get);
void flm_nthw_stat_lrn_fail_update(const struct flm_nthw *p);

/* Stat Unl _done */
void flm_nthw_stat_unl_done_cnt(const struct flm_nthw *p, uint32_t *val, int get);
void flm_nthw_stat_unl_done_update(const struct flm_nthw *p);

/* Stat Unl Ignore */
void flm_nthw_stat_unl_ignore_cnt(const struct flm_nthw *p, uint32_t *val, int get);
void flm_nthw_stat_unl_ignore_update(const struct flm_nthw *p);

/* Stat Prb _done */
void flm_nthw_stat_prb_done_cnt(const struct flm_nthw *p, uint32_t *val, int get);
void flm_nthw_stat_prb_done_update(const struct flm_nthw *p);

/* Stat Prb Ignore */
void flm_nthw_stat_prb_ignore_cnt(const struct flm_nthw *p, uint32_t *val, int get);
void flm_nthw_stat_prb_ignore_update(const struct flm_nthw *p);

/* Stat Rel _done */
void flm_nthw_stat_rel_done_cnt(const struct flm_nthw *p, uint32_t *val, int get);
void flm_nthw_stat_rel_done_update(const struct flm_nthw *p);

/* Stat Rel Ignore */
void flm_nthw_stat_rel_ignore_cnt(const struct flm_nthw *p, uint32_t *val, int get);
void flm_nthw_stat_rel_ignore_update(const struct flm_nthw *p);

/* Stat Aul _done */
void flm_nthw_stat_aul_done_cnt(const struct flm_nthw *p, uint32_t *val, int get);
void flm_nthw_stat_aul_done_update(const struct flm_nthw *p);

/* Stat Aul Ignore */
void flm_nthw_stat_aul_ignore_cnt(const struct flm_nthw *p, uint32_t *val, int get);
void flm_nthw_stat_aul_ignore_update(const struct flm_nthw *p);

/* Stat Aul Fail */
void flm_nthw_stat_aul_fail_cnt(const struct flm_nthw *p, uint32_t *val, int get);
void flm_nthw_stat_aul_fail_update(const struct flm_nthw *p);

/* Stat Tul _done */
void flm_nthw_stat_tul_done_cnt(const struct flm_nthw *p, uint32_t *val, int get);
void flm_nthw_stat_tul_done_update(const struct flm_nthw *p);

/* Stat Flows */
void flm_nthw_stat_flows_cnt(const struct flm_nthw *p, uint32_t *val, int get);
void flm_nthw_stat_flows_update(const struct flm_nthw *p);

/* Stat Sta _done */
void flm_nthw_stat_sta_done_cnt(const struct flm_nthw *p, uint32_t *val, int get);
void flm_nthw_stat_sta_done_update(const struct flm_nthw *p);

/* Stat Inf _done */
void flm_nthw_stat_inf_done_cnt(const struct flm_nthw *p, uint32_t *val, int get);
void flm_nthw_stat_inf_done_update(const struct flm_nthw *p);

/* Stat Inf Skip */
void flm_nthw_stat_inf_skip_cnt(const struct flm_nthw *p, uint32_t *val, int get);
void flm_nthw_stat_inf_skip_update(const struct flm_nthw *p);

/* Stat Pck Hit */
void flm_nthw_stat_pck_hit_cnt(const struct flm_nthw *p, uint32_t *val, int get);
void flm_nthw_stat_pck_hit_update(const struct flm_nthw *p);

/* Stat Pck Miss */
void flm_nthw_stat_pck_miss_cnt(const struct flm_nthw *p, uint32_t *val, int get);
void flm_nthw_stat_pck_miss_update(const struct flm_nthw *p);

/* Stat Pck Unh */
void flm_nthw_stat_pck_unh_cnt(const struct flm_nthw *p, uint32_t *val, int get);
void flm_nthw_stat_pck_unh_update(const struct flm_nthw *p);

/* Stat Pck Dis */
void flm_nthw_stat_pck_dis_cnt(const struct flm_nthw *p, uint32_t *val, int get);
void flm_nthw_stat_pck_dis_update(const struct flm_nthw *p);

/* Stat Csh Hit */
void flm_nthw_stat_csh_hit_cnt(const struct flm_nthw *p, uint32_t *val, int get);
void flm_nthw_stat_csh_hit_update(const struct flm_nthw *p);

/* Stat Csh Miss */
void flm_nthw_stat_csh_miss_cnt(const struct flm_nthw *p, uint32_t *val, int get);
void flm_nthw_stat_csh_miss_update(const struct flm_nthw *p);

/* Stat Csh Unh */
void flm_nthw_stat_csh_unh_cnt(const struct flm_nthw *p, uint32_t *val, int get);
void flm_nthw_stat_csh_unh_update(const struct flm_nthw *p);

/* Stat Cuc Start */
void flm_nthw_stat_cuc_start_cnt(const struct flm_nthw *p, uint32_t *val, int get);
void flm_nthw_stat_cuc_start_update(const struct flm_nthw *p);

/* Stat Cuc Move */
void flm_nthw_stat_cuc_move_cnt(const struct flm_nthw *p, uint32_t *val, int get);
void flm_nthw_stat_cuc_move_update(const struct flm_nthw *p);

struct flm_nthw {
	uint8_t m_physical_adapter_no;
	nt_fpga_t *mp_fpga;
	void *mp_rac;

	nt_module_t *m_flm;

	nt_register_t *mp_control;
	nt_field_t *mp_control_enable;
	nt_field_t *mp_control_init;
	nt_field_t *mp_control_lds;
	nt_field_t *mp_control_lfs;
	nt_field_t *mp_control_lis;
	nt_field_t *mp_control_uds;
	nt_field_t *mp_control_uis;
	nt_field_t *mp_control_rds;
	nt_field_t *mp_control_ris;
	nt_field_t *mp_control_pds;
	nt_field_t *mp_control_pis;
	nt_field_t *mp_control_crcwr;
	nt_field_t *mp_control_crcrd;
	nt_field_t *mp_control_rbl;
	nt_field_t *mp_control_eab;
	nt_field_t *mp_control_split_sdram_usage;

	nt_register_t *mp_status;
	nt_field_t *mp_status_calibdone;
	nt_field_t *mp_status_initdone;
	nt_field_t *mp_status_idle;
	nt_field_t *mp_status_critical;
	nt_field_t *mp_status_panic;
	nt_field_t *mp_status_crcerr;
	nt_field_t *mp_status_eft_bp;

	nt_register_t *mp_timeout;
	nt_field_t *mp_timeout_t;

	nt_register_t *mp_scrub;
	nt_field_t *mp_scrub_i;

	nt_register_t *mp_load_bin;
	nt_field_t *mp_load_bin_bin;

	nt_register_t *mp_load_pps;
	nt_field_t *mp_load_pps_pps;

	nt_register_t *mp_load_lps;
	nt_field_t *mp_load_lps_lps;

	nt_register_t *mp_load_aps;
	nt_field_t *mp_load_aps_aps;

	nt_register_t *mp_prio;
	nt_field_t *mp_prio_limit0;
	nt_field_t *mp_prio_ft0;
	nt_field_t *mp_prio_limit1;
	nt_field_t *mp_prio_ft1;
	nt_field_t *mp_prio_limit2;
	nt_field_t *mp_prio_ft2;
	nt_field_t *mp_prio_limit3;
	nt_field_t *mp_prio_ft3;

	nt_register_t *mp_pst_ctrl;
	nt_field_t *mp_pst_ctrl_adr;
	nt_field_t *mp_pst_ctrl_cnt;
	nt_register_t *mp_pst_data;
	nt_field_t *mp_pst_data_bp;
	nt_field_t *mp_pst_data_pp;
	nt_field_t *mp_pst_data_tp;

	nt_register_t *mp_rcp_ctrl;
	nt_field_t *mp_rcp_ctrl_adr;
	nt_field_t *mp_rcp_ctrl_cnt;
	nt_register_t *mp_rcp_data;
	nt_field_t *mp_rcp_data_lookup;
	nt_field_t *mp_rcp_data_qw0_dyn;
	nt_field_t *mp_rcp_data_qw0_ofs;
	nt_field_t *mp_rcp_data_qw0_sel;
	nt_field_t *mp_rcp_data_qw4_dyn;
	nt_field_t *mp_rcp_data_qw4_ofs;
	nt_field_t *mp_rcp_data_sw8_dyn;
	nt_field_t *mp_rcp_data_sw8_ofs;
	nt_field_t *mp_rcp_data_sw8_sel;
	nt_field_t *mp_rcp_data_sw9_dyn;
	nt_field_t *mp_rcp_data_sw9_ofs;
	nt_field_t *mp_rcp_data_mask;
	nt_field_t *mp_rcp_data_kid;
	nt_field_t *mp_rcp_data_opn;
	nt_field_t *mp_rcp_data_ipn;
	nt_field_t *mp_rcp_data_byt_dyn;
	nt_field_t *mp_rcp_data_byt_ofs;
	nt_field_t *mp_rcp_data_txplm;
	nt_field_t *mp_rcp_data_auto_ipv4_mask;

	nt_register_t *mp_buf_ctrl;
	nt_field_t *mp_buf_ctrl_lrn_free;
	nt_field_t *mp_buf_ctrl_inf_avail;
	nt_field_t *mp_buf_ctrl_sta_avail;

	nt_register_t *mp_lrn_data;
	nt_register_t *mp_inf_data;
	nt_register_t *mp_sta_data;

	nt_register_t *mp_stat_lrn_done;
	nt_field_t *mp_stat_lrn_done_cnt;

	nt_register_t *mp_stat_lrn_ignore;
	nt_field_t *mp_stat_lrn_ignore_cnt;

	nt_register_t *mp_stat_lrn_fail;
	nt_field_t *mp_stat_lrn_fail_cnt;

	nt_register_t *mp_stat_unl_done;
	nt_field_t *mp_stat_unl_done_cnt;

	nt_register_t *mp_stat_unl_ignore;
	nt_field_t *mp_stat_unl_ignore_cnt;

	nt_register_t *mp_stat_prb_done;
	nt_field_t *mp_stat_prb_done_cnt;

	nt_register_t *mp_stat_prb_ignore;
	nt_field_t *mp_stat_prb_ignore_cnt;

	nt_register_t *mp_stat_rel_done;
	nt_field_t *mp_stat_rel_done_cnt;

	nt_register_t *mp_stat_rel_ignore;
	nt_field_t *mp_stat_rel_ignore_cnt;

	nt_register_t *mp_stat_aul_done;
	nt_field_t *mp_stat_aul_done_cnt;

	nt_register_t *mp_stat_aul_ignore;
	nt_field_t *mp_stat_aul_ignore_cnt;

	nt_register_t *mp_stat_aul_fail;
	nt_field_t *mp_stat_aul_fail_cnt;

	nt_register_t *mp_stat_tul_done;
	nt_field_t *mp_stat_tul_done_cnt;

	nt_register_t *mp_stat_flows;
	nt_field_t *mp_stat_flows_cnt;

	nt_register_t *mp_stat_sta_done;
	nt_field_t *mp_stat_sta_done_cnt;

	nt_register_t *mp_stat_inf_done;
	nt_field_t *mp_stat_inf_done_cnt;

	nt_register_t *mp_stat_inf_skip;
	nt_field_t *mp_stat_inf_skip_cnt;

	nt_register_t *mp_stat_pck_hit;
	nt_field_t *mp_stat_pck_hit_cnt;

	nt_register_t *mp_stat_pck_miss;
	nt_field_t *mp_stat_pck_miss_cnt;

	nt_register_t *mp_stat_pck_unh;
	nt_field_t *mp_stat_pck_unh_cnt;

	nt_register_t *mp_stat_pck_dis;
	nt_field_t *mp_stat_pck_dis_cnt;

	nt_register_t *mp_stat_csh_hit;
	nt_field_t *mp_stat_csh_hit_cnt;

	nt_register_t *mp_stat_csh_miss;
	nt_field_t *mp_stat_csh_miss_cnt;

	nt_register_t *mp_stat_csh_unh;
	nt_field_t *mp_stat_csh_unh_cnt;

	nt_register_t *mp_stat_cuc_start;
	nt_field_t *mp_stat_cuc_start_cnt;

	nt_register_t *mp_stat_cuc_move;
	nt_field_t *mp_stat_cuc_move_cnt;
};

#endif /* __FLOW_NTHW_FLM_H__ */

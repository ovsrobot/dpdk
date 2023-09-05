/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _HW_MOD_FLM_V20_H_
#define _HW_MOD_FLM_V20_H_

struct flm_v20_stat_sta_done_s {
	uint32_t cnt;
};

struct flm_v20_stat_inf_done_s {
	uint32_t cnt;
};

struct flm_v20_stat_inf_skip_s {
	uint32_t cnt;
};

struct flm_v20_stat_pck_hit_s {
	uint32_t cnt;
};

struct flm_v20_stat_pck_miss_s {
	uint32_t cnt;
};

struct flm_v20_stat_pck_unh_s {
	uint32_t cnt;
};

struct flm_v20_stat_pck_dis_s {
	uint32_t cnt;
};

struct flm_v20_stat_csh_hit_s {
	uint32_t cnt;
};

struct flm_v20_stat_csh_miss_s {
	uint32_t cnt;
};

struct flm_v20_stat_csh_unh_s {
	uint32_t cnt;
};

struct flm_v20_stat_cuc_start_s {
	uint32_t cnt;
};

struct flm_v20_stat_cuc_move_s {
	uint32_t cnt;
};

struct hw_mod_flm_v20_s {
	struct flm_v17_control_s *control;
	struct flm_v17_status_s *status;
	struct flm_v17_timeout_s *timeout;
	struct flm_v17_scrub_s *scrub;
	struct flm_v17_load_bin_s *load_bin;
	struct flm_v17_load_pps_s *load_pps;
	struct flm_v17_load_lps_s *load_lps;
	struct flm_v17_load_aps_s *load_aps;
	struct flm_v17_prio_s *prio;
	struct flm_v17_pst_s *pst;
	struct flm_v17_rcp_s *rcp;
	struct flm_v17_buf_ctrl_s *buf_ctrl;
	/*
	 * lrn_data is not handled by struct
	 * inf_data is not handled by struct
	 * sta_data is not handled by struct
	 */
	struct flm_v17_stat_lrn_done_s *lrn_done;
	struct flm_v17_stat_lrn_ignore_s *lrn_ignore;
	struct flm_v17_stat_lrn_fail_s *lrn_fail;
	struct flm_v17_stat_unl_done_s *unl_done;
	struct flm_v17_stat_unl_ignore_s *unl_ignore;
	struct flm_v17_stat_rel_done_s *rel_done;
	struct flm_v17_stat_rel_ignore_s *rel_ignore;
	struct flm_v17_stat_aul_done_s *aul_done;
	struct flm_v17_stat_aul_ignore_s *aul_ignore;
	struct flm_v17_stat_aul_fail_s *aul_fail;
	struct flm_v17_stat_tul_done_s *tul_done;
	struct flm_v17_stat_flows_s *flows;
	struct flm_v17_stat_prb_done_s *prb_done;
	struct flm_v17_stat_prb_ignore_s *prb_ignore;
	struct flm_v20_stat_sta_done_s *sta_done;
	struct flm_v20_stat_inf_done_s *inf_done;
	struct flm_v20_stat_inf_skip_s *inf_skip;
	struct flm_v20_stat_pck_hit_s *pck_hit;
	struct flm_v20_stat_pck_miss_s *pck_miss;
	struct flm_v20_stat_pck_unh_s *pck_unh;
	struct flm_v20_stat_pck_dis_s *pck_dis;
	struct flm_v20_stat_csh_hit_s *csh_hit;
	struct flm_v20_stat_csh_miss_s *csh_miss;
	struct flm_v20_stat_csh_unh_s *csh_unh;
	struct flm_v20_stat_cuc_start_s *cuc_start;
	struct flm_v20_stat_cuc_move_s *cuc_move;
};

#endif /* _HW_MOD_FLM_V20_H_ */

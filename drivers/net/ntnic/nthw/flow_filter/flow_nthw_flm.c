/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "ntlog.h"

#include "nthw_drv.h"
#include "nthw_register.h"
#include "nthw_rac.h"

#include "flow_nthw_flm.h"

#include <stdlib.h> /* malloc */
#include <string.h> /* memset */

struct flm_nthw *flm_nthw_new(void)
{
	struct flm_nthw *p = malloc(sizeof(struct flm_nthw));

	if (p)
		(void)memset(p, 0, sizeof(*p));

	return p;
}

void flm_nthw_delete(struct flm_nthw *p)
{
	if (p) {
		(void)memset(p, 0, sizeof(*p));
		free(p);
	}
}

void flm_nthw_set_debug_mode(struct flm_nthw *p, unsigned int n_debug_mode)
{
	module_set_debug_mode(p->m_flm, n_debug_mode);
}

int flm_nthw_init(struct flm_nthw *p, nt_fpga_t *p_fpga, int n_instance)
{
	const char *const p_adapter_id_str = p_fpga->p_fpga_info->mp_adapter_id_str;
	nt_module_t *p_mod = fpga_query_module(p_fpga, MOD_FLM, n_instance);

	assert(n_instance >= 0 && n_instance < 256);

	if (p == NULL)
		return p_mod == NULL ? -1 : 0;

	if (p_mod == NULL) {
		NT_LOG(ERR, NTHW, "%s: Flm %d: no such instance\n",
		       p_adapter_id_str, n_instance);
		return -1;
	}

	p->mp_rac = p_fpga->p_fpga_info->mp_nthw_rac;

	p->mp_fpga = p_fpga;
	p->m_physical_adapter_no = (uint8_t)n_instance;
	p->m_flm = p_mod;

	p->mp_control = module_get_register(p->m_flm, FLM_CONTROL);
	p->mp_control_enable =
		register_get_field(p->mp_control, FLM_CONTROL_ENABLE);
	p->mp_control_init = register_get_field(p->mp_control, FLM_CONTROL_INIT);
	p->mp_control_lds = register_get_field(p->mp_control, FLM_CONTROL_LDS);
	p->mp_control_lfs = register_get_field(p->mp_control, FLM_CONTROL_LFS);
	p->mp_control_lis = register_get_field(p->mp_control, FLM_CONTROL_LIS);
	p->mp_control_uds = register_get_field(p->mp_control, FLM_CONTROL_UDS);
	p->mp_control_uis = register_get_field(p->mp_control, FLM_CONTROL_UIS);
	p->mp_control_rds = register_get_field(p->mp_control, FLM_CONTROL_RDS);
	p->mp_control_ris = register_get_field(p->mp_control, FLM_CONTROL_RIS);
	p->mp_control_pds = register_query_field(p->mp_control, FLM_CONTROL_PDS);
	p->mp_control_pis = register_query_field(p->mp_control, FLM_CONTROL_PIS);
	p->mp_control_crcwr = register_get_field(p->mp_control, FLM_CONTROL_CRCWR);
	p->mp_control_crcrd = register_get_field(p->mp_control, FLM_CONTROL_CRCRD);
	p->mp_control_rbl = register_get_field(p->mp_control, FLM_CONTROL_RBL);
	p->mp_control_eab = register_get_field(p->mp_control, FLM_CONTROL_EAB);
	p->mp_control_split_sdram_usage =
		register_get_field(p->mp_control, FLM_CONTROL_SPLIT_SDRAM_USAGE);

	p->mp_status = module_get_register(p->m_flm, FLM_STATUS);
	p->mp_status_calibdone =
		register_get_field(p->mp_status, FLM_STATUS_CALIBDONE);
	p->mp_status_initdone =
		register_get_field(p->mp_status, FLM_STATUS_INITDONE);
	p->mp_status_idle = register_get_field(p->mp_status, FLM_STATUS_IDLE);
	p->mp_status_critical =
		register_get_field(p->mp_status, FLM_STATUS_CRITICAL);
	p->mp_status_panic = register_get_field(p->mp_status, FLM_STATUS_PANIC);
	p->mp_status_crcerr = register_get_field(p->mp_status, FLM_STATUS_CRCERR);
	p->mp_status_eft_bp = register_get_field(p->mp_status, FLM_STATUS_EFT_BP);

	p->mp_timeout = module_get_register(p->m_flm, FLM_TIMEOUT);
	p->mp_timeout_t = register_get_field(p->mp_timeout, FLM_TIMEOUT_T);

	p->mp_scrub = module_get_register(p->m_flm, FLM_SCRUB);
	p->mp_scrub_i = register_get_field(p->mp_scrub, FLM_SCRUB_I);

	p->mp_load_bin = module_get_register(p->m_flm, FLM_LOAD_BIN);
	p->mp_load_bin_bin = register_get_field(p->mp_load_bin, FLM_LOAD_BIN_BIN);

	p->mp_load_pps = module_get_register(p->m_flm, FLM_LOAD_PPS);
	p->mp_load_pps_pps = register_get_field(p->mp_load_pps, FLM_LOAD_PPS_PPS);

	p->mp_load_lps = module_get_register(p->m_flm, FLM_LOAD_LPS);
	p->mp_load_lps_lps = register_get_field(p->mp_load_lps, FLM_LOAD_LPS_LPS);

	p->mp_load_aps = module_get_register(p->m_flm, FLM_LOAD_APS);
	p->mp_load_aps_aps = register_get_field(p->mp_load_aps, FLM_LOAD_APS_APS);

	p->mp_prio = module_get_register(p->m_flm, FLM_PRIO);
	p->mp_prio_limit0 = register_get_field(p->mp_prio, FLM_PRIO_LIMIT0);
	p->mp_prio_ft0 = register_get_field(p->mp_prio, FLM_PRIO_FT0);
	p->mp_prio_limit1 = register_get_field(p->mp_prio, FLM_PRIO_LIMIT1);
	p->mp_prio_ft1 = register_get_field(p->mp_prio, FLM_PRIO_FT1);
	p->mp_prio_limit2 = register_get_field(p->mp_prio, FLM_PRIO_LIMIT2);
	p->mp_prio_ft2 = register_get_field(p->mp_prio, FLM_PRIO_FT2);
	p->mp_prio_limit3 = register_get_field(p->mp_prio, FLM_PRIO_LIMIT3);
	p->mp_prio_ft3 = register_get_field(p->mp_prio, FLM_PRIO_FT3);

	p->mp_pst_ctrl = module_get_register(p->m_flm, FLM_PST_CTRL);
	p->mp_pst_ctrl_adr = register_get_field(p->mp_pst_ctrl, FLM_PST_CTRL_ADR);
	p->mp_pst_ctrl_cnt = register_get_field(p->mp_pst_ctrl, FLM_PST_CTRL_CNT);
	p->mp_pst_data = module_get_register(p->m_flm, FLM_PST_DATA);
	p->mp_pst_data_bp = register_get_field(p->mp_pst_data, FLM_PST_DATA_BP);
	p->mp_pst_data_pp = register_get_field(p->mp_pst_data, FLM_PST_DATA_PP);
	p->mp_pst_data_tp = register_get_field(p->mp_pst_data, FLM_PST_DATA_TP);

	p->mp_rcp_ctrl = module_get_register(p->m_flm, FLM_RCP_CTRL);
	p->mp_rcp_ctrl_adr = register_get_field(p->mp_rcp_ctrl, FLM_RCP_CTRL_ADR);
	p->mp_rcp_ctrl_cnt = register_get_field(p->mp_rcp_ctrl, FLM_RCP_CTRL_CNT);
	p->mp_rcp_data = module_get_register(p->m_flm, FLM_RCP_DATA);
	p->mp_rcp_data_lookup =
		register_get_field(p->mp_rcp_data, FLM_RCP_DATA_LOOKUP);
	p->mp_rcp_data_qw0_dyn =
		register_get_field(p->mp_rcp_data, FLM_RCP_DATA_QW0_DYN);
	p->mp_rcp_data_qw0_ofs =
		register_get_field(p->mp_rcp_data, FLM_RCP_DATA_QW0_OFS);
	p->mp_rcp_data_qw0_sel =
		register_get_field(p->mp_rcp_data, FLM_RCP_DATA_QW0_SEL);
	p->mp_rcp_data_qw4_dyn =
		register_get_field(p->mp_rcp_data, FLM_RCP_DATA_QW4_DYN);
	p->mp_rcp_data_qw4_ofs =
		register_get_field(p->mp_rcp_data, FLM_RCP_DATA_QW4_OFS);
	p->mp_rcp_data_sw8_dyn =
		register_get_field(p->mp_rcp_data, FLM_RCP_DATA_SW8_DYN);
	p->mp_rcp_data_sw8_ofs =
		register_get_field(p->mp_rcp_data, FLM_RCP_DATA_SW8_OFS);
	p->mp_rcp_data_sw8_sel =
		register_get_field(p->mp_rcp_data, FLM_RCP_DATA_SW8_SEL);
	p->mp_rcp_data_sw9_dyn =
		register_get_field(p->mp_rcp_data, FLM_RCP_DATA_SW9_DYN);
	p->mp_rcp_data_sw9_ofs =
		register_get_field(p->mp_rcp_data, FLM_RCP_DATA_SW9_OFS);
	p->mp_rcp_data_mask = register_get_field(p->mp_rcp_data, FLM_RCP_DATA_MASK);
	p->mp_rcp_data_kid = register_get_field(p->mp_rcp_data, FLM_RCP_DATA_KID);
	p->mp_rcp_data_opn = register_get_field(p->mp_rcp_data, FLM_RCP_DATA_OPN);
	p->mp_rcp_data_ipn = register_get_field(p->mp_rcp_data, FLM_RCP_DATA_IPN);
	p->mp_rcp_data_byt_dyn =
		register_get_field(p->mp_rcp_data, FLM_RCP_DATA_BYT_DYN);
	p->mp_rcp_data_byt_ofs =
		register_get_field(p->mp_rcp_data, FLM_RCP_DATA_BYT_OFS);
	p->mp_rcp_data_txplm = register_get_field(p->mp_rcp_data, FLM_RCP_DATA_TXPLM);
	p->mp_rcp_data_auto_ipv4_mask =
		register_get_field(p->mp_rcp_data, FLM_RCP_DATA_AUTO_IPV4_MASK);

	p->mp_buf_ctrl = module_get_register(p->m_flm, FLM_BUF_CTRL);

	p->mp_lrn_data = module_get_register(p->m_flm, FLM_LRN_DATA);
	p->mp_inf_data = module_get_register(p->m_flm, FLM_INF_DATA);
	p->mp_sta_data = module_get_register(p->m_flm, FLM_STA_DATA);

	p->mp_stat_lrn_done = module_get_register(p->m_flm, FLM_STAT_LRN_DONE);
	p->mp_stat_lrn_done_cnt =
		register_get_field(p->mp_stat_lrn_done, FLM_STAT_LRN_DONE_CNT);

	p->mp_stat_lrn_ignore = module_get_register(p->m_flm, FLM_STAT_LRN_IGNORE);
	p->mp_stat_lrn_ignore_cnt =
		register_get_field(p->mp_stat_lrn_ignore, FLM_STAT_LRN_IGNORE_CNT);

	p->mp_stat_lrn_fail = module_get_register(p->m_flm, FLM_STAT_LRN_FAIL);
	p->mp_stat_lrn_fail_cnt =
		register_get_field(p->mp_stat_lrn_fail, FLM_STAT_LRN_FAIL_CNT);

	p->mp_stat_unl_done = module_get_register(p->m_flm, FLM_STAT_UNL_DONE);
	p->mp_stat_unl_done_cnt =
		register_get_field(p->mp_stat_unl_done, FLM_STAT_UNL_DONE_CNT);

	p->mp_stat_unl_ignore = module_get_register(p->m_flm, FLM_STAT_UNL_IGNORE);
	p->mp_stat_unl_ignore_cnt =
		register_get_field(p->mp_stat_unl_ignore, FLM_STAT_UNL_IGNORE_CNT);

	p->mp_stat_prb_done = module_query_register(p->m_flm, FLM_STAT_PRB_DONE);
	p->mp_stat_prb_done_cnt =
		register_query_field(p->mp_stat_prb_done, FLM_STAT_PRB_DONE_CNT);

	p->mp_stat_prb_ignore = module_query_register(p->m_flm, FLM_STAT_PRB_IGNORE);
	p->mp_stat_prb_ignore_cnt = register_query_field(p->mp_stat_prb_ignore,
				FLM_STAT_PRB_IGNORE_CNT);

	p->mp_stat_rel_done = module_get_register(p->m_flm, FLM_STAT_REL_DONE);
	p->mp_stat_rel_done_cnt =
		register_get_field(p->mp_stat_rel_done, FLM_STAT_REL_DONE_CNT);

	p->mp_stat_rel_ignore = module_get_register(p->m_flm, FLM_STAT_REL_IGNORE);
	p->mp_stat_rel_ignore_cnt =
		register_get_field(p->mp_stat_rel_ignore, FLM_STAT_REL_IGNORE_CNT);

	p->mp_stat_aul_done = module_get_register(p->m_flm, FLM_STAT_AUL_DONE);
	p->mp_stat_aul_done_cnt =
		register_get_field(p->mp_stat_aul_done, FLM_STAT_AUL_DONE_CNT);

	p->mp_stat_aul_ignore = module_get_register(p->m_flm, FLM_STAT_AUL_IGNORE);
	p->mp_stat_aul_ignore_cnt =
		register_get_field(p->mp_stat_aul_ignore, FLM_STAT_AUL_IGNORE_CNT);

	p->mp_stat_aul_fail = module_get_register(p->m_flm, FLM_STAT_AUL_FAIL);
	p->mp_stat_aul_fail_cnt =
		register_get_field(p->mp_stat_aul_fail, FLM_STAT_AUL_FAIL_CNT);

	p->mp_stat_tul_done = module_get_register(p->m_flm, FLM_STAT_TUL_DONE);
	p->mp_stat_tul_done_cnt =
		register_get_field(p->mp_stat_tul_done, FLM_STAT_TUL_DONE_CNT);

	p->mp_stat_flows = module_get_register(p->m_flm, FLM_STAT_FLOWS);
	p->mp_stat_flows_cnt =
		register_get_field(p->mp_stat_flows, FLM_STAT_FLOWS_CNT);

	p->mp_stat_sta_done = module_query_register(p->m_flm, FLM_STAT_STA_DONE);
	p->mp_stat_sta_done_cnt =
		register_query_field(p->mp_stat_sta_done, FLM_STAT_STA_DONE_CNT);

	p->mp_stat_inf_done = module_query_register(p->m_flm, FLM_STAT_INF_DONE);
	p->mp_stat_inf_done_cnt =
		register_query_field(p->mp_stat_inf_done, FLM_STAT_INF_DONE_CNT);

	p->mp_stat_inf_skip = module_query_register(p->m_flm, FLM_STAT_INF_SKIP);
	p->mp_stat_inf_skip_cnt =
		register_query_field(p->mp_stat_inf_skip, FLM_STAT_INF_SKIP_CNT);

	p->mp_stat_pck_hit = module_query_register(p->m_flm, FLM_STAT_PCK_HIT);
	p->mp_stat_pck_hit_cnt =
		register_query_field(p->mp_stat_pck_hit, FLM_STAT_PCK_HIT_CNT);

	p->mp_stat_pck_miss = module_query_register(p->m_flm, FLM_STAT_PCK_MISS);
	p->mp_stat_pck_miss_cnt =
		register_query_field(p->mp_stat_pck_miss, FLM_STAT_PCK_MISS_CNT);

	p->mp_stat_pck_unh = module_query_register(p->m_flm, FLM_STAT_PCK_UNH);
	p->mp_stat_pck_unh_cnt =
		register_query_field(p->mp_stat_pck_unh, FLM_STAT_PCK_UNH_CNT);

	p->mp_stat_pck_dis = module_query_register(p->m_flm, FLM_STAT_PCK_DIS);
	p->mp_stat_pck_dis_cnt =
		register_query_field(p->mp_stat_pck_dis, FLM_STAT_PCK_DIS_CNT);

	p->mp_stat_csh_hit = module_query_register(p->m_flm, FLM_STAT_CSH_HIT);
	p->mp_stat_csh_hit_cnt =
		register_query_field(p->mp_stat_csh_hit, FLM_STAT_CSH_HIT_CNT);

	p->mp_stat_csh_miss = module_query_register(p->m_flm, FLM_STAT_CSH_MISS);
	p->mp_stat_csh_miss_cnt =
		register_query_field(p->mp_stat_csh_miss, FLM_STAT_CSH_MISS_CNT);

	p->mp_stat_csh_unh = module_query_register(p->m_flm, FLM_STAT_CSH_UNH);
	p->mp_stat_csh_unh_cnt =
		register_query_field(p->mp_stat_csh_unh, FLM_STAT_CSH_UNH_CNT);

	p->mp_stat_cuc_start = module_query_register(p->m_flm, FLM_STAT_CUC_START);
	p->mp_stat_cuc_start_cnt =
		register_query_field(p->mp_stat_cuc_start, FLM_STAT_CUC_START_CNT);

	p->mp_stat_cuc_move = module_query_register(p->m_flm, FLM_STAT_CUC_MOVE);
	p->mp_stat_cuc_move_cnt =
		register_query_field(p->mp_stat_cuc_move, FLM_STAT_CUC_MOVE_CNT);

	return 0;
}

void flm_nthw_control_enable(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_control_enable, val);
}

void flm_nthw_control_init(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_control_init, val);
}

void flm_nthw_control_lds(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_control_lds, val);
}

void flm_nthw_control_lfs(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_control_lfs, val);
}

void flm_nthw_control_lis(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_control_lis, val);
}

void flm_nthw_control_uds(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_control_uds, val);
}

void flm_nthw_control_uis(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_control_uis, val);
}

void flm_nthw_control_rds(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_control_rds, val);
}

void flm_nthw_control_ris(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_control_ris, val);
}

void flm_nthw_control_pds(const struct flm_nthw *p, uint32_t val)
{
	assert(p->mp_control_pds);
	field_set_val32(p->mp_control_pds, val);
}

void flm_nthw_control_pis(const struct flm_nthw *p, uint32_t val)
{
	assert(p->mp_control_pis);
	field_set_val32(p->mp_control_pis, val);
}

void flm_nthw_control_crcwr(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_control_crcwr, val);
}

void flm_nthw_control_crcrd(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_control_crcrd, val);
}

void flm_nthw_control_rbl(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_control_rbl, val);
}

void flm_nthw_control_eab(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_control_eab, val);
}

void flm_nthw_control_split_sdram_usage(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_control_split_sdram_usage, val);
}

void flm_nthw_control_flush(const struct flm_nthw *p)
{
	register_flush(p->mp_control, 1);
}

void flm_nthw_status_calibdone(const struct flm_nthw *p, uint32_t *val, int get)
{
	if (get)
		*val = field_get_val32(p->mp_status_calibdone);
}

void flm_nthw_status_initdone(const struct flm_nthw *p, uint32_t *val, int get)
{
	if (get)
		*val = field_get_val32(p->mp_status_initdone);
}

void flm_nthw_status_idle(const struct flm_nthw *p, uint32_t *val, int get)
{
	if (get)
		*val = field_get_val32(p->mp_status_idle);
}

void flm_nthw_status_critical(const struct flm_nthw *p, uint32_t *val, int get)
{
	if (get)
		*val = field_get_val32(p->mp_status_critical);

	else
		field_set_val32(p->mp_status_critical, *val);
}

void flm_nthw_status_panic(const struct flm_nthw *p, uint32_t *val, int get)
{
	if (get)
		*val = field_get_val32(p->mp_status_panic);

	else
		field_set_val32(p->mp_status_panic, *val);
}

void flm_nthw_status_crcerr(const struct flm_nthw *p, uint32_t *val, int get)
{
	if (get)
		*val = field_get_val32(p->mp_status_crcerr);

	else
		field_set_val32(p->mp_status_crcerr, *val);
}

void flm_nthw_status_eft_bp(const struct flm_nthw *p, uint32_t *val, int get)
{
	if (get)
		*val = field_get_val32(p->mp_status_eft_bp);
}

void flm_nthw_status_flush(const struct flm_nthw *p)
{
	register_flush(p->mp_status, 1);
}

void flm_nthw_status_update(const struct flm_nthw *p)
{
	register_update(p->mp_status);
}

void flm_nthw_timeout_t(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_timeout_t, val);
}

void flm_nthw_timeout_flush(const struct flm_nthw *p)
{
	register_flush(p->mp_timeout, 1);
}

void flm_nthw_scrub_i(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_scrub_i, val);
}

void flm_nthw_scrub_flush(const struct flm_nthw *p)
{
	register_flush(p->mp_scrub, 1);
}

void flm_nthw_load_bin(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_load_bin_bin, val);
}

void flm_nthw_load_bin_flush(const struct flm_nthw *p)
{
	register_flush(p->mp_load_bin, 1);
}

void flm_nthw_load_pps(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_load_pps_pps, val);
}

void flm_nthw_load_pps_flush(const struct flm_nthw *p)
{
	register_flush(p->mp_load_pps, 1);
}

void flm_nthw_load_lps(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_load_lps_lps, val);
}

void flm_nthw_load_lps_flush(const struct flm_nthw *p)
{
	register_flush(p->mp_load_lps, 1);
}

void flm_nthw_load_aps(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_load_aps_aps, val);
}

void flm_nthw_load_aps_flush(const struct flm_nthw *p)
{
	register_flush(p->mp_load_aps, 1);
}

void flm_nthw_prio_limit0(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_prio_limit0, val);
}

void flm_nthw_prio_ft0(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_prio_ft0, val);
}

void flm_nthw_prio_limit1(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_prio_limit1, val);
}

void flm_nthw_prio_ft1(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_prio_ft1, val);
}

void flm_nthw_prio_limit2(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_prio_limit2, val);
}

void flm_nthw_prio_ft2(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_prio_ft2, val);
}

void flm_nthw_prio_limit3(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_prio_limit3, val);
}

void flm_nthw_prio_ft3(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_prio_ft3, val);
}

void flm_nthw_prio_flush(const struct flm_nthw *p)
{
	register_flush(p->mp_prio, 1);
}

void flm_nthw_pst_select(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_pst_ctrl_adr, val);
}

void flm_nthw_pst_cnt(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_pst_ctrl_cnt, val);
}

void flm_nthw_pst_bp(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_pst_data_bp, val);
}

void flm_nthw_pst_pp(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_pst_data_pp, val);
}

void flm_nthw_pst_tp(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_pst_data_tp, val);
}

void flm_nthw_pst_flush(const struct flm_nthw *p)
{
	register_flush(p->mp_pst_ctrl, 1);
	register_flush(p->mp_pst_data, 1);
}

void flm_nthw_rcp_select(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_ctrl_adr, val);
}

void flm_nthw_rcp_cnt(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_ctrl_cnt, val);
}

void flm_nthw_rcp_lookup(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_lookup, val);
}

void flm_nthw_rcp_qw0_dyn(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_qw0_dyn, val);
}

void flm_nthw_rcp_qw0_ofs(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_qw0_ofs, val);
}

void flm_nthw_rcp_qw0_sel(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_qw0_sel, val);
}

void flm_nthw_rcp_qw4_dyn(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_qw4_dyn, val);
}

void flm_nthw_rcp_qw4_ofs(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_qw4_ofs, val);
}

void flm_nthw_rcp_sw8_dyn(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_sw8_dyn, val);
}

void flm_nthw_rcp_sw8_ofs(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_sw8_ofs, val);
}

void flm_nthw_rcp_sw8_sel(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_sw8_sel, val);
}

void flm_nthw_rcp_sw9_dyn(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_sw9_dyn, val);
}

void flm_nthw_rcp_sw9_ofs(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_sw9_ofs, val);
}

void flm_nthw_rcp_mask(const struct flm_nthw *p, const uint32_t *val)
{
	field_set_val(p->mp_rcp_data_mask, val, 10);
}

void flm_nthw_rcp_kid(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_kid, val);
}

void flm_nthw_rcp_opn(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_opn, val);
}

void flm_nthw_rcp_ipn(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_ipn, val);
}

void flm_nthw_rcp_byt_dyn(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_byt_dyn, val);
}

void flm_nthw_rcp_byt_ofs(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_byt_ofs, val);
}

void flm_nthw_rcp_txplm(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_txplm, val);
}

void flm_nthw_rcp_auto_ipv4_mask(const struct flm_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_auto_ipv4_mask, val);
}

void flm_nthw_rcp_flush(const struct flm_nthw *p)
{
	register_flush(p->mp_rcp_ctrl, 1);
	register_flush(p->mp_rcp_data, 1);
}

int flm_nthw_buf_ctrl_update(const struct flm_nthw *p, uint32_t *lrn_free,
			  uint32_t *inf_avail, uint32_t *sta_avail)
{
	int ret = -1;

	struct nthw_rac *rac = (struct nthw_rac *)p->mp_rac;
	uint32_t address_bufctrl = register_get_address(p->mp_buf_ctrl);
	rab_bus_id_t bus_id = 1;
	struct dma_buf_ptr bc_buf;

	ret = nthw_rac_rab_dma_begin(rac);
	if (ret == 0) {
		nthw_rac_rab_read32_dma(rac, address_bufctrl, bus_id, 2, &bc_buf);
		ret = nthw_rac_rab_dma_commit(rac);
		if (ret != 0)
			return ret;

		uint32_t bc_mask = bc_buf.size - 1;
		uint32_t bc_index = bc_buf.index;
		*lrn_free = bc_buf.base[bc_index & bc_mask] & 0xffff;
		*inf_avail = (bc_buf.base[bc_index & bc_mask] >> 16) & 0xffff;
		*sta_avail = bc_buf.base[(bc_index + 1) & bc_mask] & 0xffff;
	}

	return ret;
}

int flm_nthw_lrn_data_flush(const struct flm_nthw *p, const uint32_t *data,
			 uint32_t word_count, uint32_t *lrn_free,
			 uint32_t *inf_avail, uint32_t *sta_avail)
{
	int ret = -1;

	struct nthw_rac *rac = (struct nthw_rac *)p->mp_rac;
	uint32_t address = register_get_address(p->mp_lrn_data);
	uint32_t address_bufctrl = register_get_address(p->mp_buf_ctrl);
	rab_bus_id_t bus_id = 1;
	struct dma_buf_ptr bc_buf;

	if (nthw_rac_rab_dma_begin(rac) == 0) {
		/* Announce the number of words to write to LRN_DATA */
		uint32_t bufctrl_data[2];

		bufctrl_data[0] = word_count;
		bufctrl_data[1] = 0;
		nthw_rac_rab_write32_dma(rac, address_bufctrl, bus_id, 2,
					bufctrl_data);
		nthw_rac_rab_write32_dma(rac, address, bus_id, word_count, data);
		nthw_rac_rab_read32_dma(rac, address_bufctrl, bus_id, 2, &bc_buf);
		ret = nthw_rac_rab_dma_commit(rac);
		if (ret != 0)
			return ret;

		uint32_t bc_mask = bc_buf.size - 1;
		uint32_t bc_index = bc_buf.index;
		*lrn_free = bc_buf.base[bc_index & bc_mask] & 0xffff;
		*inf_avail = (bc_buf.base[bc_index & bc_mask] >> 16) & 0xffff;
		*sta_avail = bc_buf.base[(bc_index + 1) & bc_mask] & 0xffff;
	}

	return ret;
}

int flm_nthw_inf_data_update(const struct flm_nthw *p, uint32_t *data,
			  uint32_t word_count, uint32_t *lrn_free,
			  uint32_t *inf_avail, uint32_t *sta_avail)
{
	int ret = -1;

	struct nthw_rac *rac = (struct nthw_rac *)p->mp_rac;
	uint32_t address_infdata = register_get_address(p->mp_inf_data);
	uint32_t address_bufctrl = register_get_address(p->mp_buf_ctrl);
	rab_bus_id_t bus_id = 1;
	struct dma_buf_ptr buf;
	struct dma_buf_ptr bc_buf;

	ret = nthw_rac_rab_dma_begin(rac);
	if (ret == 0) {
		/* Announce the number of words to read from INF_DATA */
		uint32_t bufctrl_data[2];

		bufctrl_data[0] = word_count << 16;
		bufctrl_data[1] = 0;
		nthw_rac_rab_write32_dma(rac, address_bufctrl, bus_id, 2,
					bufctrl_data);
		nthw_rac_rab_read32_dma(rac, address_infdata, bus_id, word_count,
				       &buf);
		nthw_rac_rab_read32_dma(rac, address_bufctrl, bus_id, 2, &bc_buf);
		ret = nthw_rac_rab_dma_commit(rac);
		if (ret != 0)
			return ret;

		uint32_t mask = buf.size - 1;
		uint32_t index = buf.index;

		for (uint32_t i = 0; i < word_count; ++index, ++i)
			data[i] = buf.base[index & mask];

		uint32_t bc_mask = bc_buf.size - 1;
		uint32_t bc_index = bc_buf.index;
		*lrn_free = bc_buf.base[bc_index & bc_mask] & 0xffff;
		*inf_avail = (bc_buf.base[bc_index & bc_mask] >> 16) & 0xffff;
		*sta_avail = bc_buf.base[(bc_index + 1) & bc_mask] & 0xffff;
	}

	return ret;
}

int flm_nthw_sta_data_update(const struct flm_nthw *p, uint32_t *data,
			  uint32_t word_count, uint32_t *lrn_free,
			  uint32_t *inf_avail, uint32_t *sta_avail)
{
	int ret = -1;

	struct nthw_rac *rac = (struct nthw_rac *)p->mp_rac;
	uint32_t address_stadata = register_get_address(p->mp_sta_data);
	uint32_t address_bufctrl = register_get_address(p->mp_buf_ctrl);
	rab_bus_id_t bus_id = 1;
	struct dma_buf_ptr buf;
	struct dma_buf_ptr bc_buf;

	ret = nthw_rac_rab_dma_begin(rac);
	if (ret == 0) {
		/* Announce the number of words to read from STA_DATA */
		uint32_t bufctrl_data[2];

		bufctrl_data[0] = 0;
		bufctrl_data[1] = word_count;
		nthw_rac_rab_write32_dma(rac, address_bufctrl, bus_id, 2,
					bufctrl_data);
		nthw_rac_rab_read32_dma(rac, address_stadata, bus_id, word_count,
				       &buf);
		nthw_rac_rab_read32_dma(rac, address_bufctrl, bus_id, 2, &bc_buf);
		ret = nthw_rac_rab_dma_commit(rac);
		if (ret != 0)
			return ret;

		uint32_t mask = buf.size - 1;
		uint32_t index = buf.index;

		for (uint32_t i = 0; i < word_count; ++index, ++i)
			data[i] = buf.base[index & mask];

		uint32_t bc_mask = bc_buf.size - 1;
		uint32_t bc_index = bc_buf.index;
		*lrn_free = bc_buf.base[bc_index & bc_mask] & 0xffff;
		*inf_avail = (bc_buf.base[bc_index & bc_mask] >> 16) & 0xffff;
		*sta_avail = bc_buf.base[(bc_index + 1) & bc_mask] & 0xffff;
	}

	return ret;
}

void flm_nthw_stat_lrn_done_cnt(const struct flm_nthw *p, uint32_t *val, int get)
{
	if (get)
		*val = field_get_val32(p->mp_stat_lrn_done_cnt);
}

void flm_nthw_stat_lrn_done_update(const struct flm_nthw *p)
{
	register_update(p->mp_stat_lrn_done);
}

void flm_nthw_stat_lrn_ignore_cnt(const struct flm_nthw *p, uint32_t *val, int get)
{
	if (get)
		*val = field_get_val32(p->mp_stat_lrn_ignore_cnt);
}

void flm_nthw_stat_lrn_ignore_update(const struct flm_nthw *p)
{
	register_update(p->mp_stat_lrn_ignore);
}

void flm_nthw_stat_lrn_fail_cnt(const struct flm_nthw *p, uint32_t *val, int get)
{
	if (get)
		*val = field_get_val32(p->mp_stat_lrn_fail_cnt);
}

void flm_nthw_stat_lrn_fail_update(const struct flm_nthw *p)
{
	register_update(p->mp_stat_lrn_fail);
}

void flm_nthw_stat_unl_done_cnt(const struct flm_nthw *p, uint32_t *val, int get)
{
	if (get)
		*val = field_get_val32(p->mp_stat_unl_done_cnt);
}

void flm_nthw_stat_unl_done_update(const struct flm_nthw *p)
{
	register_update(p->mp_stat_unl_done);
}

void flm_nthw_stat_unl_ignore_cnt(const struct flm_nthw *p, uint32_t *val, int get)
{
	if (get)
		*val = field_get_val32(p->mp_stat_unl_ignore_cnt);
}

void flm_nthw_stat_unl_ignore_update(const struct flm_nthw *p)
{
	register_update(p->mp_stat_unl_ignore);
}

void flm_nthw_stat_prb_done_cnt(const struct flm_nthw *p, uint32_t *val, int get)
{
	assert(p->mp_stat_prb_done_cnt);
	if (get)
		*val = field_get_val32(p->mp_stat_prb_done_cnt);
}

void flm_nthw_stat_prb_done_update(const struct flm_nthw *p)
{
	assert(p->mp_stat_prb_done);
	register_update(p->mp_stat_prb_done);
}

void flm_nthw_stat_prb_ignore_cnt(const struct flm_nthw *p, uint32_t *val, int get)
{
	assert(p->mp_stat_prb_ignore_cnt);
	if (get)
		*val = field_get_val32(p->mp_stat_prb_ignore_cnt);
}

void flm_nthw_stat_prb_ignore_update(const struct flm_nthw *p)
{
	assert(p->mp_stat_prb_ignore);
	register_update(p->mp_stat_prb_ignore);
}

void flm_nthw_stat_rel_done_cnt(const struct flm_nthw *p, uint32_t *val, int get)
{
	if (get)
		*val = field_get_val32(p->mp_stat_rel_done_cnt);
}

void flm_nthw_stat_rel_done_update(const struct flm_nthw *p)
{
	register_update(p->mp_stat_rel_done);
}

void flm_nthw_stat_rel_ignore_cnt(const struct flm_nthw *p, uint32_t *val, int get)
{
	if (get)
		*val = field_get_val32(p->mp_stat_rel_ignore_cnt);
}

void flm_nthw_stat_rel_ignore_update(const struct flm_nthw *p)
{
	register_update(p->mp_stat_rel_ignore);
}

void flm_nthw_stat_aul_done_cnt(const struct flm_nthw *p, uint32_t *val, int get)
{
	if (get)
		*val = field_get_val32(p->mp_stat_aul_done_cnt);
}

void flm_nthw_stat_aul_done_update(const struct flm_nthw *p)
{
	register_update(p->mp_stat_aul_done);
}

void flm_nthw_stat_aul_ignore_cnt(const struct flm_nthw *p, uint32_t *val, int get)
{
	if (get)
		*val = field_get_val32(p->mp_stat_aul_ignore_cnt);
}

void flm_nthw_stat_aul_ignore_update(const struct flm_nthw *p)
{
	register_update(p->mp_stat_aul_ignore);
}

void flm_nthw_stat_aul_fail_cnt(const struct flm_nthw *p, uint32_t *val, int get)
{
	if (get)
		*val = field_get_val32(p->mp_stat_aul_fail_cnt);
}

void flm_nthw_stat_aul_fail_update(const struct flm_nthw *p)
{
	register_update(p->mp_stat_aul_fail);
}

void flm_nthw_stat_tul_done_cnt(const struct flm_nthw *p, uint32_t *val, int get)
{
	if (get)
		*val = field_get_val32(p->mp_stat_tul_done_cnt);
}

void flm_nthw_stat_tul_done_update(const struct flm_nthw *p)
{
	register_update(p->mp_stat_tul_done);
}

void flm_nthw_stat_flows_cnt(const struct flm_nthw *p, uint32_t *val, int get)
{
	if (get)
		*val = field_get_val32(p->mp_stat_flows_cnt);
}

void flm_nthw_stat_flows_update(const struct flm_nthw *p)
{
	register_update(p->mp_stat_flows);
}

void flm_nthw_stat_sta_done_cnt(const struct flm_nthw *p, uint32_t *val, int get)
{
	assert(p->mp_stat_sta_done_cnt);
	if (get)
		*val = field_get_val32(p->mp_stat_sta_done_cnt);
}

void flm_nthw_stat_sta_done_update(const struct flm_nthw *p)
{
	assert(p->mp_stat_sta_done);
	register_update(p->mp_stat_sta_done);
}

void flm_nthw_stat_inf_done_cnt(const struct flm_nthw *p, uint32_t *val, int get)
{
	assert(p->mp_stat_inf_done_cnt);
	if (get)
		*val = field_get_val32(p->mp_stat_inf_done_cnt);
}

void flm_nthw_stat_inf_done_update(const struct flm_nthw *p)
{
	assert(p->mp_stat_inf_done);
	register_update(p->mp_stat_inf_done);
}

void flm_nthw_stat_inf_skip_cnt(const struct flm_nthw *p, uint32_t *val, int get)
{
	assert(p->mp_stat_inf_skip_cnt);
	if (get)
		*val = field_get_val32(p->mp_stat_inf_skip_cnt);
}

void flm_nthw_stat_inf_skip_update(const struct flm_nthw *p)
{
	assert(p->mp_stat_inf_skip);
	register_update(p->mp_stat_inf_skip);
}

void flm_nthw_stat_pck_hit_cnt(const struct flm_nthw *p, uint32_t *val, int get)
{
	assert(p->mp_stat_pck_hit_cnt);
	if (get)
		*val = field_get_val32(p->mp_stat_pck_hit_cnt);
}

void flm_nthw_stat_pck_hit_update(const struct flm_nthw *p)
{
	assert(p->mp_stat_pck_hit);
	register_update(p->mp_stat_pck_hit);
}

void flm_nthw_stat_pck_miss_cnt(const struct flm_nthw *p, uint32_t *val, int get)
{
	assert(p->mp_stat_pck_miss_cnt);
	if (get)
		*val = field_get_val32(p->mp_stat_pck_miss_cnt);
}

void flm_nthw_stat_pck_miss_update(const struct flm_nthw *p)
{
	assert(p->mp_stat_pck_miss);
	register_update(p->mp_stat_pck_miss);
}

void flm_nthw_stat_pck_unh_cnt(const struct flm_nthw *p, uint32_t *val, int get)
{
	assert(p->mp_stat_pck_unh_cnt);
	if (get)
		*val = field_get_val32(p->mp_stat_pck_unh_cnt);
}

void flm_nthw_stat_pck_unh_update(const struct flm_nthw *p)
{
	assert(p->mp_stat_pck_unh);
	register_update(p->mp_stat_pck_unh);
}

void flm_nthw_stat_pck_dis_cnt(const struct flm_nthw *p, uint32_t *val, int get)
{
	assert(p->mp_stat_pck_dis_cnt);
	if (get)
		*val = field_get_val32(p->mp_stat_pck_dis_cnt);
}

void flm_nthw_stat_pck_dis_update(const struct flm_nthw *p)
{
	assert(p->mp_stat_pck_dis);
	register_update(p->mp_stat_pck_dis);
}

void flm_nthw_stat_csh_hit_cnt(const struct flm_nthw *p, uint32_t *val, int get)
{
	assert(p->mp_stat_csh_hit_cnt);
	if (get)
		*val = field_get_val32(p->mp_stat_csh_hit_cnt);
}

void flm_nthw_stat_csh_hit_update(const struct flm_nthw *p)
{
	assert(p->mp_stat_csh_hit);
	register_update(p->mp_stat_csh_hit);
}

void flm_nthw_stat_csh_miss_cnt(const struct flm_nthw *p, uint32_t *val, int get)
{
	assert(p->mp_stat_csh_miss_cnt);
	if (get)
		*val = field_get_val32(p->mp_stat_csh_miss_cnt);
}

void flm_nthw_stat_csh_miss_update(const struct flm_nthw *p)
{
	assert(p->mp_stat_csh_miss);
	register_update(p->mp_stat_csh_miss);
}

void flm_nthw_stat_csh_unh_cnt(const struct flm_nthw *p, uint32_t *val, int get)
{
	assert(p->mp_stat_csh_unh_cnt);
	if (get)
		*val = field_get_val32(p->mp_stat_csh_unh_cnt);
}

void flm_nthw_stat_csh_unh_update(const struct flm_nthw *p)
{
	assert(p->mp_stat_csh_unh);
	register_update(p->mp_stat_csh_unh);
}

void flm_nthw_stat_cuc_start_cnt(const struct flm_nthw *p, uint32_t *val, int get)
{
	assert(p->mp_stat_cuc_start_cnt);
	if (get)
		*val = field_get_val32(p->mp_stat_cuc_start_cnt);
}

void flm_nthw_stat_cuc_start_update(const struct flm_nthw *p)
{
	assert(p->mp_stat_cuc_start);
	register_update(p->mp_stat_cuc_start);
}

void flm_nthw_stat_cuc_move_cnt(const struct flm_nthw *p, uint32_t *val, int get)
{
	assert(p->mp_stat_cuc_move_cnt);
	if (get)
		*val = field_get_val32(p->mp_stat_cuc_move_cnt);
}

void flm_nthw_stat_cuc_move_update(const struct flm_nthw *p)
{
	assert(p->mp_stat_cuc_move);
	register_update(p->mp_stat_cuc_move);
}

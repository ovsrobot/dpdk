/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __FLOW_NTHW_CAT_H__
#define __FLOW_NTHW_CAT_H__

#include <stdint.h> /* uint32_t */
#include "nthw_fpga_model.h"

struct cat_nthw;

typedef struct cat_nthw cat_nthw_t;

struct cat_nthw *cat_nthw_new(void);
void cat_nthw_delete(struct cat_nthw *p);
int cat_nthw_init(struct cat_nthw *p, nt_fpga_t *p_fpga, int n_instance);

int cat_nthw_setup(struct cat_nthw *p, int n_idx, int n_idx_cnt);
void cat_nthw_set_debug_mode(struct cat_nthw *p, unsigned int n_debug_mode);

/* CFN */
void cat_nthw_cfn_select(const struct cat_nthw *p, uint32_t val);
void r(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_enable(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_inv(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_ptc_inv(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_ptc_isl(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_ptc_cfp(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_ptc_mac(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_ptc_l2(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_ptc_vn_tag(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_ptc_vlan(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_ptc_mpls(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_ptc_l3(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_ptc_frag(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_ptc_ip_prot(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_ptc_l4(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_ptc_tunnel(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_ptc_tnl_l2(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_ptc_tnl_vlan(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_ptc_tnl_mpls(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_ptc_tnl_l3(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_ptc_tnl_frag(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_ptc_tnl_ip_prot(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_ptc_tnl_l4(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_err_inv(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_err_cv(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_err_fcs(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_err_trunc(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_err_l3_cs(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_err_l4_cs(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_err_tnl_l3_cs(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_err_tnl_l4_cs(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_err_ttl_exp(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_err_tnl_ttl_exp(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_mac_port(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_pm_cmp(const struct cat_nthw *p, const uint32_t *val);
void cat_nthw_cfn_pm_dct(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_pm_ext_inv(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_pm_cmb(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_pm_and_inv(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_pm_or_inv(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_pm_inv(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_lc(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_lc_inv(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_km0_or(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_km1_or(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cfn_flush(const struct cat_nthw *p);
/* KCE 0/1 */
void cat_nthw_kce_select(const struct cat_nthw *p, int index, uint32_t val);
void cat_nthw_kce_cnt(const struct cat_nthw *p, int index, uint32_t val);
void cat_nthw_kce_enable(const struct cat_nthw *p, int index, uint32_t val);
void cat_nthw_kce_flush(const struct cat_nthw *p, int index);
/* KCS 0/1 */
void cat_nthw_kcs_select(const struct cat_nthw *p, int index, uint32_t val);
void cat_nthw_kcs_cnt(const struct cat_nthw *p, int index, uint32_t val);
void cat_nthw_kcs_category(const struct cat_nthw *p, int index, uint32_t val);
void cat_nthw_kcs_flush(const struct cat_nthw *p, int index);
/* FTE 0/1 */
void cat_nthw_fte_select(const struct cat_nthw *p, int index, uint32_t val);
void cat_nthw_fte_cnt(const struct cat_nthw *p, int index, uint32_t val);
void cat_nthw_fte_enable(const struct cat_nthw *p, int index, uint32_t val);
void cat_nthw_fte_flush(const struct cat_nthw *p, int index);
/* CTE */
void cat_nthw_cte_select(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cte_cnt(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cte_enable_col(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cte_enable_cor(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cte_enable_hsh(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cte_enable_qsl(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cte_enable_ipf(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cte_enable_slc(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cte_enable_pdb(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cte_enable_msk(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cte_enable_hst(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cte_enable_epp(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cte_enable_tpe(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cte_enable_rrb(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cte_flush(const struct cat_nthw *p);
/* CTS */
void cat_nthw_cts_select(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cts_cnt(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cts_flush(const struct cat_nthw *p);
void cat_nthw_cts_cat_a(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cts_cat_b(const struct cat_nthw *p, uint32_t val);
/* COT */
void cat_nthw_cot_select(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cot_cnt(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cot_color(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cot_km(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cot_nfv_sb(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cot_flush(const struct cat_nthw *p);
/* CCT */
void cat_nthw_cct_select(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cct_cnt(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cct_color(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cct_km(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cct_flush(const struct cat_nthw *p);
/* EXO */
void cat_nthw_exo_select(const struct cat_nthw *p, uint32_t val);
void cat_nthw_exo_cnt(const struct cat_nthw *p, uint32_t val);
void cat_nthw_exo_dyn(const struct cat_nthw *p, uint32_t val);
void cat_nthw_exo_ofs(const struct cat_nthw *p, int32_t val);
void cat_nthw_exo_flush(const struct cat_nthw *p);
/* RCK */
void cat_nthw_rck_select(const struct cat_nthw *p, uint32_t val);
void cat_nthw_rck_cnt(const struct cat_nthw *p, uint32_t val);
void cat_nthw_rck_data(const struct cat_nthw *p, uint32_t val);
void cat_nthw_rck_flush(const struct cat_nthw *p);
/* LEN */
void cat_nthw_len_select(const struct cat_nthw *p, uint32_t val);
void cat_nthw_len_cnt(const struct cat_nthw *p, uint32_t val);
void cat_nthw_len_lower(const struct cat_nthw *p, uint32_t val);
void cat_nthw_len_upper(const struct cat_nthw *p, uint32_t val);
void cat_nthw_len_dyn1(const struct cat_nthw *p, uint32_t val);
void cat_nthw_len_dyn2(const struct cat_nthw *p, uint32_t val);
void cat_nthw_len_inv(const struct cat_nthw *p, uint32_t val);
void cat_nthw_len_flush(const struct cat_nthw *p);
/* KCC */
void cat_nthw_kcc_select(const struct cat_nthw *p, uint32_t val);
void cat_nthw_kcc_cnt(const struct cat_nthw *p, uint32_t val);
void cat_nthw_kcc_key(const struct cat_nthw *p, uint32_t *val);
void cat_nthw_kcc_category(const struct cat_nthw *p, uint32_t val);
void cat_nthw_kcc_id(const struct cat_nthw *p, uint32_t val);
void cat_nthw_kcc_flush(const struct cat_nthw *p);
/* CCE */
void cat_nthw_cce_select(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cce_cnt(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cce_data_imm(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cce_data_ind(const struct cat_nthw *p, uint32_t val);
void cat_nthw_cce_flush(const struct cat_nthw *p);
/* CCS */
void cat_nthw_ccs_select(const struct cat_nthw *p, uint32_t val);
void cat_nthw_ccs_cnt(const struct cat_nthw *p, uint32_t val);
void cat_nthw_ccs_data_cor_en(const struct cat_nthw *p, uint32_t val);
void cat_nthw_ccs_data_cor(const struct cat_nthw *p, uint32_t val);
void cat_nthw_ccs_data_hsh_en(const struct cat_nthw *p, uint32_t val);
void cat_nthw_ccs_data_hsh(const struct cat_nthw *p, uint32_t val);
void cat_nthw_ccs_data_qsl_en(const struct cat_nthw *p, uint32_t val);
void cat_nthw_ccs_data_qsl(const struct cat_nthw *p, uint32_t val);
void cat_nthw_ccs_data_ipf_en(const struct cat_nthw *p, uint32_t val);
void cat_nthw_ccs_data_ipf(const struct cat_nthw *p, uint32_t val);
void cat_nthw_ccs_data_slc_en(const struct cat_nthw *p, uint32_t val);
void cat_nthw_ccs_data_slc(const struct cat_nthw *p, uint32_t val);
void cat_nthw_ccs_data_pdb_en(const struct cat_nthw *p, uint32_t val);
void cat_nthw_ccs_data_pdb(const struct cat_nthw *p, uint32_t val);
void cat_nthw_ccs_data_msk_en(const struct cat_nthw *p, uint32_t val);
void cat_nthw_ccs_data_msk(const struct cat_nthw *p, uint32_t val);
void cat_nthw_ccs_data_hst_en(const struct cat_nthw *p, uint32_t val);
void cat_nthw_ccs_data_hst(const struct cat_nthw *p, uint32_t val);
void cat_nthw_ccs_data_epp_en(const struct cat_nthw *p, uint32_t val);
void cat_nthw_ccs_data_epp(const struct cat_nthw *p, uint32_t val);
void cat_nthw_ccs_data_tpe_en(const struct cat_nthw *p, uint32_t val);
void cat_nthw_ccs_data_tpe(const struct cat_nthw *p, uint32_t val);
void cat_nthw_ccs_data_rrb_en(const struct cat_nthw *p, uint32_t val);
void cat_nthw_ccs_data_rrb(const struct cat_nthw *p, uint32_t val);
void cat_nthw_ccs_data_sb0_type(const struct cat_nthw *p, uint32_t val);
void cat_nthw_ccs_data_sb0_data(const struct cat_nthw *p, uint32_t val);
void cat_nthw_ccs_data_sb1_type(const struct cat_nthw *p, uint32_t val);
void cat_nthw_ccs_data_sb1_data(const struct cat_nthw *p, uint32_t val);
void cat_nthw_ccs_data_sb2_type(const struct cat_nthw *p, uint32_t val);
void cat_nthw_ccs_data_sb2_data(const struct cat_nthw *p, uint32_t val);
void cat_nthw_ccs_flush(const struct cat_nthw *p);

struct cat_nthw {
	uint8_t m_physical_adapter_no;
	nt_fpga_t *mp_fpga;
	nt_module_t *m_cat;
	int m_km_if_cnt;

	nt_register_t *mp_cfn_ctrl;
	nt_field_t *mp_cfn_addr;
	nt_field_t *mp_cfn_cnt;
	nt_register_t *mp_cfn_data;
	nt_field_t *mp_cfn_data_enable;
	nt_field_t *mp_cfn_data_inv;
	nt_field_t *mp_cfn_data_ptc_inv;
	nt_field_t *mp_cfn_data_ptc_isl;
	nt_field_t *mp_cfn_data_ptc_cfp;
	nt_field_t *mp_cfn_data_ptc_mac;
	nt_field_t *mp_cfn_data_ptc_l2;
	nt_field_t *mp_cfn_data_ptc_vn_tag;
	nt_field_t *mp_cfn_data_ptc_vlan;
	nt_field_t *mp_cfn_data_ptc_mpls;
	nt_field_t *mp_cfn_data_ptc_l3;
	nt_field_t *mp_cfn_data_ptc_frag;
	nt_field_t *mp_cfn_data_ptc_ip_prot;
	nt_field_t *mp_cfn_data_ptc_l4;
	nt_field_t *mp_cfn_data_ptc_tunnel;
	nt_field_t *mp_cfn_data_ptc_tnl_l2;
	nt_field_t *mp_cfn_data_ptc_tnl_vlan;
	nt_field_t *mp_cfn_data_ptc_tnl_mpls;
	nt_field_t *mp_cfn_data_ptc_tnl_l3;
	nt_field_t *mp_cfn_data_ptc_tnl_frag;
	nt_field_t *mp_cfn_data_ptc_tnl_ip_prot;
	nt_field_t *mp_cfn_data_ptc_tnl_l4;
	nt_field_t *mp_cfn_data_err_inv;
	nt_field_t *mp_cfn_data_err_cv;
	nt_field_t *mp_cfn_data_err_fcs;
	nt_field_t *mp_cfn_data_err_trunc;
	nt_field_t *mp_cfn_data_err_l3_cs;
	nt_field_t *mp_cfn_data_err_l4_cs;
	nt_field_t *mp_cfn_data_err_tnl_l3_cs;
	nt_field_t *mp_cfn_data_err_tnl_l4_cs;
	nt_field_t *mp_cfn_data_err_ttl_exp;
	nt_field_t *mp_cfn_data_err_tnl_ttl_exp;
	nt_field_t *mp_cfn_data_mac_port;
	nt_field_t *mp_cfn_data_pm_cmp;
	nt_field_t *mp_cfn_data_pm_dct;
	nt_field_t *mp_cfn_data_pm_ext_inv;
	nt_field_t *mp_cfn_data_pm_cmb;
	nt_field_t *mp_cfn_data_pm_and_inv;
	nt_field_t *mp_cfn_data_pm_or_inv;
	nt_field_t *mp_cfn_data_pm_inv;
	nt_field_t *mp_cfn_data_lc;
	nt_field_t *mp_cfn_data_lc_inv;
	nt_field_t *mp_cfn_data_km0_or;
	nt_field_t *mp_cfn_data_km1_or;

	nt_register_t *mp_kce_ctrl[2];
	nt_field_t *mp_kce_addr[2];
	nt_field_t *mp_kce_cnt[2];
	nt_register_t *mp_kce_data[2];
	nt_field_t *mp_kce_data_enable[2];

	nt_register_t *mp_kcs_ctrl[2];
	nt_field_t *mp_kcs_addr[2];
	nt_field_t *mp_kcs_cnt[2];
	nt_register_t *mp_kcs_data[2];
	nt_field_t *mp_kcs_data_category[2];

	nt_register_t *mp_fte_ctrl[2];
	nt_field_t *mp_fte_addr[2];
	nt_field_t *mp_fte_cnt[2];
	nt_register_t *mp_fte_data[2];
	nt_field_t *mp_fte_data_enable[2];

	nt_register_t *mp_cte_ctrl;
	nt_field_t *mp_cte_addr;
	nt_field_t *mp_cte_cnt;
	nt_register_t *mp_cte_data;
	nt_field_t *mp_cte_data_col;
	nt_field_t *mp_cte_data_cor;
	nt_field_t *mp_cte_data_hsh;
	nt_field_t *mp_cte_data_qsl;
	nt_field_t *mp_cte_data_ipf;
	nt_field_t *mp_cte_data_slc;
	nt_field_t *mp_cte_data_pdb;
	nt_field_t *mp_cte_data_msk;
	nt_field_t *mp_cte_data_hst;
	nt_field_t *mp_cte_data_epp;
	nt_field_t *mp_cte_data_tpe;
	nt_field_t *mp_cte_data_rrb;

	nt_register_t *mp_cts_ctrl;
	nt_field_t *mp_cts_addr;
	nt_field_t *mp_cts_cnt;
	nt_register_t *mp_cts_data;
	nt_field_t *mp_cts_data_cat_a;
	nt_field_t *mp_cts_data_cat_b;

	nt_register_t *mp_cot_ctrl;
	nt_field_t *mp_cot_addr;
	nt_field_t *mp_cot_cnt;
	nt_register_t *mp_cot_data;
	nt_field_t *mp_cot_data_color;
	nt_field_t *mp_cot_data_km;
	nt_field_t *mp_cot_data_nfv_sb;

	nt_register_t *mp_cct_ctrl;
	nt_field_t *mp_cct_addr;
	nt_field_t *mp_cct_cnt;
	nt_register_t *mp_cct_data;
	nt_field_t *mp_cct_data_color;
	nt_field_t *mp_cct_data_km;

	nt_register_t *mp_exo_ctrl;
	nt_field_t *mp_exo_addr;
	nt_field_t *mp_exo_cnt;
	nt_register_t *mp_exo_data;
	nt_field_t *mp_exo_data_dyn;
	nt_field_t *mp_exo_data_ofs;

	nt_register_t *mp_rck_ctrl;
	nt_field_t *mp_rck_addr;
	nt_field_t *mp_rck_cnt;
	nt_register_t *mp_rck_data;

	nt_register_t *mp_len_ctrl;
	nt_field_t *mp_len_addr;
	nt_field_t *mp_len_cnt;
	nt_register_t *mp_len_data;
	nt_field_t *mp_len_data_lower;
	nt_field_t *mp_len_data_upper;
	nt_field_t *mp_len_data_dyn1;
	nt_field_t *mp_len_data_dyn2;
	nt_field_t *mp_len_data_inv;
	nt_register_t *mp_kcc_ctrl;
	nt_field_t *mp_kcc_addr;
	nt_field_t *mp_kcc_cnt;

	nt_register_t *mp_kcc_data;
	nt_field_t *mp_kcc_data_key;
	nt_field_t *mp_kcc_data_category;
	nt_field_t *mp_kcc_data_id;

	nt_register_t *mp_cce_ctrl;
	nt_field_t *mp_cce_addr;
	nt_field_t *mp_cce_cnt;

	nt_register_t *mp_cce_data;
	nt_field_t *mp_cce_data_imm;
	nt_field_t *mp_cce_data_ind;

	nt_register_t *mp_ccs_ctrl;
	nt_field_t *mp_ccs_addr;
	nt_field_t *mp_ccs_cnt;

	nt_register_t *mp_ccs_data;
	nt_field_t *mp_ccs_data_cor_en;
	nt_field_t *mp_ccs_data_cor;

	nt_field_t *mp_ccs_data_hsh_en;
	nt_field_t *mp_ccs_data_hsh;
	nt_field_t *mp_ccs_data_qsl_en;
	nt_field_t *mp_ccs_data_qsl;
	nt_field_t *mp_ccs_data_ipf_en;
	nt_field_t *mp_ccs_data_ipf;
	nt_field_t *mp_ccs_data_slc_en;
	nt_field_t *mp_ccs_data_slc;
	nt_field_t *mp_ccs_data_pdb_en;
	nt_field_t *mp_ccs_data_pdb;
	nt_field_t *mp_ccs_data_msk_en;
	nt_field_t *mp_ccs_data_msk;
	nt_field_t *mp_ccs_data_hst_en;
	nt_field_t *mp_ccs_data_hst;
	nt_field_t *mp_ccs_data_epp_en;
	nt_field_t *mp_ccs_data_epp;
	nt_field_t *mp_ccs_data_tpe_en;
	nt_field_t *mp_ccs_data_tpe;
	nt_field_t *mp_ccs_data_rrb_en;
	nt_field_t *mp_ccs_data_rrb;
	nt_field_t *mp_ccs_data_sb0_type;
	nt_field_t *mp_ccs_data_sb0_data;
	nt_field_t *mp_ccs_data_sb1_type;
	nt_field_t *mp_ccs_data_sb1_data;
	nt_field_t *mp_ccs_data_sb2_type;
	nt_field_t *mp_ccs_data_sb2_data;
};

#endif /* __FLOW_NTHW_CAT_H__ */

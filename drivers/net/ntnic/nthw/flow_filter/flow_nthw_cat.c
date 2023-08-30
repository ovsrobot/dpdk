/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "ntlog.h"

#include "nthw_drv.h"
#include "nthw_register.h"

#include "flow_nthw_cat.h"

#include <stdlib.h> /* malloc */
#include <string.h> /* memset */

struct cat_nthw *cat_nthw_new(void)
{
	struct cat_nthw *p = malloc(sizeof(struct cat_nthw));

	if (p)
		(void)memset(p, 0, sizeof(*p));

	return p;
}

void cat_nthw_delete(struct cat_nthw *p)
{
	if (p) {
		(void)memset(p, 0, sizeof(*p));
		free(p);
	}
}

void cat_nthw_set_debug_mode(struct cat_nthw *p, unsigned int n_debug_mode)
{
	module_set_debug_mode(p->m_cat, n_debug_mode);
}

int cat_nthw_init(struct cat_nthw *p, nt_fpga_t *p_fpga, int n_instance)
{
	const char *const p_adapter_id_str = p_fpga->p_fpga_info->mp_adapter_id_str;
	nt_module_t *p_mod = fpga_query_module(p_fpga, MOD_CAT, n_instance);

	assert(n_instance >= 0 && n_instance < 256);

	if (p == NULL)
		return p_mod == NULL ? -1 : 0;

	if (p_mod == NULL) {
		NT_LOG(ERR, NTHW, "%s: Cat %d: no such instance\n",
		       p_adapter_id_str, n_instance);
		return -1;
	}

	p->mp_fpga = p_fpga;
	p->m_physical_adapter_no = (uint8_t)n_instance;
	p->m_cat = p_mod;

	p->m_km_if_cnt = fpga_get_product_param(p->mp_fpga, NT_CAT_KM_IF_CNT, -1);

	/* CFN */
	p->mp_cfn_ctrl = module_get_register(p->m_cat, CAT_CFN_CTRL);
	p->mp_cfn_addr = register_get_field(p->mp_cfn_ctrl, CAT_CFN_CTRL_ADR);
	p->mp_cfn_cnt = register_get_field(p->mp_cfn_ctrl, CAT_CFN_CTRL_CNT);
	p->mp_cfn_data = module_get_register(p->m_cat, CAT_CFN_DATA);
	p->mp_cfn_data_enable =
		register_get_field(p->mp_cfn_data, CAT_CFN_DATA_ENABLE);
	p->mp_cfn_data_inv = register_get_field(p->mp_cfn_data, CAT_CFN_DATA_INV);
	p->mp_cfn_data_ptc_inv =
		register_get_field(p->mp_cfn_data, CAT_CFN_DATA_PTC_INV);
	p->mp_cfn_data_ptc_isl =
		register_get_field(p->mp_cfn_data, CAT_CFN_DATA_PTC_ISL);
	p->mp_cfn_data_ptc_mac =
		register_get_field(p->mp_cfn_data, CAT_CFN_DATA_PTC_MAC);
	p->mp_cfn_data_ptc_l2 =
		register_get_field(p->mp_cfn_data, CAT_CFN_DATA_PTC_L2);
	p->mp_cfn_data_ptc_vn_tag =
		register_get_field(p->mp_cfn_data, CAT_CFN_DATA_PTC_VNTAG);
	p->mp_cfn_data_ptc_vlan =
		register_get_field(p->mp_cfn_data, CAT_CFN_DATA_PTC_VLAN);
	p->mp_cfn_data_ptc_mpls =
		register_get_field(p->mp_cfn_data, CAT_CFN_DATA_PTC_MPLS);
	p->mp_cfn_data_ptc_l3 =
		register_get_field(p->mp_cfn_data, CAT_CFN_DATA_PTC_L3);
	p->mp_cfn_data_ptc_frag =
		register_get_field(p->mp_cfn_data, CAT_CFN_DATA_PTC_FRAG);
	p->mp_cfn_data_ptc_ip_prot =
		register_get_field(p->mp_cfn_data, CAT_CFN_DATA_PTC_IP_PROT);
	p->mp_cfn_data_ptc_l4 =
		register_get_field(p->mp_cfn_data, CAT_CFN_DATA_PTC_L4);
	p->mp_cfn_data_ptc_tunnel =
		register_get_field(p->mp_cfn_data, CAT_CFN_DATA_PTC_TUNNEL);
	p->mp_cfn_data_ptc_tnl_l2 =
		register_get_field(p->mp_cfn_data, CAT_CFN_DATA_PTC_TNL_L2);
	p->mp_cfn_data_ptc_tnl_vlan =
		register_get_field(p->mp_cfn_data, CAT_CFN_DATA_PTC_TNL_VLAN);
	p->mp_cfn_data_ptc_tnl_mpls =
		register_get_field(p->mp_cfn_data, CAT_CFN_DATA_PTC_TNL_MPLS);
	p->mp_cfn_data_ptc_tnl_l3 =
		register_get_field(p->mp_cfn_data, CAT_CFN_DATA_PTC_TNL_L3);
	p->mp_cfn_data_ptc_tnl_frag =
		register_get_field(p->mp_cfn_data, CAT_CFN_DATA_PTC_TNL_FRAG);
	p->mp_cfn_data_ptc_tnl_ip_prot =
		register_get_field(p->mp_cfn_data, CAT_CFN_DATA_PTC_TNL_IP_PROT);
	p->mp_cfn_data_ptc_tnl_l4 =
		register_get_field(p->mp_cfn_data, CAT_CFN_DATA_PTC_TNL_L4);
	p->mp_cfn_data_err_inv =
		register_get_field(p->mp_cfn_data, CAT_CFN_DATA_ERR_INV);
	p->mp_cfn_data_err_cv =
		register_get_field(p->mp_cfn_data, CAT_CFN_DATA_ERR_CV);
	p->mp_cfn_data_err_fcs =
		register_get_field(p->mp_cfn_data, CAT_CFN_DATA_ERR_FCS);
	p->mp_cfn_data_err_trunc =
		register_get_field(p->mp_cfn_data, CAT_CFN_DATA_ERR_TRUNC);
	p->mp_cfn_data_mac_port =
		register_get_field(p->mp_cfn_data, CAT_CFN_DATA_MAC_PORT);
	p->mp_cfn_data_pm_cmp =
		register_get_field(p->mp_cfn_data, CAT_CFN_DATA_PM_CMP);
	p->mp_cfn_data_pm_dct =
		register_get_field(p->mp_cfn_data, CAT_CFN_DATA_PM_DCT);
	p->mp_cfn_data_pm_ext_inv =
		register_get_field(p->mp_cfn_data, CAT_CFN_DATA_PM_EXT_INV);
	p->mp_cfn_data_pm_cmb =
		register_get_field(p->mp_cfn_data, CAT_CFN_DATA_PM_CMB);
	p->mp_cfn_data_pm_and_inv =
		register_get_field(p->mp_cfn_data, CAT_CFN_DATA_PM_AND_INV);
	p->mp_cfn_data_pm_or_inv =
		register_get_field(p->mp_cfn_data, CAT_CFN_DATA_PM_OR_INV);
	p->mp_cfn_data_pm_inv =
		register_get_field(p->mp_cfn_data, CAT_CFN_DATA_PM_INV);
	p->mp_cfn_data_lc = register_get_field(p->mp_cfn_data, CAT_CFN_DATA_LC);
	p->mp_cfn_data_lc_inv =
		register_get_field(p->mp_cfn_data, CAT_CFN_DATA_LC_INV);

	if (p->m_km_if_cnt == -1) {
		p->mp_cfn_data_km0_or =
			register_get_field(p->mp_cfn_data, CAT_CFN_DATA_KM_OR);
	} else {
		p->mp_cfn_data_km0_or =
			register_get_field(p->mp_cfn_data, CAT_CFN_DATA_KM0_OR);
		p->mp_cfn_data_km1_or =
			register_query_field(p->mp_cfn_data, CAT_CFN_DATA_KM1_OR);
	}

	if (p->m_km_if_cnt < 0) {
		/* KCE */
		p->mp_kce_ctrl[0] = module_get_register(p->m_cat, CAT_KCE_CTRL);
		p->mp_kce_addr[0] =
			register_get_field(p->mp_kce_ctrl[0], CAT_KCE_CTRL_ADR);
		p->mp_kce_cnt[0] =
			register_get_field(p->mp_kce_ctrl[0], CAT_KCE_CTRL_CNT);
		p->mp_kce_data[0] = module_get_register(p->m_cat, CAT_KCE_DATA);
		p->mp_kce_data_enable[0] =
			register_get_field(p->mp_kce_data[0], CAT_KCE_DATA_ENABLE);
		/* KCS */
		p->mp_kcs_ctrl[0] = module_get_register(p->m_cat, CAT_KCS_CTRL);
		p->mp_kcs_addr[0] =
			register_get_field(p->mp_kcs_ctrl[0], CAT_KCS_CTRL_ADR);
		p->mp_kcs_cnt[0] =
			register_get_field(p->mp_kcs_ctrl[0], CAT_KCS_CTRL_CNT);
		p->mp_kcs_data[0] = module_get_register(p->m_cat, CAT_KCS_DATA);
		p->mp_kcs_data_category[0] =
			register_get_field(p->mp_kcs_data[0], CAT_KCS_DATA_CATEGORY);
		/* FTE */
		p->mp_fte_ctrl[0] = module_get_register(p->m_cat, CAT_FTE_CTRL);
		p->mp_fte_addr[0] =
			register_get_field(p->mp_fte_ctrl[0], CAT_FTE_CTRL_ADR);
		p->mp_fte_cnt[0] =
			register_get_field(p->mp_fte_ctrl[0], CAT_FTE_CTRL_CNT);
		p->mp_fte_data[0] = module_get_register(p->m_cat, CAT_FTE_DATA);
		p->mp_fte_data_enable[0] =
			register_get_field(p->mp_fte_data[0], CAT_FTE_DATA_ENABLE);
	} else {
		/* KCE 0 */
		p->mp_kce_ctrl[0] = module_get_register(p->m_cat, CAT_KCE0_CTRL);
		p->mp_kce_addr[0] =
			register_get_field(p->mp_kce_ctrl[0], CAT_KCE0_CTRL_ADR);
		p->mp_kce_cnt[0] =
			register_get_field(p->mp_kce_ctrl[0], CAT_KCE0_CTRL_CNT);
		p->mp_kce_data[0] = module_get_register(p->m_cat, CAT_KCE0_DATA);
		p->mp_kce_data_enable[0] = register_get_field(p->mp_kce_data[0],
					CAT_KCE0_DATA_ENABLE);
		/* KCS 0 */
		p->mp_kcs_ctrl[0] = module_get_register(p->m_cat, CAT_KCS0_CTRL);
		p->mp_kcs_addr[0] =
			register_get_field(p->mp_kcs_ctrl[0], CAT_KCS0_CTRL_ADR);
		p->mp_kcs_cnt[0] =
			register_get_field(p->mp_kcs_ctrl[0], CAT_KCS0_CTRL_CNT);
		p->mp_kcs_data[0] = module_get_register(p->m_cat, CAT_KCS0_DATA);
		p->mp_kcs_data_category[0] =
			register_get_field(p->mp_kcs_data[0], CAT_KCS0_DATA_CATEGORY);
		/* FTE 0 */
		p->mp_fte_ctrl[0] = module_get_register(p->m_cat, CAT_FTE0_CTRL);
		p->mp_fte_addr[0] =
			register_get_field(p->mp_fte_ctrl[0], CAT_FTE0_CTRL_ADR);
		p->mp_fte_cnt[0] =
			register_get_field(p->mp_fte_ctrl[0], CAT_FTE0_CTRL_CNT);
		p->mp_fte_data[0] = module_get_register(p->m_cat, CAT_FTE0_DATA);
		p->mp_fte_data_enable[0] = register_get_field(p->mp_fte_data[0],
					CAT_FTE0_DATA_ENABLE);
		/* KCE 1 */
		p->mp_kce_ctrl[1] = module_get_register(p->m_cat, CAT_KCE1_CTRL);
		p->mp_kce_addr[1] =
			register_get_field(p->mp_kce_ctrl[1], CAT_KCE1_CTRL_ADR);
		p->mp_kce_cnt[1] =
			register_get_field(p->mp_kce_ctrl[1], CAT_KCE1_CTRL_CNT);
		p->mp_kce_data[1] = module_get_register(p->m_cat, CAT_KCE1_DATA);
		p->mp_kce_data_enable[1] = register_get_field(p->mp_kce_data[1],
					CAT_KCE1_DATA_ENABLE);
		/* KCS 1 */
		p->mp_kcs_ctrl[1] = module_get_register(p->m_cat, CAT_KCS1_CTRL);
		p->mp_kcs_addr[1] =
			register_get_field(p->mp_kcs_ctrl[1], CAT_KCS1_CTRL_ADR);
		p->mp_kcs_cnt[1] =
			register_get_field(p->mp_kcs_ctrl[1], CAT_KCS1_CTRL_CNT);
		p->mp_kcs_data[1] = module_get_register(p->m_cat, CAT_KCS1_DATA);
		p->mp_kcs_data_category[1] =
			register_get_field(p->mp_kcs_data[1], CAT_KCS1_DATA_CATEGORY);
		/* FTE 1 */
		p->mp_fte_ctrl[1] = module_get_register(p->m_cat, CAT_FTE1_CTRL);
		p->mp_fte_addr[1] =
			register_get_field(p->mp_fte_ctrl[1], CAT_FTE1_CTRL_ADR);
		p->mp_fte_cnt[1] =
			register_get_field(p->mp_fte_ctrl[1], CAT_FTE1_CTRL_CNT);
		p->mp_fte_data[1] = module_get_register(p->m_cat, CAT_FTE1_DATA);
		p->mp_fte_data_enable[1] = register_get_field(p->mp_fte_data[1],
					CAT_FTE1_DATA_ENABLE);
	}

	/* CTE */
	p->mp_cte_ctrl = module_get_register(p->m_cat, CAT_CTE_CTRL);
	p->mp_cte_addr = register_get_field(p->mp_cte_ctrl, CAT_CTE_CTRL_ADR);
	p->mp_cte_cnt = register_get_field(p->mp_cte_ctrl, CAT_CTE_CTRL_CNT);
	p->mp_cte_data = module_get_register(p->m_cat, CAT_CTE_DATA);
	p->mp_cte_data_col =
		register_get_field(p->mp_cte_data, CAT_CTE_DATA_COL_ENABLE);
	p->mp_cte_data_cor =
		register_get_field(p->mp_cte_data, CAT_CTE_DATA_COR_ENABLE);
	p->mp_cte_data_hsh =
		register_get_field(p->mp_cte_data, CAT_CTE_DATA_HSH_ENABLE);
	p->mp_cte_data_qsl =
		register_get_field(p->mp_cte_data, CAT_CTE_DATA_QSL_ENABLE);
	p->mp_cte_data_ipf =
		register_get_field(p->mp_cte_data, CAT_CTE_DATA_IPF_ENABLE);
	p->mp_cte_data_slc =
		register_get_field(p->mp_cte_data, CAT_CTE_DATA_SLC_ENABLE);
	p->mp_cte_data_pdb =
		register_get_field(p->mp_cte_data, CAT_CTE_DATA_PDB_ENABLE);
	p->mp_cte_data_msk =
		register_query_field(p->mp_cte_data, CAT_CTE_DATA_MSK_ENABLE);
	p->mp_cte_data_hst =
		register_query_field(p->mp_cte_data, CAT_CTE_DATA_HST_ENABLE);
	p->mp_cte_data_epp =
		register_query_field(p->mp_cte_data, CAT_CTE_DATA_EPP_ENABLE);
	p->mp_cte_data_tpe =
		register_query_field(p->mp_cte_data, CAT_CTE_DATA_TPE_ENABLE);
	p->mp_cte_data_rrb =
		register_query_field(p->mp_cte_data, CAT_CTE_DATA_RRB_ENABLE);
	/* CTS */
	p->mp_cts_ctrl = module_get_register(p->m_cat, CAT_CTS_CTRL);
	p->mp_cts_addr = register_get_field(p->mp_cts_ctrl, CAT_CTS_CTRL_ADR);
	p->mp_cts_cnt = register_get_field(p->mp_cts_ctrl, CAT_CTS_CTRL_CNT);
	p->mp_cts_data = module_get_register(p->m_cat, CAT_CTS_DATA);
	p->mp_cts_data_cat_a = register_get_field(p->mp_cts_data, CAT_CTS_DATA_CAT_A);
	p->mp_cts_data_cat_b = register_get_field(p->mp_cts_data, CAT_CTS_DATA_CAT_B);
	/* COT */
	p->mp_cot_ctrl = module_get_register(p->m_cat, CAT_COT_CTRL);
	p->mp_cot_addr = register_get_field(p->mp_cot_ctrl, CAT_COT_CTRL_ADR);
	p->mp_cot_cnt = register_get_field(p->mp_cot_ctrl, CAT_COT_CTRL_CNT);
	p->mp_cot_data = module_get_register(p->m_cat, CAT_COT_DATA);
	p->mp_cot_data_color = register_get_field(p->mp_cot_data, CAT_COT_DATA_COLOR);
	p->mp_cot_data_km = register_get_field(p->mp_cot_data, CAT_COT_DATA_KM);
	p->mp_cot_data_nfv_sb =
		register_query_field(p->mp_cot_data, CAT_COT_DATA_NFV_SB);
	/* CCT */
	p->mp_cct_ctrl = module_get_register(p->m_cat, CAT_CCT_CTRL);
	p->mp_cct_addr = register_get_field(p->mp_cct_ctrl, CAT_CCT_CTRL_ADR);
	p->mp_cct_cnt = register_get_field(p->mp_cct_ctrl, CAT_CCT_CTRL_CNT);
	p->mp_cct_data = module_get_register(p->m_cat, CAT_CCT_DATA);
	p->mp_cct_data_color = register_get_field(p->mp_cct_data, CAT_CCT_DATA_COLOR);
	p->mp_cct_data_km = register_get_field(p->mp_cct_data, CAT_CCT_DATA_KM);
	/* EXO */
	p->mp_exo_ctrl = module_get_register(p->m_cat, CAT_EXO_CTRL);
	p->mp_exo_addr = register_get_field(p->mp_exo_ctrl, CAT_EXO_CTRL_ADR);
	p->mp_exo_cnt = register_get_field(p->mp_exo_ctrl, CAT_EXO_CTRL_CNT);
	p->mp_exo_data = module_get_register(p->m_cat, CAT_EXO_DATA);
	p->mp_exo_data_dyn = register_get_field(p->mp_exo_data, CAT_EXO_DATA_DYN);
	p->mp_exo_data_ofs = register_get_field(p->mp_exo_data, CAT_EXO_DATA_OFS);
	/* RCK */
	p->mp_rck_ctrl = module_get_register(p->m_cat, CAT_RCK_CTRL);
	p->mp_rck_addr = register_get_field(p->mp_rck_ctrl, CAT_RCK_CTRL_ADR);
	p->mp_rck_cnt = register_get_field(p->mp_rck_ctrl, CAT_RCK_CTRL_CNT);
	p->mp_rck_data = module_get_register(p->m_cat, CAT_RCK_DATA);
	/* LEN */
	p->mp_len_ctrl = module_get_register(p->m_cat, CAT_LEN_CTRL);
	p->mp_len_addr = register_get_field(p->mp_len_ctrl, CAT_LEN_CTRL_ADR);
	p->mp_len_cnt = register_get_field(p->mp_len_ctrl, CAT_LEN_CTRL_CNT);
	p->mp_len_data = module_get_register(p->m_cat, CAT_LEN_DATA);
	p->mp_len_data_lower = register_get_field(p->mp_len_data, CAT_LEN_DATA_LOWER);
	p->mp_len_data_upper = register_get_field(p->mp_len_data, CAT_LEN_DATA_UPPER);
	p->mp_len_data_dyn1 = register_get_field(p->mp_len_data, CAT_LEN_DATA_DYN1);
	p->mp_len_data_dyn2 = register_get_field(p->mp_len_data, CAT_LEN_DATA_DYN2);
	p->mp_len_data_inv = register_get_field(p->mp_len_data, CAT_LEN_DATA_INV);

	p->mp_cfn_data_ptc_cfp =
		register_query_field(p->mp_cfn_data, CAT_CFN_DATA_PTC_CFP);
	p->mp_cfn_data_err_l3_cs =
		register_query_field(p->mp_cfn_data, CAT_CFN_DATA_ERR_L3_CS);
	p->mp_cfn_data_err_l4_cs =
		register_query_field(p->mp_cfn_data, CAT_CFN_DATA_ERR_L4_CS);
	p->mp_cfn_data_err_tnl_l3_cs =
		register_query_field(p->mp_cfn_data, CAT_CFN_DATA_ERR_TNL_L3_CS);
	p->mp_cfn_data_err_tnl_l4_cs =
		register_query_field(p->mp_cfn_data, CAT_CFN_DATA_ERR_TNL_L4_CS);
	p->mp_cfn_data_err_ttl_exp =
		register_query_field(p->mp_cfn_data, CAT_CFN_DATA_ERR_TTL_EXP);
	p->mp_cfn_data_err_tnl_ttl_exp =
		register_query_field(p->mp_cfn_data, CAT_CFN_DATA_ERR_TNL_TTL_EXP);

	p->mp_kcc_ctrl = module_query_register(p->m_cat, CAT_KCC_CTRL);
	if (p->mp_kcc_ctrl != NULL) {
		p->mp_kcc_addr =
			register_query_field(p->mp_kcc_ctrl, CAT_KCC_CTRL_ADR);
		p->mp_kcc_cnt =
			register_query_field(p->mp_kcc_ctrl, CAT_KCC_CTRL_CNT);
	}
	p->mp_kcc_data = module_query_register(p->m_cat, CAT_KCC_DATA);
	if (p->mp_kcc_data != NULL) {
		p->mp_kcc_data_key =
			register_query_field(p->mp_kcc_data, CAT_KCC_DATA_KEY);
		p->mp_kcc_data_category =
			register_query_field(p->mp_kcc_data, CAT_KCC_DATA_CATEGORY);
		p->mp_kcc_data_id =
			register_query_field(p->mp_kcc_data, CAT_KCC_DATA_ID);
	}

	p->mp_cce_ctrl = module_query_register(p->m_cat, CAT_CCE_CTRL);
	if (p->mp_cce_ctrl != NULL) {
		p->mp_cce_addr =
			register_query_field(p->mp_cce_ctrl, CAT_CCE_CTRL_ADR);
		p->mp_cce_cnt =
			register_query_field(p->mp_cce_ctrl, CAT_CCE_CTRL_CNT);
	}
	p->mp_cce_data = module_query_register(p->m_cat, CAT_CCE_DATA);
	if (p->mp_cce_data != NULL) {
		p->mp_cce_data_imm =
			register_query_field(p->mp_cce_data, CAT_CCE_DATA_IMM);
		p->mp_cce_data_ind =
			register_query_field(p->mp_cce_data, CAT_CCE_DATA_IND);
	}

	p->mp_ccs_ctrl = module_query_register(p->m_cat, CAT_CCS_CTRL);
	if (p->mp_ccs_ctrl != NULL) {
		p->mp_ccs_addr =
			register_query_field(p->mp_ccs_ctrl, CAT_CCS_CTRL_ADR);
		p->mp_ccs_cnt =
			register_query_field(p->mp_ccs_ctrl, CAT_CCS_CTRL_CNT);
	}
	p->mp_ccs_data = module_query_register(p->m_cat, CAT_CCS_DATA);
	if (p->mp_ccs_data != NULL) {
		p->mp_ccs_data_cor_en =
			register_query_field(p->mp_ccs_data, CAT_CCS_DATA_COR_EN);
		p->mp_ccs_data_cor =
			register_query_field(p->mp_ccs_data, CAT_CCS_DATA_COR);
		p->mp_ccs_data_hsh_en =
			register_query_field(p->mp_ccs_data, CAT_CCS_DATA_HSH_EN);
		p->mp_ccs_data_hsh =
			register_query_field(p->mp_ccs_data, CAT_CCS_DATA_HSH);
		p->mp_ccs_data_qsl_en =
			register_query_field(p->mp_ccs_data, CAT_CCS_DATA_QSL_EN);
		p->mp_ccs_data_qsl =
			register_query_field(p->mp_ccs_data, CAT_CCS_DATA_QSL);
		p->mp_ccs_data_ipf_en =
			register_query_field(p->mp_ccs_data, CAT_CCS_DATA_IPF_EN);
		p->mp_ccs_data_ipf =
			register_query_field(p->mp_ccs_data, CAT_CCS_DATA_IPF);
		p->mp_ccs_data_slc_en =
			register_query_field(p->mp_ccs_data, CAT_CCS_DATA_SLC_EN);
		p->mp_ccs_data_slc =
			register_query_field(p->mp_ccs_data, CAT_CCS_DATA_SLC);
		p->mp_ccs_data_pdb_en =
			register_query_field(p->mp_ccs_data, CAT_CCS_DATA_PDB_EN);
		p->mp_ccs_data_pdb =
			register_query_field(p->mp_ccs_data, CAT_CCS_DATA_PDB);
		p->mp_ccs_data_msk_en =
			register_query_field(p->mp_ccs_data, CAT_CCS_DATA_MSK_EN);
		p->mp_ccs_data_msk =
			register_query_field(p->mp_ccs_data, CAT_CCS_DATA_MSK);
		p->mp_ccs_data_hst_en =
			register_query_field(p->mp_ccs_data, CAT_CCS_DATA_HST_EN);
		p->mp_ccs_data_hst =
			register_query_field(p->mp_ccs_data, CAT_CCS_DATA_HST);
		p->mp_ccs_data_epp_en =
			register_query_field(p->mp_ccs_data, CAT_CCS_DATA_EPP_EN);
		p->mp_ccs_data_epp =
			register_query_field(p->mp_ccs_data, CAT_CCS_DATA_EPP);
		p->mp_ccs_data_tpe_en =
			register_query_field(p->mp_ccs_data, CAT_CCS_DATA_TPE_EN);
		p->mp_ccs_data_tpe =
			register_query_field(p->mp_ccs_data, CAT_CCS_DATA_TPE);
		p->mp_ccs_data_rrb_en =
			register_query_field(p->mp_ccs_data, CAT_CCS_DATA_RRB_EN);
		p->mp_ccs_data_rrb =
			register_query_field(p->mp_ccs_data, CAT_CCS_DATA_RRB);
		p->mp_ccs_data_sb0_type =
			register_query_field(p->mp_ccs_data, CAT_CCS_DATA_SB0_TYPE);
		p->mp_ccs_data_sb0_data =
			register_query_field(p->mp_ccs_data, CAT_CCS_DATA_SB0_DATA);
		p->mp_ccs_data_sb1_type =
			register_query_field(p->mp_ccs_data, CAT_CCS_DATA_SB1_TYPE);
		p->mp_ccs_data_sb1_data =
			register_query_field(p->mp_ccs_data, CAT_CCS_DATA_SB1_DATA);
		p->mp_ccs_data_sb2_type =
			register_query_field(p->mp_ccs_data, CAT_CCS_DATA_SB2_TYPE);
		p->mp_ccs_data_sb2_data =
			register_query_field(p->mp_ccs_data, CAT_CCS_DATA_SB2_DATA);
	}

	return 0;
}

/* CFN */
void cat_nthw_cfn_select(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cfn_addr, val);
}

void r(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cfn_cnt, val);
}

void cat_nthw_cfn_enable(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cfn_data_enable, val);
}

void cat_nthw_cfn_inv(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cfn_data_inv, val);
}

void cat_nthw_cfn_ptc_inv(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cfn_data_ptc_inv, val);
}

void cat_nthw_cfn_ptc_isl(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cfn_data_ptc_isl, val);
}

void cat_nthw_cfn_ptc_mac(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cfn_data_ptc_mac, val);
}

void cat_nthw_cfn_ptc_l2(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cfn_data_ptc_l2, val);
}

void cat_nthw_cfn_ptc_vn_tag(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cfn_data_ptc_vn_tag, val);
}

void cat_nthw_cfn_ptc_vlan(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cfn_data_ptc_vlan, val);
}

void cat_nthw_cfn_ptc_mpls(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cfn_data_ptc_mpls, val);
}

void cat_nthw_cfn_ptc_l3(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cfn_data_ptc_l3, val);
}

void cat_nthw_cfn_ptc_frag(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cfn_data_ptc_frag, val);
}

void cat_nthw_cfn_ptc_ip_prot(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cfn_data_ptc_ip_prot, val);
}

void cat_nthw_cfn_ptc_l4(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cfn_data_ptc_l4, val);
}

void cat_nthw_cfn_ptc_tunnel(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cfn_data_ptc_tunnel, val);
}

void cat_nthw_cfn_ptc_tnl_l2(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cfn_data_ptc_tnl_l2, val);
}

void cat_nthw_cfn_ptc_tnl_vlan(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cfn_data_ptc_tnl_vlan, val);
}

void cat_nthw_cfn_ptc_tnl_mpls(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cfn_data_ptc_tnl_mpls, val);
}

void cat_nthw_cfn_ptc_tnl_l3(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cfn_data_ptc_tnl_l3, val);
}

void cat_nthw_cfn_ptc_tnl_frag(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cfn_data_ptc_tnl_frag, val);
}

void cat_nthw_cfn_ptc_tnl_ip_prot(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cfn_data_ptc_tnl_ip_prot, val);
}

void cat_nthw_cfn_ptc_tnl_l4(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cfn_data_ptc_tnl_l4, val);
}

void cat_nthw_cfn_ptc_cfp(const struct cat_nthw *p, uint32_t val)
{
	assert(p->mp_cfn_data_ptc_cfp);
	field_set_val32(p->mp_cfn_data_ptc_cfp, val);
}

void cat_nthw_cfn_err_l3_cs(const struct cat_nthw *p, uint32_t val)
{
	assert(p->mp_cfn_data_err_l3_cs);
	field_set_val32(p->mp_cfn_data_err_l3_cs, val);
}

void cat_nthw_cfn_err_l4_cs(const struct cat_nthw *p, uint32_t val)
{
	assert(p->mp_cfn_data_err_l4_cs);
	field_set_val32(p->mp_cfn_data_err_l4_cs, val);
}

void cat_nthw_cfn_err_tnl_l3_cs(const struct cat_nthw *p, uint32_t val)
{
	assert(p->mp_cfn_data_err_tnl_l3_cs);
	field_set_val32(p->mp_cfn_data_err_tnl_l3_cs, val);
}

void cat_nthw_cfn_err_tnl_l4_cs(const struct cat_nthw *p, uint32_t val)
{
	assert(p->mp_cfn_data_err_tnl_l4_cs);
	field_set_val32(p->mp_cfn_data_err_tnl_l4_cs, val);
}

void cat_nthw_cfn_err_ttl_exp(const struct cat_nthw *p, uint32_t val)
{
	assert(p->mp_cfn_data_err_ttl_exp);
	field_set_val32(p->mp_cfn_data_err_ttl_exp, val);
}

void cat_nthw_cfn_err_tnl_ttl_exp(const struct cat_nthw *p, uint32_t val)
{
	assert(p->mp_cfn_data_err_tnl_ttl_exp);
	field_set_val32(p->mp_cfn_data_err_tnl_ttl_exp, val);
}

void cat_nthw_cfn_err_inv(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cfn_data_err_inv, val);
}

void cat_nthw_cfn_err_cv(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cfn_data_err_cv, val);
}

void cat_nthw_cfn_err_fcs(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cfn_data_err_fcs, val);
}

void cat_nthw_cfn_err_trunc(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cfn_data_err_trunc, val);
}

void cat_nthw_cfn_mac_port(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cfn_data_mac_port, val);
}

void cat_nthw_cfn_pm_cmp(const struct cat_nthw *p, const uint32_t *val)
{
	field_set_val(p->mp_cfn_data_pm_cmp, val, p->mp_cfn_data_pm_cmp->mn_words);
}

void cat_nthw_cfn_pm_dct(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cfn_data_pm_dct, val);
}

void cat_nthw_cfn_pm_ext_inv(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cfn_data_pm_ext_inv, val);
}

void cat_nthw_cfn_pm_cmb(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cfn_data_pm_cmb, val);
}

void cat_nthw_cfn_pm_and_inv(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cfn_data_pm_and_inv, val);
}

void cat_nthw_cfn_pm_or_inv(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cfn_data_pm_or_inv, val);
}

void cat_nthw_cfn_pm_inv(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cfn_data_pm_inv, val);
}

void cat_nthw_cfn_lc(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cfn_data_lc, val);
}

void cat_nthw_cfn_lc_inv(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cfn_data_lc_inv, val);
}

void cat_nthw_cfn_km0_or(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cfn_data_km0_or, val);
}

void cat_nthw_cfn_km1_or(const struct cat_nthw *p, uint32_t val)
{
	assert(p->mp_cfn_data_km1_or);
	field_set_val32(p->mp_cfn_data_km1_or, val);
}

void cat_nthw_cfn_flush(const struct cat_nthw *p)
{
	register_flush(p->mp_cfn_ctrl, 1);
	register_flush(p->mp_cfn_data, 1);
}

void cat_nthw_kce_select(const struct cat_nthw *p, int index, uint32_t val)
{
	field_set_val32(p->mp_kce_addr[index], val);
}

void cat_nthw_kce_cnt(const struct cat_nthw *p, int index, uint32_t val)
{
	field_set_val32(p->mp_kce_cnt[index], val);
}

void cat_nthw_kce_enable(const struct cat_nthw *p, int index, uint32_t val)
{
	field_set_val32(p->mp_kce_data_enable[index], val);
}

void cat_nthw_kce_flush(const struct cat_nthw *p, int index)
{
	register_flush(p->mp_kce_ctrl[index], 1);
	register_flush(p->mp_kce_data[index], 1);
}

void cat_nthw_kcs_select(const struct cat_nthw *p, int index, uint32_t val)
{
	field_set_val32(p->mp_kcs_addr[index], val);
}

void cat_nthw_kcs_cnt(const struct cat_nthw *p, int index, uint32_t val)
{
	field_set_val32(p->mp_kcs_cnt[index], val);
}

void cat_nthw_kcs_category(const struct cat_nthw *p, int index, uint32_t val)
{
	field_set_val32(p->mp_kcs_data_category[index], val);
}

void cat_nthw_kcs_flush(const struct cat_nthw *p, int index)
{
	register_flush(p->mp_kcs_ctrl[index], 1);
	register_flush(p->mp_kcs_data[index], 1);
}

void cat_nthw_fte_select(const struct cat_nthw *p, int index, uint32_t val)
{
	field_set_val32(p->mp_fte_addr[index], val);
}

void cat_nthw_fte_cnt(const struct cat_nthw *p, int index, uint32_t val)
{
	field_set_val32(p->mp_fte_cnt[index], val);
}

void cat_nthw_fte_enable(const struct cat_nthw *p, int index, uint32_t val)
{
	field_set_val32(p->mp_fte_data_enable[index], val);
}

void cat_nthw_fte_flush(const struct cat_nthw *p, int index)
{
	register_flush(p->mp_fte_ctrl[index], 1);
	register_flush(p->mp_fte_data[index], 1);
}

void cat_nthw_cte_select(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cte_addr, val);
}

void cat_nthw_cte_cnt(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cte_cnt, val);
}

void cat_nthw_cte_enable_col(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cte_data_col, val);
}

void cat_nthw_cte_enable_cor(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cte_data_cor, val);
}

void cat_nthw_cte_enable_hsh(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cte_data_hsh, val);
}

void cat_nthw_cte_enable_qsl(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cte_data_qsl, val);
}

void cat_nthw_cte_enable_ipf(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cte_data_ipf, val);
}

void cat_nthw_cte_enable_slc(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cte_data_slc, val);
}

void cat_nthw_cte_enable_pdb(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cte_data_pdb, val);
}

void cat_nthw_cte_enable_msk(const struct cat_nthw *p, uint32_t val)
{
	assert(p->mp_cte_data_msk);
	field_set_val32(p->mp_cte_data_msk, val);
}

void cat_nthw_cte_enable_hst(const struct cat_nthw *p, uint32_t val)
{
	assert(p->mp_cte_data_hst);
	field_set_val32(p->mp_cte_data_hst, val);
}

void cat_nthw_cte_enable_epp(const struct cat_nthw *p, uint32_t val)
{
	assert(p->mp_cte_data_epp);
	field_set_val32(p->mp_cte_data_epp, val);
}

void cat_nthw_cte_enable_tpe(const struct cat_nthw *p, uint32_t val)
{
	assert(p->mp_cte_data_tpe);
	field_set_val32(p->mp_cte_data_tpe, val);
}

void cat_nthw_cte_enable_rrb(const struct cat_nthw *p, uint32_t val)
{
	assert(p->mp_cte_data_rrb);
	field_set_val32(p->mp_cte_data_rrb, val);
}

void cat_nthw_cte_flush(const struct cat_nthw *p)
{
	register_flush(p->mp_cte_ctrl, 1);
	register_flush(p->mp_cte_data, 1);
}

void cat_nthw_cts_select(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cts_addr, val);
}

void cat_nthw_cts_cnt(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cts_cnt, val);
}

void cat_nthw_cts_cat_a(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cts_data_cat_a, val);
}

void cat_nthw_cts_cat_b(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cts_data_cat_b, val);
}

void cat_nthw_cts_flush(const struct cat_nthw *p)
{
	register_flush(p->mp_cts_ctrl, 1);
	register_flush(p->mp_cts_data, 1);
}

void cat_nthw_cot_select(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cot_addr, val);
}

void cat_nthw_cot_cnt(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cot_cnt, val);
}

void cat_nthw_cot_color(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cot_data_color, val);
}

void cat_nthw_cot_km(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cot_data_km, val);
}

void cat_nthw_cot_nfv_sb(const struct cat_nthw *p, uint32_t val)
{
	assert(p->mp_cot_data_nfv_sb);
	field_set_val32(p->mp_cot_data_nfv_sb, val);
}

void cat_nthw_cot_flush(const struct cat_nthw *p)
{
	register_flush(p->mp_cot_ctrl, 1);
	register_flush(p->mp_cot_data, 1);
}

void cat_nthw_cct_select(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cct_addr, val);
}

void cat_nthw_cct_cnt(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cct_cnt, val);
}

void cat_nthw_cct_color(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cct_data_color, val);
}

void cat_nthw_cct_km(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_cct_data_km, val);
}

void cat_nthw_cct_flush(const struct cat_nthw *p)
{
	register_flush(p->mp_cct_ctrl, 1);
	register_flush(p->mp_cct_data, 1);
}

void cat_nthw_exo_select(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_exo_addr, val);
}

void cat_nthw_exo_cnt(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_exo_cnt, val);
}

void cat_nthw_exo_dyn(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_exo_data_dyn, val);
}

void cat_nthw_exo_ofs(const struct cat_nthw *p, int32_t val)
{
	field_set_val32(p->mp_exo_data_ofs, val);
}

void cat_nthw_exo_flush(const struct cat_nthw *p)
{
	register_flush(p->mp_exo_ctrl, 1);
	register_flush(p->mp_exo_data, 1);
}

void cat_nthw_rck_select(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rck_addr, val);
}

void cat_nthw_rck_cnt(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rck_cnt, val);
}

void cat_nthw_rck_data(const struct cat_nthw *p, uint32_t val)
{
	register_set_val(p->mp_rck_data, &val, 1);
	register_make_dirty(p->mp_rck_data);
}

void cat_nthw_rck_flush(const struct cat_nthw *p)
{
	register_flush(p->mp_rck_ctrl, 1);
	register_flush(p->mp_rck_data, 1);
}

void cat_nthw_len_select(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_len_addr, val);
}

void cat_nthw_len_cnt(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_len_cnt, val);
}

void cat_nthw_len_lower(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_len_data_lower, val);
}

void cat_nthw_len_upper(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_len_data_upper, val);
}

void cat_nthw_len_dyn1(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_len_data_dyn1, val);
}

void cat_nthw_len_dyn2(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_len_data_dyn2, val);
}

void cat_nthw_len_inv(const struct cat_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_len_data_inv, val);
}

void cat_nthw_len_flush(const struct cat_nthw *p)
{
	register_flush(p->mp_len_ctrl, 1);
	register_flush(p->mp_len_data, 1);
}

void cat_nthw_kcc_select(const struct cat_nthw *p, uint32_t val)
{
	assert(p->mp_kcc_addr);
	field_set_val32(p->mp_kcc_addr, val);
}

void cat_nthw_kcc_cnt(const struct cat_nthw *p, uint32_t val)
{
	assert(p->mp_kcc_cnt);
	field_set_val32(p->mp_kcc_cnt, val);
}

void cat_nthw_kcc_key(const struct cat_nthw *p, uint32_t *val)
{
	assert(p->mp_kcc_data_key);
	field_set_val(p->mp_kcc_data_key, val, 2);
}

void cat_nthw_kcc_category(const struct cat_nthw *p, uint32_t val)
{
	assert(p->mp_kcc_data_category);
	field_set_val32(p->mp_kcc_data_category, val);
}

void cat_nthw_kcc_id(const struct cat_nthw *p, uint32_t val)
{
	assert(p->mp_kcc_data_id);
	field_set_val32(p->mp_kcc_data_id, val);
}

void cat_nthw_kcc_flush(const struct cat_nthw *p)
{
	assert(p->mp_kcc_ctrl);
	assert(p->mp_kcc_data);
	register_flush(p->mp_kcc_ctrl, 1);
	register_flush(p->mp_kcc_data, 1);
}

void cat_nthw_cce_select(const struct cat_nthw *p, uint32_t val)
{
	assert(p->mp_cce_addr);
	field_set_val32(p->mp_cce_addr, val);
}

void cat_nthw_cce_cnt(const struct cat_nthw *p, uint32_t val)
{
	assert(p->mp_cce_cnt);
	field_set_val32(p->mp_cce_cnt, val);
}

void cat_nthw_cce_data_imm(const struct cat_nthw *p, uint32_t val)
{
	assert(p->mp_cce_data_imm);
	field_set_val32(p->mp_cce_data_imm, val);
}

void cat_nthw_cce_data_ind(const struct cat_nthw *p, uint32_t val)
{
	assert(p->mp_cce_data_ind);
	field_set_val32(p->mp_cce_data_ind, val);
}

void cat_nthw_cce_flush(const struct cat_nthw *p)
{
	assert(p->mp_cce_ctrl);
	assert(p->mp_cce_data);
	register_flush(p->mp_cce_ctrl, 1);
	register_flush(p->mp_cce_data, 1);
}

void cat_nthw_ccs_select(const struct cat_nthw *p, uint32_t val)
{
	assert(p->mp_ccs_addr);
	field_set_val32(p->mp_ccs_addr, val);
}

void cat_nthw_ccs_cnt(const struct cat_nthw *p, uint32_t val)
{
	assert(p->mp_ccs_cnt);
	field_set_val32(p->mp_ccs_cnt, val);
}

#define CATNTHW_CCS_SET(name)                                             \
	void cat_nthw_ccs_data_##name(const struct cat_nthw *p, uint32_t val) \
	{                                                                 \
		assert(p->mp_ccs_data_##name);                               \
		field_set_val32(p->mp_ccs_data_##name, val);                  \
	}

CATNTHW_CCS_SET(cor_en);
CATNTHW_CCS_SET(cor);
CATNTHW_CCS_SET(hsh_en);
CATNTHW_CCS_SET(hsh);
CATNTHW_CCS_SET(qsl_en);
CATNTHW_CCS_SET(qsl);
CATNTHW_CCS_SET(ipf_en);
CATNTHW_CCS_SET(ipf);
CATNTHW_CCS_SET(slc_en);
CATNTHW_CCS_SET(slc);
CATNTHW_CCS_SET(pdb_en);
CATNTHW_CCS_SET(pdb);
CATNTHW_CCS_SET(msk_en);
CATNTHW_CCS_SET(msk);
CATNTHW_CCS_SET(hst_en);
CATNTHW_CCS_SET(hst);
CATNTHW_CCS_SET(epp_en);
CATNTHW_CCS_SET(epp);
CATNTHW_CCS_SET(tpe_en);
CATNTHW_CCS_SET(tpe);
CATNTHW_CCS_SET(rrb_en);
CATNTHW_CCS_SET(rrb);
CATNTHW_CCS_SET(sb0_type);
CATNTHW_CCS_SET(sb0_data);
CATNTHW_CCS_SET(sb1_type);
CATNTHW_CCS_SET(sb1_data);
CATNTHW_CCS_SET(sb2_type);
CATNTHW_CCS_SET(sb2_data);

void cat_nthw_ccs_flush(const struct cat_nthw *p)
{
	assert(p->mp_ccs_ctrl);
	assert(p->mp_ccs_data);
	register_flush(p->mp_ccs_ctrl, 1);
	register_flush(p->mp_ccs_data, 1);
}

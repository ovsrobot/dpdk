/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "flow_api_backend.h"

#define _MOD_ "CAT"
#define _VER_ be->cat.ver

static int hw_mod_cat_kce_flush(struct flow_api_backend_s *be,
				enum km_flm_if_select_e if_num, int km_if_id,
				int start_idx, int count);
static int hw_mod_cat_kcs_flush(struct flow_api_backend_s *be,
				enum km_flm_if_select_e if_num, int km_if_id,
				int start_idx, int count);
static int hw_mod_cat_fte_flush(struct flow_api_backend_s *be,
				enum km_flm_if_select_e if_num, int km_if_id,
				int start_idx, int count);

bool hw_mod_cat_present(struct flow_api_backend_s *be)
{
	return be->iface->get_cat_present(be->be_dev);
}

int hw_mod_cat_alloc(struct flow_api_backend_s *be)
{
	_VER_ = be->iface->get_cat_version(be->be_dev);
	NT_LOG(DBG, FILTER, "CAT MODULE VERSION  %i.%i\n", VER_MAJOR(_VER_),
	       VER_MINOR(_VER_));

	int nb = be->iface->get_nb_cat_funcs(be->be_dev);

	if (nb <= 0)
		return error_resource_count(__func__, "cat_funcs", _MOD_, _VER_);
	be->cat.nb_cat_funcs = (uint32_t)nb;

	nb = be->iface->get_nb_km_flow_types(be->be_dev);
	if (nb <= 0)
		return error_resource_count(__func__, "km_flow_types", _MOD_, _VER_);
	be->cat.nb_flow_types = (uint32_t)nb;

	nb = be->iface->get_nb_pm_ext(be->be_dev);
	if (nb <= 0)
		return error_resource_count(__func__, "pm_ext", _MOD_, _VER_);
	be->cat.nb_pm_ext = (uint32_t)nb;

	nb = be->iface->get_nb_len(be->be_dev);
	if (nb <= 0)
		return error_resource_count(__func__, "len", _MOD_, _VER_);
	be->cat.nb_len = (uint32_t)nb;

	nb = be->iface->get_kcc_size(be->be_dev);
	if (nb < 0)
		return error_resource_count(__func__, "kcc_size", _MOD_, _VER_);
	be->cat.kcc_size = (uint32_t)nb;

	nb = be->iface->get_kcc_banks(be->be_dev);
	if (nb < 0)
		return error_resource_count(__func__, "kcc_banks", _MOD_, _VER_);
	be->cat.kcc_banks = (uint32_t)nb;

	nb = be->iface->get_nb_cat_km_if_cnt(be->be_dev);
	if (nb < 0)
		return error_resource_count(__func__, "km_if_count", _MOD_, _VER_);
	be->cat.km_if_count = (uint32_t)nb;

	int idx = be->iface->get_nb_cat_km_if_m0(be->be_dev);

	be->cat.km_if_m0 = idx;

	idx = be->iface->get_nb_cat_km_if_m1(be->be_dev);
	be->cat.km_if_m1 = idx;

	if (be->cat.kcc_banks)
		be->cat.kcc_records = be->cat.kcc_size / be->cat.kcc_banks;
	else
		be->cat.kcc_records = 0;

	be->cat.kcc_id_bit_size = 10;

	switch (_VER_) {
	case 18:
		be->cat.cts_num = 11;
		if (!callocate_mod(CAST_COMMON(&be->cat), 12,
			&be->cat.v18.cfn,
			be->cat.nb_cat_funcs,
			sizeof(struct cat_v18_cfn_s),
			&be->cat.v18.kce,
			(be->cat.nb_cat_funcs / 8),
			sizeof(struct cat_v18_kce_s),
			&be->cat.v18.kcs,
			be->cat.nb_cat_funcs,
			sizeof(struct cat_v18_kcs_s),
			&be->cat.v18.fte,
			(be->cat.nb_cat_funcs / 8) * be->cat.nb_flow_types * 2,
			sizeof(struct cat_v18_fte_s),
			&be->cat.v18.cte,
			be->cat.nb_cat_funcs,
			sizeof(struct cat_v18_cte_s),
			&be->cat.v18.cts,
			be->cat.nb_cat_funcs * ((be->cat.cts_num + 1) / 2),
			sizeof(struct cat_v18_cts_s),
			&be->cat.v18.cot,
			be->max_categories,
			sizeof(struct cat_v18_cot_s),
			&be->cat.v18.cct,
			be->max_categories * 4,
			sizeof(struct cat_v18_cct_s),
			&be->cat.v18.exo,
			be->cat.nb_pm_ext,
			sizeof(struct cat_v18_exo_s),
			&be->cat.v18.rck,
			be->cat.nb_pm_ext * 64,
			sizeof(struct cat_v18_rck_s),
			&be->cat.v18.len,
			be->cat.nb_len,
			sizeof(struct cat_v18_len_s),
			&be->cat.v18.kcc_cam,
			be->cat.kcc_size,
			sizeof(struct cat_v18_kcc_s)))
			return -1;

		break;
	/* end case 18 */
	case 21:
		be->cat.cts_num = 11;
		if (!callocate_mod(CAST_COMMON(&be->cat), 12,
			&be->cat.v21.cfn,
			be->cat.nb_cat_funcs,
			sizeof(struct cat_v21_cfn_s),
			&be->cat.v21.kce,
			(be->cat.nb_cat_funcs / 8),
			sizeof(struct cat_v21_kce_s),
			&be->cat.v21.kcs,
			be->cat.nb_cat_funcs,
			sizeof(struct cat_v21_kcs_s),
			&be->cat.v21.fte,
			(be->cat.nb_cat_funcs / 8) * be->cat.nb_flow_types * 4,
			sizeof(struct cat_v21_fte_s),
			&be->cat.v21.cte,
			be->cat.nb_cat_funcs,
			sizeof(struct cat_v18_cte_s),
			&be->cat.v21.cts,
			be->cat.nb_cat_funcs * ((be->cat.cts_num + 1) / 2),
			sizeof(struct cat_v18_cts_s),
			&be->cat.v21.cot,
			be->max_categories,
			sizeof(struct cat_v18_cot_s),
			&be->cat.v21.cct,
			be->max_categories * 4,
			sizeof(struct cat_v18_cct_s),
			&be->cat.v21.exo,
			be->cat.nb_pm_ext,
			sizeof(struct cat_v18_exo_s),
			&be->cat.v21.rck,
			be->cat.nb_pm_ext * 64,
			sizeof(struct cat_v18_rck_s),
			&be->cat.v21.len,
			be->cat.nb_len,
			sizeof(struct cat_v18_len_s),
			&be->cat.v21.kcc_cam,
			be->cat.kcc_size,
			sizeof(struct cat_v18_kcc_s)))
			return -1;

		break;
	/* end case 21 */
	case 22:
		be->cat.cts_num = 12;
		if (!callocate_mod(CAST_COMMON(&be->cat), 14,
			&be->cat.v22.cfn,
			be->cat.nb_cat_funcs,
			sizeof(struct cat_v21_cfn_s),
			&be->cat.v22.kce,
			(be->cat.nb_cat_funcs / 8),
			sizeof(struct cat_v21_kce_s),
			&be->cat.v22.kcs,
			be->cat.nb_cat_funcs,
			sizeof(struct cat_v21_kcs_s),
			&be->cat.v22.fte,
			(be->cat.nb_cat_funcs / 8) * be->cat.nb_flow_types * 4,
			sizeof(struct cat_v21_fte_s),
			&be->cat.v22.cte,
			be->cat.nb_cat_funcs,
			sizeof(struct cat_v22_cte_s),
			&be->cat.v22.cts,
			be->cat.nb_cat_funcs * ((be->cat.cts_num + 1) / 2),
			sizeof(struct cat_v18_cts_s),
			&be->cat.v22.cot,
			be->max_categories,
			sizeof(struct cat_v18_cot_s),
			&be->cat.v22.cct,
			be->max_categories * 4,
			sizeof(struct cat_v18_cct_s),
			&be->cat.v22.exo,
			be->cat.nb_pm_ext,
			sizeof(struct cat_v18_exo_s),
			&be->cat.v22.rck,
			be->cat.nb_pm_ext * 64,
			sizeof(struct cat_v18_rck_s),
			&be->cat.v22.len,
			be->cat.nb_len,
			sizeof(struct cat_v18_len_s),
			&be->cat.v22.kcc_cam,
			be->cat.kcc_size,
			sizeof(struct cat_v18_kcc_s),
			&be->cat.v22.cce,
			4,
			sizeof(struct cat_v22_cce_s),
			&be->cat.v22.ccs,
			1024,
			sizeof(struct cat_v22_ccs_s)))
			return -1;

		break;
	/* end case 22 */
	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

void hw_mod_cat_free(struct flow_api_backend_s *be)
{
	if (be->cat.base) {
		free(be->cat.base);
		be->cat.base = NULL;
	}
}

static int cfn_reset(struct flow_api_backend_s *be, int i)
{
	int err = hw_mod_cat_cfn_set(be, HW_CAT_CFN_PRESET_ALL, i, 0, 0);

	hw_mod_cat_cfn_set(be, HW_CAT_CFN_PTC_ISL, i, 0,
			   0xffffffff); /* accept both ISL or not ISL */
	hw_mod_cat_cfn_set(be, HW_CAT_CFN_PTC_CFP, i, 0,
			   0xffffffff); /* accept both CFP or not CFP */
	hw_mod_cat_cfn_set(be, HW_CAT_CFN_PTC_MAC, i, 0,
			   0xffffffff); /* accept all MACs */
	hw_mod_cat_cfn_set(be, HW_CAT_CFN_PTC_L2, i, 0,
			   0xffffffff); /* accept all L2 prot */
	hw_mod_cat_cfn_set(be, HW_CAT_CFN_PTC_VNTAG, i, 0,
			   0xffffffff); /* accept all */
	hw_mod_cat_cfn_set(be, HW_CAT_CFN_PTC_VLAN, i, 0,
			   0xffffffff); /* accept all */
	hw_mod_cat_cfn_set(be, HW_CAT_CFN_PTC_MPLS, i, 0,
			   0xffffffff); /* accept all */
	hw_mod_cat_cfn_set(be, HW_CAT_CFN_PTC_L3, i, 0,
			   0xffffffff); /* accept all L3 prot */
	hw_mod_cat_cfn_set(be, HW_CAT_CFN_PTC_FRAG, i, 0,
			   0xffffffff); /* accept all fragments */
	hw_mod_cat_cfn_set(be, HW_CAT_CFN_PTC_IP_PROT, i, 0,
			   0xffffffff); /* IP prot check disabled */
	hw_mod_cat_cfn_set(be, HW_CAT_CFN_PTC_L4, i, 0,
			   0xffffffff); /* accept all */
	hw_mod_cat_cfn_set(be, HW_CAT_CFN_PTC_TUNNEL, i, 0,
			   0xffffffff); /* accept all */
	hw_mod_cat_cfn_set(be, HW_CAT_CFN_PTC_TNL_L2, i, 0,
			   0xffffffff); /* accept all */
	hw_mod_cat_cfn_set(be, HW_CAT_CFN_PTC_TNL_VLAN, i, 0,
			   0xffffffff); /* accept all */
	hw_mod_cat_cfn_set(be, HW_CAT_CFN_PTC_TNL_MPLS, i, 0,
			   0xffffffff); /* accept all */
	hw_mod_cat_cfn_set(be, HW_CAT_CFN_PTC_TNL_L3, i, 0,
			   0xffffffff); /* accept all */
	hw_mod_cat_cfn_set(be, HW_CAT_CFN_PTC_TNL_FRAG, i, 0,
			   0xffffffff); /* accept all */
	hw_mod_cat_cfn_set(be, HW_CAT_CFN_PTC_TNL_IP_PROT, i, 0,
			   0xffffffff); /* inner IP prot check disabled */
	hw_mod_cat_cfn_set(be, HW_CAT_CFN_PTC_TNL_L4, i, 0,
			   0xffffffff); /* accept all */
	hw_mod_cat_cfn_set(be, HW_CAT_CFN_ERR_CV, i, 0, 3); /* accept all */
	hw_mod_cat_cfn_set(be, HW_CAT_CFN_ERR_FCS, i, 0, 3); /* accept all */
	hw_mod_cat_cfn_set(be, HW_CAT_CFN_ERR_TRUNC, i, 0,
			   0xffffffff); /* accept all truncations */
	hw_mod_cat_cfn_set(be, HW_CAT_CFN_ERR_L3_CS, i, 0, 3); /* accept all */
	hw_mod_cat_cfn_set(be, HW_CAT_CFN_ERR_L4_CS, i, 0, 3); /* accept all */
	hw_mod_cat_cfn_set(be, HW_CAT_CFN_PM_OR_INV, i, 0, 1); /*  */
	hw_mod_cat_cfn_set(be, HW_CAT_CFN_LC_INV, i, 0, 1); /*  */
	hw_mod_cat_cfn_set(be, HW_CAT_CFN_KM0_OR, i, 0,
			   0xffffffff); /* or all */
	if (_VER_ >= 21) {
		hw_mod_cat_cfn_set(be, HW_CAT_CFN_KM1_OR, i, 0,
				   0xffffffff); /* or all */
		hw_mod_cat_cfn_set(be, HW_CAT_CFN_ERR_TNL_L3_CS, i, 0,
				   0xffffffff); /* or all */
		hw_mod_cat_cfn_set(be, HW_CAT_CFN_ERR_TNL_L4_CS, i, 0,
				   0xffffffff); /* or all */
		hw_mod_cat_cfn_set(be, HW_CAT_CFN_ERR_TTL_EXP, i, 0,
				   0xffffffff); /* or all */
		hw_mod_cat_cfn_set(be, HW_CAT_CFN_ERR_TNL_TTL_EXP, i, 0,
				   0xffffffff); /* or all */
	}
	return err;
}

int hw_mod_cat_reset(struct flow_api_backend_s *be)
{
	/* Zero entire cache area */
	ZERO_MOD_CACHE(&be->cat);

	NT_LOG(DBG, FILTER, "INIT CAT CFN\n");
	if (hw_mod_cat_cfn_flush(be, 0, ALL_ENTRIES))
		return -1;

	if (_VER_ <= 18) {
		NT_LOG(DBG, FILTER, "INIT CAT KCE\n");
		if (hw_mod_cat_kce_flush(be, KM_FLM_IF_FIRST, 0, 0,
					 ALL_ENTRIES))
			return -1;

		NT_LOG(DBG, FILTER, "INIT CAT KCS\n");
		if (hw_mod_cat_kcs_flush(be, KM_FLM_IF_FIRST, 0, 0,
					 ALL_ENTRIES))
			return -1;

		NT_LOG(DBG, FILTER, "INIT CAT FTE\n");
		if (hw_mod_cat_fte_flush(be, KM_FLM_IF_FIRST, 0, 0,
					 ALL_ENTRIES))
			return -1;
	} else {
		NT_LOG(DBG, FILTER, "INIT CAT KCE 0\n");
		if (hw_mod_cat_kce_flush(be, KM_FLM_IF_FIRST, be->cat.km_if_m0,
					 0, ALL_ENTRIES))
			return -1;

		NT_LOG(DBG, FILTER, "INIT CAT KCS 0\n");
		if (hw_mod_cat_kcs_flush(be, KM_FLM_IF_FIRST, be->cat.km_if_m0,
					 0, ALL_ENTRIES))
			return -1;

		NT_LOG(DBG, FILTER, "INIT CAT FTE 0\n");
		if (hw_mod_cat_fte_flush(be, KM_FLM_IF_FIRST, be->cat.km_if_m0,
					 0, ALL_ENTRIES))
			return -1;

		if (be->cat.km_if_count > 1) {
			NT_LOG(DBG, FILTER, "INIT CAT KCE 1\n");
			if (hw_mod_cat_kce_flush(be, KM_FLM_IF_SECOND,
						 be->cat.km_if_m1, 0,
						 ALL_ENTRIES))
				return -1;

			NT_LOG(DBG, FILTER, "INIT CAT KCS 1\n");
			if (hw_mod_cat_kcs_flush(be, KM_FLM_IF_SECOND,
						 be->cat.km_if_m1, 0,
						 ALL_ENTRIES))
				return -1;

			NT_LOG(DBG, FILTER, "INIT CAT FTE 1\n");
			if (hw_mod_cat_fte_flush(be, KM_FLM_IF_SECOND,
						 be->cat.km_if_m1, 0,
						 ALL_ENTRIES))
				return -1;
		}
	}

	NT_LOG(DBG, FILTER, "INIT CAT CTE\n");
	if (hw_mod_cat_cte_flush(be, 0, ALL_ENTRIES))
		return -1;

	NT_LOG(DBG, FILTER, "INIT CAT CTS\n");
	if (hw_mod_cat_cts_flush(be, 0, ALL_ENTRIES))
		return -1;

	NT_LOG(DBG, FILTER, "INIT CAT COT\n");
	if (hw_mod_cat_cot_flush(be, 0, ALL_ENTRIES))
		return -1;

	NT_LOG(DBG, FILTER, "INIT CAT CCT\n");
	if (hw_mod_cat_cct_flush(be, 0, ALL_ENTRIES))
		return -1;

	NT_LOG(DBG, FILTER, "INIT CAT EXO\n");
	if (hw_mod_cat_exo_flush(be, 0, ALL_ENTRIES))
		return -1;

	NT_LOG(DBG, FILTER, "INIT CAT RCK\n");
	if (hw_mod_cat_rck_flush(be, 0, ALL_ENTRIES))
		return -1;

	NT_LOG(DBG, FILTER, "INIT CAT LEN\n");
	if (hw_mod_cat_len_flush(be, 0, ALL_ENTRIES))
		return -1;

	if (be->cat.kcc_size) {
		NT_LOG(DBG, FILTER, "INIT CAT KCC\n");
		if (hw_mod_cat_kcc_flush(be, 0, ALL_ENTRIES))
			return -1;
	}

	if (_VER_ > 21) {
		NT_LOG(DBG, FILTER, "INIT CAT CCE\n");
		if (hw_mod_cat_cce_flush(be, 0, ALL_ENTRIES))
			return -1;
		NT_LOG(DBG, FILTER, "INIT CAT CCS\n");
		if (hw_mod_cat_ccs_flush(be, 0, ALL_ENTRIES))
			return -1;
	}

	return 0;
}

int hw_mod_cat_cfn_flush(struct flow_api_backend_s *be, int start_idx,
			 int count)
{
	switch (count) {
	case ALL_ENTRIES:
		if (start_idx != 0)
			return error_index_too_large(__func__);
		return be->iface->cat_cfn_flush(be->be_dev, &be->cat, start_idx,
						be->cat.nb_cat_funcs);

	default:
		if ((unsigned int)(start_idx + count) > be->cat.nb_cat_funcs)
			return error_index_too_large(__func__);
		return be->iface->cat_cfn_flush(be->be_dev, &be->cat, start_idx,
						count);
	}
}

static int hw_mod_cat_cfn_mod(struct flow_api_backend_s *be,
			      enum hw_cat_e field, int index, int word_off,
			      uint32_t *value, int get)
{
	int rv = 0;
	if ((unsigned int)index >= be->cat.nb_cat_funcs)
		return error_index_too_large(__func__);
	switch (_VER_) {
	case 18:
		switch (field) {
		case HW_CAT_CFN_SET_ALL_DEFAULTS:
			if (get)
				return error_unsup_field(__func__);
			return cfn_reset(be, index);
		case HW_CAT_CFN_PRESET_ALL:
			if (get)
				return error_unsup_field(__func__);
			memset(&be->cat.v18.cfn[index], (uint8_t)*value,
			       sizeof(struct cat_v18_cfn_s));
			break;
		case HW_CAT_CFN_COMPARE:
			rv = do_compare_indexes(be->cat.v18.cfn,
				sizeof(struct cat_v18_cfn_s), index, word_off,
				be->cat.nb_cat_funcs, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_CAT_CFN_FIND:
			rv = find_equal_index(be->cat.v18.cfn,
				sizeof(struct cat_v18_cfn_s), index, word_off,
				be->cat.nb_cat_funcs, value, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_CAT_CFN_ENABLE:
			get_set(&be->cat.v18.cfn[index].enable, value, get);
			break;
		case HW_CAT_CFN_INV:
			get_set(&be->cat.v18.cfn[index].inv, value, get);
			break;
		case HW_CAT_CFN_PTC_INV:
			get_set(&be->cat.v18.cfn[index].ptc_inv, value, get);
			break;
		case HW_CAT_CFN_PTC_ISL:
			get_set(&be->cat.v18.cfn[index].ptc_isl, value, get);
			break;
		case HW_CAT_CFN_PTC_CFP:
			get_set(&be->cat.v18.cfn[index].ptc_cfp, value, get);
			break;
		case HW_CAT_CFN_PTC_MAC:
			get_set(&be->cat.v18.cfn[index].ptc_mac, value, get);
			break;
		case HW_CAT_CFN_PTC_L2:
			get_set(&be->cat.v18.cfn[index].ptc_l2, value, get);
			break;
		case HW_CAT_CFN_PTC_VNTAG:
			get_set(&be->cat.v18.cfn[index].ptc_vntag, value, get);
			break;
		case HW_CAT_CFN_PTC_VLAN:
			get_set(&be->cat.v18.cfn[index].ptc_vlan, value, get);
			break;
		case HW_CAT_CFN_PTC_MPLS:
			get_set(&be->cat.v18.cfn[index].ptc_mpls, value, get);
			break;
		case HW_CAT_CFN_PTC_L3:
			get_set(&be->cat.v18.cfn[index].ptc_l3, value, get);
			break;
		case HW_CAT_CFN_PTC_FRAG:
			get_set(&be->cat.v18.cfn[index].ptc_frag, value, get);
			break;
		case HW_CAT_CFN_PTC_IP_PROT:
			get_set(&be->cat.v18.cfn[index].ptc_ip_prot, value, get);
			break;
		case HW_CAT_CFN_PTC_L4:
			get_set(&be->cat.v18.cfn[index].ptc_l4, value, get);
			break;
		case HW_CAT_CFN_PTC_TUNNEL:
			get_set(&be->cat.v18.cfn[index].ptc_tunnel, value, get);
			break;
		case HW_CAT_CFN_PTC_TNL_L2:
			get_set(&be->cat.v18.cfn[index].ptc_tnl_l2, value, get);
			break;
		case HW_CAT_CFN_PTC_TNL_VLAN:
			get_set(&be->cat.v18.cfn[index].ptc_tnl_vlan, value, get);
			break;
		case HW_CAT_CFN_PTC_TNL_MPLS:
			get_set(&be->cat.v18.cfn[index].ptc_tnl_mpls, value, get);
			break;
		case HW_CAT_CFN_PTC_TNL_L3:
			get_set(&be->cat.v18.cfn[index].ptc_tnl_l3, value, get);
			break;
		case HW_CAT_CFN_PTC_TNL_FRAG:
			get_set(&be->cat.v18.cfn[index].ptc_tnl_frag, value, get);
			break;
		case HW_CAT_CFN_PTC_TNL_IP_PROT:
			get_set(&be->cat.v18.cfn[index].ptc_tnl_ip_prot, value, get);
			break;
		case HW_CAT_CFN_PTC_TNL_L4:
			get_set(&be->cat.v18.cfn[index].ptc_tnl_l4, value, get);
			break;
		case HW_CAT_CFN_ERR_INV:
			get_set(&be->cat.v18.cfn[index].err_inv, value, get);
			break;
		case HW_CAT_CFN_ERR_CV:
			get_set(&be->cat.v18.cfn[index].err_cv, value, get);
			break;
		case HW_CAT_CFN_ERR_FCS:
			get_set(&be->cat.v18.cfn[index].err_fcs, value, get);
			break;
		case HW_CAT_CFN_ERR_TRUNC:
			get_set(&be->cat.v18.cfn[index].err_trunc, value, get);
			break;
		case HW_CAT_CFN_ERR_L3_CS:
			get_set(&be->cat.v18.cfn[index].err_l3_cs, value, get);
			break;
		case HW_CAT_CFN_ERR_L4_CS:
			get_set(&be->cat.v18.cfn[index].err_l4_cs, value, get);
			break;
		case HW_CAT_CFN_MAC_PORT:
			get_set(&be->cat.v18.cfn[index].mac_port, value, get);
			break;
		case HW_CAT_CFN_PM_CMP:
			if (word_off > 1)
				return error_word_off_too_large(__func__);
			get_set(&be->cat.v18.cfn[index].pm_cmp[word_off], value, get);
			break;
		case HW_CAT_CFN_PM_DCT:
			get_set(&be->cat.v18.cfn[index].pm_dct, value, get);
			break;
		case HW_CAT_CFN_PM_EXT_INV:
			get_set(&be->cat.v18.cfn[index].pm_ext_inv, value, get);
			break;
		case HW_CAT_CFN_PM_CMB:
			get_set(&be->cat.v18.cfn[index].pm_cmb, value, get);
			break;
		case HW_CAT_CFN_PM_AND_INV:
			get_set(&be->cat.v18.cfn[index].pm_and_inv, value, get);
			break;
		case HW_CAT_CFN_PM_OR_INV:
			get_set(&be->cat.v18.cfn[index].pm_or_inv, value, get);
			break;
		case HW_CAT_CFN_PM_INV:
			get_set(&be->cat.v18.cfn[index].pm_inv, value, get);
			break;
		case HW_CAT_CFN_LC:
			get_set(&be->cat.v18.cfn[index].lc, value, get);
			break;
		case HW_CAT_CFN_LC_INV:
			get_set(&be->cat.v18.cfn[index].lc_inv, value, get);
			break;
		case HW_CAT_CFN_KM0_OR:
			get_set(&be->cat.v18.cfn[index].km_or, value, get);
			break;
		default:
			return error_unsup_field(__func__);
		}
		break;
	/* end case 18 */
	case 21:
	case 22:
		switch (field) {
		case HW_CAT_CFN_SET_ALL_DEFAULTS:
			if (get)
				return error_unsup_field(__func__);
			return cfn_reset(be, index);
		case HW_CAT_CFN_PRESET_ALL:
			if (get)
				return error_unsup_field(__func__);
			memset(&be->cat.v21.cfn[index], (uint8_t)*value,
			       sizeof(struct cat_v21_cfn_s));
			break;
		case HW_CAT_CFN_COMPARE:
			rv = do_compare_indexes(be->cat.v21.cfn,
				sizeof(struct cat_v21_cfn_s), index, word_off,
				be->cat.nb_cat_funcs, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_CAT_CFN_FIND:
			rv = find_equal_index(be->cat.v21.cfn,
				sizeof(struct cat_v21_cfn_s), index, word_off,
				be->cat.nb_cat_funcs, value, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_CAT_CFN_COPY_FROM:
			if (get)
				return error_unsup_field(__func__);
			memcpy(&be->cat.v21.cfn[index],
			       &be->cat.v21.cfn[*value],
			       sizeof(struct cat_v21_cfn_s));
			break;
		case HW_CAT_CFN_ENABLE:
			get_set(&be->cat.v21.cfn[index].enable, value, get);
			break;
		case HW_CAT_CFN_INV:
			get_set(&be->cat.v21.cfn[index].inv, value, get);
			break;
		case HW_CAT_CFN_PTC_INV:
			get_set(&be->cat.v21.cfn[index].ptc_inv, value, get);
			break;
		case HW_CAT_CFN_PTC_ISL:
			get_set(&be->cat.v21.cfn[index].ptc_isl, value, get);
			break;
		case HW_CAT_CFN_PTC_CFP:
			get_set(&be->cat.v21.cfn[index].ptc_cfp, value, get);
			break;
		case HW_CAT_CFN_PTC_MAC:
			get_set(&be->cat.v21.cfn[index].ptc_mac, value, get);
			break;
		case HW_CAT_CFN_PTC_L2:
			get_set(&be->cat.v21.cfn[index].ptc_l2, value, get);
			break;
		case HW_CAT_CFN_PTC_VNTAG:
			get_set(&be->cat.v21.cfn[index].ptc_vntag, value, get);
			break;
		case HW_CAT_CFN_PTC_VLAN:
			get_set(&be->cat.v21.cfn[index].ptc_vlan, value, get);
			break;
		case HW_CAT_CFN_PTC_MPLS:
			get_set(&be->cat.v21.cfn[index].ptc_mpls, value, get);
			break;
		case HW_CAT_CFN_PTC_L3:
			get_set(&be->cat.v21.cfn[index].ptc_l3, value, get);
			break;
		case HW_CAT_CFN_PTC_FRAG:
			get_set(&be->cat.v21.cfn[index].ptc_frag, value, get);
			break;
		case HW_CAT_CFN_PTC_IP_PROT:
			get_set(&be->cat.v21.cfn[index].ptc_ip_prot, value, get);
			break;
		case HW_CAT_CFN_PTC_L4:
			get_set(&be->cat.v21.cfn[index].ptc_l4, value, get);
			break;
		case HW_CAT_CFN_PTC_TUNNEL:
			get_set(&be->cat.v21.cfn[index].ptc_tunnel, value, get);
			break;
		case HW_CAT_CFN_PTC_TNL_L2:
			get_set(&be->cat.v21.cfn[index].ptc_tnl_l2, value, get);
			break;
		case HW_CAT_CFN_PTC_TNL_VLAN:
			get_set(&be->cat.v21.cfn[index].ptc_tnl_vlan, value, get);
			break;
		case HW_CAT_CFN_PTC_TNL_MPLS:
			get_set(&be->cat.v21.cfn[index].ptc_tnl_mpls, value, get);
			break;
		case HW_CAT_CFN_PTC_TNL_L3:
			get_set(&be->cat.v21.cfn[index].ptc_tnl_l3, value, get);
			break;
		case HW_CAT_CFN_PTC_TNL_FRAG:
			get_set(&be->cat.v21.cfn[index].ptc_tnl_frag, value, get);
			break;
		case HW_CAT_CFN_PTC_TNL_IP_PROT:
			get_set(&be->cat.v21.cfn[index].ptc_tnl_ip_prot, value, get);
			break;
		case HW_CAT_CFN_PTC_TNL_L4:
			get_set(&be->cat.v21.cfn[index].ptc_tnl_l4, value, get);
			break;
		case HW_CAT_CFN_ERR_INV:
			get_set(&be->cat.v21.cfn[index].err_inv, value, get);
			break;
		case HW_CAT_CFN_ERR_CV:
			get_set(&be->cat.v21.cfn[index].err_cv, value, get);
			break;
		case HW_CAT_CFN_ERR_FCS:
			get_set(&be->cat.v21.cfn[index].err_fcs, value, get);
			break;
		case HW_CAT_CFN_ERR_TRUNC:
			get_set(&be->cat.v21.cfn[index].err_trunc, value, get);
			break;
		case HW_CAT_CFN_ERR_L3_CS:
			get_set(&be->cat.v21.cfn[index].err_l3_cs, value, get);
			break;
		case HW_CAT_CFN_ERR_L4_CS:
			get_set(&be->cat.v21.cfn[index].err_l4_cs, value, get);
			break;
		case HW_CAT_CFN_ERR_TNL_L3_CS:
			get_set(&be->cat.v21.cfn[index].err_tnl_l3_cs, value, get);
			break;
		case HW_CAT_CFN_ERR_TNL_L4_CS:
			get_set(&be->cat.v21.cfn[index].err_tnl_l4_cs, value, get);
			break;
		case HW_CAT_CFN_ERR_TTL_EXP:
			get_set(&be->cat.v21.cfn[index].err_ttl_exp, value, get);
			break;
		case HW_CAT_CFN_ERR_TNL_TTL_EXP:
			get_set(&be->cat.v21.cfn[index].err_tnl_ttl_exp, value, get);
			break;
		case HW_CAT_CFN_MAC_PORT:
			get_set(&be->cat.v21.cfn[index].mac_port, value, get);
			break;
		case HW_CAT_CFN_PM_CMP:
			if (word_off > 1)
				return error_word_off_too_large(__func__);
			get_set(&be->cat.v21.cfn[index].pm_cmp[word_off], value, get);
			break;
		case HW_CAT_CFN_PM_DCT:
			get_set(&be->cat.v21.cfn[index].pm_dct, value, get);
			break;
		case HW_CAT_CFN_PM_EXT_INV:
			get_set(&be->cat.v21.cfn[index].pm_ext_inv, value, get);
			break;
		case HW_CAT_CFN_PM_CMB:
			get_set(&be->cat.v21.cfn[index].pm_cmb, value, get);
			break;
		case HW_CAT_CFN_PM_AND_INV:
			get_set(&be->cat.v21.cfn[index].pm_and_inv, value, get);
			break;
		case HW_CAT_CFN_PM_OR_INV:
			get_set(&be->cat.v21.cfn[index].pm_or_inv, value, get);
			break;
		case HW_CAT_CFN_PM_INV:
			get_set(&be->cat.v21.cfn[index].pm_inv, value, get);
			break;
		case HW_CAT_CFN_LC:
			get_set(&be->cat.v21.cfn[index].lc, value, get);
			break;
		case HW_CAT_CFN_LC_INV:
			get_set(&be->cat.v21.cfn[index].lc_inv, value, get);
			break;
		case HW_CAT_CFN_KM0_OR:
			get_set(&be->cat.v21.cfn[index].km0_or, value, get);
			break;
		case HW_CAT_CFN_KM1_OR:
			get_set(&be->cat.v21.cfn[index].km1_or, value, get);
			break;
		default:
			return error_unsup_field(__func__);
		}
		break;
	/* end case 21/22 */

	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}
	return 0;
}

int hw_mod_cat_cfn_set(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, int word_off, uint32_t value)
{
	return hw_mod_cat_cfn_mod(be, field, index, word_off, &value, 0);
}

int hw_mod_cat_cfn_get(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, int word_off, uint32_t *value)
{
	return hw_mod_cat_cfn_mod(be, field, index, word_off, value, 1);
}

static inline int
find_km_flm_module_interface_index(struct flow_api_backend_s *be,
				   enum km_flm_if_select_e if_num, int km_if_id)
{
	int km_if_idx;

	if (_VER_ == 18) {
		km_if_idx = 0;
	} else {
		if (if_num == KM_FLM_IF_SECOND) {
			if (be->cat.km_if_m1 == km_if_id)
				km_if_idx = 1;
			else
				return error_unsup_field(__func__);
		} else {
			if (be->cat.km_if_m0 == km_if_id)
				km_if_idx = 0;
			else if (be->cat.km_if_m1 == km_if_id)
				km_if_idx = 1;
			else
				return error_unsup_field(__func__);
		}
	}
	return km_if_idx;
}

/*
 * KCE
 */

static int hw_mod_cat_kce_flush(struct flow_api_backend_s *be,
				enum km_flm_if_select_e if_num, int km_if_id,
				int start_idx, int count)
{
	/* writes 8 bits - one for each cfn - at a time */
	if (count == ALL_ENTRIES)
		count = be->cat.nb_cat_funcs / 8;
	if ((unsigned int)(start_idx + count) > (be->cat.nb_cat_funcs / 8))
		return error_index_too_large(__func__);
	/* find KM module */
	int km_if_idx;

	km_if_idx = find_km_flm_module_interface_index(be, if_num, km_if_id);
	if (km_if_idx < 0)
		return km_if_idx;

	return be->iface->cat_kce_flush(be->be_dev, &be->cat, km_if_idx,
					start_idx, count);
}

int hw_mod_cat_kce_km_flush(struct flow_api_backend_s *be,
			    enum km_flm_if_select_e if_num, int start_idx,
			    int count)
{
	return hw_mod_cat_kce_flush(be, if_num, 0, start_idx, count);
}

int hw_mod_cat_kce_flm_flush(struct flow_api_backend_s *be,
			     enum km_flm_if_select_e if_num, int start_idx,
			     int count)
{
	return hw_mod_cat_kce_flush(be, if_num, 1, start_idx, count);
}

static int hw_mod_cat_kce_mod(struct flow_api_backend_s *be,
			      enum hw_cat_e field,
			      enum km_flm_if_select_e if_num, int km_if_id,
			      int index, uint32_t *value, int get)
{
	if ((unsigned int)index >= (be->cat.nb_cat_funcs / 8))
		return error_index_too_large(__func__);

	/* find KM module */
	int km_if_idx;

	km_if_idx = find_km_flm_module_interface_index(be, if_num, km_if_id);
	if (km_if_idx < 0)
		return km_if_idx;

	switch (_VER_) {
	case 18:
		switch (field) {
		case HW_CAT_KCE_ENABLE_BM:
			get_set(&be->cat.v18.kce[index].enable_bm, value, get);
			break;

		default:
			return error_unsup_field(__func__);
		}
		break;
	/* end case 18 */
	case 21:
	case 22:
		switch (field) {
		case HW_CAT_KCE_ENABLE_BM:
			get_set(&be->cat.v21.kce[index].enable_bm[km_if_idx],
				value, get);
			break;

		default:
			return error_unsup_field(__func__);
		}
		break;
	/* end case 21/22 */

	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

int hw_mod_cat_kce_km_set(struct flow_api_backend_s *be, enum hw_cat_e field,
			  enum km_flm_if_select_e if_num, int index,
			  uint32_t value)
{
	return hw_mod_cat_kce_mod(be, field, if_num, 0, index, &value, 0);
}

int hw_mod_cat_kce_km_get(struct flow_api_backend_s *be, enum hw_cat_e field,
			  enum km_flm_if_select_e if_num, int index,
			  uint32_t *value)
{
	return hw_mod_cat_kce_mod(be, field, if_num, 0, index, value, 1);
}

int hw_mod_cat_kce_flm_set(struct flow_api_backend_s *be, enum hw_cat_e field,
			   enum km_flm_if_select_e if_num, int index,
			   uint32_t value)
{
	return hw_mod_cat_kce_mod(be, field, if_num, 1, index, &value, 0);
}

int hw_mod_cat_kce_flm_get(struct flow_api_backend_s *be, enum hw_cat_e field,
			   enum km_flm_if_select_e if_num, int index,
			   uint32_t *value)
{
	return hw_mod_cat_kce_mod(be, field, if_num, 1, index, value, 1);
}

/*
 * KCS
 */
static int hw_mod_cat_kcs_flush(struct flow_api_backend_s *be,
				enum km_flm_if_select_e if_num, int km_if_id,
				int start_idx, int count)
{
	if (count == ALL_ENTRIES)
		count = be->cat.nb_cat_funcs;
	if ((unsigned int)(start_idx + count) > be->cat.nb_cat_funcs)
		return error_index_too_large(__func__);

	/* find KM module */
	int km_if_idx;

	km_if_idx = find_km_flm_module_interface_index(be, if_num, km_if_id);
	if (km_if_idx < 0)
		return km_if_idx;

	return be->iface->cat_kcs_flush(be->be_dev, &be->cat, km_if_idx,
					start_idx, count);
}

int hw_mod_cat_kcs_km_flush(struct flow_api_backend_s *be,
			    enum km_flm_if_select_e if_num, int start_idx,
			    int count)
{
	return hw_mod_cat_kcs_flush(be, if_num, 0, start_idx, count);
}

int hw_mod_cat_kcs_flm_flush(struct flow_api_backend_s *be,
			     enum km_flm_if_select_e if_num, int start_idx,
			     int count)
{
	return hw_mod_cat_kcs_flush(be, if_num, 1, start_idx, count);
}

static int hw_mod_cat_kcs_mod(struct flow_api_backend_s *be,
			      enum hw_cat_e field,
			      enum km_flm_if_select_e if_num, int km_if_id,
			      int index, uint32_t *value, int get)
{
	if ((unsigned int)index >= be->cat.nb_cat_funcs)
		return error_index_too_large(__func__);
	/* find KM module */
	int km_if_idx;

	km_if_idx = find_km_flm_module_interface_index(be, if_num, km_if_id);
	if (km_if_idx < 0)
		return km_if_idx;

	switch (_VER_) {
	case 18:
		switch (field) {
		case HW_CAT_KCS_CATEGORY:
			get_set(&be->cat.v18.kcs[index].category, value, get);
			break;

		default:
			return error_unsup_field(__func__);
		}
		break;
	/* end case 18 */
	case 21:
	case 22:
		switch (field) {
		case HW_CAT_KCS_CATEGORY:
			get_set(&be->cat.v21.kcs[index].category[km_if_idx],
				value, get);
			break;

		default:
			return error_unsup_field(__func__);
		}
		break;
	/* end case 21/22 */

	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

int hw_mod_cat_kcs_km_set(struct flow_api_backend_s *be, enum hw_cat_e field,
			  enum km_flm_if_select_e if_num, int index,
			  uint32_t value)
{
	return hw_mod_cat_kcs_mod(be, field, if_num, 0, index, &value, 0);
}

int hw_mod_cat_kcs_km_get(struct flow_api_backend_s *be, enum hw_cat_e field,
			  enum km_flm_if_select_e if_num, int index,
			  uint32_t *value)
{
	return hw_mod_cat_kcs_mod(be, field, if_num, 0, index, value, 1);
}

int hw_mod_cat_kcs_flm_set(struct flow_api_backend_s *be, enum hw_cat_e field,
			   enum km_flm_if_select_e if_num, int index,
			   uint32_t value)
{
	return hw_mod_cat_kcs_mod(be, field, if_num, 1, index, &value, 0);
}

int hw_mod_cat_kcs_flm_get(struct flow_api_backend_s *be, enum hw_cat_e field,
			   enum km_flm_if_select_e if_num, int index,
			   uint32_t *value)
{
	return hw_mod_cat_kcs_mod(be, field, if_num, 1, index, value, 1);
}

/*
 * FTE
 */
static int hw_mod_cat_fte_flush(struct flow_api_backend_s *be,
				enum km_flm_if_select_e if_num, int km_if_id,
				int start_idx, int count)
{
	const uint32_t key_cnt = (_VER_ >= 20) ? 4 : 2;

	if (count == ALL_ENTRIES)
		count = be->cat.nb_cat_funcs / 8 * be->cat.nb_flow_types *
			key_cnt;
	if ((unsigned int)(start_idx + count) >
			(be->cat.nb_cat_funcs / 8 * be->cat.nb_flow_types * key_cnt))
		return error_index_too_large(__func__);

	/* find KM module */
	int km_if_idx;

	km_if_idx = find_km_flm_module_interface_index(be, if_num, km_if_id);
	if (km_if_idx < 0)
		return km_if_idx;

	return be->iface->cat_fte_flush(be->be_dev, &be->cat, km_if_idx,
					start_idx, count);
}

int hw_mod_cat_fte_km_flush(struct flow_api_backend_s *be,
			    enum km_flm_if_select_e if_num, int start_idx,
			    int count)
{
	return hw_mod_cat_fte_flush(be, if_num, 0, start_idx, count);
}

int hw_mod_cat_fte_flm_flush(struct flow_api_backend_s *be,
			     enum km_flm_if_select_e if_num, int start_idx,
			     int count)
{
	return hw_mod_cat_fte_flush(be, if_num, 1, start_idx, count);
}

static int hw_mod_cat_fte_mod(struct flow_api_backend_s *be,
			      enum hw_cat_e field,
			      enum km_flm_if_select_e if_num, int km_if_id,
			      int index, uint32_t *value, int get)
{
	const uint32_t key_cnt = (_VER_ >= 20) ? 4 : 2;

	if ((unsigned int)index >=
			(be->cat.nb_cat_funcs / 8 * be->cat.nb_flow_types * key_cnt))
		return error_index_too_large(__func__);
	/* find KM module */
	int km_if_idx;

	km_if_idx = find_km_flm_module_interface_index(be, if_num, km_if_id);
	if (km_if_idx < 0)
		return km_if_idx;

	switch (_VER_) {
	case 18:
		switch (field) {
		case HW_CAT_FTE_ENABLE_BM:
			get_set(&be->cat.v18.fte[index].enable_bm, value, get);
			break;

		default:
			return error_unsup_field(__func__);
		}
		break;
	/* end case 18 */
	case 21:
	case 22:
		switch (field) {
		case HW_CAT_FTE_ENABLE_BM:
			get_set(&be->cat.v21.fte[index].enable_bm[km_if_idx],
				value, get);
			break;

		default:
			return error_unsup_field(__func__);
		}
		break;
	/* end case 21/22 */

	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

int hw_mod_cat_fte_km_set(struct flow_api_backend_s *be, enum hw_cat_e field,
			  enum km_flm_if_select_e if_num, int index,
			  uint32_t value)
{
	return hw_mod_cat_fte_mod(be, field, if_num, 0, index, &value, 0);
}

int hw_mod_cat_fte_km_get(struct flow_api_backend_s *be, enum hw_cat_e field,
			  enum km_flm_if_select_e if_num, int index,
			  uint32_t *value)
{
	return hw_mod_cat_fte_mod(be, field, if_num, 0, index, value, 1);
}

int hw_mod_cat_fte_flm_set(struct flow_api_backend_s *be, enum hw_cat_e field,
			   enum km_flm_if_select_e if_num, int index,
			   uint32_t value)
{
	return hw_mod_cat_fte_mod(be, field, if_num, 1, index, &value, 0);
}

int hw_mod_cat_fte_flm_get(struct flow_api_backend_s *be, enum hw_cat_e field,
			   enum km_flm_if_select_e if_num, int index,
			   uint32_t *value)
{
	return hw_mod_cat_fte_mod(be, field, if_num, 1, index, value, 1);
}

int hw_mod_cat_cte_flush(struct flow_api_backend_s *be, int start_idx,
			 int count)
{
	if (count == ALL_ENTRIES)
		count = be->cat.nb_cat_funcs;
	if ((unsigned int)(start_idx + count) > be->cat.nb_cat_funcs)
		return error_index_too_large(__func__);
	return be->iface->cat_cte_flush(be->be_dev, &be->cat, start_idx, count);
}

static int hw_mod_cat_cte_mod(struct flow_api_backend_s *be,
			      enum hw_cat_e field, int index, uint32_t *value,
			      int get)
{
	if ((unsigned int)index >= be->cat.nb_cat_funcs)
		return error_index_too_large(__func__);
	switch (_VER_) {
	case 18:
	case 21:
	case 22:
		switch (field) {
		case HW_CAT_CTE_ENABLE_BM:
			get_set(&be->cat.v18.cte[index].enable_bm, value, get);
			break;

		default:
			return error_unsup_field(__func__);
		}
		break;
	/* end case 18/21/22 */

	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

int hw_mod_cat_cte_set(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, uint32_t value)
{
	return hw_mod_cat_cte_mod(be, field, index, &value, 0);
}

int hw_mod_cat_cte_get(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, uint32_t *value)
{
	return hw_mod_cat_cte_mod(be, field, index, value, 1);
}

int hw_mod_cat_cts_flush(struct flow_api_backend_s *be, int start_idx,
			 int count)
{
	int addr_size = (_VER_ < 15) ? 8 : ((be->cat.cts_num + 1) / 2);

	if (count == ALL_ENTRIES)
		count = be->cat.nb_cat_funcs * addr_size;
	if ((unsigned int)(start_idx + count) >
			(be->cat.nb_cat_funcs * addr_size))
		return error_index_too_large(__func__);
	return be->iface->cat_cts_flush(be->be_dev, &be->cat, start_idx, count);
}

static int hw_mod_cat_cts_mod(struct flow_api_backend_s *be,
			      enum hw_cat_e field, int index, uint32_t *value,
			      int get)
{
	int addr_size = (be->cat.cts_num + 1) / 2;

	if ((unsigned int)index >= (be->cat.nb_cat_funcs * addr_size))
		return error_index_too_large(__func__);

	switch (_VER_) {
	case 18:
	case 21:
	case 22:
		switch (field) {
		case HW_CAT_CTS_CAT_A:
			get_set(&be->cat.v18.cts[index].cat_a, value, get);
			break;
		case HW_CAT_CTS_CAT_B:
			get_set(&be->cat.v18.cts[index].cat_b, value, get);
			break;

		default:
			return error_unsup_field(__func__);
		}
		break;
	/* end case 18/21/22 */

	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

int hw_mod_cat_cts_set(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, uint32_t value)
{
	return hw_mod_cat_cts_mod(be, field, index, &value, 0);
}

int hw_mod_cat_cts_get(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, uint32_t *value)
{
	return hw_mod_cat_cts_mod(be, field, index, value, 1);
}

int hw_mod_cat_cot_flush(struct flow_api_backend_s *be, int start_idx,
			 int count)
{
	if (count == ALL_ENTRIES)
		count = be->max_categories;
	if ((unsigned int)(start_idx + count) > be->max_categories)
		return error_index_too_large(__func__);
	return be->iface->cat_cot_flush(be->be_dev, &be->cat, start_idx, count);
}

static int hw_mod_cat_cot_mod(struct flow_api_backend_s *be,
			      enum hw_cat_e field, int index, uint32_t *value,
			      int get)
{
	int rv = 0;
	if ((unsigned int)index >= be->max_categories)
		return error_index_too_large(__func__);
	switch (_VER_) {
	case 18:
	case 21:
	case 22:
		switch (field) {
		case HW_CAT_COT_PRESET_ALL:
			if (get)
				return error_unsup_field(__func__);
			memset(&be->cat.v18.cot[index], (uint8_t)*value,
			       sizeof(struct cat_v18_cot_s));
			break;
		case HW_CAT_COT_COMPARE:
			rv = do_compare_indexes(be->cat.v18.cot,
				sizeof(struct cat_v18_cot_s), index, *value,
				be->max_categories, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_CAT_COT_FIND:
			rv = find_equal_index(be->cat.v18.cot,
				sizeof(struct cat_v18_cot_s), index, *value,
				be->max_categories, value, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_CAT_COT_COLOR:
			get_set(&be->cat.v18.cot[index].color, value, get);
			break;
		case HW_CAT_COT_KM:
			get_set(&be->cat.v18.cot[index].km, value, get);
			break;

		default:
			return error_unsup_field(__func__);
		}
		break;
	/* end case 18/21/22 */

	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

int hw_mod_cat_cot_set(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, uint32_t value)
{
	return hw_mod_cat_cot_mod(be, field, index, &value, 0);
}

int hw_mod_cat_cot_get(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, uint32_t *value)
{
	return hw_mod_cat_cot_mod(be, field, index, value, 1);
}

int hw_mod_cat_cct_flush(struct flow_api_backend_s *be, int start_idx,
			 int count)
{
	if (count == ALL_ENTRIES)
		count = be->cat.nb_cat_funcs * 4;
	if ((unsigned int)(start_idx + count) > be->cat.nb_cat_funcs * 4)
		return error_index_too_large(__func__);
	return be->iface->cat_cct_flush(be->be_dev, &be->cat, start_idx, count);
}

static int hw_mod_cat_cct_mod(struct flow_api_backend_s *be,
			      enum hw_cat_e field, int index, uint32_t *value,
			      int get)
{
	if ((unsigned int)index >= be->cat.nb_cat_funcs * 4)
		return error_index_too_large(__func__);
	switch (_VER_) {
	case 18:
	case 21:
	case 22:
		switch (field) {
		case HW_CAT_CCT_COLOR:
			get_set(&be->cat.v18.cct[index].color, value, get);
			break;
		case HW_CAT_CCT_KM:
			get_set(&be->cat.v18.cct[index].km, value, get);
			break;

		default:
			return error_unsup_field(__func__);
		}
		break;
	/* end case 18/21/22 */

	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

int hw_mod_cat_cct_set(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, uint32_t value)
{
	return hw_mod_cat_cct_mod(be, field, index, &value, 0);
}

int hw_mod_cat_cct_get(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, uint32_t *value)
{
	return hw_mod_cat_cct_mod(be, field, index, value, 1);
}

int hw_mod_cat_kcc_flush(struct flow_api_backend_s *be, int start_idx,
			 int count)
{
	if (count == ALL_ENTRIES)
		count = be->cat.kcc_size;
	if ((unsigned int)(start_idx + count) > be->cat.kcc_size)
		return error_index_too_large(__func__);
	return be->iface->cat_kcc_flush(be->be_dev, &be->cat, start_idx, count);
}

static int hw_mod_cat_kcc_mod(struct flow_api_backend_s *be,
			      enum hw_cat_e field, int index, int word_off,
			      uint32_t *value, int get)
{
	if ((unsigned int)index >= be->cat.kcc_size)
		return error_index_too_large(__func__);
	switch (_VER_) {
	case 18:
	case 21:
	case 22:
		switch (field) {
		case HW_CAT_KCC_KEY:
			if (word_off > 1)
				return error_word_off_too_large(__func__);
			get_set(&be->cat.v18.kcc_cam[index].key[word_off], value,
				get);
			break;

		case HW_CAT_KCC_CATEGORY:
			get_set(&be->cat.v18.kcc_cam[index].category, value, get);
			break;

		case HW_CAT_KCC_ID:
			get_set(&be->cat.v18.kcc_cam[index].id, value, get);
			break;

		default:
			return error_unsup_field(__func__);
		}
		break;
	/* end case 18/21/22 */

	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

int hw_mod_cat_kcc_set(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, int word_off, uint32_t value)
{
	return hw_mod_cat_kcc_mod(be, field, index, word_off, &value, 0);
}

int hw_mod_cat_kcc_get(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, int word_off, uint32_t *value)
{
	return hw_mod_cat_kcc_mod(be, field, index, word_off, value, 1);
}

int hw_mod_cat_exo_flush(struct flow_api_backend_s *be, int start_idx,
			 int count)
{
	if (count == ALL_ENTRIES)
		count = be->cat.nb_pm_ext;
	if ((unsigned int)(start_idx + count) > be->cat.nb_pm_ext)
		return error_index_too_large(__func__);
	return be->iface->cat_exo_flush(be->be_dev, &be->cat, start_idx, count);
}

static int hw_mod_cat_exo_mod(struct flow_api_backend_s *be,
			      enum hw_cat_e field, int index, uint32_t *value,
			      int get)
{
	if ((unsigned int)index >= be->cat.nb_pm_ext)
		return error_index_too_large(__func__);
	switch (_VER_) {
	case 18:
	case 21:
	case 22:
		switch (field) {
		case HW_CAT_EXO_DYN:
			get_set(&be->cat.v18.exo[index].dyn, value, get);
			break;
		case HW_CAT_EXO_OFS:
			get_set_signed(&be->cat.v18.exo[index].ofs, value, get);
			break;

		default:
			return error_unsup_field(__func__);
		}
		break;
	/* end case 18/21/22 */

	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

int hw_mod_cat_exo_set(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, uint32_t value)
{
	return hw_mod_cat_exo_mod(be, field, index, &value, 0);
}

int hw_mod_cat_exo_get(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, uint32_t *value)
{
	return hw_mod_cat_exo_mod(be, field, index, value, 1);
}

int hw_mod_cat_rck_flush(struct flow_api_backend_s *be, int start_idx,
			 int count)
{
	if (count == ALL_ENTRIES)
		count = be->cat.nb_pm_ext * 64;
	if ((unsigned int)(start_idx + count) > (be->cat.nb_pm_ext * 64))
		return error_index_too_large(__func__);
	return be->iface->cat_rck_flush(be->be_dev, &be->cat, start_idx, count);
}

static int hw_mod_cat_rck_mod(struct flow_api_backend_s *be,
			      enum hw_cat_e field, int index, uint32_t *value,
			      int get)
{
	if ((unsigned int)index >= (be->cat.nb_pm_ext * 64))
		return error_index_too_large(__func__);
	switch (_VER_) {
	case 18:
	case 21:
	case 22:
		switch (field) {
		case HW_CAT_RCK_DATA:
			get_set(&be->cat.v18.rck[index].rck_data, value, get);
			break;

		default:
			return error_unsup_field(__func__);
		}
		break;
	/* end case 18/21/22 */

	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

int hw_mod_cat_rck_set(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, uint32_t value)
{
	return hw_mod_cat_rck_mod(be, field, index, &value, 0);
}

int hw_mod_cat_rck_get(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, uint32_t *value)
{
	return hw_mod_cat_rck_mod(be, field, index, value, 1);
}

int hw_mod_cat_len_flush(struct flow_api_backend_s *be, int start_idx,
			 int count)
{
	if (count == ALL_ENTRIES)
		count = be->cat.nb_len;
	if ((unsigned int)(start_idx + count) > be->cat.nb_len)
		return error_index_too_large(__func__);
	return be->iface->cat_len_flush(be->be_dev, &be->cat, start_idx, count);
}

static int hw_mod_cat_len_mod(struct flow_api_backend_s *be,
			      enum hw_cat_e field, int index, uint32_t *value,
			      int get)
{
	if ((unsigned int)index >= be->cat.nb_len)
		return error_index_too_large(__func__);
	switch (_VER_) {
	case 18:
	case 21:
	case 22:
		switch (field) {
		case HW_CAT_LEN_LOWER:
			get_set(&be->cat.v18.len[index].lower, value, get);
			break;
		case HW_CAT_LEN_UPPER:
			get_set(&be->cat.v18.len[index].upper, value, get);
			break;
		case HW_CAT_LEN_DYN1:
			get_set(&be->cat.v18.len[index].dyn1, value, get);
			break;
		case HW_CAT_LEN_DYN2:
			get_set(&be->cat.v18.len[index].dyn2, value, get);
			break;
		case HW_CAT_LEN_INV:
			get_set(&be->cat.v18.len[index].inv, value, get);
			break;

		default:
			return error_unsup_field(__func__);
		}
		break;
	/* end case 18/21/22 */

	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

int hw_mod_cat_len_set(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, uint32_t value)
{
	return hw_mod_cat_len_mod(be, field, index, &value, 0);
}

int hw_mod_cat_len_get(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, uint32_t *value)
{
	return hw_mod_cat_len_mod(be, field, index, value, 1);
}

int hw_mod_cat_cce_flush(struct flow_api_backend_s *be, int start_idx,
			 int count)
{
	if (count == ALL_ENTRIES)
		count = 4;
	if ((unsigned int)(start_idx + count) > 4)
		return error_index_too_large(__func__);
	return be->iface->cat_cce_flush(be->be_dev, &be->cat, start_idx, count);
}

static int hw_mod_cat_cce_mod(struct flow_api_backend_s *be,
			      enum hw_cat_e field, int index, uint32_t *value,
			      int get)
{
	if ((unsigned int)index >= be->cat.nb_len)
		return error_index_too_large(__func__);
	switch (_VER_) {
	case 22:
		switch (field) {
		case HW_CAT_CCE_IMM:
			get_set(&be->cat.v22.cce[index].imm, value, get);
			break;
		case HW_CAT_CCE_IND:
			get_set(&be->cat.v22.cce[index].ind, value, get);
			break;

		default:
			return error_unsup_field(__func__);
		}
		break;
	/* end case 22 */

	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

int hw_mod_cat_cce_set(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, uint32_t value)
{
	return hw_mod_cat_cce_mod(be, field, index, &value, 0);
}

int hw_mod_cat_cce_get(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, uint32_t *value)
{
	return hw_mod_cat_cce_mod(be, field, index, value, 1);
}

int hw_mod_cat_ccs_flush(struct flow_api_backend_s *be, int start_idx,
			 int count)
{
	if (count == ALL_ENTRIES)
		count = 1024;
	if ((unsigned int)(start_idx + count) > 1024)
		return error_index_too_large(__func__);
	return be->iface->cat_ccs_flush(be->be_dev, &be->cat, start_idx, count);
}

static int hw_mod_cat_ccs_mod(struct flow_api_backend_s *be,
			      enum hw_cat_e field, int index, uint32_t *value,
			      int get)
{
	if ((unsigned int)index >= be->cat.nb_len)
		return error_index_too_large(__func__);
	switch (_VER_) {
	case 22:
		switch (field) {
		case HW_CAT_CCS_COR_EN:
			get_set(&be->cat.v22.ccs[index].cor_en, value, get);
			break;
		case HW_CAT_CCS_COR:
			get_set(&be->cat.v22.ccs[index].cor, value, get);
			break;
		case HW_CAT_CCS_HSH_EN:
			get_set(&be->cat.v22.ccs[index].hsh_en, value, get);
			break;
		case HW_CAT_CCS_HSH:
			get_set(&be->cat.v22.ccs[index].hsh, value, get);
			break;
		case HW_CAT_CCS_QSL_EN:
			get_set(&be->cat.v22.ccs[index].qsl_en, value, get);
			break;
		case HW_CAT_CCS_QSL:
			get_set(&be->cat.v22.ccs[index].qsl, value, get);
			break;
		case HW_CAT_CCS_IPF_EN:
			get_set(&be->cat.v22.ccs[index].ipf_en, value, get);
			break;
		case HW_CAT_CCS_IPF:
			get_set(&be->cat.v22.ccs[index].ipf, value, get);
			break;
		case HW_CAT_CCS_SLC_EN:
			get_set(&be->cat.v22.ccs[index].slc_en, value, get);
			break;
		case HW_CAT_CCS_SLC:
			get_set(&be->cat.v22.ccs[index].slc, value, get);
			break;
		case HW_CAT_CCS_PDB_EN:
			get_set(&be->cat.v22.ccs[index].pdb_en, value, get);
			break;
		case HW_CAT_CCS_PDB:
			get_set(&be->cat.v22.ccs[index].pdb, value, get);
			break;
		case HW_CAT_CCS_MSK_EN:
			get_set(&be->cat.v22.ccs[index].msk_en, value, get);
			break;
		case HW_CAT_CCS_MSK:
			get_set(&be->cat.v22.ccs[index].msk, value, get);
			break;
		case HW_CAT_CCS_HST_EN:
			get_set(&be->cat.v22.ccs[index].hst_en, value, get);
			break;
		case HW_CAT_CCS_HST:
			get_set(&be->cat.v22.ccs[index].hst, value, get);
			break;
		case HW_CAT_CCS_EPP_EN:
			get_set(&be->cat.v22.ccs[index].epp_en, value, get);
			break;
		case HW_CAT_CCS_EPP:
			get_set(&be->cat.v22.ccs[index].epp, value, get);
			break;
		case HW_CAT_CCS_TPE_EN:
			get_set(&be->cat.v22.ccs[index].tpe_en, value, get);
			break;
		case HW_CAT_CCS_TPE:
			get_set(&be->cat.v22.ccs[index].tpe, value, get);
			break;
		case HW_CAT_CCS_RRB_EN:
			get_set(&be->cat.v22.ccs[index].rrb_en, value, get);
			break;
		case HW_CAT_CCS_RRB:
			get_set(&be->cat.v22.ccs[index].rrb, value, get);
			break;
		case HW_CAT_CCS_SB0_TYPE:
			get_set(&be->cat.v22.ccs[index].sb0_type, value, get);
			break;
		case HW_CAT_CCS_SB0_DATA:
			get_set(&be->cat.v22.ccs[index].sb0_data, value, get);
			break;
		case HW_CAT_CCS_SB1_TYPE:
			get_set(&be->cat.v22.ccs[index].sb1_type, value, get);
			break;
		case HW_CAT_CCS_SB1_DATA:
			get_set(&be->cat.v22.ccs[index].sb1_data, value, get);
			break;
		case HW_CAT_CCS_SB2_TYPE:
			get_set(&be->cat.v22.ccs[index].sb2_type, value, get);
			break;
		case HW_CAT_CCS_SB2_DATA:
			get_set(&be->cat.v22.ccs[index].sb2_data, value, get);
			break;

		default:
			return error_unsup_field(__func__);
		}
		break;
	/* end case 22 */

	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

int hw_mod_cat_ccs_set(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, uint32_t value)
{
	return hw_mod_cat_ccs_mod(be, field, index, &value, 0);
}

int hw_mod_cat_ccs_get(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, uint32_t *value)
{
	return hw_mod_cat_ccs_mod(be, field, index, value, 1);
}

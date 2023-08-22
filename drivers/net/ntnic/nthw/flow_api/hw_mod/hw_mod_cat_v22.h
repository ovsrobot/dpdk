/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _HW_MOD_CAT_V22_H_
#define _HW_MOD_CAT_V22_H_

#include "hw_mod_cat_v21.h"

struct cat_v22_cte_s {
	union {
		uint32_t enable_bm;
		struct {
			uint32_t col : 1;
			uint32_t cor : 1;
			uint32_t hsh : 1;
			uint32_t qsl : 1;
			uint32_t ipf : 1;
			uint32_t slc : 1;
			uint32_t pdb : 1;
			uint32_t msk : 1;
			uint32_t hst : 1;
			uint32_t epp : 1;
			uint32_t tpe : 1;
			uint32_t rrb : 1;
		} b;
	};
};

struct cat_v22_cce_s {
	uint32_t imm;
	uint32_t ind;
};

struct cat_v22_ccs_s {
	uint32_t cor_en;
	uint32_t cor;
	uint32_t hsh_en;
	uint32_t hsh;
	uint32_t qsl_en;
	uint32_t qsl;
	uint32_t ipf_en;
	uint32_t ipf;
	uint32_t slc_en;
	uint32_t slc;
	uint32_t pdb_en;
	uint32_t pdb;
	uint32_t msk_en;
	uint32_t msk;
	uint32_t hst_en;
	uint32_t hst;
	uint32_t epp_en;
	uint32_t epp;
	uint32_t tpe_en;
	uint32_t tpe;
	uint32_t rrb_en;
	uint32_t rrb;
	uint32_t sb0_type;
	uint32_t sb0_data;
	uint32_t sb1_type;
	uint32_t sb1_data;
	uint32_t sb2_type;
	uint32_t sb2_data;
};

struct hw_mod_cat_v22_s {
	struct cat_v21_cfn_s *cfn;
	struct cat_v21_kce_s *kce; /* KCE 0/1 */
	struct cat_v21_kcs_s *kcs; /* KCS 0/1 */
	struct cat_v21_fte_s *fte; /* FTE 0/1 */
	struct cat_v22_cte_s *cte;
	struct cat_v18_cts_s *cts;
	struct cat_v18_cot_s *cot;
	struct cat_v18_cct_s *cct;
	struct cat_v18_exo_s *exo;
	struct cat_v18_rck_s *rck;
	struct cat_v18_len_s *len;
	struct cat_v18_kcc_s *kcc_cam;
	struct cat_v22_cce_s *cce;
	struct cat_v22_ccs_s *ccs;
};

#endif /* _HW_MOD_CAT_V22_H_ */

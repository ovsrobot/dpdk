/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _HW_MOD_HST_V2_H_
#define _HW_MOD_HST_V2_H_

struct hst_v2_rcp_s {
	uint32_t strip_mode;
	uint32_t start_dyn;
	uint32_t start_ofs;
	uint32_t end_dyn;
	uint32_t end_ofs;
	uint32_t modif0_cmd;
	uint32_t modif0_dyn;
	uint32_t modif0_ofs;
	uint32_t modif0_value;
	uint32_t modif1_cmd;
	uint32_t modif1_dyn;
	uint32_t modif1_ofs;
	uint32_t modif1_value;
	uint32_t modif2_cmd;
	uint32_t modif2_dyn;
	uint32_t modif2_ofs;
	uint32_t modif2_value;
};

struct hw_mod_hst_v2_s {
	struct hst_v2_rcp_s *rcp;
};

#endif /* _HW_MOD_HST_V2_H_ */

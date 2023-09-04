/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _HW_MOD_TPE_V2_H_
#define _HW_MOD_TPE_V2_H_

struct tpe_v2_rpp_v1_ifr_rcp_s {
	uint32_t en;
	uint32_t mtu;
};

struct tpe_v2_ifr_v1_rcp_s {
	uint32_t en;
	uint32_t mtu;
};

struct hw_mod_tpe_v2_s {
	struct tpe_v1_rpp_v0_rcp_s *rpp_rcp;

	struct tpe_v1_ins_v1_rcp_s *ins_rcp;

	struct tpe_v1_rpl_v2_rcp_s *rpl_rcp;
	struct tpe_v1_rpl_v2_ext_s *rpl_ext;
	struct tpe_v1_rpl_v2_rpl_s *rpl_rpl;

	struct tpe_v1_cpy_v1_rcp_s *cpy_rcp;

	struct tpe_v1_hfu_v1_rcp_s *hfu_rcp;

	struct tpe_v1_csu_v0_rcp_s *csu_rcp;

	struct tpe_v2_rpp_v1_ifr_rcp_s *rpp_ifr_rcp;
	struct tpe_v2_ifr_v1_rcp_s *ifr_rcp;
};

#endif /* _HW_MOD_TPE_V2_H_ */

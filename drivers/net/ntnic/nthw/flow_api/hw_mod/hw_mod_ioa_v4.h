/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _HW_MOD_IOA_V4_H_
#define _HW_MOD_IOA_V4_H_

struct ioa_v4_rcp_s {
	uint32_t tunnel_pop;
	uint32_t vlan_pop;
	uint32_t vlan_push;
	uint32_t vlan_vid;
	uint32_t vlan_dei;
	uint32_t vlan_pcp;
	uint32_t vlan_tpid_sel;
	uint32_t queue_override_en;
	uint32_t queue_id;
};

struct ioa_v4_special_tpid_s {
	uint32_t cust_tpid_0;
	uint32_t cust_tpid_1;
};

struct ioa_v4_roa_epp_s {
	uint32_t push_tunnel;
	uint32_t tx_port;
};

struct hw_mod_ioa_v4_s {
	struct ioa_v4_rcp_s *rcp;
	struct ioa_v4_special_tpid_s *tpid;
	struct ioa_v4_roa_epp_s *roa_epp;
};

#endif /* _HW_MOD_IOA_V4_H_ */

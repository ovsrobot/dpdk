/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _HW_MOD_ROA_V6_H_
#define _HW_MOD_ROA_V6_H_

struct roa_v6_tunhdr_s {
	uint32_t tunnel_hdr[4 * 4];
};

struct roa_v6_tuncfg_s {
	uint32_t tun_len;
	uint32_t tun_type;
	uint32_t tun_vlan;
	uint32_t ip_type;
	uint32_t ipcs_upd;
	uint32_t ipcs_precalc;
	uint32_t iptl_upd;
	uint32_t iptl_precalc;
	uint32_t vxlan_udp_len_upd;
	uint32_t tx_lag_ix;
	uint32_t recirculate;
	uint32_t push_tunnel;
	uint32_t recirc_port;
	uint32_t recirc_bypass;
};

struct roa_v6_config_s {
	uint32_t fwd_recirculate;
	uint32_t fwd_normal_pcks;
	uint32_t fwd_txport0;
	uint32_t fwd_txport1;
	uint32_t fwd_cellbuilder_pcks;
	uint32_t fwd_non_normal_pcks;
};

struct roa_v6_lagcfg_s {
	uint32_t txphy_port;
};

struct hw_mod_roa_v6_s {
	struct roa_v6_tunhdr_s *tunhdr;
	struct roa_v6_tuncfg_s *tuncfg;
	struct roa_v6_config_s *config;
	struct roa_v6_lagcfg_s *lagcfg;
};

#endif /* _HW_MOD_ROA_V6_H_ */

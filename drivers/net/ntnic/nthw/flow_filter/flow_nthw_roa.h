/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __FLOW_NTHW_ROA_H__
#define __FLOW_NTHW_ROA_H__

#include <stdint.h> /* uint32_t */
#include "nthw_fpga_model.h"

struct roa_nthw;

typedef struct roa_nthw roa_nthw_t;

struct roa_nthw *roa_nthw_new(void);
void roa_nthw_delete(struct roa_nthw *p);
int roa_nthw_init(struct roa_nthw *p, nt_fpga_t *p_fpga, int n_instance);

int roa_nthw_setup(struct roa_nthw *p, int n_idx, int n_idx_cnt);
void roa_nthw_set_debug_mode(struct roa_nthw *p, unsigned int n_debug_mode);

/* TUN HDR */
void roa_nthw_tun_hdr_select(const struct roa_nthw *p, uint32_t val);
void roa_nthw_tun_hdr_cnt(const struct roa_nthw *p, uint32_t val);

void roa_nthw_tun_hdr_tunnel_hdr(const struct roa_nthw *p, uint32_t *val);
void roa_nthw_tun_hdr_flush(const struct roa_nthw *p);

/* TUN CFG */
void roa_nthw_tun_cfg_select(const struct roa_nthw *p, uint32_t val);
void roa_nthw_tun_cfg_cnt(const struct roa_nthw *p, uint32_t val);
void roa_nthw_tun_cfg_tun_len(const struct roa_nthw *p, uint32_t val);
void roa_nthw_tun_cfg_tun_type(const struct roa_nthw *p, uint32_t val);
void roa_nthw_tun_cfg_tun_vlan(const struct roa_nthw *p, uint32_t val);
void roa_nthw_tun_cfg_ip_type(const struct roa_nthw *p, uint32_t val);
void roa_nthw_tun_cfg_ipcs_upd(const struct roa_nthw *p, uint32_t val);
void roa_nthw_tun_cfg_ipcs_precalc(const struct roa_nthw *p, uint32_t val);
void roa_nthw_tun_cfg_iptl_upd(const struct roa_nthw *p, uint32_t val);
void roa_nthw_tun_cfg_iptl_precalc(const struct roa_nthw *p, uint32_t val);
void roa_nthw_tun_cfg_vxlan_udp_len_upd(const struct roa_nthw *p, uint32_t val);
void roa_nthw_tun_cfg_tx_lag_ix(const struct roa_nthw *p, uint32_t val);
void roa_nthw_tun_cfg_recirculate(const struct roa_nthw *p, uint32_t val);
void roa_nthw_tun_cfg_push_tunnel(const struct roa_nthw *p, uint32_t val);
void roa_nthw_tun_cfg_recirc_port(const struct roa_nthw *p, uint32_t val);
void roa_nthw_tun_cfg_recirc_bypass(const struct roa_nthw *p, uint32_t val);
void roa_nthw_tun_cfg_flush(const struct roa_nthw *p);

/* ROA CONFIG */
void roa_nthw_config_fwd_recirculate(const struct roa_nthw *p, uint32_t val);
void roa_nthw_config_fwd_normal_pcks(const struct roa_nthw *p, uint32_t val);
void roa_nthw_config_fwd_tx_port0(const struct roa_nthw *p, uint32_t val);
void roa_nthw_config_fwd_tx_port1(const struct roa_nthw *p, uint32_t val);
void roa_nthw_config_fwd_cell_builder_pcks(const struct roa_nthw *p, uint32_t val);
void roa_nthw_config_fwd_non_normal_pcks(const struct roa_nthw *p, uint32_t val);
void roa_nthw_config_flush(const struct roa_nthw *p);

/* LAG */
void roa_nthw_lag_cfg_select(const struct roa_nthw *p, uint32_t val);
void roa_nthw_lag_cfg_cnt(const struct roa_nthw *p, uint32_t val);
void roa_nthw_lag_cfg_tx_phy_port(const struct roa_nthw *p, uint32_t val);
void roa_nthw_lag_cfg_flush(const struct roa_nthw *p);

struct roa_nthw {
	uint8_t m_physical_adapter_no;
	nt_fpga_t *mp_fpga;

	nt_module_t *m_roa;

	nt_register_t *mp_tun_hdr_ctrl;
	nt_field_t *mp_tun_hdr_addr;
	nt_field_t *mp_tun_hdr_cnt;
	nt_register_t *mp_tun_hdr_data;
	nt_field_t *mp_tun_hdr_data_tunnel_hdr;

	nt_register_t *mp_tun_cfg_ctrl;
	nt_field_t *mp_tun_cfg_addr;
	nt_field_t *mp_tun_cfg_cnt;
	nt_register_t *mp_tun_cfg_data;
	nt_field_t *mp_tun_cfg_data_tun_len;
	nt_field_t *mp_tun_cfg_data_tun_type;
	nt_field_t *mp_tun_cfg_data_tun_vlan;
	nt_field_t *mp_tun_cfg_data_ip_type;
	nt_field_t *mp_tun_cfg_data_ipcs_upd;
	nt_field_t *mp_tun_cfg_data_ipcs_precalc;
	nt_field_t *mp_tun_cfg_data_iptl_upd;
	nt_field_t *mp_tun_cfg_data_iptl_precalc;
	nt_field_t *mp_tun_cfg_data_vxlan_udp_len_upd;
	nt_field_t *mp_tun_cfg_data_tx_lag_ix;
	nt_field_t *mp_tun_cfg_data_recirculate;
	nt_field_t *mp_tun_cfg_data_push_tunnel;
	nt_field_t *mp_tun_cfg_data_recirc_port;
	nt_field_t *mp_tun_cfg_data_recirc_bypass;

	nt_register_t *mp_config;
	nt_field_t *mp_config_fwd_recirculate;
	nt_field_t *mp_config_fwd_normal_pcks;
	nt_field_t *mp_config_fwd_tx_port0;
	nt_field_t *mp_config_fwd_tx_port1;
	nt_field_t *mp_config_fwd_cell_builder_pcks;
	nt_field_t *mp_config_fwd_non_normal_pcks;

	nt_register_t *mp_lag_cfg_ctrl;
	nt_field_t *mp_lag_cfg_addr;
	nt_field_t *mp_lag_cfg_cnt;
	nt_register_t *mp_lag_cfg_data;
	nt_field_t *mp_lag_cfg_data_tx_phy_port;
};

#endif /* __FLOW_NTHW_ROA_H__ */

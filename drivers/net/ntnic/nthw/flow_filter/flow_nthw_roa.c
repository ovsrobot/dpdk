/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "ntlog.h"

#include "nthw_drv.h"
#include "nthw_register.h"

#include "flow_nthw_roa.h"

#include <stdlib.h> /* malloc */
#include <string.h> /* memset */

void roa_nthw_set_debug_mode(struct roa_nthw *p, unsigned int n_debug_mode)
{
	module_set_debug_mode(p->m_roa, n_debug_mode);
}

struct roa_nthw *roa_nthw_new(void)
{
	struct roa_nthw *p = malloc(sizeof(struct roa_nthw));

	if (p)
		(void)memset(p, 0, sizeof(*p));

	return p;
}

void roa_nthw_delete(struct roa_nthw *p)
{
	if (p) {
		(void)memset(p, 0, sizeof(*p));
		free(p);
	}
}

int roa_nthw_init(struct roa_nthw *p, nt_fpga_t *p_fpga, int n_instance)
{
	const char *const p_adapter_id_str = p_fpga->p_fpga_info->mp_adapter_id_str;
	nt_module_t *p_mod = fpga_query_module(p_fpga, MOD_ROA, n_instance);

	assert(n_instance >= 0 && n_instance < 256);

	if (p == NULL)
		return p_mod == NULL ? -1 : 0;

	if (p_mod == NULL) {
		NT_LOG(ERR, NTHW, "%s: ROA %d: no such instance\n",
		       p_adapter_id_str, n_instance);
		return -1;
	}

	p->mp_fpga = p_fpga;
	p->m_physical_adapter_no = (uint8_t)n_instance;
	p->m_roa = p_mod;

	/* TUN HDR */
	p->mp_tun_hdr_ctrl = module_get_register(p->m_roa, ROA_TUNHDR_CTRL);
	p->mp_tun_hdr_addr =
		register_get_field(p->mp_tun_hdr_ctrl, ROA_TUNHDR_CTRL_ADR);
	p->mp_tun_hdr_cnt =
		register_get_field(p->mp_tun_hdr_ctrl, ROA_TUNHDR_CTRL_CNT);
	p->mp_tun_hdr_data = module_get_register(p->m_roa, ROA_TUNHDR_DATA);
	p->mp_tun_hdr_data_tunnel_hdr =
		register_get_field(p->mp_tun_hdr_data, ROA_TUNHDR_DATA_TUNNEL_HDR);
	/* TUN CFG */
	p->mp_tun_cfg_ctrl = module_get_register(p->m_roa, ROA_TUNCFG_CTRL);
	p->mp_tun_cfg_addr =
		register_get_field(p->mp_tun_cfg_ctrl, ROA_TUNCFG_CTRL_ADR);
	p->mp_tun_cfg_cnt =
		register_get_field(p->mp_tun_cfg_ctrl, ROA_TUNCFG_CTRL_CNT);
	p->mp_tun_cfg_data = module_get_register(p->m_roa, ROA_TUNCFG_DATA);
	p->mp_tun_cfg_data_tun_len =
		register_get_field(p->mp_tun_cfg_data, ROA_TUNCFG_DATA_TUN_LEN);
	p->mp_tun_cfg_data_tun_type =
		register_get_field(p->mp_tun_cfg_data, ROA_TUNCFG_DATA_TUN_TYPE);
	p->mp_tun_cfg_data_tun_vlan =
		register_get_field(p->mp_tun_cfg_data, ROA_TUNCFG_DATA_TUN_VLAN);
	p->mp_tun_cfg_data_ip_type =
		register_get_field(p->mp_tun_cfg_data, ROA_TUNCFG_DATA_TUN_IP_TYPE);
	p->mp_tun_cfg_data_ipcs_upd =
		register_get_field(p->mp_tun_cfg_data, ROA_TUNCFG_DATA_TUN_IPCS_UPD);
	p->mp_tun_cfg_data_ipcs_precalc =
		register_get_field(p->mp_tun_cfg_data, ROA_TUNCFG_DATA_TUN_IPCS_PRECALC);
	p->mp_tun_cfg_data_iptl_upd =
		register_get_field(p->mp_tun_cfg_data, ROA_TUNCFG_DATA_TUN_IPTL_UPD);
	p->mp_tun_cfg_data_iptl_precalc =
		register_get_field(p->mp_tun_cfg_data, ROA_TUNCFG_DATA_TUN_IPTL_PRECALC);
	p->mp_tun_cfg_data_vxlan_udp_len_upd =
		register_get_field(p->mp_tun_cfg_data, ROA_TUNCFG_DATA_TUN_VXLAN_UDP_LEN_UPD);
	p->mp_tun_cfg_data_tx_lag_ix =
		register_get_field(p->mp_tun_cfg_data, ROA_TUNCFG_DATA_TX_LAG_IX);
	p->mp_tun_cfg_data_recirculate =
		register_get_field(p->mp_tun_cfg_data, ROA_TUNCFG_DATA_RECIRCULATE);
	p->mp_tun_cfg_data_push_tunnel =
		register_get_field(p->mp_tun_cfg_data, ROA_TUNCFG_DATA_PUSH_TUNNEL);
	p->mp_tun_cfg_data_recirc_port =
		register_get_field(p->mp_tun_cfg_data, ROA_TUNCFG_DATA_RECIRC_PORT);
	p->mp_tun_cfg_data_recirc_bypass =
		register_get_field(p->mp_tun_cfg_data, ROA_TUNCFG_DATA_RECIRC_BYPASS);
	/* CONFIG */
	p->mp_config = module_get_register(p->m_roa, ROA_CONFIG);
	p->mp_config_fwd_recirculate =
		register_get_field(p->mp_config, ROA_CONFIG_FWD_RECIRCULATE);
	p->mp_config_fwd_normal_pcks =
		register_get_field(p->mp_config, ROA_CONFIG_FWD_NORMAL_PCKS);
	p->mp_config_fwd_tx_port0 =
		register_get_field(p->mp_config, ROA_CONFIG_FWD_TXPORT0);
	p->mp_config_fwd_tx_port1 =
		register_get_field(p->mp_config, ROA_CONFIG_FWD_TXPORT1);
	p->mp_config_fwd_cell_builder_pcks =
		register_get_field(p->mp_config, ROA_CONFIG_FWD_CELLBUILDER_PCKS);
	p->mp_config_fwd_non_normal_pcks =
		register_get_field(p->mp_config, ROA_CONFIG_FWD_NON_NORMAL_PCKS);
	/* LAG */
	p->mp_lag_cfg_ctrl = module_get_register(p->m_roa, ROA_LAGCFG_CTRL);
	p->mp_lag_cfg_addr =
		register_get_field(p->mp_lag_cfg_ctrl, ROA_LAGCFG_CTRL_ADR);
	p->mp_lag_cfg_cnt =
		register_get_field(p->mp_lag_cfg_ctrl, ROA_LAGCFG_CTRL_CNT);
	p->mp_lag_cfg_data = module_get_register(p->m_roa, ROA_LAGCFG_DATA);
	p->mp_lag_cfg_data_tx_phy_port =
		register_get_field(p->mp_lag_cfg_data, ROA_LAGCFG_DATA_TXPHY_PORT);

	return 0;
}

/* TUN HDR */
void roa_nthw_tun_hdr_select(const struct roa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_tun_hdr_addr, val);
}

void roa_nthw_tun_hdr_cnt(const struct roa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_tun_hdr_cnt, val);
}

void roa_nthw_tun_hdr_tunnel_hdr(const struct roa_nthw *p, uint32_t *val)
{
	field_set_val(p->mp_tun_hdr_data_tunnel_hdr, val, 4);
}

void roa_nthw_tun_hdr_flush(const struct roa_nthw *p)
{
	register_flush(p->mp_tun_hdr_ctrl, 1);
	register_flush(p->mp_tun_hdr_data, 1);
}

/* TUN CFG */
void roa_nthw_tun_cfg_select(const struct roa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_tun_cfg_addr, val);
}

void roa_nthw_tun_cfg_cnt(const struct roa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_tun_cfg_cnt, val);
}

void roa_nthw_tun_cfg_tun_len(const struct roa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_tun_cfg_data_tun_len, val);
}

void roa_nthw_tun_cfg_tun_type(const struct roa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_tun_cfg_data_tun_type, val);
}

void roa_nthw_tun_cfg_tun_vlan(const struct roa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_tun_cfg_data_tun_vlan, val);
}

void roa_nthw_tun_cfg_ip_type(const struct roa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_tun_cfg_data_ip_type, val);
}

void roa_nthw_tun_cfg_ipcs_upd(const struct roa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_tun_cfg_data_ipcs_upd, val);
}

void roa_nthw_tun_cfg_ipcs_precalc(const struct roa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_tun_cfg_data_ipcs_precalc, val);
}

void roa_nthw_tun_cfg_iptl_upd(const struct roa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_tun_cfg_data_iptl_upd, val);
}

void roa_nthw_tun_cfg_iptl_precalc(const struct roa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_tun_cfg_data_iptl_precalc, val);
}

void roa_nthw_tun_cfg_vxlan_udp_len_upd(const struct roa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_tun_cfg_data_vxlan_udp_len_upd, val);
}

void roa_nthw_tun_cfg_tx_lag_ix(const struct roa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_tun_cfg_data_tx_lag_ix, val);
};

void roa_nthw_tun_cfg_recirculate(const struct roa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_tun_cfg_data_recirculate, val);
}

void roa_nthw_tun_cfg_push_tunnel(const struct roa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_tun_cfg_data_push_tunnel, val);
}

void roa_nthw_tun_cfg_recirc_port(const struct roa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_tun_cfg_data_recirc_port, val);
}

void roa_nthw_tun_cfg_recirc_bypass(const struct roa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_tun_cfg_data_recirc_bypass, val);
}

void roa_nthw_tun_cfg_flush(const struct roa_nthw *p)
{
	register_flush(p->mp_tun_cfg_ctrl, 1);
	register_flush(p->mp_tun_cfg_data, 1);
}

/* ROA CONFIG */
void roa_nthw_config_fwd_recirculate(const struct roa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_config_fwd_recirculate, val);
}

void roa_nthw_config_fwd_normal_pcks(const struct roa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_config_fwd_normal_pcks, val);
}

void roa_nthw_config_fwd_tx_port0(const struct roa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_config_fwd_tx_port0, val);
}

void roa_nthw_config_fwd_tx_port1(const struct roa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_config_fwd_tx_port1, val);
}

void roa_nthw_config_fwd_cell_builder_pcks(const struct roa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_config_fwd_cell_builder_pcks, val);
}

void roa_nthw_config_fwd_non_normal_pcks(const struct roa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_config_fwd_non_normal_pcks, val);
}

void roa_nthw_config_flush(const struct roa_nthw *p)
{
	register_flush(p->mp_config, 1);
}

/* LAG */
void roa_nthw_lag_cfg_select(const struct roa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_lag_cfg_addr, val);
}

void roa_nthw_lag_cfg_cnt(const struct roa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_lag_cfg_cnt, val);
}

void roa_nthw_lag_cfg_tx_phy_port(const struct roa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_lag_cfg_data_tx_phy_port, val);
}

void roa_nthw_lag_cfg_flush(const struct roa_nthw *p)
{
	register_flush(p->mp_lag_cfg_ctrl, 1);
	register_flush(p->mp_lag_cfg_data, 1);
}

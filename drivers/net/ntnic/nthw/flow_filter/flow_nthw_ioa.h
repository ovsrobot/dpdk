/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __FLOW_NTHW_IOA_H__
#define __FLOW_NTHW_IOA_H__

#include "nthw_fpga_model.h"

#include <stdint.h> /* uint32_t */

struct ioa_nthw {
	uint8_t m_physical_adapter_no;
	nt_fpga_t *mp_fpga;

	nt_module_t *m_ioa;

	nt_register_t *mp_rcp_ctrl;
	nt_field_t *mp_rcp_addr;
	nt_field_t *mp_rcp_cnt;
	nt_register_t *mp_rcp_data;

	nt_field_t *mp_rcp_data_tunnel_pop;
	nt_field_t *mp_rcp_data_vlan_pop;
	nt_field_t *mp_rcp_data_vlan_push;
	nt_field_t *mp_rcp_data_vlan_vid;
	nt_field_t *mp_rcp_data_vlan_dei;
	nt_field_t *mp_rcp_data_vlan_pcp;
	nt_field_t *mp_rcp_data_vlan_tpid_sel;
	nt_field_t *mp_rcp_data_queue_override_en;
	nt_field_t *mp_rcp_data_queue_id;

	nt_register_t *mp_special;
	nt_field_t *mp_special_vlan_tpid_cust_tpid0;
	nt_field_t *mp_special_vlan_tpid_cust_tpid1;

	nt_register_t *mp_roa_epp_ctrl;
	nt_field_t *mp_roa_epp_addr;
	nt_field_t *mp_roa_epp_cnt;
	nt_register_t *mp_roa_epp_data;
	nt_field_t *mp_roa_epp_data_push_tunnel;
	nt_field_t *mp_roa_epp_data_tx_port;
};

typedef struct ioa_nthw ioa_nthw_t;

struct ioa_nthw *ioa_nthw_new(void);
void ioa_nthw_delete(struct ioa_nthw *p);
int ioa_nthw_init(struct ioa_nthw *p, nt_fpga_t *p_fpga, int n_instance);

int ioa_nthw_setup(struct ioa_nthw *p, int n_idx, int n_idx_cnt);
void ioa_nthw_set_debug_mode(struct ioa_nthw *p, unsigned int n_debug_mode);

/* RCP */
void ioa_nthw_rcp_select(const struct ioa_nthw *p, uint32_t val);
void ioa_nthw_rcp_cnt(const struct ioa_nthw *p, uint32_t val);
void ioa_nthw_rcp_tunnel_pop(const struct ioa_nthw *p, uint32_t val);
void ioa_nthw_rcp_vlan_pop(const struct ioa_nthw *p, uint32_t val);
void ioa_nthw_rcp_vlan_push(const struct ioa_nthw *p, uint32_t val);
void ioa_nthw_rcp_vlan_vid(const struct ioa_nthw *p, uint32_t val);
void ioa_nthw_rcp_vlan_dei(const struct ioa_nthw *p, uint32_t val);
void ioa_nthw_rcp_vlan_pcp(const struct ioa_nthw *p, uint32_t val);
void ioa_nthw_rcp_vlan_tpid_sel(const struct ioa_nthw *p, uint32_t val);
void ioa_nthw_rcp_queue_override_en(const struct ioa_nthw *p, uint32_t val);
void ioa_nthw_rcp_queue_id(const struct ioa_nthw *p, uint32_t val);
void ioa_nthw_rcp_flush(const struct ioa_nthw *p);

/* Vlan Tpid Special */
void ioa_nthw_special_vlan_tpid_cust_tpid0(const struct ioa_nthw *p, uint32_t val);
void ioa_nthw_special_vlan_tpid_cust_tpid1(const struct ioa_nthw *p, uint32_t val);
void ioa_nthw_special_vlan_tpid_flush(const struct ioa_nthw *p);

/* EPP module */
void ioa_nthw_roa_epp_select(const struct ioa_nthw *p, uint32_t val);
void ioa_nthw_roa_epp_cnt(const struct ioa_nthw *p, uint32_t val);
void ioa_nthw_roa_epp_push_tunnel(const struct ioa_nthw *p, uint32_t val);
void ioa_nthw_roa_epp_tx_port(const struct ioa_nthw *p, uint32_t val);
void ioa_nthw_roa_epp_flush(const struct ioa_nthw *p);

#endif /* __FLOW_NTHW_IOA_H__ */

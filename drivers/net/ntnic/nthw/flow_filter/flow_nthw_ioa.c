/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "ntlog.h"

#include "nthw_drv.h"
#include "nthw_register.h"

#include "flow_nthw_ioa.h"

#include <stdlib.h> /* malloc */
#include <string.h> /* memset */

void ioa_nthw_set_debug_mode(struct ioa_nthw *p, unsigned int n_debug_mode)
{
	module_set_debug_mode(p->m_ioa, n_debug_mode);
}

struct ioa_nthw *ioa_nthw_new(void)
{
	struct ioa_nthw *p = malloc(sizeof(struct ioa_nthw));

	if (p)
		(void)memset(p, 0, sizeof(*p));

	return p;
}

void ioa_nthw_delete(struct ioa_nthw *p)
{
	if (p) {
		(void)memset(p, 0, sizeof(*p));
		free(p);
	}
}

int ioa_nthw_init(struct ioa_nthw *p, nt_fpga_t *p_fpga, int n_instance)
{
	const char *const p_adapter_id_str = p_fpga->p_fpga_info->mp_adapter_id_str;
	nt_module_t *p_mod = fpga_query_module(p_fpga, MOD_IOA, n_instance);

	assert(n_instance >= 0 && n_instance < 256);

	if (p == NULL)
		return p_mod == NULL ? -1 : 0;

	if (p_mod == NULL) {
		NT_LOG(ERR, NTHW, "%s: Ioa %d: no such instance\n",
		       p_adapter_id_str, n_instance);
		return -1;
	}

	p->mp_fpga = p_fpga;
	p->m_physical_adapter_no = (uint8_t)n_instance;
	p->m_ioa = p_mod;

	/* RCP */
	p->mp_rcp_ctrl = module_get_register(p->m_ioa, IOA_RECIPE_CTRL);
	p->mp_rcp_addr = register_get_field(p->mp_rcp_ctrl, IOA_RECIPE_CTRL_ADR);
	p->mp_rcp_cnt = register_get_field(p->mp_rcp_ctrl, IOA_RECIPE_CTRL_CNT);
	p->mp_rcp_data = module_get_register(p->m_ioa, IOA_RECIPE_DATA);
	p->mp_rcp_data_tunnel_pop =
		register_get_field(p->mp_rcp_data, IOA_RECIPE_DATA_TUNNEL_POP);
	p->mp_rcp_data_vlan_pop =
		register_get_field(p->mp_rcp_data, IOA_RECIPE_DATA_VLAN_POP);
	p->mp_rcp_data_vlan_push =
		register_get_field(p->mp_rcp_data, IOA_RECIPE_DATA_VLAN_PUSH);
	p->mp_rcp_data_vlan_vid =
		register_get_field(p->mp_rcp_data, IOA_RECIPE_DATA_VLAN_VID);
	p->mp_rcp_data_vlan_dei =
		register_get_field(p->mp_rcp_data, IOA_RECIPE_DATA_VLAN_DEI);
	p->mp_rcp_data_vlan_pcp =
		register_get_field(p->mp_rcp_data, IOA_RECIPE_DATA_VLAN_PCP);
	p->mp_rcp_data_vlan_tpid_sel =
		register_get_field(p->mp_rcp_data, IOA_RECIPE_DATA_VLAN_TPID_SEL);
	p->mp_rcp_data_queue_override_en =
		register_get_field(p->mp_rcp_data, IOA_RECIPE_DATA_QUEUE_OVERRIDE_EN);
	p->mp_rcp_data_queue_id =
		register_get_field(p->mp_rcp_data, IOA_RECIPE_DATA_QUEUE_ID);

	/* Special Vlan Tpid */
	p->mp_special = module_get_register(p->m_ioa, IOA_VLAN_TPID_SPECIAL);
	p->mp_special_vlan_tpid_cust_tpid0 =
		register_get_field(p->mp_special, IOA_VLAN_TPID_SPECIAL_CUSTTPID0);
	p->mp_special_vlan_tpid_cust_tpid1 =
		register_get_field(p->mp_special, IOA_VLAN_TPID_SPECIAL_CUSTTPID1);
	{
		/*
		 * This extension in IOA is a messy way FPGA have chosen to
		 * put control bits for EPP module in IOA. It is accepted as
		 * we are going towards exchange IOA and ROA modules later
		 * to get higher scalability in future.
		 */
		p->mp_roa_epp_ctrl =
			module_query_register(p->m_ioa, IOA_ROA_EPP_CTRL);
		if (p->mp_roa_epp_ctrl) {
			p->mp_roa_epp_addr =
				register_get_field(p->mp_roa_epp_ctrl,
						   IOA_ROA_EPP_CTRL_ADR);
			p->mp_roa_epp_cnt =
				register_get_field(p->mp_roa_epp_ctrl,
						   IOA_ROA_EPP_CTRL_CNT);
		} else {
			p->mp_roa_epp_addr = NULL;
			p->mp_roa_epp_cnt = NULL;
		}

		p->mp_roa_epp_data =
			module_query_register(p->m_ioa, IOA_ROA_EPP_DATA);
		if (p->mp_roa_epp_data) {
			p->mp_roa_epp_data_push_tunnel =
				register_get_field(p->mp_roa_epp_data,
						   IOA_ROA_EPP_DATA_PUSH_TUNNEL);
			p->mp_roa_epp_data_tx_port =
				register_get_field(p->mp_roa_epp_data,
						   IOA_ROA_EPP_DATA_TX_PORT);
		} else {
			p->mp_roa_epp_data_push_tunnel = NULL;
			p->mp_roa_epp_data_tx_port = NULL;
		}
	}
	return 0;
}

/* RCP */
void ioa_nthw_rcp_select(const struct ioa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_addr, val);
}

void ioa_nthw_rcp_cnt(const struct ioa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_cnt, val);
}

void ioa_nthw_rcp_tunnel_pop(const struct ioa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_tunnel_pop, val);
}

void ioa_nthw_rcp_vlan_pop(const struct ioa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_vlan_pop, val);
}

void ioa_nthw_rcp_vlan_push(const struct ioa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_vlan_push, val);
}

void ioa_nthw_rcp_vlan_vid(const struct ioa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_vlan_vid, val);
}

void ioa_nthw_rcp_vlan_dei(const struct ioa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_vlan_dei, val);
}

void ioa_nthw_rcp_vlan_pcp(const struct ioa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_vlan_pcp, val);
}

void ioa_nthw_rcp_vlan_tpid_sel(const struct ioa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_vlan_tpid_sel, val);
}

void ioa_nthw_rcp_queue_override_en(const struct ioa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_queue_override_en, val);
}

void ioa_nthw_rcp_queue_id(const struct ioa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_queue_id, val);
}

void ioa_nthw_rcp_flush(const struct ioa_nthw *p)
{
	register_flush(p->mp_rcp_ctrl, 1);
	register_flush(p->mp_rcp_data, 1);
}

/* Vlan Tpid Special */
void ioa_nthw_special_vlan_tpid_cust_tpid0(const struct ioa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_special_vlan_tpid_cust_tpid0, val);
}

void ioa_nthw_special_vlan_tpid_cust_tpid1(const struct ioa_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_special_vlan_tpid_cust_tpid1, val);
}

void ioa_nthw_special_vlan_tpid_flush(const struct ioa_nthw *p)
{
	register_flush(p->mp_special, 1);
}

void ioa_nthw_roa_epp_select(const struct ioa_nthw *p, uint32_t val)
{
	if (p->mp_roa_epp_addr)
		field_set_val32(p->mp_roa_epp_addr, val);
}

void ioa_nthw_roa_epp_cnt(const struct ioa_nthw *p, uint32_t val)
{
	if (p->mp_roa_epp_cnt)
		field_set_val32(p->mp_roa_epp_cnt, val);
}

void ioa_nthw_roa_epp_push_tunnel(const struct ioa_nthw *p, uint32_t val)
{
	if (p->mp_roa_epp_data_push_tunnel)
		field_set_val32(p->mp_roa_epp_data_push_tunnel, val);
}

void ioa_nthw_roa_epp_tx_port(const struct ioa_nthw *p, uint32_t val)
{
	if (p->mp_roa_epp_data_tx_port)
		field_set_val32(p->mp_roa_epp_data_tx_port, val);
}

void ioa_nthw_roa_epp_flush(const struct ioa_nthw *p)
{
	if (p->mp_roa_epp_ctrl)
		register_flush(p->mp_roa_epp_ctrl, 1);
	if (p->mp_roa_epp_data)
		register_flush(p->mp_roa_epp_data, 1);
}

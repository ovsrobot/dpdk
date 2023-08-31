/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "ntlog.h"
#include "nthw_drv.h"
#include "nthw_register.h"

#include "flow_nthw_ifr.h"

void ifr_nthw_set_debug_mode(struct ifr_nthw *p, unsigned int n_debug_mode)
{
	module_set_debug_mode(p->m_ifr, n_debug_mode);
}

struct ifr_nthw *ifr_nthw_new(void)
{
	struct ifr_nthw *p = malloc(sizeof(struct ifr_nthw));

	if (p)
		(void)memset(p, 0, sizeof(*p));
	return p;
}

void ifr_nthw_delete(struct ifr_nthw *p)
{
	if (p) {
		(void)memset(p, 0, sizeof(*p));
		free(p);
	}
}

int ifr_nthw_init(struct ifr_nthw *p, nt_fpga_t *p_fpga, int n_instance)
{
	const char *const p_adapter_id_str = p_fpga->p_fpga_info->mp_adapter_id_str;
	nt_module_t *p_mod = fpga_query_module(p_fpga, MOD_IFR, n_instance);

	assert(n_instance >= 0 && n_instance < 256);

	if (p == NULL)
		return p_mod == NULL ? -1 : 0;

	if (p_mod == NULL) {
		NT_LOG(ERR, NTHW, "%s: Ifr %d: no such instance\n",
		       p_adapter_id_str, n_instance);
		return -1;
	}

	p->mp_fpga = p_fpga;
	p->m_physical_adapter_no = (uint8_t)n_instance;
	p->m_ifr = fpga_query_module(p_fpga, MOD_IFR, n_instance);

	p->mp_rcp_ctrl = module_get_register(p->m_ifr, IFR_RCP_CTRL);
	p->mp_rcp_addr = register_get_field(p->mp_rcp_ctrl, IFR_RCP_CTRL_ADR);
	p->mp_rcp_cnt = register_get_field(p->mp_rcp_ctrl, IFR_RCP_CTRL_CNT);
	p->mp_rcp_data = module_get_register(p->m_ifr, IFR_RCP_DATA);
	p->mp_rcp_data_en = register_get_field(p->mp_rcp_data, IFR_RCP_DATA_EN);
	p->mp_rcp_data_mtu = register_get_field(p->mp_rcp_data, IFR_RCP_DATA_MTU);

	return 0;
}

void ifr_nthw_rcp_select(const struct ifr_nthw *p, uint32_t val)
{
	assert(p->mp_rcp_addr);
	field_set_val32(p->mp_rcp_addr, val);
}

void ifr_nthw_rcp_cnt(const struct ifr_nthw *p, uint32_t val)
{
	assert(p->mp_rcp_cnt);
	field_set_val32(p->mp_rcp_cnt, val);
}

void ifr_nthw_rcp_en(const struct ifr_nthw *p, uint32_t val)
{
	assert(p->mp_rcp_data_en);
	field_set_val32(p->mp_rcp_data_en, val);
}

void ifr_nthw_rcp_mtu(const struct ifr_nthw *p, uint32_t val)
{
	assert(p->mp_rcp_data_en);
	field_set_val32(p->mp_rcp_data_mtu, val);
}

void ifr_nthw_rcp_flush(const struct ifr_nthw *p)
{
	assert(p->mp_rcp_ctrl);
	assert(p->mp_rcp_data);
	register_flush(p->mp_rcp_ctrl, 1);
	register_flush(p->mp_rcp_data, 1);
}

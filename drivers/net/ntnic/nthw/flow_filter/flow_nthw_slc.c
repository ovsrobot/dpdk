/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "ntlog.h"

#include "nthw_drv.h"
#include "nthw_register.h"

#include "flow_nthw_slc.h"

#include <stdlib.h> /* malloc */
#include <string.h> /* memset */

void slc_nthw_set_debug_mode(struct slc_nthw *p, unsigned int n_debug_mode)
{
	module_set_debug_mode(p->m_slc, n_debug_mode);
}

struct slc_nthw *slc_nthw_new(void)
{
	struct slc_nthw *p = malloc(sizeof(struct slc_nthw));

	if (p)
		(void)memset(p, 0, sizeof(*p));

	return p;
}

void slc_nthw_delete(struct slc_nthw *p)
{
	if (p) {
		(void)memset(p, 0, sizeof(*p));
		free(p);
	}
}

int slc_nthw_init(struct slc_nthw *p, nt_fpga_t *p_fpga, int n_instance)
{
	const char *const p_adapter_id_str = p_fpga->p_fpga_info->mp_adapter_id_str;
	nt_module_t *p_mod = fpga_query_module(p_fpga, MOD_SLC, n_instance);

	assert(n_instance >= 0 && n_instance < 256);

	if (p == NULL)
		return p_mod == NULL ? -1 : 0;

	if (p_mod == NULL) {
		NT_LOG(ERR, NTHW, "%s: Slc %d: no such instance\n",
		       p_adapter_id_str, n_instance);
		return -1;
	}

	p->mp_fpga = p_fpga;
	p->m_physical_adapter_no = (uint8_t)n_instance;
	p->m_slc = fpga_query_module(p_fpga, MOD_SLC, n_instance);

	/* RCP */
	p->mp_rcp_ctrl = module_get_register(p->m_slc, SLC_RCP_CTRL);
	p->mp_rcp_addr = register_get_field(p->mp_rcp_ctrl, SLC_RCP_CTRL_ADR);
	p->mp_rcp_cnt = register_get_field(p->mp_rcp_ctrl, SLC_RCP_CTRL_CNT);
	p->mp_rcp_data = module_get_register(p->m_slc, SLC_RCP_DATA);
	p->mp_rcp_data_tail_slc_en =
		register_get_field(p->mp_rcp_data, SLC_RCP_DATA_TAIL_SLC_EN);
	p->mp_rcp_data_tail_dyn =
		register_get_field(p->mp_rcp_data, SLC_RCP_DATA_TAIL_DYN);
	p->mp_rcp_data_tail_ofs =
		register_get_field(p->mp_rcp_data, SLC_RCP_DATA_TAIL_OFS);
	p->mp_rcp_data_pcap = register_get_field(p->mp_rcp_data, SLC_RCP_DATA_PCAP);

	return 0;
}

/* RCP */
void slc_nthw_rcp_select(const struct slc_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_addr, val);
}

void slc_nthw_rcp_cnt(const struct slc_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_cnt, val);
}

void slc_nthw_rcp_tail_slc_en(const struct slc_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_tail_slc_en, val);
}

void slc_nthw_rcp_tail_dyn(const struct slc_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_tail_dyn, val);
}

void slc_nthw_rcp_tail_ofs(const struct slc_nthw *p, int32_t val)
{
	field_set_val32(p->mp_rcp_data_tail_ofs, val);
}

void slc_nthw_rcp_pcap(const struct slc_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_pcap, val);
}

void slc_nthw_rcp_flush(const struct slc_nthw *p)
{
	register_flush(p->mp_rcp_ctrl, 1);
	register_flush(p->mp_rcp_data, 1);
}

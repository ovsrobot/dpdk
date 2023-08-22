/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "ntlog.h"

#include "nthw_drv.h"
#include "nthw_register.h"

#include "flow_nthw_hst.h"

#include <stdlib.h> /* malloc */
#include <string.h> /* memset */

void hst_nthw_set_debug_mode(struct hst_nthw *p, unsigned int n_debug_mode)
{
	module_set_debug_mode(p->m_hst, n_debug_mode);
}

struct hst_nthw *hst_nthw_new(void)
{
	struct hst_nthw *p = malloc(sizeof(struct hst_nthw));

	if (p)
		(void)memset(p, 0, sizeof(*p));

	return p;
}

void hst_nthw_delete(struct hst_nthw *p)
{
	if (p) {
		(void)memset(p, 0, sizeof(*p));
		free(p);
	}
}

int hst_nthw_init(struct hst_nthw *p, nt_fpga_t *p_fpga, int n_instance)
{
	const char *const p_adapter_id_str = p_fpga->p_fpga_info->mp_adapter_id_str;
	nt_module_t *p_mod = fpga_query_module(p_fpga, MOD_HST, n_instance);

	assert(n_instance >= 0 && n_instance < 256);

	if (p == NULL)
		return p_mod == NULL ? -1 : 0;

	if (p_mod == NULL) {
		NT_LOG(ERR, NTHW, "%s: Hst %d: no such instance\n",
		       p_adapter_id_str, n_instance);
		return -1;
	}

	p->mp_fpga = p_fpga;
	p->m_physical_adapter_no = (uint8_t)n_instance;
	p->m_hst = p_mod;

	/* RCP */
	p->mp_rcp_ctrl = module_get_register(p->m_hst, HST_RCP_CTRL);
	p->mp_rcp_addr = register_get_field(p->mp_rcp_ctrl, HST_RCP_CTRL_ADR);
	p->mp_rcp_cnt = register_get_field(p->mp_rcp_ctrl, HST_RCP_CTRL_CNT);

	p->mp_rcp_data = module_get_register(p->m_hst, HST_RCP_DATA);
	p->mp_rcp_data_strip_mode =
		register_get_field(p->mp_rcp_data, HST_RCP_DATA_STRIP_MODE);
	p->mp_rcp_data_start_dyn =
		register_get_field(p->mp_rcp_data, HST_RCP_DATA_START_DYN);
	p->mp_rcp_data_start_ofs =
		register_get_field(p->mp_rcp_data, HST_RCP_DATA_START_OFS);
	p->mp_rcp_data_end_dyn =
		register_get_field(p->mp_rcp_data, HST_RCP_DATA_END_DYN);
	p->mp_rcp_data_end_ofs =
		register_get_field(p->mp_rcp_data, HST_RCP_DATA_END_OFS);
	p->mp_rcp_data_modif0_cmd =
		register_get_field(p->mp_rcp_data, HST_RCP_DATA_MODIF0_CMD);
	p->mp_rcp_data_modif0_dyn =
		register_get_field(p->mp_rcp_data, HST_RCP_DATA_MODIF0_DYN);
	p->mp_rcp_data_modif0_ofs =
		register_get_field(p->mp_rcp_data, HST_RCP_DATA_MODIF0_OFS);
	p->mp_rcp_data_modif0_value =
		register_get_field(p->mp_rcp_data, HST_RCP_DATA_MODIF0_VALUE);
	p->mp_rcp_data_modif1_cmd =
		register_get_field(p->mp_rcp_data, HST_RCP_DATA_MODIF1_CMD);
	p->mp_rcp_data_modif1_dyn =
		register_get_field(p->mp_rcp_data, HST_RCP_DATA_MODIF1_DYN);
	p->mp_rcp_data_modif1_ofs =
		register_get_field(p->mp_rcp_data, HST_RCP_DATA_MODIF1_OFS);
	p->mp_rcp_data_modif1_value =
		register_get_field(p->mp_rcp_data, HST_RCP_DATA_MODIF1_VALUE);
	p->mp_rcp_data_modif2_cmd =
		register_get_field(p->mp_rcp_data, HST_RCP_DATA_MODIF2_CMD);
	p->mp_rcp_data_modif2_dyn =
		register_get_field(p->mp_rcp_data, HST_RCP_DATA_MODIF2_DYN);
	p->mp_rcp_data_modif2_ofs =
		register_get_field(p->mp_rcp_data, HST_RCP_DATA_MODIF2_OFS);
	p->mp_rcp_data_modif2_value =
		register_get_field(p->mp_rcp_data, HST_RCP_DATA_MODIF2_VALUE);

	return 0;
}

/* RCP */
void hst_nthw_rcp_select(const struct hst_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_addr, val);
}

void hst_nthw_rcp_cnt(const struct hst_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_cnt, val);
}

void hst_nthw_rcp_strip_mode(const struct hst_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_strip_mode, val);
}

void hst_nthw_rcp_start_dyn(const struct hst_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_start_dyn, val);
}

void hst_nthw_rcp_start_ofs(const struct hst_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_start_ofs, val);
}

void hst_nthw_rcp_end_dyn(const struct hst_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_end_dyn, val);
}

void hst_nthw_rcp_end_ofs(const struct hst_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_end_ofs, val);
}

void hst_nthw_rcp_modif0_cmd(const struct hst_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_modif0_cmd, val);
}

void hst_nthw_rcp_modif0_dyn(const struct hst_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_modif0_dyn, val);
}

void hst_nthw_rcp_modif0_ofs(const struct hst_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_modif0_ofs, val);
}

void hst_nthw_rcp_modif0_value(const struct hst_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_modif0_value, val);
}

void hst_nthw_rcp_modif1_cmd(const struct hst_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_modif1_cmd, val);
}

void hst_nthw_rcp_modif1_dyn(const struct hst_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_modif1_dyn, val);
}

void hst_nthw_rcp_modif1_ofs(const struct hst_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_modif1_ofs, val);
}

void hst_nthw_rcp_modif1_value(const struct hst_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_modif1_value, val);
}

void hst_nthw_rcp_modif2_cmd(const struct hst_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_modif2_cmd, val);
}

void hst_nthw_rcp_modif2_dyn(const struct hst_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_modif2_dyn, val);
}

void hst_nthw_rcp_modif2_ofs(const struct hst_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_modif2_ofs, val);
}

void hst_nthw_rcp_modif2_value(const struct hst_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_modif2_value, val);
}

void hst_nthw_rcp_flush(const struct hst_nthw *p)
{
	register_flush(p->mp_rcp_ctrl, 1);
	register_flush(p->mp_rcp_data, 1);
}

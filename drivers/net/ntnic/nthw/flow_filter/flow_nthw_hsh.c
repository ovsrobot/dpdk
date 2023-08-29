/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "ntlog.h"

#include "nthw_drv.h"
#include "nthw_register.h"

#include "flow_nthw_hsh.h"

#include <stdlib.h> /* malloc */
#include <string.h> /* memset */

void hsh_nthw_set_debug_mode(struct hsh_nthw *p, unsigned int n_debug_mode)
{
	module_set_debug_mode(p->m_hsh, n_debug_mode);
}

struct hsh_nthw *hsh_nthw_new(void)
{
	struct hsh_nthw *p = malloc(sizeof(struct hsh_nthw));

	if (p)
		(void)memset(p, 0, sizeof(*p));

	return p;
}

void hsh_nthw_delete(struct hsh_nthw *p)
{
	if (p) {
		(void)memset(p, 0, sizeof(*p));
		free(p);
	}
}

int hsh_nthw_init(struct hsh_nthw *p, nt_fpga_t *p_fpga, int n_instance)
{
	const char *const p_adapter_id_str = p_fpga->p_fpga_info->mp_adapter_id_str;
	nt_module_t *p_mod = fpga_query_module(p_fpga, MOD_HSH, n_instance);

	assert(n_instance >= 0 && n_instance < 256);

	if (p == NULL)
		return p_mod == NULL ? -1 : 0;

	if (p_mod == NULL) {
		NT_LOG(ERR, NTHW, "%s: Hsh %d: no such instance\n",
		       p_adapter_id_str, n_instance);
		return -1;
	}

	p->mp_fpga = p_fpga;
	p->m_physical_adapter_no = (uint8_t)n_instance;
	p->m_hsh = p_mod;

	/* RCP */
	p->mp_rcp_ctrl = module_get_register(p->m_hsh, HSH_RCP_CTRL);
	p->mp_rcp_addr = register_get_field(p->mp_rcp_ctrl, HSH_RCP_CTRL_ADR);
	p->mp_rcp_cnt = register_get_field(p->mp_rcp_ctrl, HSH_RCP_CTRL_CNT);
	p->mp_rcp_data = module_get_register(p->m_hsh, HSH_RCP_DATA);
	p->mp_rcp_data_load_dist_type =
		register_get_field(p->mp_rcp_data, HSH_RCP_DATA_LOAD_DIST_TYPE);
	p->mp_rcp_data_mac_port_mask =
		register_get_field(p->mp_rcp_data, HSH_RCP_DATA_MAC_PORT_MASK);
	p->mp_rcp_data_sort = register_get_field(p->mp_rcp_data, HSH_RCP_DATA_SORT);
	p->mp_rcp_data_qw0_pe =
		register_get_field(p->mp_rcp_data, HSH_RCP_DATA_QW0_PE);
	p->mp_rcp_data_qw0_ofs =
		register_get_field(p->mp_rcp_data, HSH_RCP_DATA_QW0_OFS);
	p->mp_rcp_data_qw4_pe =
		register_get_field(p->mp_rcp_data, HSH_RCP_DATA_QW4_PE);
	p->mp_rcp_data_qw4_ofs =
		register_get_field(p->mp_rcp_data, HSH_RCP_DATA_QW4_OFS);
	p->mp_rcp_data_w8_pe = register_get_field(p->mp_rcp_data, HSH_RCP_DATA_W8_PE);
	p->mp_rcp_data_w8_ofs =
		register_get_field(p->mp_rcp_data, HSH_RCP_DATA_W8_OFS);
	p->mp_rcp_data_w8_sort =
		register_get_field(p->mp_rcp_data, HSH_RCP_DATA_W8_SORT);
	p->mp_rcp_data_w9_pe = register_get_field(p->mp_rcp_data, HSH_RCP_DATA_W9_PE);
	p->mp_rcp_data_w9_ofs =
		register_get_field(p->mp_rcp_data, HSH_RCP_DATA_W9_OFS);
	p->mp_rcp_data_w9_sort =
		register_get_field(p->mp_rcp_data, HSH_RCP_DATA_W9_SORT);
	p->mp_rcp_data_w9_p = register_get_field(p->mp_rcp_data, HSH_RCP_DATA_W9_P);
	p->mp_rcp_data_p_mask =
		register_get_field(p->mp_rcp_data, HSH_RCP_DATA_P_MASK);
	p->mp_rcp_data_word_mask =
		register_get_field(p->mp_rcp_data, HSH_RCP_DATA_WORD_MASK);
	p->mp_rcp_data_seed = register_get_field(p->mp_rcp_data, HSH_RCP_DATA_SEED);
	p->mp_rcp_data_tnl_p = register_get_field(p->mp_rcp_data, HSH_RCP_DATA_TNL_P);
	p->mp_rcp_data_hsh_valid =
		register_get_field(p->mp_rcp_data, HSH_RCP_DATA_HSH_VALID);
	p->mp_rcp_data_hsh_type =
		register_get_field(p->mp_rcp_data, HSH_RCP_DATA_HSH_TYPE);
	p->mp_rcp_data_auto_ipv4_mask =
		register_query_field(p->mp_rcp_data, HSH_RCP_DATA_AUTO_IPV4_MASK);

	/* Init */
	uint32_t val[10] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

	field_set_val32(p->mp_rcp_addr, 0);
	field_set_val32(p->mp_rcp_cnt, 1);

	field_set_val32(p->mp_rcp_data_load_dist_type, 0);
	field_set_val(p->mp_rcp_data_mac_port_mask, val,
		     p->mp_rcp_data_mac_port_mask->mn_words);
	field_set_val32(p->mp_rcp_data_sort, 0);
	field_set_val32(p->mp_rcp_data_qw0_pe, 0);
	field_set_val32(p->mp_rcp_data_qw0_ofs, 0);
	field_set_val32(p->mp_rcp_data_qw4_pe, 0);
	field_set_val32(p->mp_rcp_data_qw4_ofs, 0);
	field_set_val32(p->mp_rcp_data_w8_pe, 0);
	field_set_val32(p->mp_rcp_data_w8_ofs, 0);
	field_set_val32(p->mp_rcp_data_w8_sort, 0);
	field_set_val32(p->mp_rcp_data_w9_pe, 0);
	field_set_val32(p->mp_rcp_data_w9_ofs, 0);
	field_set_val32(p->mp_rcp_data_w9_sort, 0);
	field_set_val32(p->mp_rcp_data_w9_p, 0);
	field_set_val(p->mp_rcp_data_word_mask, val, 10);
	field_set_val32(p->mp_rcp_data_seed, 0);
	field_set_val32(p->mp_rcp_data_tnl_p, 0);
	field_set_val32(p->mp_rcp_data_hsh_valid, 0);
	field_set_val32(p->mp_rcp_data_hsh_type, 31);

	register_flush(p->mp_rcp_ctrl, 1);
	register_flush(p->mp_rcp_data, 1);

	return 0;
}

void hsh_nthw_rcp_select(const struct hsh_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_addr, val);
}

void hsh_nthw_rcp_cnt(const struct hsh_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_cnt, val);
}

void hsh_nthw_rcp_load_dist_type(const struct hsh_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_load_dist_type, val);
}

void hsh_nthw_rcp_mac_port_mask(const struct hsh_nthw *p, uint32_t *val)
{
	field_set_val(p->mp_rcp_data_mac_port_mask, val,
		     p->mp_rcp_data_mac_port_mask->mn_words);
}

void hsh_nthw_rcp_sort(const struct hsh_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_sort, val);
}

void hsh_nthw_rcp_qw0_pe(const struct hsh_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_qw0_pe, val);
}

void hsh_nthw_rcp_qw0_ofs(const struct hsh_nthw *p, int32_t val)
{
	field_set_val32(p->mp_rcp_data_qw0_ofs, val);
}

void hsh_nthw_rcp_qw4_pe(const struct hsh_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_qw4_pe, val);
}

void hsh_nthw_rcp_qw4_ofs(const struct hsh_nthw *p, int32_t val)
{
	field_set_val32(p->mp_rcp_data_qw4_ofs, val);
}

void hsh_nthw_rcp_w8_pe(const struct hsh_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_w8_pe, val);
}

void hsh_nthw_rcp_w8_ofs(const struct hsh_nthw *p, int32_t val)
{
	field_set_val32(p->mp_rcp_data_w8_ofs, val);
}

void hsh_nthw_rcp_w8_sort(const struct hsh_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_w8_sort, val);
}

void hsh_nthw_rcp_w9_pe(const struct hsh_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_w9_pe, val);
}

void hsh_nthw_rcp_w9_ofs(const struct hsh_nthw *p, int32_t val)
{
	field_set_val32(p->mp_rcp_data_w9_ofs, val);
}

void hsh_nthw_rcp_w9_sort(const struct hsh_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_w9_sort, val);
}

void hsh_nthw_rcp_w9_p(const struct hsh_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_w9_p, val);
}

void hsh_nthw_rcp_p_mask(const struct hsh_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_p_mask, val);
}

void hsh_nthw_rcp_word_mask(const struct hsh_nthw *p, uint32_t *val)
{
	field_set_val(p->mp_rcp_data_word_mask, val, 10);
}

void hsh_nthw_rcp_seed(const struct hsh_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_seed, val);
}

void hsh_nthw_rcp_tnl_p(const struct hsh_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_tnl_p, val);
}

void hsh_nthw_rcp_hsh_valid(const struct hsh_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_hsh_valid, val);
}

void hsh_nthw_rcp_hsh_type(const struct hsh_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_hsh_type, val);
}

void hsh_nthw_rcp_auto_ipv4_mask(const struct hsh_nthw *p, uint32_t val)
{
	if (p->mp_rcp_data_auto_ipv4_mask)
		field_set_val32(p->mp_rcp_data_auto_ipv4_mask, val);
}

void hsh_nthw_rcp_flush(const struct hsh_nthw *p)
{
	register_flush(p->mp_rcp_ctrl, 1);
	register_flush(p->mp_rcp_data, 1);
}

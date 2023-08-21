/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "ntlog.h"
#include "nthw_drv.h"
#include "nthw_register.h"

#include "flow_nthw_hfu.h"

#include <stdlib.h>
#include <string.h>

void hfu_nthw_set_debug_mode(struct hfu_nthw *p, unsigned int n_debug_mode)
{
	module_set_debug_mode(p->m_hfu, n_debug_mode);
}

struct hfu_nthw *hfu_nthw_new(void)
{
	struct hfu_nthw *p = malloc(sizeof(struct hfu_nthw));

	if (p)
		(void)memset(p, 0, sizeof(*p));
	return p;
}

void hfu_nthw_delete(struct hfu_nthw *p)
{
	if (p) {
		(void)memset(p, 0, sizeof(*p));
		free(p);
	}
}

int hfu_nthw_init(struct hfu_nthw *p, nt_fpga_t *p_fpga, int n_instance)
{
	const char *const p_adapter_id_str = p_fpga->p_fpga_info->mp_adapter_id_str;
	nt_module_t *p_mod = fpga_query_module(p_fpga, MOD_HFU, n_instance);

	assert(n_instance >= 0 && n_instance < 256);

	if (p == NULL)
		return p_mod == NULL ? -1 : 0;

	if (p_mod == NULL) {
		NT_LOG(ERR, NTHW, "%s: Hfu %d: no such instance\n",
		       p_adapter_id_str, n_instance);
		return -1;
	}

	p->mp_fpga = p_fpga;
	p->m_physical_adapter_no = (uint8_t)n_instance;
	p->m_hfu = fpga_query_module(p_fpga, MOD_HFU, n_instance);

	p->mp_rcp_ctrl = module_get_register(p->m_hfu, HFU_RCP_CTRL);
	p->mp_rcp_addr = register_get_field(p->mp_rcp_ctrl, HFU_RCP_CTRL_ADR);
	p->mp_rcp_cnt = register_get_field(p->mp_rcp_ctrl, HFU_RCP_CTRL_CNT);

	p->mp_rcp_data = module_get_register(p->m_hfu, HFU_RCP_DATA);
	p->mp_rcp_data_len_a_wr =
		register_get_field(p->mp_rcp_data, HFU_RCP_DATA_LEN_A_WR);
	p->mp_rcp_data_len_a_ol4len =
		register_get_field(p->mp_rcp_data, HFU_RCP_DATA_LEN_A_OL4LEN);
	p->mp_rcp_data_len_a_pos_dyn =
		register_get_field(p->mp_rcp_data, HFU_RCP_DATA_LEN_A_POS_DYN);
	p->mp_rcp_data_len_a_pos_ofs =
		register_get_field(p->mp_rcp_data, HFU_RCP_DATA_LEN_A_POS_OFS);
	p->mp_rcp_data_len_a_add_dyn =
		register_get_field(p->mp_rcp_data, HFU_RCP_DATA_LEN_A_ADD_DYN);
	p->mp_rcp_data_len_a_add_ofs =
		register_get_field(p->mp_rcp_data, HFU_RCP_DATA_LEN_A_ADD_OFS);
	p->mp_rcp_data_len_a_sub_dyn =
		register_get_field(p->mp_rcp_data, HFU_RCP_DATA_LEN_A_SUB_DYN);
	p->mp_rcp_data_len_b_wr =
		register_get_field(p->mp_rcp_data, HFU_RCP_DATA_LEN_B_WR);
	p->mp_rcp_data_len_b_pos_dyn =
		register_get_field(p->mp_rcp_data, HFU_RCP_DATA_LEN_B_POS_DYN);
	p->mp_rcp_data_len_b_pos_ofs =
		register_get_field(p->mp_rcp_data, HFU_RCP_DATA_LEN_B_POS_OFS);
	p->mp_rcp_data_len_b_add_dyn =
		register_get_field(p->mp_rcp_data, HFU_RCP_DATA_LEN_B_ADD_DYN);
	p->mp_rcp_data_len_b_add_ofs =
		register_get_field(p->mp_rcp_data, HFU_RCP_DATA_LEN_B_ADD_OFS);
	p->mp_rcp_data_len_b_sub_dyn =
		register_get_field(p->mp_rcp_data, HFU_RCP_DATA_LEN_B_SUB_DYN);
	p->mp_rcp_data_len_c_wr =
		register_get_field(p->mp_rcp_data, HFU_RCP_DATA_LEN_C_WR);
	p->mp_rcp_data_len_c_pos_dyn =
		register_get_field(p->mp_rcp_data, HFU_RCP_DATA_LEN_C_POS_DYN);
	p->mp_rcp_data_len_c_pos_ofs =
		register_get_field(p->mp_rcp_data, HFU_RCP_DATA_LEN_C_POS_OFS);
	p->mp_rcp_data_len_c_add_dyn =
		register_get_field(p->mp_rcp_data, HFU_RCP_DATA_LEN_C_ADD_DYN);
	p->mp_rcp_data_len_c_add_ofs =
		register_get_field(p->mp_rcp_data, HFU_RCP_DATA_LEN_C_ADD_OFS);
	p->mp_rcp_data_len_c_sub_dyn =
		register_get_field(p->mp_rcp_data, HFU_RCP_DATA_LEN_C_SUB_DYN);
	p->mp_rcp_data_ttl_wr =
		register_get_field(p->mp_rcp_data, HFU_RCP_DATA_TTL_WR);
	p->mp_rcp_data_ttl_pos_dyn =
		register_get_field(p->mp_rcp_data, HFU_RCP_DATA_TTL_POS_DYN);
	p->mp_rcp_data_ttl_pos_ofs =
		register_get_field(p->mp_rcp_data, HFU_RCP_DATA_TTL_POS_OFS);
	p->mp_rcp_data_csinf = register_get_field(p->mp_rcp_data, HFU_RCP_DATA_CSINF);
	p->mp_rcp_data_l3prt = register_get_field(p->mp_rcp_data, HFU_RCP_DATA_L3PRT);
	p->mp_rcp_data_l3frag =
		register_get_field(p->mp_rcp_data, HFU_RCP_DATA_L3FRAG);
	p->mp_rcp_data_tunnel =
		register_get_field(p->mp_rcp_data, HFU_RCP_DATA_TUNNEL);
	p->mp_rcp_data_l4prt = register_get_field(p->mp_rcp_data, HFU_RCP_DATA_L4PRT);
	p->mp_rcp_data_ol3ofs =
		register_get_field(p->mp_rcp_data, HFU_RCP_DATA_OL3OFS);
	p->mp_rcp_data_ol4ofs =
		register_get_field(p->mp_rcp_data, HFU_RCP_DATA_OL4OFS);
	p->mp_rcp_data_il3ofs =
		register_get_field(p->mp_rcp_data, HFU_RCP_DATA_IL3OFS);
	p->mp_rcp_data_il4ofs =
		register_get_field(p->mp_rcp_data, HFU_RCP_DATA_IL4OFS);

	return 0;
}

void hfu_nthw_rcp_select(const struct hfu_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_addr, val);
}

void hfu_nthw_rcp_cnt(const struct hfu_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_cnt, val);
}

void hfu_nthw_rcp_len_a_wr(const struct hfu_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_len_a_wr, val);
}

void hfu_nthw_rcp_len_a_ol4len(const struct hfu_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_len_a_ol4len, val);
}

void hfu_nthw_rcp_len_a_pos_dyn(const struct hfu_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_len_a_pos_dyn, val);
}

void hfu_nthw_rcp_len_a_pos_ofs(const struct hfu_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_len_a_pos_ofs, val);
}

void hfu_nthw_rcp_len_a_add_dyn(const struct hfu_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_len_a_add_dyn, val);
}

void hfu_nthw_rcp_len_a_add_ofs(const struct hfu_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_len_a_add_ofs, val);
}

void hfu_nthw_rcp_len_a_sub_dyn(const struct hfu_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_len_a_sub_dyn, val);
}

void hfu_nthw_rcp_len_b_wr(const struct hfu_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_len_b_wr, val);
}

void hfu_nthw_rcp_len_b_pos_dyn(const struct hfu_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_len_b_pos_dyn, val);
}

void hfu_nthw_rcp_len_b_pos_ofs(const struct hfu_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_len_b_pos_ofs, val);
}

void hfu_nthw_rcp_len_b_add_dyn(const struct hfu_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_len_b_add_dyn, val);
}

void hfu_nthw_rcp_len_b_add_ofs(const struct hfu_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_len_b_add_ofs, val);
}

void hfu_nthw_rcp_len_b_sub_dyn(const struct hfu_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_len_b_sub_dyn, val);
}

void hfu_nthw_rcp_len_c_wr(const struct hfu_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_len_c_wr, val);
}

void hfu_nthw_rcp_len_c_pos_dyn(const struct hfu_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_len_c_pos_dyn, val);
}

void hfu_nthw_rcp_len_c_pos_ofs(const struct hfu_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_len_c_pos_ofs, val);
}

void hfu_nthw_rcp_len_c_add_dyn(const struct hfu_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_len_c_add_dyn, val);
}

void hfu_nthw_rcp_len_c_add_ofs(const struct hfu_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_len_c_add_ofs, val);
}

void hfu_nthw_rcp_len_c_sub_dyn(const struct hfu_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_len_c_sub_dyn, val);
}

void hfu_nthw_rcp_ttl_wr(const struct hfu_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_ttl_wr, val);
}

void hfu_nthw_rcp_ttl_pos_dyn(const struct hfu_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_ttl_pos_dyn, val);
}

void hfu_nthw_rcp_ttl_pos_ofs(const struct hfu_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_ttl_pos_ofs, val);
}

void hfu_nthw_rcp_csinf(const struct hfu_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_csinf, val);
}

void hfu_nthw_rcp_l3prt(const struct hfu_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_l3prt, val);
}

void hfu_nthw_rcp_l3frag(const struct hfu_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_l3frag, val);
}

void hfu_nthw_rcp_tunnel(const struct hfu_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_tunnel, val);
}

void hfu_nthw_rcp_l4prt(const struct hfu_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_l4prt, val);
}

void hfu_nthw_rcp_ol3ofs(const struct hfu_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_ol3ofs, val);
}

void hfu_nthw_rcp_ol4ofs(const struct hfu_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_ol4ofs, val);
}

void hfu_nthw_rcp_il3ofs(const struct hfu_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_il3ofs, val);
}

void hfu_nthw_rcp_il4ofs(const struct hfu_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_il4ofs, val);
}

void hfu_nthw_rcp_flush(const struct hfu_nthw *p)
{
	register_flush(p->mp_rcp_ctrl, 1);
	register_flush(p->mp_rcp_data, 1);
}

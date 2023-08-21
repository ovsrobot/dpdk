/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __FLOW_NTHW_HFU_H__
#define __FLOW_NTHW_HFU_H__

#include <stdint.h>
#include "nthw_fpga_model.h"

struct hfu_nthw {
	uint8_t m_physical_adapter_no;
	nt_fpga_t *mp_fpga;

	nt_module_t *m_hfu;

	nt_register_t *mp_rcp_ctrl;
	nt_field_t *mp_rcp_addr;
	nt_field_t *mp_rcp_cnt;

	nt_register_t *mp_rcp_data;
	nt_field_t *mp_rcp_data_len_a_wr;
	nt_field_t *mp_rcp_data_len_a_ol4len;
	nt_field_t *mp_rcp_data_len_a_pos_dyn;
	nt_field_t *mp_rcp_data_len_a_pos_ofs;
	nt_field_t *mp_rcp_data_len_a_add_dyn;
	nt_field_t *mp_rcp_data_len_a_add_ofs;
	nt_field_t *mp_rcp_data_len_a_sub_dyn;
	nt_field_t *mp_rcp_data_len_b_wr;
	nt_field_t *mp_rcp_data_len_b_pos_dyn;
	nt_field_t *mp_rcp_data_len_b_pos_ofs;
	nt_field_t *mp_rcp_data_len_b_add_dyn;
	nt_field_t *mp_rcp_data_len_b_add_ofs;
	nt_field_t *mp_rcp_data_len_b_sub_dyn;
	nt_field_t *mp_rcp_data_len_c_wr;
	nt_field_t *mp_rcp_data_len_c_pos_dyn;
	nt_field_t *mp_rcp_data_len_c_pos_ofs;
	nt_field_t *mp_rcp_data_len_c_add_dyn;
	nt_field_t *mp_rcp_data_len_c_add_ofs;
	nt_field_t *mp_rcp_data_len_c_sub_dyn;
	nt_field_t *mp_rcp_data_ttl_wr;
	nt_field_t *mp_rcp_data_ttl_pos_dyn;
	nt_field_t *mp_rcp_data_ttl_pos_ofs;
	nt_field_t *mp_rcp_data_csinf;
	nt_field_t *mp_rcp_data_l3prt;
	nt_field_t *mp_rcp_data_l3frag;
	nt_field_t *mp_rcp_data_tunnel;
	nt_field_t *mp_rcp_data_l4prt;
	nt_field_t *mp_rcp_data_ol3ofs;
	nt_field_t *mp_rcp_data_ol4ofs;
	nt_field_t *mp_rcp_data_il3ofs;
	nt_field_t *mp_rcp_data_il4ofs;
};

struct hfu_nthw *hfu_nthw_new(void);
void hfu_nthw_delete(struct hfu_nthw *p);
int hfu_nthw_init(struct hfu_nthw *p, nt_fpga_t *p_fpga, int n_instance);

int hfu_nthw_setup(struct hfu_nthw *p, int n_idx, int n_idx_cnt);
void hfu_nthw_set_debug_mode(struct hfu_nthw *p, unsigned int n_debug_mode);

/* RCP */
void hfu_nthw_rcp_select(const struct hfu_nthw *p, uint32_t val);
void hfu_nthw_rcp_cnt(const struct hfu_nthw *p, uint32_t val);

void hfu_nthw_rcp_len_a_wr(const struct hfu_nthw *p, uint32_t val);
void hfu_nthw_rcp_len_a_ol4len(const struct hfu_nthw *p, uint32_t val);
void hfu_nthw_rcp_len_a_pos_dyn(const struct hfu_nthw *p, uint32_t val);
void hfu_nthw_rcp_len_a_pos_ofs(const struct hfu_nthw *p, uint32_t val);
void hfu_nthw_rcp_len_a_add_dyn(const struct hfu_nthw *p, uint32_t val);
void hfu_nthw_rcp_len_a_add_ofs(const struct hfu_nthw *p, uint32_t val);
void hfu_nthw_rcp_len_a_sub_dyn(const struct hfu_nthw *p, uint32_t val);
void hfu_nthw_rcp_len_b_wr(const struct hfu_nthw *p, uint32_t val);
void hfu_nthw_rcp_len_b_pos_dyn(const struct hfu_nthw *p, uint32_t val);
void hfu_nthw_rcp_len_b_pos_ofs(const struct hfu_nthw *p, uint32_t val);
void hfu_nthw_rcp_len_b_add_dyn(const struct hfu_nthw *p, uint32_t val);
void hfu_nthw_rcp_len_b_add_ofs(const struct hfu_nthw *p, uint32_t val);
void hfu_nthw_rcp_len_b_sub_dyn(const struct hfu_nthw *p, uint32_t val);
void hfu_nthw_rcp_len_c_wr(const struct hfu_nthw *p, uint32_t val);
void hfu_nthw_rcp_len_c_pos_dyn(const struct hfu_nthw *p, uint32_t val);
void hfu_nthw_rcp_len_c_pos_ofs(const struct hfu_nthw *p, uint32_t val);
void hfu_nthw_rcp_len_c_add_dyn(const struct hfu_nthw *p, uint32_t val);
void hfu_nthw_rcp_len_c_add_ofs(const struct hfu_nthw *p, uint32_t val);
void hfu_nthw_rcp_len_c_sub_dyn(const struct hfu_nthw *p, uint32_t val);
void hfu_nthw_rcp_ttl_wr(const struct hfu_nthw *p, uint32_t val);
void hfu_nthw_rcp_ttl_pos_dyn(const struct hfu_nthw *p, uint32_t val);
void hfu_nthw_rcp_ttl_pos_ofs(const struct hfu_nthw *p, uint32_t val);
void hfu_nthw_rcp_csinf(const struct hfu_nthw *p, uint32_t val);
void hfu_nthw_rcp_l3prt(const struct hfu_nthw *p, uint32_t val);
void hfu_nthw_rcp_l3frag(const struct hfu_nthw *p, uint32_t val);
void hfu_nthw_rcp_tunnel(const struct hfu_nthw *p, uint32_t val);
void hfu_nthw_rcp_l4prt(const struct hfu_nthw *p, uint32_t val);
void hfu_nthw_rcp_ol3ofs(const struct hfu_nthw *p, uint32_t val);
void hfu_nthw_rcp_ol4ofs(const struct hfu_nthw *p, uint32_t val);
void hfu_nthw_rcp_il3ofs(const struct hfu_nthw *p, uint32_t val);
void hfu_nthw_rcp_il4ofs(const struct hfu_nthw *p, uint32_t val);

void hfu_nthw_rcp_flush(const struct hfu_nthw *p);

#endif /* __FLOW_NTHW_HFU_H__ */

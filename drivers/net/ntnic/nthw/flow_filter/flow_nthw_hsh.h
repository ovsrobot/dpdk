/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __FLOW_NTHW_HSH_H__
#define __FLOW_NTHW_HSH_H__

#include <stdint.h> /* uint32_t */
#include "nthw_fpga_model.h"

struct hsh_nthw;

typedef struct hsh_nthw hsh_nthw_t;

struct hsh_nthw *hsh_nthw_new(void);
void hsh_nthw_delete(struct hsh_nthw *p);
int hsh_nthw_init(struct hsh_nthw *p, nt_fpga_t *p_fpga, int n_instance);

int hsh_nthw_setup(struct hsh_nthw *p, int n_idx, int n_idx_cnt);
void hsh_nthw_set_debug_mode(struct hsh_nthw *p, unsigned int n_debug_mode);

/* RCP */
void hsh_nthw_rcp_select(const struct hsh_nthw *p, uint32_t val);
void hsh_nthw_rcp_cnt(const struct hsh_nthw *p, uint32_t val);
void hsh_nthw_rcp_load_dist_type(const struct hsh_nthw *p, uint32_t val);
void hsh_nthw_rcp_mac_port_mask(const struct hsh_nthw *p, uint32_t *val);
void hsh_nthw_rcp_sort(const struct hsh_nthw *p, uint32_t val);
void hsh_nthw_rcp_qw0_pe(const struct hsh_nthw *p, uint32_t val);
void hsh_nthw_rcp_qw0_ofs(const struct hsh_nthw *p, int32_t val);
void hsh_nthw_rcp_qw4_pe(const struct hsh_nthw *p, uint32_t val);
void hsh_nthw_rcp_qw4_ofs(const struct hsh_nthw *p, int32_t val);
void hsh_nthw_rcp_w8_pe(const struct hsh_nthw *p, uint32_t val);
void hsh_nthw_rcp_w8_ofs(const struct hsh_nthw *p, int32_t val);
void hsh_nthw_rcp_w8_sort(const struct hsh_nthw *p, uint32_t val);
void hsh_nthw_rcp_w9_pe(const struct hsh_nthw *p, uint32_t val);
void hsh_nthw_rcp_w9_ofs(const struct hsh_nthw *p, int32_t val);
void hsh_nthw_rcp_w9_sort(const struct hsh_nthw *p, uint32_t val);
void hsh_nthw_rcp_w9_p(const struct hsh_nthw *p, uint32_t val);
void hsh_nthw_rcp_p_mask(const struct hsh_nthw *p, uint32_t val);
void hsh_nthw_rcp_word_mask(const struct hsh_nthw *p, uint32_t *val);
void hsh_nthw_rcp_seed(const struct hsh_nthw *p, uint32_t val);
void hsh_nthw_rcp_tnl_p(const struct hsh_nthw *p, uint32_t val);
void hsh_nthw_rcp_hsh_valid(const struct hsh_nthw *p, uint32_t val);
void hsh_nthw_rcp_hsh_type(const struct hsh_nthw *p, uint32_t val);
void hsh_nthw_rcp_auto_ipv4_mask(const struct hsh_nthw *p, uint32_t val);
void hsh_nthw_rcp_flush(const struct hsh_nthw *p);

struct hsh_nthw {
	uint8_t m_physical_adapter_no;
	nt_fpga_t *mp_fpga;

	nt_module_t *m_hsh;

	nt_register_t *mp_rcp_ctrl;
	nt_field_t *mp_rcp_addr;
	nt_field_t *mp_rcp_cnt;
	nt_register_t *mp_rcp_data;
	nt_field_t *mp_rcp_data_load_dist_type;
	nt_field_t *mp_rcp_data_mac_port_mask;
	nt_field_t *mp_rcp_data_sort;
	nt_field_t *mp_rcp_data_qw0_pe;
	nt_field_t *mp_rcp_data_qw0_ofs;
	nt_field_t *mp_rcp_data_qw4_pe;
	nt_field_t *mp_rcp_data_qw4_ofs;
	nt_field_t *mp_rcp_data_w8_pe;
	nt_field_t *mp_rcp_data_w8_ofs;
	nt_field_t *mp_rcp_data_w8_sort;
	nt_field_t *mp_rcp_data_w9_pe;
	nt_field_t *mp_rcp_data_w9_ofs;
	nt_field_t *mp_rcp_data_w9_sort;
	nt_field_t *mp_rcp_data_w9_p;
	nt_field_t *mp_rcp_data_p_mask;
	nt_field_t *mp_rcp_data_word_mask;
	nt_field_t *mp_rcp_data_seed;
	nt_field_t *mp_rcp_data_tnl_p;
	nt_field_t *mp_rcp_data_hsh_valid;
	nt_field_t *mp_rcp_data_hsh_type;
	nt_field_t *mp_rcp_data_auto_ipv4_mask;
};

#endif /* __FLOW_NTHW_HSH_H__ */

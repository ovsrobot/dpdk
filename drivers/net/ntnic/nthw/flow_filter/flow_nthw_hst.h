/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __FLOW_NTHW_HST_H__
#define __FLOW_NTHW_HST_H__

#include <stdint.h> /* uint32_t */
#include "nthw_fpga_model.h"

struct hst_nthw {
	uint8_t m_physical_adapter_no;
	nt_fpga_t *mp_fpga;

	nt_module_t *m_hst;

	nt_register_t *mp_rcp_ctrl;
	nt_field_t *mp_rcp_addr;
	nt_field_t *mp_rcp_cnt;
	nt_register_t *mp_rcp_data;
	nt_field_t *mp_rcp_data_strip_mode;
	nt_field_t *mp_rcp_data_start_dyn;
	nt_field_t *mp_rcp_data_start_ofs;
	nt_field_t *mp_rcp_data_end_dyn;
	nt_field_t *mp_rcp_data_end_ofs;
	nt_field_t *mp_rcp_data_modif0_cmd;
	nt_field_t *mp_rcp_data_modif0_dyn;
	nt_field_t *mp_rcp_data_modif0_ofs;
	nt_field_t *mp_rcp_data_modif0_value;
	nt_field_t *mp_rcp_data_modif1_cmd;
	nt_field_t *mp_rcp_data_modif1_dyn;
	nt_field_t *mp_rcp_data_modif1_ofs;
	nt_field_t *mp_rcp_data_modif1_value;
	nt_field_t *mp_rcp_data_modif2_cmd;
	nt_field_t *mp_rcp_data_modif2_dyn;
	nt_field_t *mp_rcp_data_modif2_ofs;
	nt_field_t *mp_rcp_data_modif2_value;
};

typedef struct hst_nthw hst_nthw_t;

struct hst_nthw *hst_nthw_new(void);
void hst_nthw_delete(struct hst_nthw *p);
int hst_nthw_init(struct hst_nthw *p, nt_fpga_t *p_fpga, int n_instance);

int hst_nthw_setup(struct hst_nthw *p, int n_idx, int n_idx_cnt);
void hst_nthw_set_debug_mode(struct hst_nthw *p, unsigned int n_debug_mode);

/* RCP */
void hst_nthw_rcp_select(const struct hst_nthw *p, uint32_t val);
void hst_nthw_rcp_cnt(const struct hst_nthw *p, uint32_t val);

void hst_nthw_rcp_strip_mode(const struct hst_nthw *p, uint32_t val);
void hst_nthw_rcp_start_dyn(const struct hst_nthw *p, uint32_t val);
void hst_nthw_rcp_start_ofs(const struct hst_nthw *p, uint32_t val);
void hst_nthw_rcp_end_dyn(const struct hst_nthw *p, uint32_t val);
void hst_nthw_rcp_end_ofs(const struct hst_nthw *p, uint32_t val);
void hst_nthw_rcp_modif0_cmd(const struct hst_nthw *p, uint32_t val);
void hst_nthw_rcp_modif0_dyn(const struct hst_nthw *p, uint32_t val);
void hst_nthw_rcp_modif0_ofs(const struct hst_nthw *p, uint32_t val);
void hst_nthw_rcp_modif0_value(const struct hst_nthw *p, uint32_t val);
void hst_nthw_rcp_modif1_cmd(const struct hst_nthw *p, uint32_t val);
void hst_nthw_rcp_modif1_dyn(const struct hst_nthw *p, uint32_t val);
void hst_nthw_rcp_modif1_ofs(const struct hst_nthw *p, uint32_t val);
void hst_nthw_rcp_modif1_value(const struct hst_nthw *p, uint32_t val);
void hst_nthw_rcp_modif2_cmd(const struct hst_nthw *p, uint32_t val);
void hst_nthw_rcp_modif2_dyn(const struct hst_nthw *p, uint32_t val);
void hst_nthw_rcp_modif2_ofs(const struct hst_nthw *p, uint32_t val);
void hst_nthw_rcp_modif2_value(const struct hst_nthw *p, uint32_t val);
void hst_nthw_rcp_flush(const struct hst_nthw *p);

#endif /* __FLOW_NTHW_HST_H__ */

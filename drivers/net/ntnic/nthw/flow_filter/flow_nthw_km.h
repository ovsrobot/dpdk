/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __FLOW_NTHW_KM_H__
#define __FLOW_NTHW_KM_H__

#include <stdint.h> /* uint32_t */
#include "nthw_fpga_model.h"

struct km_nthw;

typedef struct km_nthw km_nthw_t;

struct km_nthw *km_nthw_new(void);
void km_nthw_delete(struct km_nthw *p);
int km_nthw_init(struct km_nthw *p, nt_fpga_t *p_fpga, int n_instance);

int km_nthw_setup(struct km_nthw *p, int n_idx, int n_idx_cnt);
void km_nthw_set_debug_mode(struct km_nthw *p, unsigned int n_debug_mode);

/* RCP initial v3 */
void km_nthw_rcp_select(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_cnt(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_qw0_dyn(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_qw0_ofs(const struct km_nthw *p, int32_t val);
void km_nthw_rcp_qw0_sel_a(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_qw0_sel_b(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_qw4_dyn(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_qw4_ofs(const struct km_nthw *p, int32_t val);
void km_nthw_rcp_qw4_sel_a(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_qw4_sel_b(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_sw8_dyn(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_sw8_ofs(const struct km_nthw *p, int32_t val);
void km_nthw_rcp_sw8_sel_a(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_sw8_sel_b(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_sw9_dyn(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_sw9_ofs(const struct km_nthw *p, int32_t val);
void km_nthw_rcp_sw9_sel_a(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_sw9_sel_b(const struct km_nthw *p, uint32_t val);
/* subst in v6 */
void km_nthw_rcp_dw8_dyn(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_dw8_ofs(const struct km_nthw *p, int32_t val);
void km_nthw_rcp_dw8_sel_a(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_dw8_sel_b(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_dw10_dyn(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_dw10_ofs(const struct km_nthw *p, int32_t val);
void km_nthw_rcp_dw10_sel_a(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_dw10_sel_b(const struct km_nthw *p, uint32_t val);

void km_nthw_rcp_swx_ovs_sb(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_swx_cch(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_swx_sel_a(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_swx_sel_b(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_mask_a(const struct km_nthw *p, const uint32_t *val);
void km_nthw_rcp_mask_d_a(const struct km_nthw *p, const uint32_t *val);
void km_nthw_rcp_mask_b(const struct km_nthw *p, const uint32_t *val);
void km_nthw_rcp_dual(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_paired(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_el_a(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_el_b(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_info_a(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_info_b(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_ftm_a(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_ftm_b(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_bank_a(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_bank_b(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_kl_a(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_kl_b(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_flow_set(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_keyway_a(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_keyway_b(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_synergy_mode(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_dw0_b_dyn(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_dw0_b_ofs(const struct km_nthw *p, int32_t val);
void km_nthw_rcp_dw2_b_dyn(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_dw2_b_ofs(const struct km_nthw *p, int32_t val);
void km_nthw_rcp_sw4_b_dyn(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_sw4_b_ofs(const struct km_nthw *p, int32_t val);
void km_nthw_rcp_sw5_b_dyn(const struct km_nthw *p, uint32_t val);
void km_nthw_rcp_sw5_b_ofs(const struct km_nthw *p, int32_t val);
void km_nthw_rcp_flush(const struct km_nthw *p);
/* CAM */
void km_nthw_cam_select(const struct km_nthw *p, uint32_t val);
void km_nthw_cam_cnt(const struct km_nthw *p, uint32_t val);
void km_nthw_cam_w0(const struct km_nthw *p, uint32_t val);
void km_nthw_cam_w1(const struct km_nthw *p, uint32_t val);
void km_nthw_cam_w2(const struct km_nthw *p, uint32_t val);
void km_nthw_cam_w3(const struct km_nthw *p, uint32_t val);
void km_nthw_cam_w4(const struct km_nthw *p, uint32_t val);
void km_nthw_cam_w5(const struct km_nthw *p, uint32_t val);
void km_nthw_cam_ft0(const struct km_nthw *p, uint32_t val);
void km_nthw_cam_ft1(const struct km_nthw *p, uint32_t val);
void km_nthw_cam_ft2(const struct km_nthw *p, uint32_t val);
void km_nthw_cam_ft3(const struct km_nthw *p, uint32_t val);
void km_nthw_cam_ft4(const struct km_nthw *p, uint32_t val);
void km_nthw_cam_ft5(const struct km_nthw *p, uint32_t val);
void km_nthw_cam_flush(const struct km_nthw *p);
/* TCAM */
void km_nthw_tcam_select(const struct km_nthw *p, uint32_t val);
void km_nthw_tcam_cnt(const struct km_nthw *p, uint32_t val);
void km_nthw_tcam_t(const struct km_nthw *p, uint32_t *val);
void km_nthw_tcam_flush(const struct km_nthw *p);
/* TCI */
void km_nthw_tci_select(const struct km_nthw *p, uint32_t val);
void km_nthw_tci_cnt(const struct km_nthw *p, uint32_t val);
void km_nthw_tci_color(const struct km_nthw *p, uint32_t val);
void km_nthw_tci_ft(const struct km_nthw *p, uint32_t val);
void km_nthw_tci_flush(const struct km_nthw *p);
/* TCQ */
void km_nthw_tcq_select(const struct km_nthw *p, uint32_t val);
void km_nthw_tcq_cnt(const struct km_nthw *p, uint32_t val);
void km_nthw_tcq_bank_mask(const struct km_nthw *p, uint32_t val);
void km_nthw_tcq_qual(const struct km_nthw *p, uint32_t val);
void km_nthw_tcq_qual72(const struct km_nthw *p, uint32_t *val);

void km_nthw_tcq_flush(const struct km_nthw *p);

struct km_nthw {
	uint8_t m_physical_adapter_no;
	nt_fpga_t *mp_fpga;

	nt_module_t *m_km;

	nt_register_t *mp_rcp_ctrl;
	nt_field_t *mp_rcp_addr;
	nt_field_t *mp_rcp_cnt;
	nt_register_t *mp_rcp_data;
	nt_field_t *mp_rcp_data_qw0_dyn;
	nt_field_t *mp_rcp_data_qw0_ofs;
	nt_field_t *mp_rcp_data_qw0_sel_a;
	nt_field_t *mp_rcp_data_qw0_sel_b;
	nt_field_t *mp_rcp_data_qw4_dyn;
	nt_field_t *mp_rcp_data_qw4_ofs;
	nt_field_t *mp_rcp_data_qw4_sel_a;
	nt_field_t *mp_rcp_data_qw4_sel_b;
	nt_field_t *mp_rcp_data_sw8_dyn;
	nt_field_t *mp_rcp_data_sw8_ofs;
	nt_field_t *mp_rcp_data_sw8_sel_a;
	nt_field_t *mp_rcp_data_sw8_sel_b;
	nt_field_t *mp_rcp_data_sw9_dyn;
	nt_field_t *mp_rcp_data_sw9_ofs;
	nt_field_t *mp_rcp_data_sw9_sel_a;
	nt_field_t *mp_rcp_data_sw9_sel_b;

	nt_field_t *mp_rcp_data_dw8_dyn; /* substituted Sw<x> from v6+ */
	nt_field_t *mp_rcp_data_dw8_ofs; /* substituted Sw<x> from v6+ */
	nt_field_t *mp_rcp_data_dw8_sel_a; /* substituted Sw<x> from v6+ */
	nt_field_t *mp_rcp_data_dw8_sel_b; /* substituted Sw<x> from v6+ */
	nt_field_t *mp_rcp_data_dw10_dyn; /* substituted Sw<x> from v6+ */
	nt_field_t *mp_rcp_data_dw10_ofs; /* substituted Sw<x> from v6+ */
	nt_field_t *mp_rcp_data_dw10_sel_a; /* substituted Sw<x> from v6+ */
	nt_field_t *mp_rcp_data_dw10_sel_b; /* substituted Sw<x> from v6+ */

	nt_field_t *mp_rcp_data_swx_ovs_sb;
	nt_field_t *mp_rcp_data_swx_cch;
	nt_field_t *mp_rcp_data_swx_sel_a;
	nt_field_t *mp_rcp_data_swx_sel_b;
	nt_field_t *mp_rcp_data_mask_a;
	nt_field_t *mp_rcp_data_mask_b;
	nt_field_t *mp_rcp_data_dual;
	nt_field_t *mp_rcp_data_paired;
	nt_field_t *mp_rcp_data_el_a;
	nt_field_t *mp_rcp_data_el_b;
	nt_field_t *mp_rcp_data_info_a;
	nt_field_t *mp_rcp_data_info_b;
	nt_field_t *mp_rcp_data_ftm_a;
	nt_field_t *mp_rcp_data_ftm_b;
	nt_field_t *mp_rcp_data_bank_a;
	nt_field_t *mp_rcp_data_bank_b;
	nt_field_t *mp_rcp_data_kl_a;
	nt_field_t *mp_rcp_data_kl_b;
	nt_field_t *mp_rcp_data_flow_set;
	nt_field_t *mp_rcp_data_keyway_a;
	nt_field_t *mp_rcp_data_keyway_b;
	nt_field_t *mp_rcp_data_synergy_mode;
	nt_field_t *mp_rcp_data_dw0_b_dyn;
	nt_field_t *mp_rcp_data_dw0_b_ofs;
	nt_field_t *mp_rcp_data_dw2_b_dyn;
	nt_field_t *mp_rcp_data_dw2_b_ofs;
	nt_field_t *mp_rcp_data_sw4_b_dyn;
	nt_field_t *mp_rcp_data_sw4_b_ofs;
	nt_field_t *mp_rcp_data_sw5_b_dyn;
	nt_field_t *mp_rcp_data_sw5_b_ofs;

	nt_register_t *mp_cam_ctrl;
	nt_field_t *mp_cam_addr;
	nt_field_t *mp_cam_cnt;
	nt_register_t *mp_cam_data;
	nt_field_t *mp_cam_data_w0;
	nt_field_t *mp_cam_data_w1;
	nt_field_t *mp_cam_data_w2;
	nt_field_t *mp_cam_data_w3;
	nt_field_t *mp_cam_data_w4;
	nt_field_t *mp_cam_data_w5;
	nt_field_t *mp_cam_data_ft0;
	nt_field_t *mp_cam_data_ft1;
	nt_field_t *mp_cam_data_ft2;
	nt_field_t *mp_cam_data_ft3;
	nt_field_t *mp_cam_data_ft4;
	nt_field_t *mp_cam_data_ft5;

	nt_register_t *mp_tcam_ctrl;
	nt_field_t *mp_tcam_addr;
	nt_field_t *mp_tcam_cnt;
	nt_register_t *mp_tcam_data;
	nt_field_t *mp_tcam_data_t;

	nt_register_t *mp_tci_ctrl;
	nt_field_t *mp_tci_addr;
	nt_field_t *mp_tci_cnt;
	nt_register_t *mp_tci_data;
	nt_field_t *mp_tci_data_color;
	nt_field_t *mp_tci_data_ft;

	nt_register_t *mp_tcq_ctrl;
	nt_field_t *mp_tcq_addr;
	nt_field_t *mp_tcq_cnt;
	nt_register_t *mp_tcq_data;
	nt_field_t *mp_tcq_data_bank_mask;
	nt_field_t *mp_tcq_data_qual;
};

#endif /* __FLOW_NTHW_KM_H__ */

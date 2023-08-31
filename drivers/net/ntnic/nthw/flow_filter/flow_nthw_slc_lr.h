/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __FLOW_NTHW_SLC_LR_H__
#define __FLOW_NTHW_SLC_LR_H__

#include <stdint.h> /* uint32_t */
#include "nthw_fpga_model.h"

struct slc_lr_nthw {
	uint8_t m_physical_adapter_no;
	nt_fpga_t *mp_fpga;

	nt_module_t *m_slc_lr;

	nt_register_t *mp_rcp_ctrl;
	nt_field_t *mp_rcp_addr;
	nt_field_t *mp_rcp_cnt;
	nt_register_t *mp_rcp_data;

	nt_field_t *mp_rcp_data_tail_slc_en;
	nt_field_t *mp_rcp_data_tail_dyn;
	nt_field_t *mp_rcp_data_tail_ofs;
	nt_field_t *mp_rcp_data_pcap;
};

typedef struct slc_lr_nthw slc_lr_nthw_t;

struct slc_lr_nthw *slc_lr_nthw_new(void);
void slc_lr_nthw_delete(struct slc_lr_nthw *p);
int slc_lr_nthw_init(struct slc_lr_nthw *p, nt_fpga_t *p_fpga, int n_instance);

int slc_lr_nthw_setup(struct slc_lr_nthw *p, int n_idx, int n_idx_cnt);
void slc_lr_nthw_set_debug_mode(struct slc_lr_nthw *p, unsigned int n_debug_mode);

/* RCP */
void slc_lr_nthw_rcp_select(const struct slc_lr_nthw *p, uint32_t val);
void slc_lr_nthw_rcp_cnt(const struct slc_lr_nthw *p, uint32_t val);
void slc_lr_nthw_rcp_tail_slc_en(const struct slc_lr_nthw *p, uint32_t val);
void slc_lr_nthw_rcp_tail_dyn(const struct slc_lr_nthw *p, uint32_t val);
void slc_lr_nthw_rcp_tail_ofs(const struct slc_lr_nthw *p, int32_t val);
void slc_lr_nthw_rcp_pcap(const struct slc_lr_nthw *p, uint32_t val);
void slc_lr_nthw_rcp_flush(const struct slc_lr_nthw *p);

#endif /* __FLOW_NTHW_SLC_LR_H__ */

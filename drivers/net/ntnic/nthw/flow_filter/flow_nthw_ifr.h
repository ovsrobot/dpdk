/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __FLOW_NTHW_IFR_H__
#define __FLOW_NTHW_IFR_H__

#include "nthw_fpga_model.h"

struct ifr_nthw {
	uint8_t m_physical_adapter_no;
	nt_fpga_t *mp_fpga;

	nt_module_t *m_ifr;

	nt_register_t *mp_rcp_ctrl;
	nt_field_t *mp_rcp_addr;
	nt_field_t *mp_rcp_cnt;

	nt_register_t *mp_rcp_data;
	nt_field_t *mp_rcp_data_en;
	nt_field_t *mp_rcp_data_mtu;
};

struct ifr_nthw *ifr_nthw_new(void);
void ifr_nthw_delete(struct ifr_nthw *p);
int ifr_nthw_init(struct ifr_nthw *p, nt_fpga_t *p_fpga, int n_instance);

int ifr_nthw_setup(struct ifr_nthw *p, int n_idx, int n_idx_cnt);
void ifr_nthw_set_debug_mode(struct ifr_nthw *p, unsigned int n_debug_mode);

/* IFR */
void ifr_nthw_rcp_select(const struct ifr_nthw *p, uint32_t val);
void ifr_nthw_rcp_cnt(const struct ifr_nthw *p, uint32_t val);
void ifr_nthw_rcp_en(const struct ifr_nthw *p, uint32_t val);
void ifr_nthw_rcp_mtu(const struct ifr_nthw *p, uint32_t val);
void ifr_nthw_rcp_flush(const struct ifr_nthw *p);

#endif /* __FLOW_NTHW_IFR_H__ */

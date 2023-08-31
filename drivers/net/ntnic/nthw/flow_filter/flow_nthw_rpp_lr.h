/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __FLOW_NTHW_RPP_LR_H__
#define __FLOW_NTHW_RPP_LR_H__

#include <stdint.h>
#include "nthw_fpga_model.h"

struct rpp_lr_nthw {
	uint8_t m_physical_adapter_no;
	nt_fpga_t *mp_fpga;

	nt_module_t *m_rpp_lr;

	nt_register_t *mp_rcp_ctrl;
	nt_field_t *mp_rcp_addr;
	nt_field_t *mp_rcp_cnt;

	nt_register_t *mp_rcp_data;
	nt_field_t *mp_rcp_data_exp;

	nt_register_t *mp_ifr_rcp_ctrl;
	nt_field_t *mp_ifr_rcp_addr;
	nt_field_t *mp_ifr_rcp_cnt;

	nt_register_t *mp_ifr_rcp_data;
	nt_field_t *mp_ifr_rcp_data_en;
	nt_field_t *mp_ifr_rcp_data_mtu;
};

struct rpp_lr_nthw *rpp_lr_nthw_new(void);
void rpp_lr_nthw_delete(struct rpp_lr_nthw *p);
int rpp_lr_nthw_init(struct rpp_lr_nthw *p, nt_fpga_t *p_fpga, int n_instance);

int rpp_lr_nthw_setup(struct rpp_lr_nthw *p, int n_idx, int n_idx_cnt);
void rpp_lr_nthw_set_debug_mode(struct rpp_lr_nthw *p, unsigned int n_debug_mode);

/* RCP */
void rpp_lr_nthw_rcp_select(const struct rpp_lr_nthw *p, uint32_t val);
void rpp_lr_nthw_rcp_cnt(const struct rpp_lr_nthw *p, uint32_t val);
void rpp_lr_nthw_rcp_exp(const struct rpp_lr_nthw *p, uint32_t val);
void rpp_lr_nthw_rcp_flush(const struct rpp_lr_nthw *p);

/* RCP IFR */
void rpp_lr_nthw_ifr_rcp_select(const struct rpp_lr_nthw *p, uint32_t val);
void rpp_lr_nthw_ifr_rcp_cnt(const struct rpp_lr_nthw *p, uint32_t val);
void rpp_lr_nthw_ifr_rcp_en(const struct rpp_lr_nthw *p, uint32_t val);
void rpp_lr_nthw_ifr_rcp_mtu(const struct rpp_lr_nthw *p, uint32_t val);
void rpp_lr_nthw_ifr_rcp_flush(const struct rpp_lr_nthw *p);

#endif /* __FLOW_NTHW_RPP_LR_H__ */

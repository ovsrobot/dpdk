/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __FLOW_NTHW_RMC_H__
#define __FLOW_NTHW_RMC_H__

#include <stdint.h> /* uint32_t */
#include "nthw_fpga_model.h"

struct rmc_nthw {
	uint8_t m_physical_adapter_no;
	nt_fpga_t *mp_fpga;

	nt_module_t *m_rmc;

	nt_register_t *mp_ctrl;
	nt_field_t *mp_ctrl_block_statt;
	nt_field_t *mp_ctrl_block_keep_a;
	nt_field_t *mp_ctrl_block_rpp_slice;
	nt_field_t *mp_ctrl_block_mac_port;
	nt_field_t *mp_ctrl_lag_phy_odd_even;
};

struct rmc_nthw *rmc_nthw_new(void);
void rmc_nthw_delete(struct rmc_nthw *p);
int rmc_nthw_init(struct rmc_nthw *p, nt_fpga_t *p_fpga, int n_instance);

int rmc_nthw_setup(struct rmc_nthw *p, int n_idx, int n_idx_cnt);
void rmc_nthw_set_debug_mode(struct rmc_nthw *p, unsigned int n_debug_mode);

/* CTRL */
void rmc_nthw_ctrl_block_statt(const struct rmc_nthw *p, uint32_t val);
void rmc_nthw_ctrl_block_keep_a(const struct rmc_nthw *p, uint32_t val);
void rmc_nthw_ctrl_block_rpp_slice(const struct rmc_nthw *p, uint32_t val);
void rmc_nthw_ctrl_block_mac_port(const struct rmc_nthw *p, uint32_t val);
void rmc_nthw_ctrl_lag_phy_odd_even(const struct rmc_nthw *p, uint32_t val);
void rmc_nthw_ctrl_flush(const struct rmc_nthw *p);

#endif /* __FLOW_NTHW_RMC_H__ */

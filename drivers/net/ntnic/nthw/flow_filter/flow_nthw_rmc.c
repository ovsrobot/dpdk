/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "ntlog.h"

#include "nthw_drv.h"
#include "nthw_register.h"

#include "flow_nthw_rmc.h"

#include <stdlib.h> /* malloc */
#include <string.h> /* memset */

void rmc_nthw_set_debug_mode(struct rmc_nthw *p, unsigned int n_debug_mode)
{
	module_set_debug_mode(p->m_rmc, n_debug_mode);
}

struct rmc_nthw *rmc_nthw_new(void)
{
	struct rmc_nthw *p = malloc(sizeof(struct rmc_nthw));

	if (p)
		(void)memset(p, 0, sizeof(*p));

	return p;
}

void rmc_nthw_delete(struct rmc_nthw *p)
{
	if (p) {
		(void)memset(p, 0, sizeof(*p));
		free(p);
	}
}

int rmc_nthw_init(struct rmc_nthw *p, nt_fpga_t *p_fpga, int n_instance)
{
	const char *const p_adapter_id_str = p_fpga->p_fpga_info->mp_adapter_id_str;
	nt_module_t *p_mod = fpga_query_module(p_fpga, MOD_RMC, n_instance);

	assert(n_instance >= 0 && n_instance < 256);

	if (p == NULL)
		return p_mod == NULL ? -1 : 0;

	if (p_mod == NULL) {
		NT_LOG(ERR, NTHW, "%s: RMC %d: no such instance\n",
		       p_adapter_id_str, n_instance);
		return -1;
	}

	p->mp_fpga = p_fpga;
	p->m_physical_adapter_no = (uint8_t)n_instance;
	p->m_rmc = p_mod;

	/* CTRL */
	p->mp_ctrl = module_get_register(p->m_rmc, RMC_CTRL);
	p->mp_ctrl_block_statt =
		register_get_field(p->mp_ctrl, RMC_CTRL_BLOCK_STATT);
	p->mp_ctrl_block_keep_a =
		register_get_field(p->mp_ctrl, RMC_CTRL_BLOCK_KEEPA);
	p->mp_ctrl_block_rpp_slice =
		register_query_field(p->mp_ctrl, RMC_CTRL_BLOCK_RPP_SLICE);
	p->mp_ctrl_block_mac_port =
		register_get_field(p->mp_ctrl, RMC_CTRL_BLOCK_MAC_PORT);
	p->mp_ctrl_lag_phy_odd_even =
		register_get_field(p->mp_ctrl, RMC_CTRL_LAG_PHY_ODD_EVEN);
	return 0;
}

int rmc_nthw_setup(struct rmc_nthw *p, int n_idx, int n_idx_cnt)
{
	(void)p;
	(void)n_idx;
	(void)n_idx_cnt;

	return 0;
}

/* CTRL */
void rmc_nthw_ctrl_block_statt(const struct rmc_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_ctrl_block_statt, val);
}

void rmc_nthw_ctrl_block_keep_a(const struct rmc_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_ctrl_block_keep_a, val);
}

void rmc_nthw_ctrl_block_rpp_slice(const struct rmc_nthw *p, uint32_t val)
{
	if (p->mp_ctrl_block_rpp_slice)
		field_set_val32(p->mp_ctrl_block_rpp_slice, val);
}

void rmc_nthw_ctrl_block_mac_port(const struct rmc_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_ctrl_block_mac_port, val);
}

void rmc_nthw_ctrl_lag_phy_odd_even(const struct rmc_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_ctrl_lag_phy_odd_even, val);
}

void rmc_nthw_ctrl_flush(const struct rmc_nthw *p)
{
	register_flush(p->mp_ctrl, 1);
}

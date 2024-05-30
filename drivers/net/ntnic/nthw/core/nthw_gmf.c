/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <limits.h>
#include <math.h>
#include "ntlog.h"

#include "nthw_drv.h"
#include "nthw_register.h"

#include "nthw_gmf.h"

int nthw_gmf_init(nthw_gmf_t *p, nthw_fpga_t *p_fpga, int n_instance)
{
	nthw_module_t *mod = nthw_fpga_query_module(p_fpga, MOD_GMF, n_instance);

	if (p == NULL)
		return mod == NULL ? -1 : 0;

	if (mod == NULL) {
		NT_LOG(ERR, NTHW, "%s: GMF %d: no such instance\n",
			p_fpga->p_fpga_info->mp_adapter_id_str, n_instance);
		return -1;
	}

	p->mp_fpga = p_fpga;
	p->mn_instance = n_instance;
	p->mp_mod_gmf = mod;

	p->mp_ctrl = nthw_module_get_register(p->mp_mod_gmf, GMF_CTRL);
	p->mp_ctrl_enable = nthw_register_get_field(p->mp_ctrl, GMF_CTRL_ENABLE);
	p->mp_ctrl_ifg_enable = nthw_register_get_field(p->mp_ctrl, GMF_CTRL_IFG_ENABLE);
	p->mp_ctrl_ifg_auto_adjust_enable =
		nthw_register_get_field(p->mp_ctrl, GMF_CTRL_IFG_AUTO_ADJUST_ENABLE);
	p->mp_ctrl_ts_inject_always =
		nthw_register_query_field(p->mp_ctrl, GMF_CTRL_TS_INJECT_ALWAYS);
	p->mp_ctrl_fcs_always = nthw_register_query_field(p->mp_ctrl, GMF_CTRL_FCS_ALWAYS);

	p->mp_speed = nthw_module_get_register(p->mp_mod_gmf, GMF_SPEED);
	p->mp_speed_ifg_speed = nthw_register_get_field(p->mp_speed, GMF_SPEED_IFG_SPEED);

	p->mp_ifg_clock_delta = nthw_module_get_register(p->mp_mod_gmf, GMF_IFG_SET_CLOCK_DELTA);
	p->mp_ifg_clock_delta_delta =
		nthw_register_get_field(p->mp_ifg_clock_delta, GMF_IFG_SET_CLOCK_DELTA_DELTA);

	p->mp_ifg_max_adjust_slack =
		nthw_module_get_register(p->mp_mod_gmf, GMF_IFG_MAX_ADJUST_SLACK);
	p->mp_ifg_max_adjust_slack_slack = nthw_register_get_field(p->mp_ifg_max_adjust_slack,
			GMF_IFG_MAX_ADJUST_SLACK_SLACK);

	p->mp_debug_lane_marker = nthw_module_get_register(p->mp_mod_gmf, GMF_DEBUG_LANE_MARKER);
	p->mp_debug_lane_marker_compensation =
		nthw_register_get_field(p->mp_debug_lane_marker,
			GMF_DEBUG_LANE_MARKER_COMPENSATION);

	p->mp_stat_sticky = nthw_module_get_register(p->mp_mod_gmf, GMF_STAT_STICKY);
	p->mp_stat_sticky_data_underflowed =
		nthw_register_get_field(p->mp_stat_sticky, GMF_STAT_STICKY_DATA_UNDERFLOWED);
	p->mp_stat_sticky_ifg_adjusted =
		nthw_register_get_field(p->mp_stat_sticky, GMF_STAT_STICKY_IFG_ADJUSTED);

	p->mn_param_gmf_ifg_speed_mul =
		nthw_fpga_get_product_param(p_fpga, NT_GMF_IFG_SPEED_MUL, 1);
	p->mn_param_gmf_ifg_speed_div =
		nthw_fpga_get_product_param(p_fpga, NT_GMF_IFG_SPEED_DIV, 1);

	p->m_administrative_block = false;

	p->mp_stat_next_pkt = nthw_module_query_register(p->mp_mod_gmf, GMF_STAT_NEXT_PKT);

	if (p->mp_stat_next_pkt) {
		p->mp_stat_next_pkt_ns =
			nthw_register_query_field(p->mp_stat_next_pkt, GMF_STAT_NEXT_PKT_NS);

	} else {
		p->mp_stat_next_pkt_ns = NULL;
	}

	p->mp_stat_max_delayed_pkt =
		nthw_module_query_register(p->mp_mod_gmf, GMF_STAT_MAX_DELAYED_PKT);

	if (p->mp_stat_max_delayed_pkt) {
		p->mp_stat_max_delayed_pkt_ns =
			nthw_register_query_field(p->mp_stat_max_delayed_pkt,
				GMF_STAT_MAX_DELAYED_PKT_NS);

	} else {
		p->mp_stat_max_delayed_pkt_ns = NULL;
	}

	p->mp_ctrl_ifg_tx_now_always =
		nthw_register_query_field(p->mp_ctrl, GMF_CTRL_IFG_TX_NOW_ALWAYS);
	p->mp_ctrl_ifg_tx_on_ts_always =
		nthw_register_query_field(p->mp_ctrl, GMF_CTRL_IFG_TX_ON_TS_ALWAYS);

	p->mp_ctrl_ifg_tx_on_ts_adjust_on_set_clock =
		nthw_register_query_field(p->mp_ctrl, GMF_CTRL_IFG_TX_ON_TS_ADJUST_ON_SET_CLOCK);

	p->mp_ifg_clock_delta_adjust =
		nthw_module_query_register(p->mp_mod_gmf, GMF_IFG_SET_CLOCK_DELTA_ADJUST);

	if (p->mp_ifg_clock_delta_adjust) {
		p->mp_ifg_clock_delta_adjust_delta =
			nthw_register_query_field(p->mp_ifg_clock_delta_adjust,
				GMF_IFG_SET_CLOCK_DELTA_ADJUST_DELTA);

	} else {
		p->mp_ifg_clock_delta_adjust_delta = NULL;
	}

	p->mp_ts_inject = nthw_module_query_register(p->mp_mod_gmf, GMF_TS_INJECT);

	if (p->mp_ts_inject) {
		p->mp_ts_inject_offset =
			nthw_register_query_field(p->mp_ts_inject, GMF_TS_INJECT_OFFSET);
		p->mp_ts_inject_pos =
			nthw_register_query_field(p->mp_ts_inject, GMF_TS_INJECT_POS);

	} else {
		p->mp_ts_inject_offset = NULL;
		p->mp_ts_inject_pos = NULL;
	}

	return 0;
}

void nthw_gmf_set_enable(nthw_gmf_t *p, bool enable)
{
	if (!p->m_administrative_block)
		nthw_field_set_val_flush32(p->mp_ctrl_enable, enable ? 1 : 0);
}

int nthw_gmf_set_ifg_speed_raw(nthw_gmf_t *p, uint64_t n_speed_val)
{
	if (n_speed_val <= (1ULL << (nthw_field_get_bit_width(p->mp_speed_ifg_speed) - 1))) {
		nthw_field_set_val(p->mp_speed_ifg_speed, (uint32_t *)&n_speed_val,
			(nthw_field_get_bit_width(p->mp_speed_ifg_speed) <= 32 ? 1
				: 2));
		nthw_field_flush_register(p->mp_speed_ifg_speed);
		return 0;
	}

	return -1;
}

int nthw_gmf_get_ifg_speed_bit_width(nthw_gmf_t *p)
{
	const int n_bit_width = nthw_field_get_bit_width(p->mp_speed_ifg_speed);
	/* Sanity check: GMF ver 1.2 is bw 22 - GMF ver 1.3 is bw 64 */
	assert(n_bit_width >= 22);
	return n_bit_width;
}

int nthw_gmf_set_ifg_speed_percent(nthw_gmf_t *p, const double f_rate_limit_percent)
{
	uint64_t n_speed_val;

	if (f_rate_limit_percent == 0.0 || f_rate_limit_percent == 100.0) {
		n_speed_val = 0;

	} else if (f_rate_limit_percent <= 99) {
		const int n_bit_width = (nthw_gmf_get_ifg_speed_bit_width(p) / 2);
		const double f_adj_rate =
			((double)(f_rate_limit_percent * (double)p->mn_param_gmf_ifg_speed_mul) /
				p->mn_param_gmf_ifg_speed_div / 100);
		const double f_speed = ((1UL / f_adj_rate) - 1) * exp2(n_bit_width);
		n_speed_val = (uint64_t)f_speed;

	} else {
		return -1;
	}

	return nthw_gmf_set_ifg_speed_raw(p, n_speed_val);
}

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <limits.h>
#include <math.h>
#include "ntlog.h"

#include "nthw_drv.h"
#include "nthw_register.h"

#include "nthw_gmf.h"

nthw_gmf_t *nthw_gmf_new(void)
{
	nthw_gmf_t *p = malloc(sizeof(nthw_gmf_t));

	if (p)
		memset(p, 0, sizeof(nthw_gmf_t));
	return p;
}

void nthw_gmf_delete(nthw_gmf_t *p)
{
	if (p) {
		memset(p, 0, sizeof(nthw_gmf_t));
		free(p);
	}
}

int nthw_gmf_init(nthw_gmf_t *p, nt_fpga_t *p_fpga, int n_instance)
{
	nt_module_t *mod = fpga_query_module(p_fpga, MOD_GMF, n_instance);

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

	p->mp_ctrl = module_get_register(p->mp_mod_gmf, GMF_CTRL);
	p->mp_ctrl_enable = register_get_field(p->mp_ctrl, GMF_CTRL_ENABLE);
	p->mp_ctrl_ifg_enable = register_get_field(p->mp_ctrl, GMF_CTRL_IFG_ENABLE);
	p->mp_ctrl_ifg_auto_adjust_enable =
		register_get_field(p->mp_ctrl, GMF_CTRL_IFG_AUTO_ADJUST_ENABLE);

	p->mp_speed = module_get_register(p->mp_mod_gmf, GMF_SPEED);
	p->mp_speed_ifg_speed = register_get_field(p->mp_speed, GMF_SPEED_IFG_SPEED);

	p->mp_ifg_clock_delta =
		module_get_register(p->mp_mod_gmf, GMF_IFG_SET_CLOCK_DELTA);
	p->mp_ifg_clock_delta_delta =
		register_get_field(p->mp_ifg_clock_delta, GMF_IFG_SET_CLOCK_DELTA_DELTA);

	p->mp_ifg_max_adjust_slack =
		module_get_register(p->mp_mod_gmf, GMF_IFG_MAX_ADJUST_SLACK);
	p->mp_ifg_max_adjust_slack_slack =
		register_get_field(p->mp_ifg_max_adjust_slack, GMF_IFG_MAX_ADJUST_SLACK_SLACK);

	p->mp_debug_lane_marker =
		module_get_register(p->mp_mod_gmf, GMF_DEBUG_LANE_MARKER);
	p->mp_debug_lane_marker_compensation =
		register_get_field(p->mp_debug_lane_marker, GMF_DEBUG_LANE_MARKER_COMPENSATION);

	p->mp_stat_sticky = module_get_register(p->mp_mod_gmf, GMF_STAT_STICKY);
	p->mp_stat_sticky_data_underflowed =
		register_get_field(p->mp_stat_sticky, GMF_STAT_STICKY_DATA_UNDERFLOWED);
	p->mp_stat_sticky_ifg_adjusted =
		register_get_field(p->mp_stat_sticky, GMF_STAT_STICKY_IFG_ADJUSTED);

	p->mn_param_gmf_ifg_speed_mul =
		fpga_get_product_param(p_fpga, NT_GMF_IFG_SPEED_MUL, 1);
	p->mn_param_gmf_ifg_speed_div =
		fpga_get_product_param(p_fpga, NT_GMF_IFG_SPEED_DIV, 1);

	p->m_administrative_block = false;

	p->mp_stat_next_pkt = module_query_register(p->mp_mod_gmf, GMF_STAT_NEXT_PKT);
	if (p->mp_stat_next_pkt) {
		p->mp_stat_next_pkt_ns =
			register_query_field(p->mp_stat_next_pkt,
					     GMF_STAT_NEXT_PKT_NS);
	} else {
		p->mp_stat_next_pkt_ns = NULL;
	}
	p->mp_stat_max_delayed_pkt =
		module_query_register(p->mp_mod_gmf, GMF_STAT_MAX_DELAYED_PKT);
	if (p->mp_stat_max_delayed_pkt) {
		p->mp_stat_max_delayed_pkt_ns =
			register_query_field(p->mp_stat_max_delayed_pkt,
					     GMF_STAT_MAX_DELAYED_PKT_NS);
	} else {
		p->mp_stat_max_delayed_pkt_ns = NULL;
	}
	p->mp_ctrl_ifg_tx_now_always =
		register_query_field(p->mp_ctrl, GMF_CTRL_IFG_TX_NOW_ALWAYS);
	p->mp_ctrl_ifg_tx_on_ts_always =
		register_query_field(p->mp_ctrl, GMF_CTRL_IFG_TX_ON_TS_ALWAYS);

	p->mp_ctrl_ifg_tx_on_ts_adjust_on_set_clock =
		register_query_field(p->mp_ctrl, GMF_CTRL_IFG_TX_ON_TS_ADJUST_ON_SET_CLOCK);

	p->mp_ifg_clock_delta_adjust =
		module_query_register(p->mp_mod_gmf, GMF_IFG_SET_CLOCK_DELTA_ADJUST);
	if (p->mp_ifg_clock_delta_adjust) {
		p->mp_ifg_clock_delta_adjust_delta =
			register_query_field(p->mp_ifg_clock_delta_adjust,
					     GMF_IFG_SET_CLOCK_DELTA_ADJUST_DELTA);
	} else {
		p->mp_ifg_clock_delta_adjust_delta = NULL;
	}
	return 0;
}

void nthw_gmf_set_enable(nthw_gmf_t *p, bool enable)
{
	if (!p->m_administrative_block)
		field_set_val_flush32(p->mp_ctrl_enable, enable ? 1 : 0);
}

void nthw_gmf_set_ifg_enable(nthw_gmf_t *p, bool enable)
{
	field_set_val_flush32(p->mp_ctrl_ifg_enable, enable ? 1 : 0);
}

void nthw_gmf_set_tx_now_always_enable(nthw_gmf_t *p, bool enable)
{
	if (p->mp_ctrl_ifg_tx_now_always)
		field_set_val_flush32(p->mp_ctrl_ifg_tx_now_always, enable ? 1 : 0);
}

void nthw_gmf_set_tx_on_ts_always_enable(nthw_gmf_t *p, bool enable)
{
	if (p->mp_ctrl_ifg_tx_on_ts_always)
		field_set_val_flush32(p->mp_ctrl_ifg_tx_on_ts_always, enable ? 1 : 0);
}

void nthw_gmf_set_tx_on_ts_adjust_on_set_clock(nthw_gmf_t *p, bool enable)
{
	if (p->mp_ctrl_ifg_tx_on_ts_adjust_on_set_clock) {
		field_set_val_flush32(p->mp_ctrl_ifg_tx_on_ts_adjust_on_set_clock,
				    enable ? 1 : 0);
	}
}

void nthw_gmf_set_ifg_auto_adjust_enable(nthw_gmf_t *p, bool enable)
{
	field_set_val_flush32(p->mp_ctrl_ifg_auto_adjust_enable, enable);
}

int nthw_gmf_set_ifg_speed_raw(nthw_gmf_t *p, uint64_t n_speed_val)
{
	if (n_speed_val <=
			(1ULL << (field_get_bit_width(p->mp_speed_ifg_speed) - 1))) {
		field_set_val(p->mp_speed_ifg_speed, (uint32_t *)&n_speed_val,
			     (field_get_bit_width(p->mp_speed_ifg_speed) <= 32 ? 1 :
			      2));
		field_flush_register(p->mp_speed_ifg_speed);
		return 0;
	}
	return -1;
}

int nthw_gmf_get_ifg_speed_bit_width(nthw_gmf_t *p)
{
	const int n_bit_width = field_get_bit_width(p->mp_speed_ifg_speed);

	assert(n_bit_width >=
	       22); /* Sanity check: GMF ver 1.2 is bw 22 - GMF ver 1.3 is bw 64 */
	return n_bit_width;
}

int nthw_gmf_set_ifg_speed_bits(nthw_gmf_t *p, const uint64_t n_rate_limit_bits,
			    const uint64_t n_link_speed)
{
	const int n_bit_width = (nthw_gmf_get_ifg_speed_bit_width(p) / 2);
	const double f_adj_rate =
		((double)((((double)n_rate_limit_bits) / (double)n_link_speed) *
			  p->mn_param_gmf_ifg_speed_mul) /
		 p->mn_param_gmf_ifg_speed_div);
	const double f_speed = ((1UL / f_adj_rate) - 1) * exp2(n_bit_width);
	uint64_t n_speed_val = (uint64_t)round(f_speed);

	return nthw_gmf_set_ifg_speed_raw(p, n_speed_val);
}

int nthw_gmf_set_ifg_speed_percent(nthw_gmf_t *p, const double f_rate_limit_percent)
{
	uint64_t n_speed_val;

	if (f_rate_limit_percent == 0.0 || f_rate_limit_percent == 100.0) {
		n_speed_val = 0;
	} else if (f_rate_limit_percent <= 99) {
		const int n_bit_width = (nthw_gmf_get_ifg_speed_bit_width(p) / 2);
		const double f_adj_rate =
			((double)(f_rate_limit_percent *
				  (double)p->mn_param_gmf_ifg_speed_mul) /
			 p->mn_param_gmf_ifg_speed_div / 100);
		const double f_speed = ((1UL / f_adj_rate) - 1) * exp2(n_bit_width);

		n_speed_val = (uint64_t)f_speed;
	} else {
		return -1;
	}

	return nthw_gmf_set_ifg_speed_raw(p, n_speed_val);
}

void nthw_gmf_set_delta(nthw_gmf_t *p, uint64_t delta)
{
	field_set_val(p->mp_ifg_clock_delta_delta, (uint32_t *)&delta, 2);
	field_flush_register(p->mp_ifg_clock_delta_delta);
}

void nthw_gmf_set_delta_adjust(nthw_gmf_t *p, uint64_t delta_adjust)
{
	if (p->mp_ifg_clock_delta_adjust) {
		field_set_val(p->mp_ifg_clock_delta_adjust_delta,
			     (uint32_t *)&delta_adjust, 2);
		field_flush_register(p->mp_ifg_clock_delta_adjust_delta);
	}
}

void nthw_gmf_set_slack(nthw_gmf_t *p, uint64_t slack)
{
	field_set_val(p->mp_ifg_max_adjust_slack_slack, (uint32_t *)&slack, 2);
	field_flush_register(p->mp_ifg_max_adjust_slack_slack);
}

void nthw_gmf_set_compensation(nthw_gmf_t *p, uint32_t compensation)
{
	field_set_val_flush32(p->mp_debug_lane_marker_compensation, compensation);
}

uint32_t nthw_gmf_get_status_sticky(nthw_gmf_t *p)
{
	uint32_t status = 0;

	register_update(p->mp_stat_sticky);

	if (field_get_val32(p->mp_stat_sticky_data_underflowed))
		status |= GMF_STATUS_MASK_DATA_UNDERFLOWED;
	if (field_get_val32(p->mp_stat_sticky_ifg_adjusted))
		status |= GMF_STATUS_MASK_IFG_ADJUSTED;

	return status;
}

void nthw_gmf_set_status_sticky(nthw_gmf_t *p, uint32_t status)
{
	if (status & GMF_STATUS_MASK_DATA_UNDERFLOWED)
		field_set_flush(p->mp_stat_sticky_data_underflowed);
	if (status & GMF_STATUS_MASK_IFG_ADJUSTED)
		field_set_flush(p->mp_stat_sticky_ifg_adjusted);
}

uint64_t nthw_gmf_get_stat_next_pkt_ns(nthw_gmf_t *p)
{
	uint64_t value = ULONG_MAX;

	if (p->mp_stat_next_pkt) {
		register_update(p->mp_stat_next_pkt);
		field_get_val(p->mp_stat_next_pkt_ns, (uint32_t *)&value, 2);
	}
	return value;
}

uint64_t nthw_gmf_get_stat_max_pk_delayedt_ns(nthw_gmf_t *p)
{
	uint64_t value = ULONG_MAX;

	if (p->mp_stat_max_delayed_pkt) {
		register_update(p->mp_stat_max_delayed_pkt);
		field_get_val(p->mp_stat_max_delayed_pkt_ns, (uint32_t *)&value, 2);
	}
	return value;
}

void nthw_gmf_administrative_block(nthw_gmf_t *p)
{
	nthw_gmf_set_enable(p, false);
	p->m_administrative_block = true;
}

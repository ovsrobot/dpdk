/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __NTHW_GMF_H__
#define __NTHW_GMF_H__

enum gmf_status_mask {
	GMF_STATUS_MASK_DATA_UNDERFLOWED = 1,
	GMF_STATUS_MASK_IFG_ADJUSTED
};

struct nthw_gmf {
	nt_fpga_t *mp_fpga;
	nt_module_t *mp_mod_gmf;
	int mn_instance;
	/*  */

	nt_register_t *mp_ctrl;
	nt_field_t *mp_ctrl_enable;
	nt_field_t *mp_ctrl_ifg_enable;
	nt_field_t *mp_ctrl_ifg_tx_now_always;
	nt_field_t *mp_ctrl_ifg_tx_on_ts_always;
	nt_field_t *mp_ctrl_ifg_tx_on_ts_adjust_on_set_clock;
	nt_field_t *mp_ctrl_ifg_auto_adjust_enable;

	nt_register_t *mp_speed;
	nt_field_t *mp_speed_ifg_speed;

	nt_register_t *mp_ifg_clock_delta;
	nt_field_t *mp_ifg_clock_delta_delta;

	nt_register_t *mp_ifg_clock_delta_adjust;
	nt_field_t *mp_ifg_clock_delta_adjust_delta;

	nt_register_t *mp_ifg_max_adjust_slack;
	nt_field_t *mp_ifg_max_adjust_slack_slack;

	nt_register_t *mp_debug_lane_marker;
	nt_field_t *mp_debug_lane_marker_compensation;

	nt_register_t *mp_stat_sticky;
	nt_field_t *mp_stat_sticky_data_underflowed;
	nt_field_t *mp_stat_sticky_ifg_adjusted;

	nt_register_t *mp_stat_next_pkt;
	nt_field_t *mp_stat_next_pkt_ns;

	nt_register_t *mp_stat_max_delayed_pkt;
	nt_field_t *mp_stat_max_delayed_pkt_ns;

	int mn_param_gmf_ifg_speed_mul;
	int mn_param_gmf_ifg_speed_div;

	bool m_administrative_block; /* Used to enforce license expiry */
};

typedef struct nthw_gmf nthw_gmf_t;
typedef struct nthw_gmf nthw_gmf;

nthw_gmf_t *nthw_gmf_new(void);
void nthw_gmf_delete(nthw_gmf_t *p);
int nthw_gmf_init(nthw_gmf_t *p, nt_fpga_t *p_fpga, int n_instance);

void nthw_gmf_set_enable(nthw_gmf_t *p, bool enable);
void nthw_gmf_set_ifg_enable(nthw_gmf_t *p, bool enable);

void nthw_gmf_set_tx_now_always_enable(nthw_gmf_t *p, bool enable);
void nthw_gmf_set_tx_on_ts_always_enable(nthw_gmf_t *p, bool enable);
void nthw_gmf_set_tx_on_ts_adjust_on_set_clock(nthw_gmf_t *p, bool enable);
void nthw_gmf_set_ifg_auto_adjust_enable(nthw_gmf_t *p, bool enable);

int nthw_gmf_get_ifg_speed_bit_width(nthw_gmf_t *p);

int nthw_gmf_set_ifg_speed_raw(nthw_gmf_t *p, uint64_t n_speed_val);
int nthw_gmf_set_ifg_speed_bits(nthw_gmf_t *p, const uint64_t n_rate_limit_bits,
			    const uint64_t n_link_speed);
int nthw_gmf_set_ifg_speed_percent(nthw_gmf_t *p, const double f_rate_limit_percent);

void nthw_gmf_set_delta(nthw_gmf_t *p, uint64_t delta);
void nthw_gmf_set_delta_adjust(nthw_gmf_t *p, uint64_t delta_adjust);
void nthw_gmf_set_slack(nthw_gmf_t *p, uint64_t slack);
void nthw_gmf_set_compensation(nthw_gmf_t *p, uint32_t compensation);

uint32_t nthw_gmf_get_status_sticky(nthw_gmf_t *p);
void nthw_gmf_set_status_sticky(nthw_gmf_t *p, uint32_t status);

uint64_t nthw_gmf_get_stat_next_pkt_ns(nthw_gmf_t *p);
uint64_t nthw_gmf_get_stat_max_pk_delayedt_ns(nthw_gmf_t *p);

void nthw_gmf_administrative_block(nthw_gmf_t *p); /* Used to enforce license expiry blocking */

#endif /* __NTHW_GMF_H__ */

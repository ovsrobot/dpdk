/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef NTHW_MAC_PCS_XXV_H_
#define NTHW_MAC_PCS_XXV_H_

#include <stdint.h>
#include <stdbool.h>
#include "nthw_fpga_model.h"

enum nthw_mac_pcs_xxv_led_mode_e {
	NTHW_MAC_PCS_XXV_LED_AUTO = 0x00,
	NTHW_MAC_PCS_XXV_LED_ON = 0x01,
	NTHW_MAC_PCS_XXV_LED_OFF = 0x02,
	NTHW_MAC_PCS_XXV_LED_PORTID = 0x03,
};

enum nthw_mac_pcs_xxv_dac_mode_e {
	NTHW_MAC_PCS_XXV_DAC_OFF = 0x00,
	NTHW_MAC_PCS_XXV_DAC_CA_25G_N = 0x01,
	NTHW_MAC_PCS_XXV_DAC_CA_25G_S = 0x02,
	NTHW_MAC_PCS_XXV_DAC_CA_25G_L = 0x03,
};

struct nthw_mac_pcs_xxv {
	nthw_fpga_t *mp_fpga;
	nthw_module_t *mp_mod_mac_pcs_xxv;
	int mn_instance;

	uint8_t m_port_no;
	bool m_mac_8x10G;

#define NTHW_MAC_PCS_XXV_NUM_ELEMS 4
	struct nthw_mac_pcs_xxv_registers_fields {
		/* CORE_CONF */
		nthw_register_t *mp_reg_core_conf;
		nthw_field_t *mp_fld_core_conf_rx_enable;
		nthw_field_t *mp_fld_core_conf_rx_force_resync;
		nthw_field_t *mp_fld_core_conf_tx_enable;
		nthw_field_t *mp_fld_core_conf_tx_ins_fcs;
		nthw_field_t *mp_fld_core_conf_tx_ign_fcs;
		nthw_field_t *mp_fld_core_conf_tx_send_lfi;
		nthw_field_t *mp_fld_core_conf_tx_send_rfi;
		nthw_field_t *mp_fld_core_conf_tx_send_idle;
		nthw_field_t *mp_fld_core_conf_inline_mode;
		nthw_field_t *mp_fld_core_conf_line_loopback;
		nthw_field_t *mp_fld_core_conf_ts_at_eop;

		/* ANEG_CONFIG */
		nthw_register_t *mp_reg_aneg_config;
		nthw_field_t *mp_fld_aneg_config_enable;
		nthw_field_t *mp_fld_aneg_config_bypass;
		nthw_field_t *mp_fld_aneg_config_restart;
		nthw_field_t *mp_fld_aneg_config_pseudo;
		nthw_field_t *mp_fld_aneg_config_nonce_seed;
		nthw_field_t *mp_fld_aneg_config_remote_fault;
		nthw_field_t *mp_fld_aneg_config_pause;
		nthw_field_t *mp_fld_aneg_config_asmdir;
		nthw_field_t *mp_fld_aneg_config_fec74_request10g;
		nthw_field_t *mp_fld_aneg_config_hide_fec74;
		nthw_field_t *mp_fld_aneg_config_fec74_request;
		nthw_field_t *mp_fld_aneg_config_fec91_request;
		nthw_field_t *mp_fld_aneg_config_fec91_ability;
		nthw_field_t *mp_fld_aneg_config_rs_fec_request;
		nthw_field_t *mp_fld_aneg_config_sw_fec_overwrite;
		nthw_field_t *mp_fld_aneg_config_sw_speed_overwrite;

		/* ANEG_ABILITY */
		nthw_register_t *mp_reg_aneg_ability;
		nthw_field_t *mp_fld_aneg_ability_25g_base_cr;
		nthw_field_t *mp_fld_aneg_ability_25g_base_crs;
		nthw_field_t *mp_fld_aneg_ability_25g_base_cr1;

		/* LT_CONF */
		nthw_register_t *mp_reg_lt_conf;
		nthw_field_t *mp_fld_lt_conf_enable;
		nthw_field_t *mp_fld_lt_conf_restart;
		nthw_field_t *mp_fld_lt_conf_seed;

		/* SUB_RST */
		nthw_register_t *mp_reg_sub_rst;
		nthw_field_t *mp_fld_sub_rst_rx_mac_pcs;
		nthw_field_t *mp_fld_sub_rst_tx_mac_pcs;
		nthw_field_t *mp_fld_sub_rst_rx_gt_data;
		nthw_field_t *mp_fld_sub_rst_tx_gt_data;
		nthw_field_t *mp_fld_sub_rst_rx_buf;
		nthw_field_t *mp_fld_sub_rst_rx_pma;
		nthw_field_t *mp_fld_sub_rst_tx_pma;
		nthw_field_t *mp_fld_sub_rst_rx_pcs;
		nthw_field_t *mp_fld_sub_rst_tx_pcs;
		nthw_field_t *mp_fld_sub_rst_an_lt;
		nthw_field_t *mp_fld_sub_rst_speed_ctrl;

		/* SUB_RST_STATUS */
		nthw_register_t *mp_reg_sub_rst_status;
		nthw_field_t *mp_fld_sub_rst_status_user_rx_rst;
		nthw_field_t *mp_fld_sub_rst_status_user_tx_rst;
		nthw_field_t *mp_fld_sub_rst_status_qpll_lock;

		/* LINK_SUMMARY */
		nthw_register_t *mp_reg_link_summary;
		nthw_field_t *mp_fld_link_summary_nt_phy_link_state;
		nthw_field_t *mp_fld_link_summary_ll_nt_phy_link_state;
		nthw_field_t *mp_fld_link_summary_abs;
		nthw_field_t *mp_fld_link_summary_lh_abs;
		nthw_field_t *mp_fld_link_summary_link_down_cnt;
		/* Begin 2 x 10/25 Gbps only fields: */
		nthw_field_t *mp_fld_link_summary_ll_rx_fec74_lock;
		nthw_field_t *mp_fld_link_summary_lh_rx_rsfec_hi_ser;
		nthw_field_t *mp_fld_link_summary_ll_rx_rsfec_lane_alignment;
		nthw_field_t *mp_fld_link_summary_ll_tx_rsfec_lane_alignment;
		nthw_field_t *mp_fld_link_summary_lh_rx_pcs_valid_ctrl_code;
		/* End 2 x 10/25 Gbps only fields. */
		nthw_field_t *mp_fld_link_summary_ll_rx_block_lock;
		nthw_field_t *mp_fld_link_summary_lh_rx_high_bit_error_rate;
		nthw_field_t *mp_fld_link_summary_lh_internal_local_fault;
		nthw_field_t *mp_fld_link_summary_lh_received_local_fault;
		nthw_field_t *mp_fld_link_summary_lh_local_fault;
		nthw_field_t *mp_fld_link_summary_lh_remote_fault;
		nthw_field_t *mp_fld_link_summary_lh_tx_local_fault;
		nthw_field_t *mp_fld_link_summary_nim_interr;

		/* GTY_LOOP */
		nthw_register_t *mp_reg_gty_loop;
		nthw_field_t *mp_fld_gty_loop_gt_loop;

		/* GTY_CTL_RX */
		nthw_register_t *mp_reg_gty_ctl_rx;
		nthw_field_t *mp_fld_gty_ctl_rx_polarity;
		nthw_field_t *mp_fld_gty_ctl_rx_lpm_en;
		nthw_field_t *mp_fld_gty_ctl_rx_equa_rst;

		/* GTY_CTL_TX */
		nthw_register_t *mp_reg_gty_ctl_tx;
		nthw_field_t *mp_fld_gty_ctl_tx_polarity;
		nthw_field_t *mp_fld_gty_ctl_tx_inhibit;

		/* LINK_SPEED */
		nthw_register_t *mp_reg_link_speed;
		nthw_field_t *mp_fld_link_speed_10g;
		nthw_field_t *mp_fld_link_speed_toggle;

		/* RS_FEC_CONF */
		nthw_register_t *mp_reg_rs_fec_conf;
		nthw_field_t *mp_fld_rs_fec_conf_rs_fec_enable;

		/* DEBOUNCE_CTRL */
		nthw_register_t *mp_reg_debounce_ctrl;
		nthw_field_t *mp_field_debounce_ctrl_nt_port_ctrl;

		/* FEC_CCW_CNT */
		nthw_register_t *mp_reg_rs_fec_ccw;
		nthw_field_t *mp_field_reg_rs_fec_ccw_reg_rs_fec_ccw_cnt;

		/* FEC_UCW_CNT */
		nthw_register_t *mp_reg_rs_fec_ucw;
		nthw_field_t *mp_field_reg_rs_fec_ucw_reg_rs_fec_ucw_cnt;

		/* TIMESTAMP_COMP */
		nthw_register_t *mp_reg_timestamp_comp;
		nthw_field_t *mp_field_timestamp_comp_rx_dly;
		nthw_field_t *mp_field_timestamp_comp_tx_dly;

		/* GTY_PRE_CURSOR */
		nthw_register_t *mp_reg_gty_pre_cursor;
		nthw_field_t *mp_field_gty_pre_cursor_tx_pre_csr;

		/* GTY_DIFF_CTL */
		nthw_register_t *mp_reg_gty_diff_ctl;
		nthw_field_t *mp_field_gty_gty_diff_ctl_tx_diff_ctl;

		/* GTY_POST_CURSOR */
		nthw_register_t *mp_reg_gty_post_cursor;
		nthw_field_t *mp_field_gty_post_cursor_tx_post_csr;
	} regs[NTHW_MAC_PCS_XXV_NUM_ELEMS];
};

typedef struct nthw_mac_pcs_xxv nthw_mac_pcs_xxv_t;
typedef struct nthw_mac_pcs_xxv nthw_mac_pcs_xxv;

nthw_mac_pcs_xxv_t *nthw_mac_pcs_xxv_new(void);
void nthw_mac_pcs_xxv_delete(nthw_mac_pcs_xxv_t *p);
int nthw_mac_pcs_xxv_init(nthw_mac_pcs_xxv_t *p,
	nthw_fpga_t *p_fpga,
	int n_instance,
	int n_channels,
	bool mac_8x10G);

void nthw_mac_pcs_xxv_get_link_summary(nthw_mac_pcs_xxv_t *p,
	uint32_t *p_abs,
	uint32_t *p_nt_phy_link_state,
	uint32_t *p_lh_abs,
	uint32_t *p_ll_nt_phy_link_state,
	uint32_t *p_link_down_cnt,
	uint32_t *p_nim_interr,
	uint32_t *p_lh_local_fault,
	uint32_t *p_lh_remote_fault,
	uint32_t *p_lh_internal_local_fault,
	uint32_t *p_lh_received_local_fault,
	uint8_t index);

void nthw_mac_pcs_xxv_reset_rx_gt_data(nthw_mac_pcs_xxv_t *p, bool enable, uint8_t index);

void nthw_mac_pcs_xxv_set_rx_mac_pcs_rst(nthw_mac_pcs_xxv_t *p, bool enable, uint8_t index);

#endif	/* NTHW_MAC_PCS_XXV_H_ */

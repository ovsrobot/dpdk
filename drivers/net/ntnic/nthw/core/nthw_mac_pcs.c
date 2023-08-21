/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "nt_util.h"
#include "ntlog.h"

#include "nthw_drv.h"
#include "nthw_register.h"

#include "nthw_mac_pcs.h"

#define NTHW_MAC_PCS_LANES (20)

static const uint8_t c_pcs_lanes = NTHW_MAC_PCS_LANES;
static const uint8_t c_mac_pcs_receiver_mode_dfe _unused;

nthw_mac_pcs_t *nthw_mac_pcs_new(void)
{
	nthw_mac_pcs_t *p = malloc(sizeof(nthw_mac_pcs_t));

	if (p)
		memset(p, 0, sizeof(nthw_mac_pcs_t));
	return p;
}

void nthw_mac_pcs_delete(nthw_mac_pcs_t *p)
{
	if (p) {
		memset(p, 0, sizeof(nthw_mac_pcs_t));
		free(p);
	}
}

/*
 * Parameters:
 *   p != NULL: init struct pointed to by p
 *   p == NULL: check fpga module(s) presence (but no struct to init)
 *
 * Return value:
 *  <0: if p == NULL then fpga module(s) is/are not present.
 *      if p != NULL then fpga module(s) is/are not present, struct undefined
 * ==0: if p == NULL then fpga module(s) is/are present (no struct to init)
 *    : if p != NULL then fpga module(s) is/are present and struct initialized
 */
int nthw_mac_pcs_init(nthw_mac_pcs_t *p, nt_fpga_t *p_fpga, int n_instance)
{
	nt_module_t *mod = fpga_query_module(p_fpga, MOD_MAC_PCS, n_instance);

	if (p == NULL)
		return mod == NULL ? -1 : 0;

	if (mod == NULL) {
		NT_LOG(ERR, NTHW, "%s: MAC_PCS %d: no such instance\n",
		       p_fpga->p_fpga_info->mp_adapter_id_str, n_instance);
		return -1;
	}

	p->mp_fpga = p_fpga;
	p->mn_instance = n_instance;
	p->mp_mod_mac_pcs = mod;

	assert(n_instance >= 0 && n_instance <= 255);
	nthw_mac_pcs_set_port_no(p, (uint8_t)n_instance);

	{
		nt_register_t *p_reg_block_lock, *p_reg_stat_pcs_rx,
			      *p_reg_stat_pcs_rx_latch;
		nt_register_t *p_reg_vl_demuxed, *p_reg_gty_stat, *p_reg_pcs_config,
			      *p_reg_phymac_misc;
		const int product_id = fpga_get_product_id(p_fpga);

		p_reg_block_lock =
			module_get_register(p->mp_mod_mac_pcs, MAC_PCS_BLOCK_LOCK);
		p->mp_reg_block_lock = p_reg_block_lock;
		p->mp_fld_block_lock_lock =
			register_get_field(p_reg_block_lock, MAC_PCS_BLOCK_LOCK_LOCK);

		p_reg_stat_pcs_rx =
			module_get_register(p->mp_mod_mac_pcs, MAC_PCS_STAT_PCS_RX);
		p->mp_reg_stat_pcs_rx = p_reg_stat_pcs_rx;
		p->mp_fld_stat_pcs_rx_status =
			register_get_field(p_reg_stat_pcs_rx, MAC_PCS_STAT_PCS_RX_STATUS);
		p->mp_fld_stat_pcs_rx_aligned =
			register_get_field(p_reg_stat_pcs_rx, MAC_PCS_STAT_PCS_RX_ALIGNED);
		p->mp_fld_stat_pcs_rx_aligned_err =
			register_get_field(p_reg_stat_pcs_rx, MAC_PCS_STAT_PCS_RX_ALIGNED_ERR);
		p->mp_fld_stat_pcs_rx_misaligned =
			register_get_field(p_reg_stat_pcs_rx, MAC_PCS_STAT_PCS_RX_MISALIGNED);
		p->mp_fld_stat_pcs_rx_internal_local_fault =
			register_get_field(p_reg_stat_pcs_rx,
					   MAC_PCS_STAT_PCS_RX_INTERNAL_LOCAL_FAULT);
		p->mp_fld_stat_pcs_rx_received_local_fault =
			register_get_field(p_reg_stat_pcs_rx,
					   MAC_PCS_STAT_PCS_RX_RECEIVED_LOCAL_FAULT);
		p->mp_fld_stat_pcs_rx_local_fault =
			register_get_field(p_reg_stat_pcs_rx,
					   MAC_PCS_STAT_PCS_RX_LOCAL_FAULT);
		p->mp_fld_stat_pcs_rx_remote_fault =
			register_get_field(p_reg_stat_pcs_rx,
					   MAC_PCS_STAT_PCS_RX_REMOTE_FAULT);
		p->mp_fld_stat_pcs_rx_hi_ber =
			register_get_field(p_reg_stat_pcs_rx,
					   MAC_PCS_STAT_PCS_RX_HI_BER);

		p_reg_stat_pcs_rx_latch =
			module_get_register(p->mp_mod_mac_pcs,
					    MAC_PCS_STAT_PCS_RX_LATCH);
		p->mp_reg_stat_pcs_rx_latch = p_reg_stat_pcs_rx_latch;
		p->mp_fld_stat_pcs_rx_latch_status =
			register_get_field(p_reg_stat_pcs_rx_latch,
					   MAC_PCS_STAT_PCS_RX_LATCH_STATUS);

		p_reg_vl_demuxed =
			module_get_register(p->mp_mod_mac_pcs, MAC_PCS_VL_DEMUXED);
		p->mp_fld_vl_demuxed_lock =
			register_get_field(p_reg_vl_demuxed, MAC_PCS_VL_DEMUXED_LOCK);

		p_reg_gty_stat =
			module_get_register(p->mp_mod_mac_pcs, MAC_PCS_GTY_STAT);
		p->mp_fld_gty_stat_tx_rst_done0 =
			register_get_field(p_reg_gty_stat, MAC_PCS_GTY_STAT_TX_RST_DONE_0);
		p->mp_fld_gty_stat_tx_rst_done1 =
			register_get_field(p_reg_gty_stat, MAC_PCS_GTY_STAT_TX_RST_DONE_1);
		p->mp_fld_gty_stat_tx_rst_done2 =
			register_get_field(p_reg_gty_stat, MAC_PCS_GTY_STAT_TX_RST_DONE_2);
		p->mp_fld_gty_stat_tx_rst_done3 =
			register_get_field(p_reg_gty_stat, MAC_PCS_GTY_STAT_TX_RST_DONE_3);
		p->mp_fld_gty_stat_rx_rst_done0 =
			register_get_field(p_reg_gty_stat, MAC_PCS_GTY_STAT_RX_RST_DONE_0);
		p->mp_fld_gty_stat_rx_rst_done1 =
			register_get_field(p_reg_gty_stat, MAC_PCS_GTY_STAT_RX_RST_DONE_1);
		p->mp_fld_gty_stat_rx_rst_done2 =
			register_get_field(p_reg_gty_stat, MAC_PCS_GTY_STAT_RX_RST_DONE_2);
		p->mp_fld_gty_stat_rx_rst_done3 =
			register_get_field(p_reg_gty_stat, MAC_PCS_GTY_STAT_RX_RST_DONE_3);

		p->m_fld_block_lock_lock_mask = 0;
		p->m_fld_vl_demuxed_lock_mask = 0;
		p->m_fld_gty_stat_tx_rst_done_mask = 0;
		p->m_fld_gty_stat_rx_rst_done_mask = 0;

		if (product_id == 9563) {
			/* NT200A01_2X100 implements 20 virtual lanes */
			p->m_fld_block_lock_lock_mask = (1 << 20) - 1;
			/* NT200A01_2X100 implements 20 virtual lanes */
			p->m_fld_vl_demuxed_lock_mask = (1 << 20) - 1;
			p->m_fld_gty_stat_tx_rst_done_mask =
				1; /* NT200A01_2X100 implements 4 GTY */
			p->m_fld_gty_stat_rx_rst_done_mask =
				1; /* NT200A01_2X100 implements 4 GTY */
		} else {
			/* Remember to add new productIds */
			assert(0);
		}

		p_reg_pcs_config = module_get_register(p->mp_mod_mac_pcs,
						   MAC_PCS_MAC_PCS_CONFIG);
		p->mp_fld_pcs_config_tx_path_rst =
			register_get_field(p_reg_pcs_config, MAC_PCS_MAC_PCS_CONFIG_TX_PATH_RST);
		p->mp_fld_pcs_config_rx_path_rst =
			register_get_field(p_reg_pcs_config, MAC_PCS_MAC_PCS_CONFIG_RX_PATH_RST);
		p->mp_fld_pcs_config_rx_enable =
			register_get_field(p_reg_pcs_config, MAC_PCS_MAC_PCS_CONFIG_RX_ENABLE);
		p->mp_fld_pcs_config_rx_force_resync =
			register_get_field(p_reg_pcs_config,
					   MAC_PCS_MAC_PCS_CONFIG_RX_FORCE_RESYNC);
		p->mp_fld_pcs_config_rx_test_pattern =
			register_get_field(p_reg_pcs_config,
					   MAC_PCS_MAC_PCS_CONFIG_RX_TEST_PATTERN);
		p->mp_fld_pcs_config_tx_enable =
			register_get_field(p_reg_pcs_config,
					   MAC_PCS_MAC_PCS_CONFIG_TX_ENABLE);
		p->mp_fld_pcs_config_tx_send_idle =
			register_get_field(p_reg_pcs_config,
					   MAC_PCS_MAC_PCS_CONFIG_TX_SEND_IDLE);
		p->mp_fld_pcs_config_tx_send_rfi =
			register_get_field(p_reg_pcs_config,
					   MAC_PCS_MAC_PCS_CONFIG_TX_SEND_RFI);
		p->mp_fld_pcs_config_tx_test_pattern =
			register_get_field(p_reg_pcs_config,
					   MAC_PCS_MAC_PCS_CONFIG_TX_TEST_PATTERN);

		p->mp_reg_gty_loop =
			module_get_register(p->mp_mod_mac_pcs, MAC_PCS_GTY_LOOP);
		p->mp_fld_gty_loop_gt_loop0 =
			register_get_field(p->mp_reg_gty_loop, MAC_PCS_GTY_LOOP_GT_LOOP_0);
		p->mp_fld_gty_loop_gt_loop1 =
			register_get_field(p->mp_reg_gty_loop, MAC_PCS_GTY_LOOP_GT_LOOP_1);
		p->mp_fld_gty_loop_gt_loop2 =
			register_get_field(p->mp_reg_gty_loop, MAC_PCS_GTY_LOOP_GT_LOOP_2);
		p->mp_fld_gty_loop_gt_loop3 =
			register_get_field(p->mp_reg_gty_loop, MAC_PCS_GTY_LOOP_GT_LOOP_3);

		p_reg_phymac_misc =
			module_get_register(p->mp_mod_mac_pcs, MAC_PCS_PHYMAC_MISC);
		p->mp_reg_phymac_misc = p_reg_phymac_misc;
		p->mp_fld_phymac_misc_tx_sel_host =
			register_get_field(p_reg_phymac_misc, MAC_PCS_PHYMAC_MISC_TX_SEL_HOST);
		p->mp_fld_phymac_misc_tx_sel_tfg =
			register_get_field(p_reg_phymac_misc, MAC_PCS_PHYMAC_MISC_TX_SEL_TFG);
		p->mp_fld_phymac_misc_tx_sel_rx_loop =
			register_get_field(p_reg_phymac_misc, MAC_PCS_PHYMAC_MISC_TX_SEL_RX_LOOP);

		/* SOP or EOP TIMESTAMP */
		p->mp_fld_phymac_misc_ts_eop =
			register_query_field(p_reg_phymac_misc, MAC_PCS_PHYMAC_MISC_TS_EOP);

		p->mp_reg_link_summary =
			module_get_register(p->mp_mod_mac_pcs, MAC_PCS_LINK_SUMMARY);
		p->mp_fld_link_summary_abs =
			register_get_field(p->mp_reg_link_summary, MAC_PCS_LINK_SUMMARY_ABS);
		p->mp_fld_link_summary_nt_phy_link_state =
			register_get_field(p->mp_reg_link_summary,
					   MAC_PCS_LINK_SUMMARY_NT_PHY_LINK_STATE);
		p->mp_fld_link_summary_lh_abs =
			register_get_field(p->mp_reg_link_summary, MAC_PCS_LINK_SUMMARY_LH_ABS);
		p->mp_fld_link_summary_ll_nt_phy_link_state =
			register_get_field(p->mp_reg_link_summary,
					   MAC_PCS_LINK_SUMMARY_LL_PHY_LINK_STATE);
		p->mp_fld_link_summary_link_down_cnt =
			register_get_field(p->mp_reg_link_summary,
					   MAC_PCS_LINK_SUMMARY_LINK_DOWN_CNT);
		p->mp_fld_link_summary_nim_interr =
			register_get_field(p->mp_reg_link_summary,
					   MAC_PCS_LINK_SUMMARY_NIM_INTERR);
		p->mp_fld_link_summary_lh_local_fault =
			register_get_field(p->mp_reg_link_summary,
					   MAC_PCS_LINK_SUMMARY_LH_LOCAL_FAULT);
		p->mp_fld_link_summary_lh_remote_fault =
			register_get_field(p->mp_reg_link_summary,
					   MAC_PCS_LINK_SUMMARY_LH_REMOTE_FAULT);
		p->mp_fld_link_summary_local_fault =
			register_get_field(p->mp_reg_link_summary,
					   MAC_PCS_LINK_SUMMARY_LOCAL_FAULT);
		p->mp_fld_link_summary_remote_fault =
			register_get_field(p->mp_reg_link_summary,
					   MAC_PCS_LINK_SUMMARY_REMOTE_FAULT);

		p->mp_reg_bip_err =
			module_get_register(p->mp_mod_mac_pcs, MAC_PCS_BIP_ERR);
		p->mp_fld_reg_bip_err_bip_err =
			register_get_field(p->mp_reg_bip_err, MAC_PCS_BIP_ERR_BIP_ERR);

		p->mp_reg_fec_ctrl =
			module_get_register(p->mp_mod_mac_pcs, MAC_PCS_FEC_CTRL);
		p->mp_field_fec_ctrl_reg_rs_fec_ctrl_in =
			register_get_field(p->mp_reg_fec_ctrl, MAC_PCS_FEC_CTRL_RS_FEC_CTRL_IN);

		p->mp_reg_fec_stat =
			module_get_register(p->mp_mod_mac_pcs, MAC_PCS_FEC_STAT);
		p->mp_field_fec_stat_bypass =
			register_get_field(p->mp_reg_fec_stat, MAC_PCS_FEC_STAT_BYPASS);
		p->mp_field_fec_stat_valid =
			register_get_field(p->mp_reg_fec_stat, MAC_PCS_FEC_STAT_VALID);
		p->mp_field_fec_stat_am_lock0 =
			register_get_field(p->mp_reg_fec_stat, MAC_PCS_FEC_STAT_AM_LOCK_0);
		p->mp_field_fec_stat_am_lock1 =
			register_get_field(p->mp_reg_fec_stat, MAC_PCS_FEC_STAT_AM_LOCK_1);
		p->mp_field_fec_stat_am_lock2 =
			register_get_field(p->mp_reg_fec_stat, MAC_PCS_FEC_STAT_AM_LOCK_2);
		p->mp_field_fec_stat_am_lock3 =
			register_get_field(p->mp_reg_fec_stat, MAC_PCS_FEC_STAT_AM_LOCK_3);
		p->mp_field_fec_stat_fec_lane_algn =
			register_get_field(p->mp_reg_fec_stat, MAC_PCS_FEC_STAT_FEC_LANE_ALGN);

		p->mp_reg_fec_cw_cnt =
			module_get_register(p->mp_mod_mac_pcs, MAC_PCS_FEC_CW_CNT);
		p->mp_field_fec_cw_cnt_cw_cnt =
			register_get_field(p->mp_reg_fec_cw_cnt, MAC_PCS_FEC_CW_CNT_CW_CNT);

		p->mp_reg_fec_ucw_cnt =
			module_get_register(p->mp_mod_mac_pcs, MAC_PCS_FEC_UCW_CNT);
		p->mp_field_fec_ucw_cnt_ucw_cnt =
			register_get_field(p->mp_reg_fec_ucw_cnt, MAC_PCS_FEC_UCW_CNT_UCW_CNT);

		/* GTY_RX_BUF_STAT */
#ifdef RXBUFSTAT
		p->mp_reg_gty_rx_buf_stat =
			module_get_register(p->mp_mod_mac_pcs, MAC_PCS_GTY_RX_BUF_STAT);
		p->mp_field_gty_rx_buf_stat_rx_buf_stat0 =
			register_get_field(p->mp_reg_gty_rx_buf_stat,
					   MAC_PCS_GTY_RX_BUF_STAT_RX_BUF_STAT_0);
		p->mp_field_gty_rx_buf_stat_rx_buf_stat1 =
			register_get_field(p->mp_reg_gty_rx_buf_stat,
					   MAC_PCS_GTY_RX_BUF_STAT_RX_BUF_STAT_1);
		p->mp_field_gty_rx_buf_stat_rx_buf_stat2 =
			register_get_field(p->mp_reg_gty_rx_buf_stat,
					   MAC_PCS_GTY_RX_BUF_STAT_RX_BUF_STAT_2);
		p->mp_field_gty_rx_buf_stat_rx_buf_stat3 =
			register_get_field(p->mp_reg_gty_rx_buf_stat,
					   MAC_PCS_GTY_RX_BUF_STAT_RX_BUF_STAT_3);
		p->mp_field_gty_rx_buf_stat_rx_buf_stat_changed0 =
			register_get_field(p->mp_reg_gty_rx_buf_stat,
					   MAC_PCS_GTY_RX_BUF_STAT_RX_BUF_STAT_CHANGED_0);
		p->mp_field_gty_rx_buf_stat_rx_buf_stat_changed1 =
			register_get_field(p->mp_reg_gty_rx_buf_stat,
					   MAC_PCS_GTY_RX_BUF_STAT_RX_BUF_STAT_CHANGED_1);
		p->mp_field_gty_rx_buf_stat_rx_buf_stat_changed2 =
			register_get_field(p->mp_reg_gty_rx_buf_stat,
					   MAC_PCS_GTY_RX_BUF_STAT_RX_BUF_STAT_CHANGED_2);
		p->mp_field_gty_rx_buf_stat_rx_buf_stat_changed3 =
			register_get_field(p->mp_reg_gty_rx_buf_stat,
					   MAC_PCS_GTY_RX_BUF_STAT_RX_BUF_STAT_CHANGED_3);
#endif

		/* GTY_PRE_CURSOR */
		p->mp_reg_gty_pre_cursor =
			module_get_register(p->mp_mod_mac_pcs, MAC_PCS_GTY_PRE_CURSOR);
		p->mp_field_gty_pre_cursor_tx_pre_csr0 =
			register_get_field(p->mp_reg_gty_pre_cursor,
					   MAC_PCS_GTY_PRE_CURSOR_TX_PRE_CSR_0);
		p->mp_field_gty_pre_cursor_tx_pre_csr1 =
			register_get_field(p->mp_reg_gty_pre_cursor,
					   MAC_PCS_GTY_PRE_CURSOR_TX_PRE_CSR_1);
		p->mp_field_gty_pre_cursor_tx_pre_csr2 =
			register_get_field(p->mp_reg_gty_pre_cursor,
					   MAC_PCS_GTY_PRE_CURSOR_TX_PRE_CSR_2);
		p->mp_field_gty_pre_cursor_tx_pre_csr3 =
			register_get_field(p->mp_reg_gty_pre_cursor,
					   MAC_PCS_GTY_PRE_CURSOR_TX_PRE_CSR_3);

		/* GTY_DIFF_CTL */
		p->mp_reg_gty_diff_ctl =
			module_get_register(p->mp_mod_mac_pcs, MAC_PCS_GTY_DIFF_CTL);
		p->mp_field_gty_gty_diff_ctl_tx_diff_ctl0 =
			register_get_field(p->mp_reg_gty_diff_ctl,
					   MAC_PCS_GTY_DIFF_CTL_TX_DIFF_CTL_0);
		p->mp_field_gty_gty_diff_ctl_tx_diff_ctl1 =
			register_get_field(p->mp_reg_gty_diff_ctl,
					   MAC_PCS_GTY_DIFF_CTL_TX_DIFF_CTL_1);
		p->mp_field_gty_gty_diff_ctl_tx_diff_ctl2 =
			register_get_field(p->mp_reg_gty_diff_ctl,
					   MAC_PCS_GTY_DIFF_CTL_TX_DIFF_CTL_2);
		p->mp_field_gty_gty_diff_ctl_tx_diff_ctl3 =
			register_get_field(p->mp_reg_gty_diff_ctl,
					   MAC_PCS_GTY_DIFF_CTL_TX_DIFF_CTL_3);

		/* GTY_POST_CURSOR */
		p->mp_reg_gty_post_cursor =
			module_get_register(p->mp_mod_mac_pcs,
					    MAC_PCS_GTY_POST_CURSOR);
		p->mp_field_gty_post_cursor_tx_post_csr0 =
			register_get_field(p->mp_reg_gty_post_cursor,
					   MAC_PCS_GTY_POST_CURSOR_TX_POST_CSR_0);
		p->mp_field_gty_post_cursor_tx_post_csr1 =
			register_get_field(p->mp_reg_gty_post_cursor,
					   MAC_PCS_GTY_POST_CURSOR_TX_POST_CSR_1);
		p->mp_field_gty_post_cursor_tx_post_csr2 =
			register_get_field(p->mp_reg_gty_post_cursor,
					   MAC_PCS_GTY_POST_CURSOR_TX_POST_CSR_2);
		p->mp_field_gty_post_cursor_tx_post_csr3 =
			register_get_field(p->mp_reg_gty_post_cursor,
					   MAC_PCS_GTY_POST_CURSOR_TX_POST_CSR_3);

		/* GTY_CTL */
		p->mp_reg_gty_ctl =
			module_query_register(p->mp_mod_mac_pcs, MAC_PCS_GTY_CTL);
		if (p->mp_reg_gty_ctl) {
			p->mp_field_gty_ctl_tx_pol0 =
				register_get_field(p->mp_reg_gty_ctl,
						   MAC_PCS_GTY_CTL_TX_POLARITY_0);
			p->mp_field_gty_ctl_tx_pol1 =
				register_get_field(p->mp_reg_gty_ctl,
						   MAC_PCS_GTY_CTL_TX_POLARITY_1);
			p->mp_field_gty_ctl_tx_pol2 =
				register_get_field(p->mp_reg_gty_ctl,
						   MAC_PCS_GTY_CTL_TX_POLARITY_2);
			p->mp_field_gty_ctl_tx_pol3 =
				register_get_field(p->mp_reg_gty_ctl,
						   MAC_PCS_GTY_CTL_TX_POLARITY_3);
		} else {
			p->mp_reg_gty_ctl =
				module_get_register(p->mp_mod_mac_pcs,
						    MAC_PCS_GTY_CTL_RX);
			p->mp_reg_gty_ctl_tx =
				module_get_register(p->mp_mod_mac_pcs,
						    MAC_PCS_GTY_CTL_TX);
			p->mp_field_gty_ctl_tx_pol0 =
				register_get_field(p->mp_reg_gty_ctl_tx,
						   MAC_PCS_GTY_CTL_TX_POLARITY_0);
			p->mp_field_gty_ctl_tx_pol1 =
				register_get_field(p->mp_reg_gty_ctl_tx,
						   MAC_PCS_GTY_CTL_TX_POLARITY_1);
			p->mp_field_gty_ctl_tx_pol2 =
				register_get_field(p->mp_reg_gty_ctl_tx,
						   MAC_PCS_GTY_CTL_TX_POLARITY_2);
			p->mp_field_gty_ctl_tx_pol3 =
				register_get_field(p->mp_reg_gty_ctl_tx,
						   MAC_PCS_GTY_CTL_TX_POLARITY_3);
		}
		p->mp_field_gty_ctl_rx_pol0 =
			register_get_field(p->mp_reg_gty_ctl,
					   MAC_PCS_GTY_CTL_RX_POLARITY_0);
		p->mp_field_gty_ctl_rx_pol1 =
			register_get_field(p->mp_reg_gty_ctl,
					   MAC_PCS_GTY_CTL_RX_POLARITY_1);
		p->mp_field_gty_ctl_rx_pol2 =
			register_get_field(p->mp_reg_gty_ctl,
					   MAC_PCS_GTY_CTL_RX_POLARITY_2);
		p->mp_field_gty_ctl_rx_pol3 =
			register_get_field(p->mp_reg_gty_ctl,
					   MAC_PCS_GTY_CTL_RX_POLARITY_3);
		p->mp_field_gty_ctl_rx_lpm_en0 =
			register_get_field(p->mp_reg_gty_ctl,
					   MAC_PCS_GTY_CTL_RX_LPM_EN_0);
		p->mp_field_gty_ctl_rx_lpm_en1 =
			register_get_field(p->mp_reg_gty_ctl,
					   MAC_PCS_GTY_CTL_RX_LPM_EN_1);
		p->mp_field_gty_ctl_rx_lpm_en2 =
			register_get_field(p->mp_reg_gty_ctl,
					   MAC_PCS_GTY_CTL_RX_LPM_EN_2);
		p->mp_field_gty_ctl_rx_lpm_en3 =
			register_get_field(p->mp_reg_gty_ctl,
					   MAC_PCS_GTY_CTL_RX_LPM_EN_3);
		p->mp_field_gty_ctl_rx_equa_rst0 =
			register_get_field(p->mp_reg_gty_ctl,
					   MAC_PCS_GTY_CTL_RX_EQUA_RST_0);
		p->mp_field_gty_ctl_rx_equa_rst1 =
			register_get_field(p->mp_reg_gty_ctl,
					   MAC_PCS_GTY_CTL_RX_EQUA_RST_1);
		p->mp_field_gty_ctl_rx_equa_rst2 =
			register_get_field(p->mp_reg_gty_ctl,
					   MAC_PCS_GTY_CTL_RX_EQUA_RST_2);
		p->mp_field_gty_ctl_rx_equa_rst3 =
			register_get_field(p->mp_reg_gty_ctl,
					   MAC_PCS_GTY_CTL_RX_EQUA_RST_3);

		/* DEBOUNCE_CTRL */
		p->mp_reg_debounce_ctrl =
			module_get_register(p->mp_mod_mac_pcs,
					    MAC_PCS_DEBOUNCE_CTRL);
		p->mp_field_debounce_ctrl_nt_port_ctrl =
			register_get_field(p->mp_reg_debounce_ctrl,
					   MAC_PCS_DEBOUNCE_CTRL_NT_PORT_CTRL);

		p->mp_reg_time_stamp_comp =
			module_query_register(p->mp_mod_mac_pcs,
					      MAC_PCS_TIMESTAMP_COMP);
		if (p->mp_reg_time_stamp_comp) {
			/* TIMESTAMP_COMP */
			p->mp_field_time_stamp_comp_rx_dly =
				register_get_field(p->mp_reg_time_stamp_comp,
						   MAC_PCS_TIMESTAMP_COMP_RX_DLY);
			p->mp_field_time_stamp_comp_tx_dly =
				register_get_field(p->mp_reg_time_stamp_comp,
						   MAC_PCS_TIMESTAMP_COMP_TX_DLY);
		}
	}
	return 0;
}

/* wrapper - for ease of use */
void nthw_mac_pcs_tx_host_enable(nthw_mac_pcs_t *p, bool enable)
{
	nthw_mac_pcs_set_tx_sel_host(p, enable);
	nthw_mac_pcs_set_tx_sel_tfg(p, !enable);
}

void nthw_mac_pcs_set_rx_enable(nthw_mac_pcs_t *p, bool enable)
{
	field_get_updated(p->mp_fld_pcs_config_rx_enable);
	if (enable)
		field_set_flush(p->mp_fld_pcs_config_rx_enable);

	else
		field_clr_flush(p->mp_fld_pcs_config_rx_enable);
}

void nthw_mac_pcs_set_tx_enable(nthw_mac_pcs_t *p, bool enable)
{
	field_get_updated(p->mp_fld_pcs_config_tx_enable);
	if (enable)
		field_set_flush(p->mp_fld_pcs_config_tx_enable);

	else
		field_clr_flush(p->mp_fld_pcs_config_tx_enable);
}

void nthw_mac_pcs_set_tx_sel_host(nthw_mac_pcs_t *p, bool enable)
{
	field_get_updated(p->mp_fld_phymac_misc_tx_sel_host);
	if (enable)
		field_set_flush(p->mp_fld_phymac_misc_tx_sel_host);

	else
		field_clr_flush(p->mp_fld_phymac_misc_tx_sel_host);
}

void nthw_mac_pcs_set_tx_sel_tfg(nthw_mac_pcs_t *p, bool enable)
{
	field_get_updated(p->mp_fld_phymac_misc_tx_sel_tfg);
	if (enable)
		field_set_flush(p->mp_fld_phymac_misc_tx_sel_tfg);

	else
		field_clr_flush(p->mp_fld_phymac_misc_tx_sel_tfg);
}

void nthw_mac_pcs_set_ts_eop(nthw_mac_pcs_t *p, bool enable)
{
	if (p->mp_fld_phymac_misc_ts_eop) {
		field_get_updated(p->mp_fld_phymac_misc_ts_eop);
		if (enable)
			field_set_flush(p->mp_fld_phymac_misc_ts_eop);

		else
			field_clr_flush(p->mp_fld_phymac_misc_ts_eop);
	}
}

bool nthw_mac_pcs_is_block_and_lane_lock_locked(nthw_mac_pcs_t *p)
{
	uint32_t block_lock;
	uint32_t lane_lock;

	block_lock = field_get_updated(p->mp_fld_block_lock_lock) &
		    p->m_fld_block_lock_lock_mask;
	lane_lock = field_get_updated(p->mp_fld_vl_demuxed_lock) &
		   p->m_fld_vl_demuxed_lock_mask;
	if (block_lock == p->m_fld_block_lock_lock_mask &&
			lane_lock == p->m_fld_vl_demuxed_lock_mask)
		return true;

	return false;
}

void nthw_mac_pcs_tx_path_rst(nthw_mac_pcs_t *p, bool enable)
{
	field_get_updated(p->mp_fld_pcs_config_tx_path_rst);
	if (enable)
		field_set_flush(p->mp_fld_pcs_config_tx_path_rst);

	else
		field_clr_flush(p->mp_fld_pcs_config_tx_path_rst);
}

void nthw_mac_pcs_rx_path_rst(nthw_mac_pcs_t *p, bool enable)
{
	field_get_updated(p->mp_fld_pcs_config_rx_path_rst);
	if (enable)
		field_set_flush(p->mp_fld_pcs_config_rx_path_rst);

	else
		field_clr_flush(p->mp_fld_pcs_config_rx_path_rst);
}

bool nthw_mac_pcs_is_rx_path_rst(nthw_mac_pcs_t *p)
{
	return field_get_updated(p->mp_fld_pcs_config_rx_path_rst);
}

void nthw_mac_pcs_tx_send_rfi(nthw_mac_pcs_t *p, bool enable)
{
	field_get_updated(p->mp_fld_pcs_config_tx_send_rfi);
	if (enable)
		field_set_flush(p->mp_fld_pcs_config_tx_send_rfi);

	else
		field_clr_flush(p->mp_fld_pcs_config_tx_send_rfi);
}

void nthw_mac_pcs_rx_force_resync(nthw_mac_pcs_t *p, bool enable)
{
	field_get_updated(p->mp_fld_pcs_config_rx_force_resync);
	if (enable)
		field_set_flush(p->mp_fld_pcs_config_rx_force_resync);

	else
		field_clr_flush(p->mp_fld_pcs_config_rx_force_resync);
}

bool nthw_mac_pcs_is_gt_fsm_rx_reset_done(nthw_mac_pcs_t *p)
{
	if ((field_get_updated(p->mp_fld_gty_stat_rx_rst_done0) &
			p->m_fld_gty_stat_rx_rst_done_mask) == p->m_fld_gty_stat_rx_rst_done_mask &&
			(field_get_updated(p->mp_fld_gty_stat_rx_rst_done1) &
			p->m_fld_gty_stat_rx_rst_done_mask) == p->m_fld_gty_stat_rx_rst_done_mask &&
			(field_get_updated(p->mp_fld_gty_stat_rx_rst_done2) &
			p->m_fld_gty_stat_rx_rst_done_mask) == p->m_fld_gty_stat_rx_rst_done_mask &&
			(field_get_updated(p->mp_fld_gty_stat_rx_rst_done3) &
			p->m_fld_gty_stat_rx_rst_done_mask) == p->m_fld_gty_stat_rx_rst_done_mask)
		return true;

	else
		return false;
}

bool nthw_mac_pcs_is_gt_fsm_tx_reset_done(nthw_mac_pcs_t *p)
{
	if ((field_get_updated(p->mp_fld_gty_stat_tx_rst_done0) &
			p->m_fld_gty_stat_tx_rst_done_mask) == p->m_fld_gty_stat_tx_rst_done_mask &&
			(field_get_updated(p->mp_fld_gty_stat_tx_rst_done1) &
			p->m_fld_gty_stat_tx_rst_done_mask) == p->m_fld_gty_stat_tx_rst_done_mask &&
			(field_get_updated(p->mp_fld_gty_stat_tx_rst_done2) &
			p->m_fld_gty_stat_tx_rst_done_mask) == p->m_fld_gty_stat_tx_rst_done_mask &&
			(field_get_updated(p->mp_fld_gty_stat_tx_rst_done3) &
			p->m_fld_gty_stat_tx_rst_done_mask) == p->m_fld_gty_stat_tx_rst_done_mask)
		return true;

	else
		return false;
}

void nthw_mac_pcs_set_host_loopback(nthw_mac_pcs_t *p, bool enable)
{
	register_update(p->mp_reg_gty_loop);
	if (enable) {
		field_set_val32(p->mp_fld_gty_loop_gt_loop0, 2);
		field_set_val32(p->mp_fld_gty_loop_gt_loop1, 2);
		field_set_val32(p->mp_fld_gty_loop_gt_loop2, 2);
		field_set_val32(p->mp_fld_gty_loop_gt_loop3, 2);
	} else {
		field_set_val32(p->mp_fld_gty_loop_gt_loop0, 0);
		field_set_val32(p->mp_fld_gty_loop_gt_loop1, 0);
		field_set_val32(p->mp_fld_gty_loop_gt_loop2, 0);
		field_set_val32(p->mp_fld_gty_loop_gt_loop3, 0);
	}
	register_flush(p->mp_reg_gty_loop, 1);
}

void nthw_mac_pcs_set_line_loopback(nthw_mac_pcs_t *p, bool enable)
{
	register_update(p->mp_reg_gty_loop);
	if (enable) {
		field_set_val32(p->mp_fld_gty_loop_gt_loop0, 4);
		field_set_val32(p->mp_fld_gty_loop_gt_loop1, 4);
		field_set_val32(p->mp_fld_gty_loop_gt_loop2, 4);
		field_set_val32(p->mp_fld_gty_loop_gt_loop3, 4);
	} else {
		field_set_val32(p->mp_fld_gty_loop_gt_loop0, 0);
		field_set_val32(p->mp_fld_gty_loop_gt_loop1, 0);
		field_set_val32(p->mp_fld_gty_loop_gt_loop2, 0);
		field_set_val32(p->mp_fld_gty_loop_gt_loop3, 0);
	}
	register_flush(p->mp_reg_gty_loop, 1);
}

void nthw_mac_pcs_reset_bip_counters(nthw_mac_pcs_t *p)
{
	uint32_t lane_bit_errors[NTHW_MAC_PCS_LANES];

	register_update(p->mp_reg_bip_err);
	field_get_val(p->mp_fld_reg_bip_err_bip_err, (uint32_t *)lane_bit_errors,
		     ARRAY_SIZE(lane_bit_errors));

#if defined(DEBUG)
	{
		uint8_t lane;

		for (lane = 0; lane < c_pcs_lanes; lane++) {
			if (lane_bit_errors[lane]) {
				NT_LOG(DBG, NTHW,
				       "Port %u: pcsLane %2u: BIP8 errors: %u\n",
				       p->m_port_no, lane, lane_bit_errors[lane]);
			}
		}
	}
#else
	(void)c_pcs_lanes; /* unused - kill warning */
#endif
}

void nthw_mac_pcs_get_status(nthw_mac_pcs_t *p, uint8_t *status)
{
	*status = field_get_updated(p->mp_fld_stat_pcs_rx_status) & 0x01;
}

bool nthw_mac_pcs_get_hi_ber(nthw_mac_pcs_t *p)
{
	return field_get_updated(p->mp_fld_stat_pcs_rx_hi_ber);
}

void nthw_mac_pcs_get_link_summary(nthw_mac_pcs_t *p, uint32_t *p_abs,
	uint32_t *p_nt_phy_link_state, uint32_t *p_lh_abs,
	uint32_t *p_ll_nt_phy_link_state,
	uint32_t *p_link_down_cnt, uint32_t *p_nim_interr,
	uint32_t *p_lh_local_fault,
	uint32_t *p_lh_remote_fault, uint32_t *p_local_fault,
	uint32_t *p_remote_fault)
{
	register_update(p->mp_reg_link_summary);
	if (p_abs)
		*p_abs = field_get_val32(p->mp_fld_link_summary_abs);
	if (p_nt_phy_link_state) {
		*p_nt_phy_link_state =
			field_get_val32(p->mp_fld_link_summary_nt_phy_link_state);
	}
	if (p_lh_abs)
		*p_lh_abs = field_get_val32(p->mp_fld_link_summary_lh_abs);
	if (p_ll_nt_phy_link_state) {
		*p_ll_nt_phy_link_state =
			field_get_val32(p->mp_fld_link_summary_ll_nt_phy_link_state);
	}
	if (p_link_down_cnt)
		*p_link_down_cnt = field_get_val32(p->mp_fld_link_summary_link_down_cnt);
	if (p_nim_interr)
		*p_nim_interr = field_get_val32(p->mp_fld_link_summary_nim_interr);
	if (p_lh_local_fault) {
		*p_lh_local_fault =
			field_get_val32(p->mp_fld_link_summary_lh_local_fault);
	}
	if (p_lh_remote_fault) {
		*p_lh_remote_fault =
			field_get_val32(p->mp_fld_link_summary_lh_remote_fault);
	}
	if (p_local_fault)
		*p_local_fault = field_get_val32(p->mp_fld_link_summary_local_fault);
	if (p_remote_fault)
		*p_remote_fault = field_get_val32(p->mp_fld_link_summary_remote_fault);
}

/*
 * Returns true if the lane/block lock bits indicate that a reset is required.
 * This is the case if Block/Lane lock is not all zero but not all set either.
 */
bool nthw_mac_pcs_reset_required(nthw_mac_pcs_t *p)
{
	uint32_t block_lock = nthw_mac_pcs_get_fld_block_lock_lock(p);
	uint32_t lane_lock = nthw_mac_pcs_get_fld_lane_lock_lock(p);
	uint32_t block_lock_mask = nthw_mac_pcs_get_fld_block_lock_lock_mask(p);
	uint32_t lane_lock_mask = nthw_mac_pcs_get_fld_lane_lock_lock_mask(p);

	return ((block_lock != 0) && (block_lock != block_lock_mask)) ||
	       ((lane_lock != 0) && (lane_lock != lane_lock_mask));
}

void nthw_mac_pcs_set_fec(nthw_mac_pcs_t *p, bool enable)
{
	NT_LOG(DBG, NTHW, "Port %u: Set FEC: %u\n", p->m_port_no, enable);

	field_get_updated(p->mp_field_fec_ctrl_reg_rs_fec_ctrl_in);
	if (enable) {
		field_set_val_flush32(p->mp_field_fec_ctrl_reg_rs_fec_ctrl_in, 0);
	} else {
		field_set_val_flush32(p->mp_field_fec_ctrl_reg_rs_fec_ctrl_in,
				    (1 << 5) - 1);
	}

	/* Both Rx and Tx must be reset for new FEC state to become active */
	nthw_mac_pcs_rx_path_rst(p, true);
	nthw_mac_pcs_tx_path_rst(p, true);
	NT_OS_WAIT_USEC(10000); /* 10ms */

	nthw_mac_pcs_rx_path_rst(p, false);
	nthw_mac_pcs_tx_path_rst(p, false);
	NT_OS_WAIT_USEC(10000); /* 10ms */

#ifdef DEBUG
	if (enable) {
		NT_LOG(DBG, NTHW, "Port %u: FEC valid: %u\n", p->m_port_no,
		       field_get_updated(p->mp_field_fec_stat_valid));
	} else {
		NT_LOG(DBG, NTHW, "Port %u: FEC bypass: %u\n", p->m_port_no,
		       field_get_updated(p->mp_field_fec_stat_bypass));
	}
#endif
}

bool nthw_mac_pcs_get_fec_bypass(nthw_mac_pcs_t *p)
{
	return field_get_updated(p->mp_field_fec_stat_bypass);
}

bool nthw_mac_pcs_get_fec_valid(nthw_mac_pcs_t *p)
{
	return field_get_updated(p->mp_field_fec_stat_valid);
}

bool nthw_mac_pcs_get_fec_aligned(nthw_mac_pcs_t *p)
{
	return field_get_updated(p->mp_field_fec_stat_fec_lane_algn);
}

bool nthw_mac_pcs_get_fec_stat_any_am_locked(nthw_mac_pcs_t *p)
{
	register_update(p->mp_reg_fec_stat);
	if ((field_get_val32(p->mp_field_fec_stat_am_lock0)) ||
			(field_get_val32(p->mp_field_fec_stat_am_lock1)) ||
			(field_get_val32(p->mp_field_fec_stat_am_lock2)) ||
			(field_get_val32(p->mp_field_fec_stat_am_lock3)))
		return true;
	return false;
}

bool nthw_mac_pcs_get_fec_stat_all_am_locked(nthw_mac_pcs_t *p)
{
	register_update(p->mp_reg_fec_stat);
	if ((field_get_val32(p->mp_field_fec_stat_am_lock0)) &&
			(field_get_val32(p->mp_field_fec_stat_am_lock1)) &&
			(field_get_val32(p->mp_field_fec_stat_am_lock2)) &&
			(field_get_val32(p->mp_field_fec_stat_am_lock3)))
		return true;
	return false;
}

void nthw_mac_pcs_dump_fec_stat_fields(nthw_mac_pcs_t *p)
{
	register_update(p->mp_reg_fec_stat);
	NT_LOG(DBG, NTHW,
	       "Port %u: FEC_STAT VALID: %u, AM_LOCK_0: %u, AM_LOCK_1: %u, AM_LOCK_2: %u, AM_LOCK_0: %u, FEC_LANE_ALGN: %u\n",
	       p->m_port_no, field_get_val32(p->mp_field_fec_stat_valid),
	       field_get_val32(p->mp_field_fec_stat_am_lock0),
	       field_get_val32(p->mp_field_fec_stat_am_lock1),
	       field_get_val32(p->mp_field_fec_stat_am_lock2),
	       field_get_val32(p->mp_field_fec_stat_am_lock3),
	       field_get_val32(p->mp_field_fec_stat_fec_lane_algn));
}

void nthw_mac_pcs_reset_fec_counters(nthw_mac_pcs_t *p)
{
	register_update(p->mp_reg_fec_cw_cnt);
	register_update(p->mp_reg_fec_ucw_cnt);

	if (field_get_val32(p->mp_field_fec_cw_cnt_cw_cnt)) {
		NT_LOG(DBG, NTHW, "Port %u: FEC_CW_CNT: %u\n", p->m_port_no,
		       field_get_val32(p->mp_field_fec_cw_cnt_cw_cnt));
	}
	if (field_get_val32(p->mp_field_fec_ucw_cnt_ucw_cnt)) {
		NT_LOG(DBG, NTHW, "Port %u: FEC_UCW_CNT: %u\n", p->m_port_no,
		       field_get_val32(p->mp_field_fec_ucw_cnt_ucw_cnt));
	}
}

bool nthw_mac_pcs_get_gty_rx_buf_stat_error(nthw_mac_pcs_t *p)
{
	register_update(p->mp_reg_gty_rx_buf_stat);

	if (field_get_val32(p->mp_field_gty_rx_buf_stat_rx_buf_stat_changed0) ||
			field_get_val32(p->mp_field_gty_rx_buf_stat_rx_buf_stat_changed1) ||
			field_get_val32(p->mp_field_gty_rx_buf_stat_rx_buf_stat_changed2) ||
			field_get_val32(p->mp_field_gty_rx_buf_stat_rx_buf_stat_changed3)) {
		if (field_get_val32(p->mp_field_gty_rx_buf_stat_rx_buf_stat0) ||
				field_get_val32(p->mp_field_gty_rx_buf_stat_rx_buf_stat1) ||
				field_get_val32(p->mp_field_gty_rx_buf_stat_rx_buf_stat2) ||
				field_get_val32(p->mp_field_gty_rx_buf_stat_rx_buf_stat3)) {
			NT_LOG(DBG, NTHW,
			       "Port %u: GTY RX_BUF_STAT_0: %u, RX_BUF_STAT_1: %u, RX_BUF_STAT_2: %u, RX_BUF_STAT_3: %u\n",
			       p->m_port_no,
			       field_get_val32(p->mp_field_gty_rx_buf_stat_rx_buf_stat0),
			       field_get_val32(p->mp_field_gty_rx_buf_stat_rx_buf_stat1),
			       field_get_val32(p->mp_field_gty_rx_buf_stat_rx_buf_stat2),
			       field_get_val32(p->mp_field_gty_rx_buf_stat_rx_buf_stat3));

			return true;
		}
	}
	return false;
}

void nthw_mac_pcs_set_gty_tx_tuning(nthw_mac_pcs_t *p, uint8_t lane, uint8_t tx_pre_csr,
			       uint8_t tx_diff_ctl, uint8_t tx_post_csr)
{
	/* GTY_PRE_CURSOR */
	register_update(p->mp_reg_gty_pre_cursor);
	switch (lane) {
	case 0:
		field_set_val_flush32(p->mp_field_gty_pre_cursor_tx_pre_csr0,
				    tx_pre_csr & 0x1F);
		break;
	case 1:
		field_set_val_flush32(p->mp_field_gty_pre_cursor_tx_pre_csr1,
				    tx_pre_csr & 0x1F);
		break;
	case 2:
		field_set_val_flush32(p->mp_field_gty_pre_cursor_tx_pre_csr2,
				    tx_pre_csr & 0x1F);
		break;
	case 3:
		field_set_val_flush32(p->mp_field_gty_pre_cursor_tx_pre_csr3,
				    tx_pre_csr & 0x1F);
		break;
	}

	/* GTY_DIFF_CTL */
	register_update(p->mp_reg_gty_diff_ctl);
	switch (lane) {
	case 0:
		field_set_val_flush32(p->mp_field_gty_gty_diff_ctl_tx_diff_ctl0,
				    tx_diff_ctl & 0x1F);
		break;
	case 1:
		field_set_val_flush32(p->mp_field_gty_gty_diff_ctl_tx_diff_ctl1,
				    tx_diff_ctl & 0x1F);
		break;
	case 2:
		field_set_val_flush32(p->mp_field_gty_gty_diff_ctl_tx_diff_ctl2,
				    tx_diff_ctl & 0x1F);
		break;
	case 3:
		field_set_val_flush32(p->mp_field_gty_gty_diff_ctl_tx_diff_ctl3,
				    tx_diff_ctl & 0x1F);
		break;
	}

	/* GTY_POST_CURSOR */
	register_update(p->mp_reg_gty_post_cursor);
	switch (lane) {
	case 0:
		field_set_val_flush32(p->mp_field_gty_post_cursor_tx_post_csr0,
				    tx_post_csr & 0x1F);
		break;
	case 1:
		field_set_val_flush32(p->mp_field_gty_post_cursor_tx_post_csr1,
				    tx_post_csr & 0x1F);
		break;
	case 2:
		field_set_val_flush32(p->mp_field_gty_post_cursor_tx_post_csr2,
				    tx_post_csr & 0x1F);
		break;
	case 3:
		field_set_val_flush32(p->mp_field_gty_post_cursor_tx_post_csr3,
				    tx_post_csr & 0x1F);
		break;
	}

	NT_LOG(DBG, NTHW,
	       "Port %u, lane %u: GTY txPreCsr: %d, txDiffCtl: %d, txPostCsr: %d\n",
	       p->m_port_no, lane, tx_pre_csr, tx_diff_ctl, tx_post_csr);
}

/*
 * Set receiver equalization mode
 *  0: enable DFE
 *  mode 1: enable LPM
 *
 * See UltraScale Architecture GTY Transceivers www.xilinx.com page 181,
 * UG578 (v1.1) November 24, 2015
 */
void nthw_mac_pcs_set_receiver_equalization_mode(nthw_mac_pcs_t *p, uint8_t mode)
{
	register_update(p->mp_reg_gty_ctl);
	field_set_val32(p->mp_field_gty_ctl_rx_lpm_en0, mode & 0x1);
	field_set_val32(p->mp_field_gty_ctl_rx_lpm_en1, mode & 0x1);
	field_set_val32(p->mp_field_gty_ctl_rx_lpm_en2, mode & 0x1);
	field_set_val_flush32(p->mp_field_gty_ctl_rx_lpm_en3, mode & 0x1);

	/* Toggle reset */
	field_set_val32(p->mp_field_gty_ctl_rx_equa_rst0, 1);
	field_set_val32(p->mp_field_gty_ctl_rx_equa_rst1, 1);
	field_set_val32(p->mp_field_gty_ctl_rx_equa_rst2, 1);
	field_set_val_flush32(p->mp_field_gty_ctl_rx_equa_rst3, 1);

	NT_OS_WAIT_USEC(1000); /* 1ms */

	field_set_val32(p->mp_field_gty_ctl_rx_equa_rst0, 0);
	field_set_val32(p->mp_field_gty_ctl_rx_equa_rst1, 0);
	field_set_val32(p->mp_field_gty_ctl_rx_equa_rst2, 0);
	field_set_val_flush32(p->mp_field_gty_ctl_rx_equa_rst3, 0);

	NT_LOG(DBG, NTHW, "Port %u: GTY receiver mode: %s\n", p->m_port_no,
	       (mode == c_mac_pcs_receiver_mode_dfe ? "DFE" : "LPM"));
}

void nthw_mac_pcs_swap_gty_tx_polarity(nthw_mac_pcs_t *p, uint8_t lane, bool swap)
{
	register_update(p->mp_reg_gty_ctl);
	switch (lane) {
	case 0:
		field_set_val_flush32(p->mp_field_gty_ctl_tx_pol0, swap);
		break;
	case 1:
		field_set_val_flush32(p->mp_field_gty_ctl_tx_pol1, swap);
		break;
	case 2:
		field_set_val_flush32(p->mp_field_gty_ctl_tx_pol2, swap);
		break;
	case 3:
		field_set_val_flush32(p->mp_field_gty_ctl_tx_pol3, swap);
		break;
	}
	NT_LOG(DBG, NTHW, "Port %u: set GTY Tx lane (%d) polarity: %d\n",
	       p->m_port_no, lane, swap);
}

void nthw_mac_pcs_swap_gty_rx_polarity(nthw_mac_pcs_t *p, uint8_t lane, bool swap)
{
	register_update(p->mp_reg_gty_ctl);
	switch (lane) {
	case 0:
		field_set_val_flush32(p->mp_field_gty_ctl_rx_pol0, swap);
		break;
	case 1:
		field_set_val_flush32(p->mp_field_gty_ctl_rx_pol1, swap);
		break;
	case 2:
		field_set_val_flush32(p->mp_field_gty_ctl_rx_pol2, swap);
		break;
	case 3:
		field_set_val_flush32(p->mp_field_gty_ctl_rx_pol3, swap);
		break;
	}
	NT_LOG(DBG, NTHW, "Port %u: set GTY Rx lane (%d) polarity: %d\n",
	       p->m_port_no, lane, swap);
}

void nthw_mac_pcs_set_led_mode(nthw_mac_pcs_t *p, uint8_t mode)
{
	field_get_updated(p->mp_field_debounce_ctrl_nt_port_ctrl);
	field_set_val_flush32(p->mp_field_debounce_ctrl_nt_port_ctrl, mode);
}

void nthw_mac_pcs_set_timestamp_comp_rx(nthw_mac_pcs_t *p, uint16_t rx_dly)
{
	if (p->mp_field_time_stamp_comp_rx_dly) {
		field_get_updated(p->mp_field_time_stamp_comp_rx_dly);
		field_set_val_flush32(p->mp_field_time_stamp_comp_rx_dly, rx_dly);
	}
}

void nthw_mac_pcs_set_port_no(nthw_mac_pcs_t *p, uint8_t port_no)
{
	p->m_port_no = port_no;
}

uint32_t nthw_mac_pcs_get_fld_block_lock_lock(nthw_mac_pcs_t *p)
{
	return field_get_updated(p->mp_fld_block_lock_lock);
}

uint32_t nthw_mac_pcs_get_fld_block_lock_lock_mask(nthw_mac_pcs_t *p)
{
	return p->m_fld_block_lock_lock_mask;
}

uint32_t nthw_mac_pcs_get_fld_lane_lock_lock(nthw_mac_pcs_t *p)
{
	return field_get_updated(p->mp_fld_vl_demuxed_lock);
}

uint32_t nthw_mac_pcs_get_fld_lane_lock_lock_mask(nthw_mac_pcs_t *p)
{
	return p->m_fld_vl_demuxed_lock_mask;
}

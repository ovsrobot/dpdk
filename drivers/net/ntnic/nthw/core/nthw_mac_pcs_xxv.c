/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "ntlog.h"

#include "nthw_drv.h"
#include "nthw_register.h"

#include "nthw_mac_pcs_xxv.h"

static void nthw_mac_pcs_xxv_field_set_or_clr_flush(const nthw_field_t *f, bool set)
{
	if (f) {
		nthw_field_get_updated(f);

		if (set)
			nthw_field_set_flush(f);

		else
			nthw_field_clr_flush(f);
	}
}

nthw_mac_pcs_xxv_t *nthw_mac_pcs_xxv_new(void)
{
	nthw_mac_pcs_xxv_t *p = malloc(sizeof(nthw_mac_pcs_xxv_t));

	if (p)
		memset(p, 0, sizeof(nthw_mac_pcs_xxv_t));

	return p;
}

void nthw_mac_pcs_xxv_delete(nthw_mac_pcs_xxv_t *p)
{
	if (p) {
		memset(p, 0, sizeof(nthw_mac_pcs_xxv_t));
		free(p);
	}
}

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
	uint8_t index)
{
	struct nthw_mac_pcs_xxv_registers_fields *r = &p->regs[index];	/* register and fields */

	assert(p);

	nthw_register_update(r->mp_reg_link_summary);

	if (p_abs)
		*p_abs = nthw_field_get_val32(r->mp_fld_link_summary_abs);

	if (p_nt_phy_link_state) {
		*p_nt_phy_link_state =
			nthw_field_get_val32(r->mp_fld_link_summary_nt_phy_link_state);
	}

	if (p_lh_abs)
		*p_lh_abs = nthw_field_get_val32(r->mp_fld_link_summary_lh_abs);

	if (p_ll_nt_phy_link_state) {
		*p_ll_nt_phy_link_state =
			nthw_field_get_val32(r->mp_fld_link_summary_ll_nt_phy_link_state);
	}

	if (p_link_down_cnt)
		*p_link_down_cnt = nthw_field_get_val32(r->mp_fld_link_summary_link_down_cnt);

	if (p_nim_interr)
		*p_nim_interr = nthw_field_get_val32(r->mp_fld_link_summary_nim_interr);

	if (p_lh_local_fault)
		*p_lh_local_fault = nthw_field_get_val32(r->mp_fld_link_summary_lh_local_fault);

	if (p_lh_remote_fault)
		*p_lh_remote_fault = nthw_field_get_val32(r->mp_fld_link_summary_lh_remote_fault);

	if (p_lh_internal_local_fault) {
		*p_lh_internal_local_fault =
			nthw_field_get_val32(r->mp_fld_link_summary_lh_internal_local_fault);
	}

	if (p_lh_received_local_fault) {
		*p_lh_received_local_fault =
			nthw_field_get_val32(r->mp_fld_link_summary_lh_received_local_fault);
	}
}

void nthw_mac_pcs_xxv_reset_rx_gt_data(nthw_mac_pcs_xxv_t *p, bool enable, uint8_t index)
{
	const nthw_field_t *const f = p->regs[index].mp_fld_sub_rst_rx_gt_data;

	nthw_mac_pcs_xxv_field_set_or_clr_flush(f, enable);
}

/*
 * QPLL lock signal.
 * For cores capable of 10G only, there are only 1 QPLL. For cores capable of
 * 10G/25G, there are 2 QPLLs.
 */
void nthw_mac_pcs_xxv_set_rx_mac_pcs_rst(nthw_mac_pcs_xxv_t *p, bool enable, uint8_t index)
{
	const nthw_field_t *const f = p->regs[index].mp_fld_sub_rst_rx_mac_pcs;

	nthw_mac_pcs_xxv_field_set_or_clr_flush(f, enable);
}

int nthw_mac_pcs_xxv_init(nthw_mac_pcs_xxv_t *p, nthw_fpga_t *p_fpga, int n_instance,
	int n_channels, bool mac_8x10G)
{
	nthw_module_t *p_mod = nthw_fpga_query_module(p_fpga, MOD_MAC_PCS_XXV, n_instance);
	const char *const p_adapter_id_str = p_fpga->p_fpga_info->mp_adapter_id_str;
	nthw_module_t *module = p_mod;
	uint64_t n_module_version_packed64 = -1;
	nthw_register_t *r;
	nthw_register_t *(*get_register)(nthw_module_t *, nthw_id_t) = nthw_module_get_register;
	nthw_field_t *(*get_field)(const nthw_register_t *, nthw_id_t) = nthw_register_get_field;
	nthw_field_t *(*query_field)(const nthw_register_t *, nthw_id_t) =
		nthw_register_query_field;
	struct nthw_mac_pcs_xxv_registers_fields *rf;

	if (p == NULL)
		return p_mod == NULL ? -1 : 0;

	if (p_mod == NULL) {
		NT_LOG(ERR, NTHW, "%s: MAC_PCS_XXV instance=%d: no such instance\n",
			p_adapter_id_str, n_instance);
		return -1;
	}

	p->mp_fpga = p_fpga;
	p->mn_instance = n_instance;
	p->mp_mod_mac_pcs_xxv = p_mod;
	p->m_mac_8x10G = mac_8x10G;

	memset(p->regs, 0, sizeof(p->regs));

	n_module_version_packed64 = nthw_module_get_version_packed64(p->mp_mod_mac_pcs_xxv);

	switch (n_module_version_packed64) {
	case (0UL << 32) | 0UL:	/* 0.0 */
	case (0UL << 32) | 1UL:	/* 0.1 */
	case (0UL << 32) | 2UL:	/* 0.2 */
	case (0UL << 32) | 3UL:	/* 0.3 */
		NT_LOG(DBG, NTHW, "%s: MAC_PCS_XXV instance=%d: version=0x%08lX\n",
			p_adapter_id_str, p->mn_instance, n_module_version_packed64);
		break;

	default:
		NT_LOG(ERR, NTHW,
			"%s: MAC_PCS_XXV instance=%d: version=0x%08lX: unsupported module version\n",
			p_adapter_id_str, p->mn_instance, n_module_version_packed64);
		return -1;
	}

	assert(n_channels == 1 || n_channels == 2 || n_channels == 4);

	/* Register MAC_PCS_XXV_CORE_CONF_0 -- MAC_PCS_XXV_CORE_CONF_3 */
	if (n_channels <= 4) {
		/* Initialize regs/fields for sub-module/channel 0 */
		rf = &p->regs[0];
		r = get_register(module, MAC_PCS_XXV_CORE_CONF_0);

		rf->mp_reg_core_conf = r;
		rf->mp_fld_core_conf_rx_enable = get_field(r, MAC_PCS_XXV_CORE_CONF_0_RX_ENABLE);
		rf->mp_fld_core_conf_rx_force_resync =
			get_field(r, MAC_PCS_XXV_CORE_CONF_0_RX_FORCE_RESYNC);
		rf->mp_fld_core_conf_tx_enable = get_field(r, MAC_PCS_XXV_CORE_CONF_0_TX_ENABLE);
		rf->mp_fld_core_conf_tx_ins_fcs = get_field(r, MAC_PCS_XXV_CORE_CONF_0_TX_INS_FCS);
		rf->mp_fld_core_conf_tx_ign_fcs = get_field(r, MAC_PCS_XXV_CORE_CONF_0_TX_IGN_FCS);
		rf->mp_fld_core_conf_tx_send_lfi =
			get_field(r, MAC_PCS_XXV_CORE_CONF_0_TX_SEND_LFI);
		rf->mp_fld_core_conf_tx_send_rfi =
			get_field(r, MAC_PCS_XXV_CORE_CONF_0_TX_SEND_RFI);
		rf->mp_fld_core_conf_tx_send_idle =
			get_field(r, MAC_PCS_XXV_CORE_CONF_0_TX_SEND_IDLE);
		rf->mp_fld_core_conf_inline_mode =
			get_field(r, MAC_PCS_XXV_CORE_CONF_0_INLINE_MODE);
		rf->mp_fld_core_conf_line_loopback =
			get_field(r, MAC_PCS_XXV_CORE_CONF_0_LINE_LOOPBACK);
		rf->mp_fld_core_conf_ts_at_eop = get_field(r, MAC_PCS_XXV_CORE_CONF_0_TS_AT_EOP);
	}

	if (n_channels >= 2) {
		/* Initialize regs/fields for sub-module/channel 1 */
		rf = &p->regs[1];
		r = get_register(module, MAC_PCS_XXV_CORE_CONF_1);

		rf->mp_reg_core_conf = r;
		rf->mp_fld_core_conf_rx_enable = get_field(r, MAC_PCS_XXV_CORE_CONF_1_RX_ENABLE);
		rf->mp_fld_core_conf_rx_force_resync =
			get_field(r, MAC_PCS_XXV_CORE_CONF_1_RX_FORCE_RESYNC);
		rf->mp_fld_core_conf_tx_enable = get_field(r, MAC_PCS_XXV_CORE_CONF_1_TX_ENABLE);
		rf->mp_fld_core_conf_tx_ins_fcs = get_field(r, MAC_PCS_XXV_CORE_CONF_1_TX_INS_FCS);
		rf->mp_fld_core_conf_tx_ign_fcs = get_field(r, MAC_PCS_XXV_CORE_CONF_1_TX_IGN_FCS);
		rf->mp_fld_core_conf_tx_send_lfi =
			get_field(r, MAC_PCS_XXV_CORE_CONF_1_TX_SEND_LFI);
		rf->mp_fld_core_conf_tx_send_rfi =
			get_field(r, MAC_PCS_XXV_CORE_CONF_1_TX_SEND_RFI);
		rf->mp_fld_core_conf_tx_send_idle =
			get_field(r, MAC_PCS_XXV_CORE_CONF_1_TX_SEND_IDLE);
		rf->mp_fld_core_conf_inline_mode =
			get_field(r, MAC_PCS_XXV_CORE_CONF_1_INLINE_MODE);
		rf->mp_fld_core_conf_line_loopback =
			get_field(r, MAC_PCS_XXV_CORE_CONF_1_LINE_LOOPBACK);
		rf->mp_fld_core_conf_ts_at_eop = get_field(r, MAC_PCS_XXV_CORE_CONF_1_TS_AT_EOP);
	}

	if (n_channels == 4) {
		/* Initialize regs/fields for sub-module/channel 2 */
		rf = &p->regs[2];
		r = get_register(module, MAC_PCS_XXV_CORE_CONF_2);

		rf->mp_reg_core_conf = r;
		rf->mp_fld_core_conf_rx_enable = get_field(r, MAC_PCS_XXV_CORE_CONF_2_RX_ENABLE);
		rf->mp_fld_core_conf_rx_force_resync =
			get_field(r, MAC_PCS_XXV_CORE_CONF_2_RX_FORCE_RESYNC);
		rf->mp_fld_core_conf_tx_enable = get_field(r, MAC_PCS_XXV_CORE_CONF_2_TX_ENABLE);
		rf->mp_fld_core_conf_tx_ins_fcs = get_field(r, MAC_PCS_XXV_CORE_CONF_2_TX_INS_FCS);
		rf->mp_fld_core_conf_tx_ign_fcs = get_field(r, MAC_PCS_XXV_CORE_CONF_2_TX_IGN_FCS);
		rf->mp_fld_core_conf_tx_send_lfi =
			get_field(r, MAC_PCS_XXV_CORE_CONF_2_TX_SEND_LFI);
		rf->mp_fld_core_conf_tx_send_rfi =
			get_field(r, MAC_PCS_XXV_CORE_CONF_2_TX_SEND_RFI);
		rf->mp_fld_core_conf_tx_send_idle =
			get_field(r, MAC_PCS_XXV_CORE_CONF_2_TX_SEND_IDLE);
		rf->mp_fld_core_conf_inline_mode =
			get_field(r, MAC_PCS_XXV_CORE_CONF_2_INLINE_MODE);
		rf->mp_fld_core_conf_line_loopback =
			get_field(r, MAC_PCS_XXV_CORE_CONF_2_LINE_LOOPBACK);
		rf->mp_fld_core_conf_ts_at_eop = get_field(r, MAC_PCS_XXV_CORE_CONF_2_TS_AT_EOP);

		/* Initialize regs/fields for sub-module/channel 3 */
		rf = &p->regs[3];
		r = get_register(module, MAC_PCS_XXV_CORE_CONF_3);

		rf->mp_reg_core_conf = r;
		rf->mp_fld_core_conf_rx_enable = get_field(r, MAC_PCS_XXV_CORE_CONF_3_RX_ENABLE);
		rf->mp_fld_core_conf_rx_force_resync =
			get_field(r, MAC_PCS_XXV_CORE_CONF_3_RX_FORCE_RESYNC);
		rf->mp_fld_core_conf_tx_enable = get_field(r, MAC_PCS_XXV_CORE_CONF_3_TX_ENABLE);
		rf->mp_fld_core_conf_tx_ins_fcs = get_field(r, MAC_PCS_XXV_CORE_CONF_3_TX_INS_FCS);
		rf->mp_fld_core_conf_tx_ign_fcs = get_field(r, MAC_PCS_XXV_CORE_CONF_3_TX_IGN_FCS);
		rf->mp_fld_core_conf_tx_send_lfi =
			get_field(r, MAC_PCS_XXV_CORE_CONF_3_TX_SEND_LFI);
		rf->mp_fld_core_conf_tx_send_rfi =
			get_field(r, MAC_PCS_XXV_CORE_CONF_3_TX_SEND_RFI);
		rf->mp_fld_core_conf_tx_send_idle =
			get_field(r, MAC_PCS_XXV_CORE_CONF_3_TX_SEND_IDLE);
		rf->mp_fld_core_conf_inline_mode =
			get_field(r, MAC_PCS_XXV_CORE_CONF_3_INLINE_MODE);
		rf->mp_fld_core_conf_line_loopback =
			get_field(r, MAC_PCS_XXV_CORE_CONF_3_LINE_LOOPBACK);
		rf->mp_fld_core_conf_ts_at_eop = get_field(r, MAC_PCS_XXV_CORE_CONF_3_TS_AT_EOP);
	}

	/*
	 * Registers MAC_PCS_XXV_ANEG_CONFIG_0 -- MAC_PCS_XXV_ANEG_CONFIG_3
	 * and       MAC_PCS_XXV_ANEG_ABILITY_0 -- MAC_PCS_XXV_ANEG_ABILITY_3
	 * and       MAC_PCS_XXV_LT_CONF_0 -- MAC_PCS_XXV_LT_CONF_3
	 */
	if (!mac_8x10G && n_channels <= 4) {
		/*
		 * 2 x 10 25 G
		 * ANEG_CONFIG
		 */
		rf = &p->regs[0];

		r = get_register(module, MAC_PCS_XXV_ANEG_CONFIG_0);
		rf->mp_reg_aneg_config = r;
		rf->mp_fld_aneg_config_enable = get_field(r, MAC_PCS_XXV_ANEG_CONFIG_0_ENABLE);
		rf->mp_fld_aneg_config_bypass = get_field(r, MAC_PCS_XXV_ANEG_CONFIG_0_BYPASS);
		rf->mp_fld_aneg_config_restart = get_field(r, MAC_PCS_XXV_ANEG_CONFIG_0_RESTART);
		rf->mp_fld_aneg_config_pseudo = get_field(r, MAC_PCS_XXV_ANEG_CONFIG_0_PSEUDO);
		rf->mp_fld_aneg_config_nonce_seed =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_0_NONCE_SEED);
		rf->mp_fld_aneg_config_remote_fault =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_0_REMOTE_FAULT);
		rf->mp_fld_aneg_config_pause = get_field(r, MAC_PCS_XXV_ANEG_CONFIG_0_PAUSE);
		rf->mp_fld_aneg_config_asmdir = get_field(r, MAC_PCS_XXV_ANEG_CONFIG_0_ASMDIR);
		rf->mp_fld_aneg_config_fec74_request10g =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_0_FEC74_REQUEST_10G);
		rf->mp_fld_aneg_config_hide_fec74 =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_0_HIDE_FEC74);
		rf->mp_fld_aneg_config_fec74_request =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_0_FEC74_REQUEST);
		rf->mp_fld_aneg_config_fec91_request =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_0_FEC91_REQUEST);
		rf->mp_fld_aneg_config_fec91_ability =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_0_FEC91_ABILITY);
		rf->mp_fld_aneg_config_rs_fec_request =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_0_RS_FEC_REQUEST);
		rf->mp_fld_aneg_config_sw_fec_overwrite =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_0_SW_FEC_OVERWRITE);
		rf->mp_fld_aneg_config_sw_speed_overwrite =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_0_SW_SPEED_OVERWRITE);

		/* ANEG_ABILITY */
		r = get_register(module, MAC_PCS_XXV_ANEG_ABILITY_0);
		rf->mp_reg_aneg_ability = r;

		rf->mp_fld_aneg_ability_25g_base_cr =
			query_field(r, MAC_PCS_XXV_ANEG_ABILITY_0_BASE25G_CR);

		if (!rf->mp_fld_aneg_ability_25g_base_cr) {
			rf->mp_fld_aneg_ability_25g_base_cr =
				query_field(r, MAC_PCS_XXV_ANEG_ABILITY_0_25GBASE_CR);
		}

		rf->mp_fld_aneg_ability_25g_base_crs =
			query_field(r, MAC_PCS_XXV_ANEG_ABILITY_0_BASE25G_CR_S);

		if (!rf->mp_fld_aneg_ability_25g_base_crs) {
			rf->mp_fld_aneg_ability_25g_base_crs =
				query_field(r, MAC_PCS_XXV_ANEG_ABILITY_0_25GBASE_CR_S);
		}

		rf->mp_fld_aneg_ability_25g_base_cr1 =
			query_field(r, MAC_PCS_XXV_ANEG_ABILITY_0_BASE25G_CR1);

		if (!rf->mp_fld_aneg_ability_25g_base_cr1) {
			rf->mp_fld_aneg_ability_25g_base_cr1 =
				query_field(r, MAC_PCS_XXV_ANEG_ABILITY_0_25GBASE_CR1);
		}

		/* LT_CONF */
		r = get_register(module, MAC_PCS_XXV_LT_CONF_0);
		rf->mp_reg_lt_conf = r;
		rf->mp_fld_lt_conf_enable = get_field(r, MAC_PCS_XXV_LT_CONF_0_ENABLE);
		rf->mp_fld_lt_conf_restart = get_field(r, MAC_PCS_XXV_LT_CONF_0_RESTART);
		rf->mp_fld_lt_conf_seed = get_field(r, MAC_PCS_XXV_LT_CONF_0_SEED);
	}

	if (!mac_8x10G && n_channels >= 2) {
		/*
		 * 2 x 10 25 G
		 * ANEG_CONFIG
		 */

		/* Initialize regs/fields for sub-module/channel 1 */
		rf = &p->regs[1];

		r = get_register(module, MAC_PCS_XXV_ANEG_CONFIG_1);
		rf->mp_reg_aneg_config = r;
		rf->mp_fld_aneg_config_enable = get_field(r, MAC_PCS_XXV_ANEG_CONFIG_1_ENABLE);
		rf->mp_fld_aneg_config_bypass = get_field(r, MAC_PCS_XXV_ANEG_CONFIG_1_BYPASS);
		rf->mp_fld_aneg_config_restart = get_field(r, MAC_PCS_XXV_ANEG_CONFIG_1_RESTART);
		rf->mp_fld_aneg_config_pseudo = get_field(r, MAC_PCS_XXV_ANEG_CONFIG_1_PSEUDO);
		rf->mp_fld_aneg_config_nonce_seed =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_1_NONCE_SEED);
		rf->mp_fld_aneg_config_remote_fault =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_1_REMOTE_FAULT);
		rf->mp_fld_aneg_config_pause = get_field(r, MAC_PCS_XXV_ANEG_CONFIG_1_PAUSE);
		rf->mp_fld_aneg_config_asmdir = get_field(r, MAC_PCS_XXV_ANEG_CONFIG_1_ASMDIR);
		rf->mp_fld_aneg_config_fec74_request10g =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_1_FEC74_REQUEST_10G);
		rf->mp_fld_aneg_config_hide_fec74 =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_1_HIDE_FEC74);
		rf->mp_fld_aneg_config_fec74_request =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_1_FEC74_REQUEST);
		rf->mp_fld_aneg_config_fec91_request =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_1_FEC91_REQUEST);
		rf->mp_fld_aneg_config_fec91_ability =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_1_FEC91_ABILITY);
		rf->mp_fld_aneg_config_rs_fec_request =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_1_RS_FEC_REQUEST);
		rf->mp_fld_aneg_config_sw_fec_overwrite =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_1_SW_FEC_OVERWRITE);
		rf->mp_fld_aneg_config_sw_speed_overwrite =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_1_SW_SPEED_OVERWRITE);

		/* ANEG_ABILITY */
		r = get_register(module, MAC_PCS_XXV_ANEG_ABILITY_1);
		rf->mp_reg_aneg_ability = r;

		rf->mp_fld_aneg_ability_25g_base_cr =
			query_field(r, MAC_PCS_XXV_ANEG_ABILITY_1_BASE25G_CR);

		if (!rf->mp_fld_aneg_ability_25g_base_cr) {
			rf->mp_fld_aneg_ability_25g_base_cr =
				get_field(r, MAC_PCS_XXV_ANEG_ABILITY_1_25GBASE_CR);
		}

		rf->mp_fld_aneg_ability_25g_base_crs =
			query_field(r, MAC_PCS_XXV_ANEG_ABILITY_1_BASE25G_CR_S);

		if (!rf->mp_fld_aneg_ability_25g_base_crs) {
			rf->mp_fld_aneg_ability_25g_base_crs =
				get_field(r, MAC_PCS_XXV_ANEG_ABILITY_1_25GBASE_CR_S);
		}

		rf->mp_fld_aneg_ability_25g_base_cr1 =
			query_field(r, MAC_PCS_XXV_ANEG_ABILITY_1_BASE25G_CR1);

		if (!rf->mp_fld_aneg_ability_25g_base_cr1) {
			rf->mp_fld_aneg_ability_25g_base_cr1 =
				get_field(r, MAC_PCS_XXV_ANEG_ABILITY_1_25GBASE_CR1);
		}

		/* LT_CONF */
		r = get_register(module, MAC_PCS_XXV_LT_CONF_1);
		rf->mp_reg_lt_conf = r;
		rf->mp_fld_lt_conf_enable = get_field(r, MAC_PCS_XXV_LT_CONF_1_ENABLE);
		rf->mp_fld_lt_conf_restart = get_field(r, MAC_PCS_XXV_LT_CONF_1_RESTART);
		rf->mp_fld_lt_conf_seed = get_field(r, MAC_PCS_XXV_LT_CONF_1_SEED);
	}

	if (!mac_8x10G && n_channels == 4) {
		/* Initialize regs/fields for sub-module/channel 2 */
		rf = &p->regs[2];

		r = get_register(module, MAC_PCS_XXV_ANEG_CONFIG_2);
		rf->mp_reg_aneg_config = r;
		rf->mp_fld_aneg_config_enable = get_field(r, MAC_PCS_XXV_ANEG_CONFIG_2_ENABLE);
		rf->mp_fld_aneg_config_bypass = get_field(r, MAC_PCS_XXV_ANEG_CONFIG_2_BYPASS);
		rf->mp_fld_aneg_config_restart = get_field(r, MAC_PCS_XXV_ANEG_CONFIG_2_RESTART);
		rf->mp_fld_aneg_config_pseudo = get_field(r, MAC_PCS_XXV_ANEG_CONFIG_2_PSEUDO);
		rf->mp_fld_aneg_config_nonce_seed =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_2_NONCE_SEED);
		rf->mp_fld_aneg_config_remote_fault =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_2_REMOTE_FAULT);
		rf->mp_fld_aneg_config_pause = get_field(r, MAC_PCS_XXV_ANEG_CONFIG_2_PAUSE);
		rf->mp_fld_aneg_config_asmdir = get_field(r, MAC_PCS_XXV_ANEG_CONFIG_2_ASMDIR);
		rf->mp_fld_aneg_config_fec74_request10g =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_2_FEC74_REQUEST_10G);
		rf->mp_fld_aneg_config_hide_fec74 =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_2_HIDE_FEC74);
		rf->mp_fld_aneg_config_fec74_request =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_2_FEC74_REQUEST);
		rf->mp_fld_aneg_config_fec91_request =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_2_FEC91_REQUEST);
		rf->mp_fld_aneg_config_fec91_ability =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_2_FEC91_ABILITY);
		rf->mp_fld_aneg_config_rs_fec_request =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_2_RS_FEC_REQUEST);
		rf->mp_fld_aneg_config_sw_fec_overwrite =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_2_SW_FEC_OVERWRITE);
		rf->mp_fld_aneg_config_sw_speed_overwrite =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_2_SW_SPEED_OVERWRITE);

		/* ANEG_ABILITY */
		r = get_register(module, MAC_PCS_XXV_ANEG_ABILITY_2);
		rf->mp_reg_aneg_ability = r;
		rf->mp_fld_aneg_ability_25g_base_cr =
			get_field(r, MAC_PCS_XXV_ANEG_ABILITY_2_25GBASE_CR);
		rf->mp_fld_aneg_ability_25g_base_crs =
			get_field(r, MAC_PCS_XXV_ANEG_ABILITY_2_25GBASE_CR_S);
		rf->mp_fld_aneg_ability_25g_base_cr1 =
			get_field(r, MAC_PCS_XXV_ANEG_ABILITY_2_25GBASE_CR1);

		/* LT_CONF */
		r = get_register(module, MAC_PCS_XXV_LT_CONF_2);
		rf->mp_reg_lt_conf = r;
		rf->mp_fld_lt_conf_enable = get_field(r, MAC_PCS_XXV_LT_CONF_2_ENABLE);
		rf->mp_fld_lt_conf_restart = get_field(r, MAC_PCS_XXV_LT_CONF_2_RESTART);
		rf->mp_fld_lt_conf_seed = get_field(r, MAC_PCS_XXV_LT_CONF_2_SEED);

		/* Initialize regs/fields for sub-module/channel 3 */
		rf = &p->regs[3];

		r = get_register(module, MAC_PCS_XXV_ANEG_CONFIG_3);
		rf->mp_reg_aneg_config = r;
		rf->mp_fld_aneg_config_enable = get_field(r, MAC_PCS_XXV_ANEG_CONFIG_3_ENABLE);
		rf->mp_fld_aneg_config_bypass = get_field(r, MAC_PCS_XXV_ANEG_CONFIG_3_BYPASS);
		rf->mp_fld_aneg_config_restart = get_field(r, MAC_PCS_XXV_ANEG_CONFIG_3_RESTART);
		rf->mp_fld_aneg_config_pseudo = get_field(r, MAC_PCS_XXV_ANEG_CONFIG_3_PSEUDO);
		rf->mp_fld_aneg_config_nonce_seed =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_3_NONCE_SEED);
		rf->mp_fld_aneg_config_remote_fault =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_3_REMOTE_FAULT);
		rf->mp_fld_aneg_config_pause = get_field(r, MAC_PCS_XXV_ANEG_CONFIG_3_PAUSE);
		rf->mp_fld_aneg_config_asmdir = get_field(r, MAC_PCS_XXV_ANEG_CONFIG_3_ASMDIR);
		rf->mp_fld_aneg_config_fec74_request10g =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_3_FEC74_REQUEST_10G);
		rf->mp_fld_aneg_config_hide_fec74 =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_3_HIDE_FEC74);
		rf->mp_fld_aneg_config_fec74_request =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_3_FEC74_REQUEST);
		rf->mp_fld_aneg_config_fec91_request =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_3_FEC91_REQUEST);
		rf->mp_fld_aneg_config_fec91_ability =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_3_FEC91_ABILITY);
		rf->mp_fld_aneg_config_rs_fec_request =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_3_RS_FEC_REQUEST);
		rf->mp_fld_aneg_config_sw_fec_overwrite =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_3_SW_FEC_OVERWRITE);
		rf->mp_fld_aneg_config_sw_speed_overwrite =
			get_field(r, MAC_PCS_XXV_ANEG_CONFIG_3_SW_SPEED_OVERWRITE);

		/* ANEG_ABILITY */
		r = get_register(module, MAC_PCS_XXV_ANEG_ABILITY_3);
		rf->mp_reg_aneg_ability = r;
		rf->mp_fld_aneg_ability_25g_base_cr =
			get_field(r, MAC_PCS_XXV_ANEG_ABILITY_3_25GBASE_CR);
		rf->mp_fld_aneg_ability_25g_base_crs =
			get_field(r, MAC_PCS_XXV_ANEG_ABILITY_3_25GBASE_CR_S);
		rf->mp_fld_aneg_ability_25g_base_cr1 =
			get_field(r, MAC_PCS_XXV_ANEG_ABILITY_3_25GBASE_CR1);

		/* LT_CONF */
		r = get_register(module, MAC_PCS_XXV_LT_CONF_3);
		rf->mp_reg_lt_conf = r;
		rf->mp_fld_lt_conf_enable = get_field(r, MAC_PCS_XXV_LT_CONF_3_ENABLE);
		rf->mp_fld_lt_conf_restart = get_field(r, MAC_PCS_XXV_LT_CONF_3_RESTART);
		rf->mp_fld_lt_conf_seed = get_field(r, MAC_PCS_XXV_LT_CONF_3_SEED);
	}

	/*
	 * Registers MAC_PCS_XXV_SUB_RST_0 -- MAC_PCS_XXV_SUB_RST_3
	 * and       MAC_PCS_XXV_SUB_RST_STATUS_0 -- MAC_PCS_XXV_SUB_RST_STATUS_3
	 */
	if (n_channels <= 4) {
		/* Initialize regs/fields for sub-module/channel 0 */
		rf = &p->regs[0];
		r = get_register(module, MAC_PCS_XXV_SUB_RST_0);

		rf->mp_reg_sub_rst = r;
		rf->mp_fld_sub_rst_rx_mac_pcs = get_field(r, MAC_PCS_XXV_SUB_RST_0_RX_MAC_PCS);
		rf->mp_fld_sub_rst_tx_mac_pcs = get_field(r, MAC_PCS_XXV_SUB_RST_0_TX_MAC_PCS);
		rf->mp_fld_sub_rst_rx_gt_data = get_field(r, MAC_PCS_XXV_SUB_RST_0_RX_GT_DATA);
		rf->mp_fld_sub_rst_tx_gt_data = get_field(r, MAC_PCS_XXV_SUB_RST_0_TX_GT_DATA);
		rf->mp_fld_sub_rst_rx_buf = get_field(r, MAC_PCS_XXV_SUB_RST_0_RX_BUF);
		rf->mp_fld_sub_rst_rx_pma = get_field(r, MAC_PCS_XXV_SUB_RST_0_RX_PMA);
		rf->mp_fld_sub_rst_tx_pma = get_field(r, MAC_PCS_XXV_SUB_RST_0_TX_PMA);
		rf->mp_fld_sub_rst_rx_pcs = get_field(r, MAC_PCS_XXV_SUB_RST_0_RX_PCS);
		rf->mp_fld_sub_rst_tx_pcs = get_field(r, MAC_PCS_XXV_SUB_RST_0_TX_PCS);
		rf->mp_fld_sub_rst_an_lt = get_field(r, MAC_PCS_XXV_SUB_RST_0_AN_LT);
		rf->mp_fld_sub_rst_speed_ctrl = query_field(r, MAC_PCS_XXV_SUB_RST_0_SPEED_CTRL);

		r = get_register(module, MAC_PCS_XXV_SUB_RST_STATUS_0);
		rf->mp_reg_sub_rst_status = r;
		rf->mp_fld_sub_rst_status_user_rx_rst =
			get_field(r, MAC_PCS_XXV_SUB_RST_STATUS_0_USER_RX_RST);
		rf->mp_fld_sub_rst_status_user_tx_rst =
			get_field(r, MAC_PCS_XXV_SUB_RST_STATUS_0_USER_TX_RST);
		rf->mp_fld_sub_rst_status_qpll_lock =
			get_field(r, MAC_PCS_XXV_SUB_RST_STATUS_0_QPLL_LOCK);
	}

	if (n_channels >= 2) {
		/* Initialize regs/fields for sub-module/channel 1 */
		rf = &p->regs[1];
		r = get_register(module, MAC_PCS_XXV_SUB_RST_1);

		rf->mp_reg_sub_rst = r;
		rf->mp_fld_sub_rst_rx_mac_pcs = get_field(r, MAC_PCS_XXV_SUB_RST_1_RX_MAC_PCS);
		rf->mp_fld_sub_rst_tx_mac_pcs = get_field(r, MAC_PCS_XXV_SUB_RST_1_TX_MAC_PCS);
		rf->mp_fld_sub_rst_rx_gt_data = get_field(r, MAC_PCS_XXV_SUB_RST_1_RX_GT_DATA);
		rf->mp_fld_sub_rst_tx_gt_data = get_field(r, MAC_PCS_XXV_SUB_RST_1_TX_GT_DATA);
		rf->mp_fld_sub_rst_rx_buf = get_field(r, MAC_PCS_XXV_SUB_RST_1_RX_BUF);
		rf->mp_fld_sub_rst_rx_pma = get_field(r, MAC_PCS_XXV_SUB_RST_1_RX_PMA);
		rf->mp_fld_sub_rst_tx_pma = get_field(r, MAC_PCS_XXV_SUB_RST_1_TX_PMA);
		rf->mp_fld_sub_rst_rx_pcs = get_field(r, MAC_PCS_XXV_SUB_RST_1_RX_PCS);
		rf->mp_fld_sub_rst_tx_pcs = get_field(r, MAC_PCS_XXV_SUB_RST_1_TX_PCS);
		rf->mp_fld_sub_rst_an_lt = get_field(r, MAC_PCS_XXV_SUB_RST_1_AN_LT);
		rf->mp_fld_sub_rst_speed_ctrl = query_field(r, MAC_PCS_XXV_SUB_RST_1_SPEED_CTRL);

		r = get_register(module, MAC_PCS_XXV_SUB_RST_STATUS_1);
		rf->mp_reg_sub_rst_status = r;
		rf->mp_fld_sub_rst_status_user_rx_rst =
			get_field(r, MAC_PCS_XXV_SUB_RST_STATUS_1_USER_RX_RST);
		rf->mp_fld_sub_rst_status_user_tx_rst =
			get_field(r, MAC_PCS_XXV_SUB_RST_STATUS_1_USER_TX_RST);
		rf->mp_fld_sub_rst_status_qpll_lock =
			get_field(r, MAC_PCS_XXV_SUB_RST_STATUS_1_QPLL_LOCK);
	}

	if (n_channels == 4) {
		/* Initialize regs/fields for sub-module/channel 2 */
		rf = &p->regs[2];
		r = get_register(module, MAC_PCS_XXV_SUB_RST_2);

		rf->mp_reg_sub_rst = r;
		rf->mp_fld_sub_rst_rx_mac_pcs = get_field(r, MAC_PCS_XXV_SUB_RST_2_RX_MAC_PCS);
		rf->mp_fld_sub_rst_tx_mac_pcs = get_field(r, MAC_PCS_XXV_SUB_RST_2_TX_MAC_PCS);
		rf->mp_fld_sub_rst_rx_gt_data = get_field(r, MAC_PCS_XXV_SUB_RST_2_RX_GT_DATA);
		rf->mp_fld_sub_rst_tx_gt_data = get_field(r, MAC_PCS_XXV_SUB_RST_2_TX_GT_DATA);
		rf->mp_fld_sub_rst_rx_buf = get_field(r, MAC_PCS_XXV_SUB_RST_2_RX_BUF);
		rf->mp_fld_sub_rst_rx_pma = get_field(r, MAC_PCS_XXV_SUB_RST_2_RX_PMA);
		rf->mp_fld_sub_rst_tx_pma = get_field(r, MAC_PCS_XXV_SUB_RST_2_TX_PMA);
		rf->mp_fld_sub_rst_rx_pcs = get_field(r, MAC_PCS_XXV_SUB_RST_2_RX_PCS);
		rf->mp_fld_sub_rst_tx_pcs = get_field(r, MAC_PCS_XXV_SUB_RST_2_TX_PCS);
		rf->mp_fld_sub_rst_an_lt = get_field(r, MAC_PCS_XXV_SUB_RST_2_AN_LT);
		rf->mp_fld_sub_rst_speed_ctrl = query_field(r, MAC_PCS_XXV_SUB_RST_2_SPEED_CTRL);

		r = get_register(module, MAC_PCS_XXV_SUB_RST_STATUS_2);
		rf->mp_reg_sub_rst_status = r;
		rf->mp_fld_sub_rst_status_user_rx_rst =
			get_field(r, MAC_PCS_XXV_SUB_RST_STATUS_2_USER_RX_RST);
		rf->mp_fld_sub_rst_status_user_tx_rst =
			get_field(r, MAC_PCS_XXV_SUB_RST_STATUS_2_USER_TX_RST);
		rf->mp_fld_sub_rst_status_qpll_lock =
			get_field(r, MAC_PCS_XXV_SUB_RST_STATUS_2_QPLL_LOCK);

		/* Initialize regs/fields for sub-module/channel 3 */
		rf = &p->regs[3];
		r = get_register(module, MAC_PCS_XXV_SUB_RST_3);

		rf->mp_reg_sub_rst = r;
		rf->mp_fld_sub_rst_rx_mac_pcs = get_field(r, MAC_PCS_XXV_SUB_RST_3_RX_MAC_PCS);
		rf->mp_fld_sub_rst_tx_mac_pcs = get_field(r, MAC_PCS_XXV_SUB_RST_3_TX_MAC_PCS);
		rf->mp_fld_sub_rst_rx_gt_data = get_field(r, MAC_PCS_XXV_SUB_RST_3_RX_GT_DATA);
		rf->mp_fld_sub_rst_tx_gt_data = get_field(r, MAC_PCS_XXV_SUB_RST_3_TX_GT_DATA);
		rf->mp_fld_sub_rst_rx_buf = get_field(r, MAC_PCS_XXV_SUB_RST_3_RX_BUF);
		rf->mp_fld_sub_rst_rx_pma = get_field(r, MAC_PCS_XXV_SUB_RST_3_RX_PMA);
		rf->mp_fld_sub_rst_tx_pma = get_field(r, MAC_PCS_XXV_SUB_RST_3_TX_PMA);
		rf->mp_fld_sub_rst_rx_pcs = get_field(r, MAC_PCS_XXV_SUB_RST_3_RX_PCS);
		rf->mp_fld_sub_rst_tx_pcs = get_field(r, MAC_PCS_XXV_SUB_RST_3_TX_PCS);
		rf->mp_fld_sub_rst_an_lt = get_field(r, MAC_PCS_XXV_SUB_RST_3_AN_LT);
		rf->mp_fld_sub_rst_speed_ctrl = query_field(r, MAC_PCS_XXV_SUB_RST_3_SPEED_CTRL);

		r = get_register(module, MAC_PCS_XXV_SUB_RST_STATUS_3);
		rf->mp_reg_sub_rst_status = r;
		rf->mp_fld_sub_rst_status_user_rx_rst =
			get_field(r, MAC_PCS_XXV_SUB_RST_STATUS_3_USER_RX_RST);
		rf->mp_fld_sub_rst_status_user_tx_rst =
			get_field(r, MAC_PCS_XXV_SUB_RST_STATUS_3_USER_TX_RST);
		rf->mp_fld_sub_rst_status_qpll_lock =
			get_field(r, MAC_PCS_XXV_SUB_RST_STATUS_3_QPLL_LOCK);
	}

	/* Registers MAC_PCS_XXV_LINK_SUMMARY_0 -- MAC_PCS_XXV_LINK_SUMMARY_3 */
	if (n_channels <= 4) {
		/* Initialize regs/fields for sub-module/channel 0 */
		rf = &p->regs[0];
		r = get_register(module, MAC_PCS_XXV_LINK_SUMMARY_0);

		rf->mp_reg_link_summary = r;
		rf->mp_fld_link_summary_nt_phy_link_state =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_0_NT_PHY_LINK_STATE);
		rf->mp_fld_link_summary_ll_nt_phy_link_state =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_0_LL_PHY_LINK_STATE);
		rf->mp_fld_link_summary_abs = get_field(r, MAC_PCS_XXV_LINK_SUMMARY_0_ABS);
		rf->mp_fld_link_summary_lh_abs = get_field(r, MAC_PCS_XXV_LINK_SUMMARY_0_LH_ABS);
		rf->mp_fld_link_summary_link_down_cnt =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_0_LINK_DOWN_CNT);

		if (!mac_8x10G) {
			rf->mp_fld_link_summary_ll_rx_fec74_lock =
				get_field(r, MAC_PCS_XXV_LINK_SUMMARY_0_LL_RX_FEC74_LOCK);
			rf->mp_fld_link_summary_lh_rx_rsfec_hi_ser =
				get_field(r, MAC_PCS_XXV_LINK_SUMMARY_0_LH_RX_RSFEC_HI_SER);
			rf->mp_fld_link_summary_ll_rx_rsfec_lane_alignment =
				get_field(r,
					MAC_PCS_XXV_LINK_SUMMARY_0_LL_RX_RSFEC_LANE_ALIGNMENT);
			rf->mp_fld_link_summary_ll_tx_rsfec_lane_alignment =
				get_field(r,
					MAC_PCS_XXV_LINK_SUMMARY_0_LL_TX_RSFEC_LANE_ALIGNMENT);
			rf->mp_fld_link_summary_lh_rx_pcs_valid_ctrl_code =
				get_field(r, MAC_PCS_XXV_LINK_SUMMARY_0_LH_RX_PCS_VALID_CTRL_CODE);
		}

		rf->mp_fld_link_summary_ll_rx_block_lock =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_0_LL_RX_BLOCK_LOCK);
		rf->mp_fld_link_summary_lh_rx_high_bit_error_rate =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_0_LH_RX_HIGH_BIT_ERROR_RATE);
		rf->mp_fld_link_summary_lh_internal_local_fault =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_0_LH_INTERNAL_LOCAL_FAULT);
		rf->mp_fld_link_summary_lh_received_local_fault =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_0_LH_RECEIVED_LOCAL_FAULT);
		rf->mp_fld_link_summary_lh_local_fault =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_0_LH_LOCAL_FAULT);
		rf->mp_fld_link_summary_lh_remote_fault =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_0_LH_REMOTE_FAULT);
		rf->mp_fld_link_summary_nim_interr =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_0_NIM_INTERR);
	}

	if (n_channels >= 2) {
		/* Initialize regs/fields for sub-module/channel 1 */
		rf = &p->regs[1];
		r = get_register(module, MAC_PCS_XXV_LINK_SUMMARY_1);

		rf->mp_reg_link_summary = r;
		rf->mp_fld_link_summary_nt_phy_link_state =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_1_NT_PHY_LINK_STATE);
		rf->mp_fld_link_summary_ll_nt_phy_link_state =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_1_LL_PHY_LINK_STATE);
		rf->mp_fld_link_summary_abs = get_field(r, MAC_PCS_XXV_LINK_SUMMARY_1_ABS);
		rf->mp_fld_link_summary_lh_abs = get_field(r, MAC_PCS_XXV_LINK_SUMMARY_1_LH_ABS);
		rf->mp_fld_link_summary_link_down_cnt =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_1_LINK_DOWN_CNT);

		if (!mac_8x10G) {
			rf->mp_fld_link_summary_ll_rx_fec74_lock =
				get_field(r, MAC_PCS_XXV_LINK_SUMMARY_1_LL_RX_FEC74_LOCK);
			rf->mp_fld_link_summary_lh_rx_rsfec_hi_ser =
				get_field(r, MAC_PCS_XXV_LINK_SUMMARY_1_LH_RX_RSFEC_HI_SER);
			rf->mp_fld_link_summary_ll_rx_rsfec_lane_alignment =
				get_field(r,
					MAC_PCS_XXV_LINK_SUMMARY_1_LL_RX_RSFEC_LANE_ALIGNMENT);
			rf->mp_fld_link_summary_ll_tx_rsfec_lane_alignment =
				get_field(r,
					MAC_PCS_XXV_LINK_SUMMARY_1_LL_TX_RSFEC_LANE_ALIGNMENT);
			rf->mp_fld_link_summary_lh_rx_pcs_valid_ctrl_code =
				get_field(r, MAC_PCS_XXV_LINK_SUMMARY_1_LH_RX_PCS_VALID_CTRL_CODE);
		}

		rf->mp_fld_link_summary_ll_rx_block_lock =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_1_LL_RX_BLOCK_LOCK);
		rf->mp_fld_link_summary_lh_rx_high_bit_error_rate =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_1_LH_RX_HIGH_BIT_ERROR_RATE);
		rf->mp_fld_link_summary_lh_internal_local_fault =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_1_LH_INTERNAL_LOCAL_FAULT);
		rf->mp_fld_link_summary_lh_received_local_fault =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_1_LH_RECEIVED_LOCAL_FAULT);
		rf->mp_fld_link_summary_lh_local_fault =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_1_LH_LOCAL_FAULT);
		rf->mp_fld_link_summary_lh_remote_fault =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_1_LH_REMOTE_FAULT);
		rf->mp_fld_link_summary_nim_interr =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_1_NIM_INTERR);
	}

	if (n_channels == 4) {
		/* Initialize regs/fields for sub-module/channel 2 */
		rf = &p->regs[2];
		r = get_register(module, MAC_PCS_XXV_LINK_SUMMARY_2);

		rf->mp_reg_link_summary = r;
		rf->mp_fld_link_summary_nt_phy_link_state =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_2_NT_PHY_LINK_STATE);
		rf->mp_fld_link_summary_ll_nt_phy_link_state =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_2_LL_PHY_LINK_STATE);
		rf->mp_fld_link_summary_abs = get_field(r, MAC_PCS_XXV_LINK_SUMMARY_2_ABS);
		rf->mp_fld_link_summary_lh_abs = get_field(r, MAC_PCS_XXV_LINK_SUMMARY_2_LH_ABS);
		rf->mp_fld_link_summary_link_down_cnt =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_2_LINK_DOWN_CNT);

		if (!mac_8x10G) {
			rf->mp_fld_link_summary_ll_rx_fec74_lock =
				get_field(r, MAC_PCS_XXV_LINK_SUMMARY_2_LL_RX_FEC74_LOCK);
			rf->mp_fld_link_summary_lh_rx_rsfec_hi_ser =
				get_field(r, MAC_PCS_XXV_LINK_SUMMARY_2_LH_RX_RSFEC_HI_SER);
			rf->mp_fld_link_summary_ll_rx_rsfec_lane_alignment =
				get_field(r,
					MAC_PCS_XXV_LINK_SUMMARY_2_LL_RX_RSFEC_LANE_ALIGNMENT);
			rf->mp_fld_link_summary_ll_tx_rsfec_lane_alignment =
				get_field(r,
					MAC_PCS_XXV_LINK_SUMMARY_2_LL_TX_RSFEC_LANE_ALIGNMENT);
			rf->mp_fld_link_summary_lh_rx_pcs_valid_ctrl_code =
				get_field(r, MAC_PCS_XXV_LINK_SUMMARY_2_LH_RX_PCS_VALID_CTRL_CODE);
		}

		rf->mp_fld_link_summary_ll_rx_block_lock =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_2_LL_RX_BLOCK_LOCK);
		rf->mp_fld_link_summary_lh_rx_high_bit_error_rate =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_2_LH_RX_HIGH_BIT_ERROR_RATE);
		rf->mp_fld_link_summary_lh_internal_local_fault =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_2_LH_INTERNAL_LOCAL_FAULT);
		rf->mp_fld_link_summary_lh_received_local_fault =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_2_LH_RECEIVED_LOCAL_FAULT);
		rf->mp_fld_link_summary_lh_local_fault =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_2_LH_LOCAL_FAULT);
		rf->mp_fld_link_summary_lh_remote_fault =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_2_LH_REMOTE_FAULT);
		rf->mp_fld_link_summary_nim_interr =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_2_NIM_INTERR);

		/* Initialize regs/fields for sub-module/channel 3 */
		rf = &p->regs[3];
		r = get_register(module, MAC_PCS_XXV_LINK_SUMMARY_3);

		rf->mp_reg_link_summary = r;
		rf->mp_fld_link_summary_nt_phy_link_state =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_3_NT_PHY_LINK_STATE);
		rf->mp_fld_link_summary_ll_nt_phy_link_state =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_3_LL_PHY_LINK_STATE);
		rf->mp_fld_link_summary_abs = get_field(r, MAC_PCS_XXV_LINK_SUMMARY_3_ABS);
		rf->mp_fld_link_summary_lh_abs = get_field(r, MAC_PCS_XXV_LINK_SUMMARY_3_LH_ABS);
		rf->mp_fld_link_summary_link_down_cnt =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_3_LINK_DOWN_CNT);

		if (!mac_8x10G) {
			rf->mp_fld_link_summary_ll_rx_fec74_lock =
				get_field(r, MAC_PCS_XXV_LINK_SUMMARY_3_LL_RX_FEC74_LOCK);
			rf->mp_fld_link_summary_lh_rx_rsfec_hi_ser =
				get_field(r, MAC_PCS_XXV_LINK_SUMMARY_3_LH_RX_RSFEC_HI_SER);
			rf->mp_fld_link_summary_ll_rx_rsfec_lane_alignment =
				get_field(r,
					MAC_PCS_XXV_LINK_SUMMARY_3_LL_RX_RSFEC_LANE_ALIGNMENT);
			rf->mp_fld_link_summary_ll_tx_rsfec_lane_alignment =
				get_field(r,
					MAC_PCS_XXV_LINK_SUMMARY_3_LL_TX_RSFEC_LANE_ALIGNMENT);
			rf->mp_fld_link_summary_lh_rx_pcs_valid_ctrl_code =
				get_field(r, MAC_PCS_XXV_LINK_SUMMARY_3_LH_RX_PCS_VALID_CTRL_CODE);
		}

		rf->mp_fld_link_summary_ll_rx_block_lock =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_3_LL_RX_BLOCK_LOCK);
		rf->mp_fld_link_summary_lh_rx_high_bit_error_rate =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_3_LH_RX_HIGH_BIT_ERROR_RATE);
		rf->mp_fld_link_summary_lh_internal_local_fault =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_3_LH_INTERNAL_LOCAL_FAULT);
		rf->mp_fld_link_summary_lh_received_local_fault =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_3_LH_RECEIVED_LOCAL_FAULT);
		rf->mp_fld_link_summary_lh_local_fault =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_3_LH_LOCAL_FAULT);
		rf->mp_fld_link_summary_lh_remote_fault =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_3_LH_REMOTE_FAULT);
		rf->mp_fld_link_summary_nim_interr =
			get_field(r, MAC_PCS_XXV_LINK_SUMMARY_3_NIM_INTERR);
	}

	/*
	 * Registers MAC_PCS_XXV_GTY_LOOP_0 -- MAC_PCS_XXV_GTY_LOOP_3
	 * and       MAC_PCS_XXV_GTY_CTL_RX_0 -- MAC_PCS_XXV_GTY_CTL_RX_3
	 * and       MAC_PCS_XXV_GTY_CTL_TX_0 -- MAC_PCS_XXV_GTY_CTL_TX_3
	 * and       MAC_PCS_XXV_LINK_SPEED_0 -- MAC_PCS_XXV_LINK_SPEED_3
	 * and       MAC_PCS_XXV_RS_FEC_CONF_0 -- MAC_PCS_XXV_RS_FEC_CONF_0
	 */
	if (n_channels <= 4) {
		/* Initialize regs/fields for sub-module/channel 0 */
		rf = &p->regs[0];

		r = get_register(module, MAC_PCS_XXV_GTY_LOOP_0);
		rf->mp_reg_gty_loop = r;
		rf->mp_fld_gty_loop_gt_loop = get_field(r, MAC_PCS_XXV_GTY_LOOP_0_GT_LOOP);

		r = get_register(module, MAC_PCS_XXV_GTY_CTL_RX_0);
		rf->mp_reg_gty_ctl_rx = r;
		rf->mp_fld_gty_ctl_rx_polarity = get_field(r, MAC_PCS_XXV_GTY_CTL_RX_0_POLARITY);
		rf->mp_fld_gty_ctl_rx_lpm_en = get_field(r, MAC_PCS_XXV_GTY_CTL_RX_0_LPM_EN);
		rf->mp_fld_gty_ctl_rx_equa_rst = get_field(r, MAC_PCS_XXV_GTY_CTL_RX_0_EQUA_RST);

		r = get_register(module, MAC_PCS_XXV_GTY_CTL_TX_0);
		rf->mp_fld_gty_ctl_tx_polarity = get_field(r, MAC_PCS_XXV_GTY_CTL_TX_0_POLARITY);
		rf->mp_fld_gty_ctl_tx_inhibit = get_field(r, MAC_PCS_XXV_GTY_CTL_TX_0_INHIBIT);

		if (!mac_8x10G) {
			r = get_register(module, MAC_PCS_XXV_LINK_SPEED_0);
			rf->mp_reg_link_speed = get_register(module, MAC_PCS_XXV_LINK_SPEED_0);

			rf->mp_fld_link_speed_10g = query_field(r, MAC_PCS_XXV_LINK_SPEED_0_SPEED);

			if (!rf->mp_fld_link_speed_10g) {
				rf->mp_fld_link_speed_10g =
					get_field(r, MAC_PCS_XXV_LINK_SPEED_0_10G);
			}

			rf->mp_fld_link_speed_toggle =
				get_field(r, MAC_PCS_XXV_LINK_SPEED_0_TOGGLE);

			r = get_register(module, MAC_PCS_XXV_RS_FEC_CONF_0);
			rf->mp_reg_rs_fec_conf = r;
			rf->mp_fld_rs_fec_conf_rs_fec_enable =
				get_field(r, MAC_PCS_XXV_RS_FEC_CONF_0_RS_FEC_ENABLE);

			r = get_register(module, MAC_PCS_XXV_RS_FEC_CCW_CNT_0);
			rf->mp_reg_rs_fec_ccw = r;
			rf->mp_field_reg_rs_fec_ccw_reg_rs_fec_ccw_cnt =
				get_field(r, MAC_PCS_XXV_RS_FEC_CCW_CNT_0_RS_FEC_CCW_CNT);

			r = get_register(module, MAC_PCS_XXV_RS_FEC_UCW_CNT_0);
			rf->mp_reg_rs_fec_ucw = r;
			rf->mp_field_reg_rs_fec_ucw_reg_rs_fec_ucw_cnt =
				get_field(r, MAC_PCS_XXV_RS_FEC_UCW_CNT_0_RS_FEC_UCW_CNT);
		}
	}

	if (n_channels >= 2) {
		/* Initialize regs/fields for sub-module/channel 1 */
		rf = &p->regs[1];

		r = get_register(module, MAC_PCS_XXV_GTY_LOOP_1);
		rf->mp_reg_gty_loop = r;
		rf->mp_fld_gty_loop_gt_loop = get_field(r, MAC_PCS_XXV_GTY_LOOP_1_GT_LOOP);

		r = get_register(module, MAC_PCS_XXV_GTY_CTL_RX_1);
		rf->mp_reg_gty_ctl_rx = r;
		rf->mp_fld_gty_ctl_rx_polarity = get_field(r, MAC_PCS_XXV_GTY_CTL_RX_1_POLARITY);
		rf->mp_fld_gty_ctl_rx_lpm_en = get_field(r, MAC_PCS_XXV_GTY_CTL_RX_1_LPM_EN);
		rf->mp_fld_gty_ctl_rx_equa_rst = get_field(r, MAC_PCS_XXV_GTY_CTL_RX_1_EQUA_RST);

		r = get_register(module, MAC_PCS_XXV_GTY_CTL_TX_1);
		rf->mp_fld_gty_ctl_tx_polarity = get_field(r, MAC_PCS_XXV_GTY_CTL_TX_1_POLARITY);
		rf->mp_fld_gty_ctl_tx_inhibit = get_field(r, MAC_PCS_XXV_GTY_CTL_TX_1_INHIBIT);

		if (!mac_8x10G) {
			r = get_register(module, MAC_PCS_XXV_LINK_SPEED_1);
			rf->mp_reg_link_speed = get_register(module, MAC_PCS_XXV_LINK_SPEED_1);

			rf->mp_fld_link_speed_10g = get_field(r, MAC_PCS_XXV_LINK_SPEED_1_SPEED);

			if (!rf->mp_fld_link_speed_10g) {
				rf->mp_fld_link_speed_10g =
					get_field(r, MAC_PCS_XXV_LINK_SPEED_1_10G);
			}

			rf->mp_fld_link_speed_toggle =
				get_field(r, MAC_PCS_XXV_LINK_SPEED_1_TOGGLE);

			r = get_register(module, MAC_PCS_XXV_RS_FEC_CONF_1);
			rf->mp_reg_rs_fec_conf = r;
			rf->mp_fld_rs_fec_conf_rs_fec_enable =
				get_field(r, MAC_PCS_XXV_RS_FEC_CONF_1_RS_FEC_ENABLE);

			r = get_register(module, MAC_PCS_XXV_RS_FEC_CCW_CNT_1);
			rf->mp_reg_rs_fec_ccw = r;
			rf->mp_field_reg_rs_fec_ccw_reg_rs_fec_ccw_cnt =
				get_field(r, MAC_PCS_XXV_RS_FEC_CCW_CNT_1_RS_FEC_CCW_CNT);

			r = get_register(module, MAC_PCS_XXV_RS_FEC_UCW_CNT_1);
			rf->mp_reg_rs_fec_ucw = r;
			rf->mp_field_reg_rs_fec_ucw_reg_rs_fec_ucw_cnt =
				get_field(r, MAC_PCS_XXV_RS_FEC_UCW_CNT_1_RS_FEC_UCW_CNT);
		}
	}

	if (n_channels == 4) {
		/* Initialize regs/fields for sub-module/channel 2 */
		rf = &p->regs[2];

		r = get_register(module, MAC_PCS_XXV_GTY_LOOP_2);
		rf->mp_reg_gty_loop = r;
		rf->mp_fld_gty_loop_gt_loop = get_field(r, MAC_PCS_XXV_GTY_LOOP_2_GT_LOOP);

		r = get_register(module, MAC_PCS_XXV_GTY_CTL_RX_2);
		rf->mp_reg_gty_ctl_rx = r;
		rf->mp_fld_gty_ctl_rx_polarity = get_field(r, MAC_PCS_XXV_GTY_CTL_RX_2_POLARITY);
		rf->mp_fld_gty_ctl_rx_lpm_en = get_field(r, MAC_PCS_XXV_GTY_CTL_RX_2_LPM_EN);
		rf->mp_fld_gty_ctl_rx_equa_rst = get_field(r, MAC_PCS_XXV_GTY_CTL_RX_2_EQUA_RST);

		r = get_register(module, MAC_PCS_XXV_GTY_CTL_TX_2);
		rf->mp_fld_gty_ctl_tx_polarity = get_field(r, MAC_PCS_XXV_GTY_CTL_TX_2_POLARITY);
		rf->mp_fld_gty_ctl_tx_inhibit = get_field(r, MAC_PCS_XXV_GTY_CTL_TX_2_INHIBIT);

		if (!mac_8x10G) {
			r = get_register(module, MAC_PCS_XXV_LINK_SPEED_2);
			rf->mp_reg_link_speed = get_register(module, MAC_PCS_XXV_LINK_SPEED_2);

			rf->mp_fld_link_speed_10g = get_field(r, MAC_PCS_XXV_LINK_SPEED_2_SPEED);

			if (!rf->mp_fld_link_speed_10g) {
				rf->mp_fld_link_speed_10g =
					get_field(r, MAC_PCS_XXV_LINK_SPEED_2_10G);
			}

			rf->mp_fld_link_speed_toggle =
				get_field(r, MAC_PCS_XXV_LINK_SPEED_2_TOGGLE);

			r = get_register(module, MAC_PCS_XXV_RS_FEC_CONF_2);
			rf->mp_reg_rs_fec_conf = r;
			rf->mp_fld_rs_fec_conf_rs_fec_enable =
				get_field(r, MAC_PCS_XXV_RS_FEC_CONF_2_RS_FEC_ENABLE);

			r = get_register(module, MAC_PCS_XXV_RS_FEC_CCW_CNT_2);
			rf->mp_reg_rs_fec_ccw = r;
			rf->mp_field_reg_rs_fec_ccw_reg_rs_fec_ccw_cnt =
				get_field(r, MAC_PCS_XXV_RS_FEC_CCW_CNT_2_RS_FEC_CCW_CNT);

			r = get_register(module, MAC_PCS_XXV_RS_FEC_UCW_CNT_2);
			rf->mp_reg_rs_fec_ucw = r;
			rf->mp_field_reg_rs_fec_ucw_reg_rs_fec_ucw_cnt =
				get_field(r, MAC_PCS_XXV_RS_FEC_UCW_CNT_2_RS_FEC_UCW_CNT);
		}

		/* Initialize regs/fields for sub-module/channel 3 */
		rf = &p->regs[3];

		r = get_register(module, MAC_PCS_XXV_GTY_LOOP_3);
		rf->mp_reg_gty_loop = r;
		rf->mp_fld_gty_loop_gt_loop = get_field(r, MAC_PCS_XXV_GTY_LOOP_3_GT_LOOP);

		r = get_register(module, MAC_PCS_XXV_GTY_CTL_RX_3);
		rf->mp_reg_gty_ctl_rx = r;
		rf->mp_fld_gty_ctl_rx_polarity = get_field(r, MAC_PCS_XXV_GTY_CTL_RX_3_POLARITY);
		rf->mp_fld_gty_ctl_rx_lpm_en = get_field(r, MAC_PCS_XXV_GTY_CTL_RX_3_LPM_EN);
		rf->mp_fld_gty_ctl_rx_equa_rst = get_field(r, MAC_PCS_XXV_GTY_CTL_RX_3_EQUA_RST);

		r = get_register(module, MAC_PCS_XXV_GTY_CTL_TX_3);
		rf->mp_fld_gty_ctl_tx_polarity = get_field(r, MAC_PCS_XXV_GTY_CTL_TX_3_POLARITY);
		rf->mp_fld_gty_ctl_tx_inhibit = get_field(r, MAC_PCS_XXV_GTY_CTL_TX_3_INHIBIT);

		if (!mac_8x10G) {
			r = get_register(module, MAC_PCS_XXV_LINK_SPEED_3);
			rf->mp_reg_link_speed = get_register(module, MAC_PCS_XXV_LINK_SPEED_3);

			rf->mp_fld_link_speed_10g = get_field(r, MAC_PCS_XXV_LINK_SPEED_3_SPEED);

			if (!rf->mp_fld_link_speed_10g) {
				rf->mp_fld_link_speed_10g =
					get_field(r, MAC_PCS_XXV_LINK_SPEED_3_10G);
			}

			rf->mp_fld_link_speed_toggle =
				get_field(r, MAC_PCS_XXV_LINK_SPEED_3_TOGGLE);

			r = get_register(module, MAC_PCS_XXV_RS_FEC_CONF_3);
			rf->mp_reg_rs_fec_conf = r;
			rf->mp_fld_rs_fec_conf_rs_fec_enable =
				get_field(r, MAC_PCS_XXV_RS_FEC_CONF_3_RS_FEC_ENABLE);

			r = get_register(module, MAC_PCS_XXV_RS_FEC_CCW_CNT_3);
			rf->mp_reg_rs_fec_ccw = r;
			rf->mp_field_reg_rs_fec_ccw_reg_rs_fec_ccw_cnt =
				get_field(r, MAC_PCS_XXV_RS_FEC_CCW_CNT_3_RS_FEC_CCW_CNT);

			r = get_register(module, MAC_PCS_XXV_RS_FEC_UCW_CNT_3);
			rf->mp_reg_rs_fec_ucw = r;
			rf->mp_field_reg_rs_fec_ucw_reg_rs_fec_ucw_cnt =
				get_field(r, MAC_PCS_XXV_RS_FEC_UCW_CNT_3_RS_FEC_UCW_CNT);
		}
	}

	/*
	 * Registers MAC_PCS_XXV_DEBOUNCE_CTRL_0 -- MAC_PCS_XXV_DEBOUNCE_CTRL_3
	 * and       MAC_PCS_XXV_TIMESTAMP_COMP_0 -- MAC_PCS_XXV_TIMESTAMP_COMP_3
	 * and       MAC_PCS_XXV_GTY_PRE_CURSOR_0 -- MAC_PCS_XXV_GTY_PRE_CURSOR_3
	 * and       MAC_PCS_XXV_GTY_DIFF_CTL_0 -- MAC_PCS_XXV_GTY_DIFF_CTL_0
	 * and       MAC_PCS_XXV_GTY_POST_CURSOR_0 -- MAC_PCS_XXV_GTY_POST_CURSOR_3
	 */
	if (n_channels <= 4) {
		/* Initialize regs/fields for sub-module/channel 0 */
		rf = &p->regs[0];

		r = get_register(module, MAC_PCS_XXV_DEBOUNCE_CTRL_0);

		rf->mp_reg_debounce_ctrl = r;
		rf->mp_field_debounce_ctrl_nt_port_ctrl =
			get_field(r, MAC_PCS_XXV_DEBOUNCE_CTRL_0_NT_PORT_CTRL);

		r = get_register(module, MAC_PCS_XXV_TIMESTAMP_COMP_0);
		rf->mp_reg_timestamp_comp = r;
		rf->mp_field_timestamp_comp_rx_dly =
			get_field(r, MAC_PCS_XXV_TIMESTAMP_COMP_0_RX_DLY);
		rf->mp_field_timestamp_comp_tx_dly =
			get_field(r, MAC_PCS_XXV_TIMESTAMP_COMP_0_TX_DLY);

		/* GTY_PRE_CURSOR */
		r = get_register(p->mp_mod_mac_pcs_xxv, MAC_PCS_XXV_GTY_PRE_CURSOR_0);
		rf->mp_reg_gty_pre_cursor = r;
		rf->mp_field_gty_pre_cursor_tx_pre_csr =
			get_field(r, MAC_PCS_XXV_GTY_PRE_CURSOR_0_TX_PRE_CSR);

		/* GTY_DIFF_CTL */
		r = get_register(module, MAC_PCS_XXV_GTY_DIFF_CTL_0);
		rf->mp_reg_gty_diff_ctl = r;
		rf->mp_field_gty_gty_diff_ctl_tx_diff_ctl =
			get_field(r, MAC_PCS_XXV_GTY_DIFF_CTL_0_TX_DIFF_CTL);

		/* GTY_POST_CURSOR */
		r = get_register(module, MAC_PCS_XXV_GTY_POST_CURSOR_0);
		rf->mp_reg_gty_post_cursor = r;
		rf->mp_field_gty_post_cursor_tx_post_csr =
			get_field(r, MAC_PCS_XXV_GTY_POST_CURSOR_0_TX_POST_CSR);
	}

	if (n_channels >= 2) {
		/* Initialize regs/fields for sub-module/channel 1 */
		rf = &p->regs[1];

		r = get_register(module, MAC_PCS_XXV_DEBOUNCE_CTRL_1);

		rf->mp_reg_debounce_ctrl = r;
		rf->mp_field_debounce_ctrl_nt_port_ctrl =
			get_field(r, MAC_PCS_XXV_DEBOUNCE_CTRL_1_NT_PORT_CTRL);

		r = get_register(module, MAC_PCS_XXV_TIMESTAMP_COMP_1);
		rf->mp_reg_timestamp_comp = r;
		rf->mp_field_timestamp_comp_rx_dly =
			get_field(r, MAC_PCS_XXV_TIMESTAMP_COMP_1_RX_DLY);
		rf->mp_field_timestamp_comp_tx_dly =
			get_field(r, MAC_PCS_XXV_TIMESTAMP_COMP_1_TX_DLY);

		/* GTY_PRE_CURSOR */
		r = get_register(p->mp_mod_mac_pcs_xxv, MAC_PCS_XXV_GTY_PRE_CURSOR_1);
		rf->mp_reg_gty_pre_cursor = r;
		rf->mp_field_gty_pre_cursor_tx_pre_csr =
			get_field(r, MAC_PCS_XXV_GTY_PRE_CURSOR_1_TX_PRE_CSR);

		/* GTY_DIFF_CTL */
		r = get_register(module, MAC_PCS_XXV_GTY_DIFF_CTL_1);
		rf->mp_reg_gty_diff_ctl = r;
		rf->mp_field_gty_gty_diff_ctl_tx_diff_ctl =
			get_field(r, MAC_PCS_XXV_GTY_DIFF_CTL_1_TX_DIFF_CTL);

		/* GTY_POST_CURSOR */
		r = get_register(module, MAC_PCS_XXV_GTY_POST_CURSOR_1);
		rf->mp_reg_gty_post_cursor = r;
		rf->mp_field_gty_post_cursor_tx_post_csr =
			get_field(r, MAC_PCS_XXV_GTY_POST_CURSOR_1_TX_POST_CSR);
	}

	if (n_channels == 4) {
		/* Initialize regs/fields for sub-module/channel 2 */
		rf = &p->regs[2];

		r = get_register(module, MAC_PCS_XXV_DEBOUNCE_CTRL_2);

		rf->mp_reg_debounce_ctrl = r;
		rf->mp_field_debounce_ctrl_nt_port_ctrl =
			get_field(r, MAC_PCS_XXV_DEBOUNCE_CTRL_2_NT_PORT_CTRL);

		r = get_register(module, MAC_PCS_XXV_TIMESTAMP_COMP_2);
		rf->mp_reg_timestamp_comp = r;
		rf->mp_field_timestamp_comp_rx_dly =
			get_field(r, MAC_PCS_XXV_TIMESTAMP_COMP_2_RX_DLY);
		rf->mp_field_timestamp_comp_tx_dly =
			get_field(r, MAC_PCS_XXV_TIMESTAMP_COMP_2_TX_DLY);

		/* GTY_PRE_CURSOR */
		r = get_register(p->mp_mod_mac_pcs_xxv, MAC_PCS_XXV_GTY_PRE_CURSOR_2);
		rf->mp_reg_gty_pre_cursor = r;
		rf->mp_field_gty_pre_cursor_tx_pre_csr =
			get_field(r, MAC_PCS_XXV_GTY_PRE_CURSOR_2_TX_PRE_CSR);

		/* GTY_DIFF_CTL */
		r = get_register(module, MAC_PCS_XXV_GTY_DIFF_CTL_2);
		rf->mp_reg_gty_diff_ctl = r;
		rf->mp_field_gty_gty_diff_ctl_tx_diff_ctl =
			get_field(r, MAC_PCS_XXV_GTY_DIFF_CTL_2_TX_DIFF_CTL);

		/* GTY_POST_CURSOR */
		r = get_register(module, MAC_PCS_XXV_GTY_POST_CURSOR_2);
		rf->mp_reg_gty_post_cursor = r;
		rf->mp_field_gty_post_cursor_tx_post_csr =
			get_field(r, MAC_PCS_XXV_GTY_POST_CURSOR_2_TX_POST_CSR);

		/* Initialize regs/fields for sub-module/channel 3 */
		rf = &p->regs[3];

		r = get_register(module, MAC_PCS_XXV_DEBOUNCE_CTRL_3);

		rf->mp_reg_debounce_ctrl = r;
		rf->mp_field_debounce_ctrl_nt_port_ctrl =
			get_field(r, MAC_PCS_XXV_DEBOUNCE_CTRL_3_NT_PORT_CTRL);

		r = get_register(module, MAC_PCS_XXV_TIMESTAMP_COMP_3);
		rf->mp_reg_timestamp_comp = r;
		rf->mp_field_timestamp_comp_rx_dly =
			get_field(r, MAC_PCS_XXV_TIMESTAMP_COMP_3_RX_DLY);
		rf->mp_field_timestamp_comp_tx_dly =
			get_field(r, MAC_PCS_XXV_TIMESTAMP_COMP_3_TX_DLY);

		/* GTY_PRE_CURSOR */
		r = get_register(p->mp_mod_mac_pcs_xxv, MAC_PCS_XXV_GTY_PRE_CURSOR_3);
		rf->mp_reg_gty_pre_cursor = r;
		rf->mp_field_gty_pre_cursor_tx_pre_csr =
			get_field(r, MAC_PCS_XXV_GTY_PRE_CURSOR_3_TX_PRE_CSR);

		/* GTY_DIFF_CTL */
		r = get_register(module, MAC_PCS_XXV_GTY_DIFF_CTL_3);
		rf->mp_reg_gty_diff_ctl = r;
		rf->mp_field_gty_gty_diff_ctl_tx_diff_ctl =
			get_field(r, MAC_PCS_XXV_GTY_DIFF_CTL_3_TX_DIFF_CTL);

		/* GTY_POST_CURSOR */
		r = get_register(module, MAC_PCS_XXV_GTY_POST_CURSOR_3);
		rf->mp_reg_gty_post_cursor = r;
		rf->mp_field_gty_post_cursor_tx_post_csr =
			get_field(r, MAC_PCS_XXV_GTY_POST_CURSOR_3_TX_POST_CSR);
	}

	return 0;
}

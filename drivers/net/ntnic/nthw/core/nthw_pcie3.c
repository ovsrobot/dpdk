/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "ntlog.h"

#include "nthw_drv.h"
#include "nthw_register.h"

#include "nthw_pcie3.h"

#define NTHW_TG_REF_FREQ (250000000ULL)

nthw_pcie3_t *nthw_pcie3_new(void)
{
	nthw_pcie3_t *p = malloc(sizeof(nthw_pcie3_t));

	if (p)
		memset(p, 0, sizeof(nthw_pcie3_t));
	return p;
}

void nthw_pcie3_delete(nthw_pcie3_t *p)
{
	if (p) {
		memset(p, 0, sizeof(nthw_pcie3_t));
		free(p);
	}
}

int nthw_pcie3_init(nthw_pcie3_t *p, nt_fpga_t *p_fpga, int n_instance)
{
	nt_module_t *mod = fpga_query_module(p_fpga, MOD_PCIE3, n_instance);

	if (p == NULL)
		return (mod == NULL ? -1 : 0);

	if (mod == NULL) {
		NT_LOG(ERR, NTHW, "%s: PCIE3 %d: no such instance\n",
		       p_fpga->p_fpga_info->mp_adapter_id_str, n_instance);
		return -1;
	}

	p->mp_fpga = p_fpga;
	p->mn_instance = n_instance;
	p->mp_mod_pcie3 = mod;

	/* PCIe3 */
	p->mp_reg_stat_ctrl = module_get_register(p->mp_mod_pcie3, PCIE3_STAT_CTRL);
	p->mp_fld_stat_ctrl_ena =
		register_get_field(p->mp_reg_stat_ctrl, PCIE3_STAT_CTRL_STAT_ENA);
	p->mp_fld_stat_ctrl_req =
		register_get_field(p->mp_reg_stat_ctrl, PCIE3_STAT_CTRL_STAT_REQ);

	p->mp_reg_stat_rx = module_get_register(p->mp_mod_pcie3, PCIE3_STAT_RX);
	p->mp_fld_stat_rx_counter =
		register_get_field(p->mp_reg_stat_rx, PCIE3_STAT_RX_COUNTER);

	p->mp_reg_stat_tx = module_get_register(p->mp_mod_pcie3, PCIE3_STAT_TX);
	p->mp_fld_stat_tx_counter =
		register_get_field(p->mp_reg_stat_tx, PCIE3_STAT_TX_COUNTER);

	p->mp_reg_stat_ref_clk =
		module_get_register(p->mp_mod_pcie3, PCIE3_STAT_REFCLK);
	p->mp_fld_stat_ref_clk_ref_clk =
		register_get_field(p->mp_reg_stat_ref_clk, PCIE3_STAT_REFCLK_REFCLK250);

	p->mp_reg_stat_rq_rdy =
		module_get_register(p->mp_mod_pcie3, PCIE3_STAT_RQ_RDY);
	p->mp_fld_stat_rq_rdy_counter =
		register_get_field(p->mp_reg_stat_rq_rdy, PCIE3_STAT_RQ_RDY_COUNTER);

	p->mp_reg_stat_rq_vld =
		module_get_register(p->mp_mod_pcie3, PCIE3_STAT_RQ_VLD);
	p->mp_fld_stat_rq_vld_counter =
		register_get_field(p->mp_reg_stat_rq_vld, PCIE3_STAT_RQ_VLD_COUNTER);

	p->mp_reg_status0 = module_get_register(p->mp_mod_pcie3, PCIE3_STATUS0);
	p->mp_fld_status0_tags_in_use =
		register_get_field(p->mp_reg_status0, PCIE3_STATUS0_TAGS_IN_USE);

	p->mp_reg_rp_to_ep_err =
		module_get_register(p->mp_mod_pcie3, PCIE3_RP_TO_EP_ERR);
	p->mp_fld_rp_to_ep_err_cor =
		register_get_field(p->mp_reg_rp_to_ep_err, PCIE3_RP_TO_EP_ERR_ERR_COR);
	p->mp_fld_rp_to_ep_err_non_fatal =
		register_get_field(p->mp_reg_rp_to_ep_err, PCIE3_RP_TO_EP_ERR_ERR_NONFATAL);
	p->mp_fld_rp_to_ep_err_fatal =
		register_get_field(p->mp_reg_rp_to_ep_err, PCIE3_RP_TO_EP_ERR_ERR_FATAL);

	p->mp_reg_ep_to_rp_err =
		module_get_register(p->mp_mod_pcie3, PCIE3_EP_TO_RP_ERR);
	p->mp_fld_ep_to_rp_err_cor = register_get_field(p->mp_reg_ep_to_rp_err,
			       PCIE3_EP_TO_RP_ERR_ERR_COR);
	p->mp_fld_ep_to_rp_err_non_fatal =
		register_get_field(p->mp_reg_ep_to_rp_err, PCIE3_EP_TO_RP_ERR_ERR_NONFATAL);
	p->mp_fld_ep_to_rp_err_fatal =
		register_get_field(p->mp_reg_ep_to_rp_err, PCIE3_EP_TO_RP_ERR_ERR_FATAL);

	p->mp_reg_sample_time =
		module_get_register(p->mp_mod_pcie3, PCIE3_SAMPLE_TIME);
	p->mp_fld_sample_time =
		register_get_field(p->mp_reg_sample_time, PCIE3_SAMPLE_TIME_SAMPLE_TIME);

	p->mp_reg_pci_end_point =
		module_get_register(p->mp_mod_pcie3, PCIE3_PCI_ENDPOINT);
	p->mp_fld_pci_end_point_if_id =
		register_get_field(p->mp_reg_pci_end_point, PCIE3_PCI_ENDPOINT_IF_ID);
	p->mp_fld_pci_end_point_send_msg =
		register_get_field(p->mp_reg_pci_end_point, PCIE3_PCI_ENDPOINT_SEND_MSG);
	p->mp_fld_pci_end_point_get_msg =
		register_get_field(p->mp_reg_pci_end_point, PCIE3_PCI_ENDPOINT_GET_MSG);
	p->mp_fld_pci_end_point_dmae_p0_allow_mask =
		register_get_field(p->mp_reg_pci_end_point, PCIE3_PCI_ENDPOINT_DMA_EP0_ALLOW_MASK);
	p->mp_fld_pci_end_point_dmae_p1_allow_mask =
		register_get_field(p->mp_reg_pci_end_point, PCIE3_PCI_ENDPOINT_DMA_EP1_ALLOW_MASK);
	if (p->mp_reg_pci_end_point)
		register_update(p->mp_reg_pci_end_point);

	p->mp_reg_pci_test0 = module_get_register(p->mp_mod_pcie3, PCIE3_PCI_TEST0);
	p->mp_fld_pci_test0 =
		register_get_field(p->mp_reg_pci_test0, PCIE3_PCI_TEST0_DATA);
	if (p->mp_reg_pci_test0)
		register_update(p->mp_reg_pci_test0);

	p->mp_reg_pci_test1 = module_get_register(p->mp_mod_pcie3, PCIE3_PCI_TEST1);
	p->mp_fld_pci_test1 =
		register_get_field(p->mp_reg_pci_test1, PCIE3_PCI_TEST1_DATA);
	if (p->mp_reg_pci_test1)
		register_update(p->mp_reg_pci_test1);

	p->mp_reg_pci_e3_mark_adr_lsb =
		module_get_register(p->mp_mod_pcie3, PCIE3_MARKADR_LSB);
	p->mp_fld_pci_e3_mark_adr_lsb_adr =
		register_get_field(p->mp_reg_pci_e3_mark_adr_lsb, PCIE3_MARKADR_LSB_ADR);
	if (p->mp_reg_pci_e3_mark_adr_lsb)
		register_update(p->mp_reg_pci_e3_mark_adr_lsb);

	p->mp_reg_pci_e3_mark_adr_msb =
		module_get_register(p->mp_mod_pcie3, PCIE3_MARKADR_MSB);
	p->mp_fld_pci_e3_mark_adr_msb_adr =
		register_get_field(p->mp_reg_pci_e3_mark_adr_msb, PCIE3_MARKADR_MSB_ADR);
	if (p->mp_reg_pci_e3_mark_adr_msb)
		register_update(p->mp_reg_pci_e3_mark_adr_msb);

	/* Initial setup - disable markerscheme and bifurcation */
	if (p->mp_fld_pci_end_point_dmae_p0_allow_mask)
		field_clr_flush(p->mp_fld_pci_end_point_dmae_p0_allow_mask);

	if (p->mp_fld_pci_end_point_dmae_p1_allow_mask)
		field_clr_flush(p->mp_fld_pci_end_point_dmae_p1_allow_mask);

	if (p->mp_fld_pci_e3_mark_adr_lsb_adr)
		field_set_val_flush32(p->mp_fld_pci_e3_mark_adr_lsb_adr, 0UL);

	if (p->mp_fld_pci_e3_mark_adr_msb_adr)
		field_set_val_flush32(p->mp_fld_pci_e3_mark_adr_msb_adr, 0UL);

	if (p->mp_fld_pci_end_point_dmae_p0_allow_mask)
		field_set_flush(p->mp_fld_pci_end_point_dmae_p0_allow_mask);

	if (p->mp_fld_pci_end_point_dmae_p1_allow_mask)
		field_clr_flush(p->mp_fld_pci_end_point_dmae_p1_allow_mask);
	return 0;
};

int nthw_pcie3_trigger_sample_time(nthw_pcie3_t *p)
{
	field_set_val_flush32(p->mp_fld_sample_time, 0xfee1dead);

	return 0;
}

int nthw_pcie3_stat_req_enable(nthw_pcie3_t *p)
{
	field_set_all(p->mp_fld_stat_ctrl_ena);
	field_set_all(p->mp_fld_stat_ctrl_req);
	field_flush_register(p->mp_fld_stat_ctrl_req);
	return 0;
}

int nthw_pcie3_stat_req_disable(nthw_pcie3_t *p)
{
	field_clr_all(p->mp_fld_stat_ctrl_ena);
	field_set_all(p->mp_fld_stat_ctrl_req);
	field_flush_register(p->mp_fld_stat_ctrl_req);
	return 0;
}

int nthw_pcie3_get_stat(nthw_pcie3_t *p, uint32_t *p_rx_cnt, uint32_t *p_tx_cnt,
			uint32_t *p_ref_clk_cnt, uint32_t *p_tg_unit_size,
			uint32_t *p_tg_ref_freq, uint32_t *p_tag_use_cnt,
			uint32_t *p_rq_rdy_cnt, uint32_t *p_rq_vld_cnt)
{
	*p_rx_cnt = field_get_updated(p->mp_fld_stat_rx_counter);
	*p_tx_cnt = field_get_updated(p->mp_fld_stat_tx_counter);

	*p_ref_clk_cnt = field_get_updated(p->mp_fld_stat_ref_clk_ref_clk);

	*p_tg_unit_size = NTHW_TG_CNT_SIZE;
	*p_tg_ref_freq = NTHW_TG_REF_FREQ;

	*p_tag_use_cnt = field_get_updated(p->mp_fld_status0_tags_in_use);

	*p_rq_rdy_cnt = field_get_updated(p->mp_fld_stat_rq_rdy_counter);
	*p_rq_vld_cnt = field_get_updated(p->mp_fld_stat_rq_vld_counter);

	return 0;
}

int nthw_pcie3_get_stat_rate(nthw_pcie3_t *p, uint64_t *p_pci_rx_rate,
			  uint64_t *p_pci_tx_rate, uint64_t *p_ref_clk_cnt,
			  uint64_t *p_tag_use_cnt, uint64_t *p_pci_nt_bus_util,
			  uint64_t *p_pci_xil_bus_util)
{
	uint32_t rx_cnt, tx_cnt, ref_clk_cnt;
	uint32_t tg_unit_size, tg_ref_freq;
	uint32_t tag_use_cnt, rq_rdy_cnt, rq_vld_cnt;

	nthw_pcie3_get_stat(p, &rx_cnt, &tx_cnt, &ref_clk_cnt, &tg_unit_size,
			  &tg_ref_freq, &tag_use_cnt, &rq_rdy_cnt, &rq_vld_cnt);

	if (ref_clk_cnt) {
		uint64_t nt_bus_util, xil_bus_util;
		uint64_t rx_rate, tx_rate;

		rx_rate = ((uint64_t)rx_cnt * tg_unit_size * tg_ref_freq) /
			 (uint64_t)ref_clk_cnt;
		*p_pci_rx_rate = rx_rate;

		tx_rate = ((uint64_t)tx_cnt * tg_unit_size * tg_ref_freq) /
			 (uint64_t)ref_clk_cnt;
		*p_pci_tx_rate = tx_rate;

		*p_ref_clk_cnt = ref_clk_cnt;

		*p_tag_use_cnt = tag_use_cnt;

		nt_bus_util =
			((uint64_t)rq_vld_cnt * 1000000ULL) / (uint64_t)ref_clk_cnt;
		*p_pci_nt_bus_util = nt_bus_util;
		xil_bus_util =
			((uint64_t)rq_rdy_cnt * 1000000ULL) / (uint64_t)ref_clk_cnt;
		*p_pci_xil_bus_util = xil_bus_util;
	} else {
		*p_ref_clk_cnt = 0;
		*p_pci_nt_bus_util = 0;
		*p_pci_xil_bus_util = 0;
	}

	return 0;
}

int nthw_pcie3_end_point_counters_sample_pre(nthw_pcie3_t *p,
					struct nthw_hif_end_point_counters *epc)
{
	NT_LOG(DBG, NTHW, "%s:%u: empty function\n", __func__, __LINE__);

	(void)p;
	(void)epc;

	return 0;
}

int nthw_pcie3_end_point_counters_sample_post(nthw_pcie3_t *p,
		struct nthw_hif_end_point_counters *epc)
{
	NT_LOG(DBG, NTHW, "%s:%u:\n", __func__, __LINE__);
	assert(epc);
	nthw_pcie3_get_stat_rate(p, &epc->cur_tx, &epc->cur_rx, &epc->n_ref_clk_cnt,
			      &epc->n_tags_in_use, &epc->cur_pci_nt_util,
			      &epc->cur_pci_xil_util);
	return 0;
}

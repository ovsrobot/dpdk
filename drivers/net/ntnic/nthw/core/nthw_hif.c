/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "nt_util.h"
#include "ntlog.h"

#include "nthw_drv.h"
#include "nthw_register.h"

#include "nthw_hif.h"

nthw_hif_t *nthw_hif_new(void)
{
	nthw_hif_t *p = malloc(sizeof(nthw_hif_t));

	if (p)
		memset(p, 0, sizeof(nthw_hif_t));
	return p;
}

void nthw_hif_delete(nthw_hif_t *p)
{
	if (p) {
		memset(p, 0, sizeof(nthw_hif_t));
		free(p);
	}
}

int nthw_hif_init(nthw_hif_t *p, nt_fpga_t *p_fpga, int n_instance)
{
	const char *const p_adapter_id_str _unused =
		p_fpga->p_fpga_info->mp_adapter_id_str;
	nt_module_t *mod = fpga_query_module(p_fpga, MOD_HIF, n_instance);

	if (p == NULL)
		return mod == NULL ? -1 : 0;

	if (mod == NULL) {
		NT_LOG(ERR, NTHW, "%s: HIF %d: no such instance\n",
		       p_fpga->p_fpga_info->mp_adapter_id_str, n_instance);
		return -1;
	}

	p->mp_fpga = p_fpga;
	p->mn_instance = n_instance;
	p->mp_mod_hif = mod;

	/* default for (Xilinx-based) products until august 2022: (1e6/4000 = 250 MHz) */
	p->mn_fpga_param_hif_per_ps =
		fpga_get_product_param(p->mp_fpga, NT_HIF_PER_PS, 4000);
	p->mn_fpga_hif_ref_clk_freq =
		(uint32_t)(1000000000000ULL /
			   (unsigned int)p->mn_fpga_param_hif_per_ps);

	p->mp_reg_prod_id_lsb = module_get_register(p->mp_mod_hif, HIF_PROD_ID_LSB);
	p->mp_fld_prod_id_lsb_rev_id =
		register_get_field(p->mp_reg_prod_id_lsb, HIF_PROD_ID_LSB_REV_ID);
	p->mp_fld_prod_id_lsb_ver_id =
		register_get_field(p->mp_reg_prod_id_lsb, HIF_PROD_ID_LSB_VER_ID);
	p->mp_fld_prod_id_lsb_group_id =
		register_get_field(p->mp_reg_prod_id_lsb, HIF_PROD_ID_LSB_GROUP_ID);

	p->mp_reg_prod_id_msb = module_get_register(p->mp_mod_hif, HIF_PROD_ID_MSB);
	p->mp_fld_prod_id_msb_type_id =
		register_get_field(p->mp_reg_prod_id_msb, HIF_PROD_ID_MSB_TYPE_ID);
	p->mp_fld_prod_id_msb_build_no =
		register_get_field(p->mp_reg_prod_id_msb, HIF_PROD_ID_MSB_BUILD_NO);

	p->mp_reg_build_time = module_get_register(p->mp_mod_hif, HIF_BUILD_TIME);
	p->mp_fld_build_time =
		register_get_field(p->mp_reg_build_time, HIF_BUILD_TIME_TIME);

	p->mn_fpga_id_prod = field_get_updated(p->mp_fld_prod_id_lsb_group_id);
	p->mn_fpga_id_ver = field_get_updated(p->mp_fld_prod_id_lsb_ver_id);
	p->mn_fpga_id_rev = field_get_updated(p->mp_fld_prod_id_lsb_rev_id);
	p->mn_fpga_id_build_no = field_get_updated(p->mp_fld_prod_id_msb_build_no);
	p->mn_fpga_id_item = field_get_updated(p->mp_fld_prod_id_msb_type_id);

	NT_LOG(DBG, NTHW, "%s: HIF %d: %s: %d-%d-%d-%d-%d\n", p_adapter_id_str,
	       p->mn_instance, __func__, p->mn_fpga_id_item, p->mn_fpga_id_prod,
	       p->mn_fpga_id_ver, p->mn_fpga_id_rev, p->mn_fpga_id_build_no);
	NT_LOG(DBG, NTHW,
	       "%s: HIF %d: %s: HIF ref clock: %d Hz (%d ticks/ps)\n",
	       p_adapter_id_str, p->mn_instance, __func__, p->mn_fpga_hif_ref_clk_freq,
	       p->mn_fpga_param_hif_per_ps);

	p->mp_reg_build_seed = NULL; /* Reg/Fld not present on HIF */
	if (p->mp_reg_build_seed)
		p->mp_fld_build_seed = NULL; /* Reg/Fld not present on HIF */
	else
		p->mp_fld_build_seed = NULL;

	p->mp_reg_core_speed = NULL; /* Reg/Fld not present on HIF */
	if (p->mp_reg_core_speed) {
		p->mp_fld_core_speed = NULL; /* Reg/Fld not present on HIF */
		p->mp_fld_ddr3_speed = NULL; /* Reg/Fld not present on HIF */
	} else {
		p->mp_reg_core_speed = NULL;
		p->mp_fld_core_speed = NULL;
		p->mp_fld_ddr3_speed = NULL;
	}

	/* Optional registers since: 2018-04-25 */
	p->mp_reg_int_mask = NULL; /* Reg/Fld not present on HIF */
	p->mp_reg_int_clr = NULL; /* Reg/Fld not present on HIF */
	p->mp_reg_int_force = NULL; /* Reg/Fld not present on HIF */

	p->mp_fld_int_mask_timer = NULL;
	p->mp_fld_int_clr_timer = NULL;
	p->mp_fld_int_force_timer = NULL;

	p->mp_fld_int_mask_port = NULL;
	p->mp_fld_int_clr_port = NULL;
	p->mp_fld_int_force_port = NULL;

	p->mp_fld_int_mask_pps = NULL;
	p->mp_fld_int_clr_pps = NULL;
	p->mp_fld_int_force_pps = NULL;

	p->mp_reg_stat_ctrl = module_get_register(p->mp_mod_hif, HIF_STAT_CTRL);
	p->mp_fld_stat_ctrl_ena =
		register_get_field(p->mp_reg_stat_ctrl, HIF_STAT_CTRL_STAT_ENA);
	p->mp_fld_stat_ctrl_req =
		register_get_field(p->mp_reg_stat_ctrl, HIF_STAT_CTRL_STAT_REQ);

	p->mp_reg_stat_rx = module_get_register(p->mp_mod_hif, HIF_STAT_RX);
	p->mp_fld_stat_rx_counter =
		register_get_field(p->mp_reg_stat_rx, HIF_STAT_RX_COUNTER);

	p->mp_reg_stat_tx = module_get_register(p->mp_mod_hif, HIF_STAT_TX);
	p->mp_fld_stat_tx_counter =
		register_get_field(p->mp_reg_stat_tx, HIF_STAT_TX_COUNTER);

	p->mp_reg_stat_ref_clk = module_get_register(p->mp_mod_hif, HIF_STAT_REFCLK);
	p->mp_fld_stat_ref_clk_ref_clk = register_get_field(p->mp_reg_stat_ref_clk,
				   HIF_STAT_REFCLK_REFCLK250);

	p->mp_reg_status = module_query_register(p->mp_mod_hif, HIF_STATUS);
	if (p->mp_reg_status) {
		p->mp_fld_status_tags_in_use =
			register_query_field(p->mp_reg_status, HIF_STATUS_TAGS_IN_USE);
		p->mp_fld_status_wr_err =
			register_query_field(p->mp_reg_status, HIF_STATUS_WR_ERR);
		p->mp_fld_status_rd_err =
			register_query_field(p->mp_reg_status, HIF_STATUS_RD_ERR);
	} else {
		p->mp_reg_status = module_query_register(p->mp_mod_hif, HIF_STATUS);
		p->mp_fld_status_tags_in_use =
			register_query_field(p->mp_reg_status, HIF_STATUS_TAGS_IN_USE);
		p->mp_fld_status_wr_err = NULL;
		p->mp_fld_status_rd_err = NULL;
	}

	p->mp_reg_pci_test0 = module_get_register(p->mp_mod_hif, HIF_TEST0);
	p->mp_fld_pci_test0 = register_get_field(p->mp_reg_pci_test0, HIF_TEST0_DATA);

	p->mp_reg_pci_test1 = module_get_register(p->mp_mod_hif, HIF_TEST1);
	p->mp_fld_pci_test1 = register_get_field(p->mp_reg_pci_test1, HIF_TEST1_DATA);

	/* Required to run TSM */
	p->mp_reg_sample_time = module_get_register(p->mp_mod_hif, HIF_SAMPLE_TIME);
	if (p->mp_reg_sample_time) {
		p->mp_fld_sample_time =
			register_get_field(p->mp_reg_sample_time, HIF_SAMPLE_TIME_SAMPLE_TIME);
	} else {
		p->mp_fld_sample_time = NULL;
	}

	/* We need to optimize PCIe3 TLP-size read-request and extended tag usage */
	{
		p->mp_reg_config = module_query_register(p->mp_mod_hif, HIF_CONFIG);
		if (p->mp_reg_config) {
			p->mp_fld_max_tlp =
				register_get_field(p->mp_reg_config, HIF_CONFIG_MAX_TLP);
			p->mp_fld_max_read =
				register_get_field(p->mp_reg_config, HIF_CONFIG_MAX_READ);
			p->mp_fld_ext_tag =
				register_get_field(p->mp_reg_config, HIF_CONFIG_EXT_TAG);
		} else {
			p->mp_fld_max_tlp = NULL;
			p->mp_fld_max_read = NULL;
			p->mp_fld_ext_tag = NULL;
		}
	}

	return 0;
}

int nthw_hif_setup_config(nthw_hif_t *p)
{
	const char *const p_adapter_id_str _unused =
		p->mp_fpga->p_fpga_info->mp_adapter_id_str;

	/*
	 * We need to optimize PCIe3 read-request and extended tag usage
	 * original check: HW_ADAPTER_ID_NT200A02 HW_ADAPTER_ID_NT100A01 HW_ADAPTER_ID_NT50B01
	 */
	if (p->mp_fpga->p_fpga_info->n_nthw_adapter_id != NT_HW_ADAPTER_ID_NT40E3) {
		if (p->mp_fld_max_read) {
			/*
			 * NOTE: On Pandion DELL server, this param was negotiated to 4096
			 * (index=5), but the server crashed. For now we need to limit this value to
			 * 512 (index=2)
			 */
			const uint32_t n_max_read_req_size =
				field_get_updated(p->mp_fld_max_read);
			if (n_max_read_req_size > 2) {
				field_set_val_flush32(p->mp_fld_max_read, 2);
				NT_LOG(INF, NTHW,
				       "%s: %s: PCIe: MaxReadReqsize %d - changed to 2 (512B)\n",
				       p_adapter_id_str, __func__,
				       n_max_read_req_size);
			}
		}

		if (p->mp_fld_ext_tag)
			field_set_val_flush32(p->mp_fld_ext_tag, 1);

		if (p->mp_fld_max_tlp && p->mp_fld_max_read && p->mp_fld_ext_tag) {
			NT_LOG(INF, NTHW,
			       "%s: %s: PCIe config: MaxTlp = %d, MaxReadReqsize = %d, ExtTagEna = %d\n",
			       p_adapter_id_str, __func__,
			       field_get_updated(p->mp_fld_max_tlp),
			       field_get_updated(p->mp_fld_max_read),
			       field_get_updated(p->mp_fld_ext_tag));
		}
	}
	return 0;
}

int nthw_hif_trigger_sample_time(nthw_hif_t *p)
{
	field_set_val_flush32(p->mp_fld_sample_time, 0xfee1dead);

	return 0;
}

int nthw_hif_get_stat(nthw_hif_t *p, uint32_t *p_rx_cnt, uint32_t *p_tx_cnt,
		    uint32_t *p_ref_clk_cnt, uint32_t *p_tg_unit_size,
		    uint32_t *p_tg_ref_freq, uint64_t *p_tags_in_use,
		    uint64_t *p_rd_err, uint64_t *p_wr_err)
{
	*p_rx_cnt = field_get_updated(p->mp_fld_stat_rx_counter);
	*p_tx_cnt = field_get_updated(p->mp_fld_stat_tx_counter);

	*p_ref_clk_cnt = field_get_updated(p->mp_fld_stat_ref_clk_ref_clk);

	*p_tg_unit_size = NTHW_TG_CNT_SIZE;
	*p_tg_ref_freq = p->mn_fpga_hif_ref_clk_freq;

	*p_tags_in_use = (p->mp_fld_status_tags_in_use ?
		       field_get_updated(p->mp_fld_status_tags_in_use) :
		       0);

	*p_rd_err = (p->mp_fld_status_rd_err ? field_get_updated(p->mp_fld_status_rd_err) :
		   0);
	*p_wr_err = (p->mp_fld_status_wr_err ? field_get_updated(p->mp_fld_status_wr_err) :
		   0);

	return 0;
}

int nthw_hif_get_stat_rate(nthw_hif_t *p, uint64_t *p_pci_rx_rate,
			uint64_t *p_pci_tx_rate, uint64_t *p_ref_clk_cnt,
			uint64_t *p_tags_in_use, uint64_t *p_rd_err_cnt,
			uint64_t *p_wr_err_cnt)
{
	uint32_t rx_cnt, tx_cnt, ref_clk_cnt, tg_unit_size, tg_ref_freq;
	uint64_t n_tags_in_use, n_rd_err, n_wr_err;

	nthw_hif_get_stat(p, &rx_cnt, &tx_cnt, &ref_clk_cnt, &tg_unit_size, &tg_ref_freq,
			&n_tags_in_use, &n_rd_err, &n_wr_err);

	*p_tags_in_use = n_tags_in_use;
	if (n_rd_err)
		(*p_rd_err_cnt)++;
	if (n_wr_err)
		(*p_wr_err_cnt)++;

	if (ref_clk_cnt) {
		uint64_t rx_rate;
		uint64_t tx_rate;

		*p_ref_clk_cnt = ref_clk_cnt;

		rx_rate = ((uint64_t)rx_cnt * tg_unit_size * tg_ref_freq) /
			 (uint64_t)ref_clk_cnt;
		*p_pci_rx_rate = rx_rate;

		tx_rate = ((uint64_t)tx_cnt * tg_unit_size * tg_ref_freq) /
			 (uint64_t)ref_clk_cnt;
		*p_pci_tx_rate = tx_rate;
	} else {
		*p_pci_rx_rate = 0;
		*p_pci_tx_rate = 0;
		*p_ref_clk_cnt = 0;
	}

	return 0;
}

int nthw_hif_stat_req_enable(nthw_hif_t *p)
{
	field_set_all(p->mp_fld_stat_ctrl_ena);
	field_set_all(p->mp_fld_stat_ctrl_req);
	field_flush_register(p->mp_fld_stat_ctrl_req);
	return 0;
}

int nthw_hif_stat_req_disable(nthw_hif_t *p)
{
	field_clr_all(p->mp_fld_stat_ctrl_ena);
	field_set_all(p->mp_fld_stat_ctrl_req);
	field_flush_register(p->mp_fld_stat_ctrl_req);
	return 0;
}

int nthw_hif_stat_sample(nthw_hif_t *p, uint64_t *p_rx_rate, uint64_t *p_tx_rate,
		       uint64_t *p_ref_clk_cnt, uint64_t *p_tags_in_use,
		       uint64_t *p_rd_err_cnt, uint64_t *p_wr_err_cnt)
{
	nthw_hif_stat_req_enable(p);
	NT_OS_WAIT_USEC(100000);
	nthw_hif_stat_req_disable(p);
	nthw_hif_get_stat_rate(p, p_rx_rate, p_tx_rate, p_ref_clk_cnt, p_tags_in_use,
			    p_rd_err_cnt, p_wr_err_cnt);

	return 0;
}

int nthw_hif_end_point_counters_sample(nthw_hif_t *p,
				   struct nthw_hif_end_point_counters *epc)
{
	assert(epc);

	/* Get stat rate and maintain rx/tx min/max */
	nthw_hif_get_stat_rate(p, &epc->cur_tx, &epc->cur_rx, &epc->n_ref_clk_cnt,
			    &epc->n_tags_in_use, &epc->n_rd_err, &epc->n_wr_err);

	return 0;
}

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __NTHW_PCIE3_H__
#define __NTHW_PCIE3_H__

struct nthw_pcie3 {
	nt_fpga_t *mp_fpga;
	nt_module_t *mp_mod_pcie3;
	int mn_instance;

	nt_register_t *mp_reg_stat_ctrl;
	nt_field_t *mp_fld_stat_ctrl_req;
	nt_field_t *mp_fld_stat_ctrl_ena;

	nt_register_t *mp_reg_stat_rx;
	nt_field_t *mp_fld_stat_rx_counter;

	nt_register_t *mp_reg_stat_tx;
	nt_field_t *mp_fld_stat_tx_counter;

	nt_register_t *mp_reg_stat_rq_rdy;
	nt_field_t *mp_fld_stat_rq_rdy_counter;

	nt_register_t *mp_reg_stat_rq_vld;
	nt_field_t *mp_fld_stat_rq_vld_counter;

	nt_register_t *mp_reg_status0;
	nt_field_t *mp_fld_status0_tags_in_use;

	nt_register_t *mp_reg_stat_ref_clk;
	nt_field_t *mp_fld_stat_ref_clk_ref_clk;

	nt_register_t *mp_reg_rp_to_ep_err;
	nt_field_t *mp_fld_rp_to_ep_err_cor;
	nt_field_t *mp_fld_rp_to_ep_err_non_fatal;
	nt_field_t *mp_fld_rp_to_ep_err_fatal;

	nt_register_t *mp_reg_ep_to_rp_err;
	nt_field_t *mp_fld_ep_to_rp_err_cor;
	nt_field_t *mp_fld_ep_to_rp_err_non_fatal;
	nt_field_t *mp_fld_ep_to_rp_err_fatal;

	nt_register_t *mp_reg_sample_time;
	nt_field_t *mp_fld_sample_time;

	nt_register_t *mp_reg_pci_end_point;
	nt_field_t *mp_fld_pci_end_point_if_id;
	nt_field_t *mp_fld_pci_end_point_send_msg;
	nt_field_t *mp_fld_pci_end_point_get_msg;
	nt_field_t *mp_fld_pci_end_point_dmae_p0_allow_mask;
	nt_field_t *mp_fld_pci_end_point_dmae_p1_allow_mask;

	nt_register_t *mp_reg_pci_e3_mark_adr_lsb;
	nt_field_t *mp_fld_pci_e3_mark_adr_lsb_adr;

	nt_register_t *mp_reg_pci_e3_mark_adr_msb;
	nt_field_t *mp_fld_pci_e3_mark_adr_msb_adr;

	nt_register_t *mp_reg_pci_test0;
	nt_field_t *mp_fld_pci_test0;

	nt_register_t *mp_reg_pci_test1;
	nt_field_t *mp_fld_pci_test1;

	nt_register_t *mp_reg_pci_test2;
	nt_field_t *mp_fld_pci_test2;

	nt_register_t *mp_reg_pci_test3;
	nt_field_t *mp_fld_pci_test3;
};

typedef struct nthw_pcie3 nthw_pcie3_t;
typedef struct nthw_pcie3 nthw_pcie3;

nthw_pcie3_t *nthw_pcie3_new(void);
void nthw_pcie3_delete(nthw_pcie3_t *p);
int nthw_pcie3_init(nthw_pcie3_t *p, nt_fpga_t *p_fpga, int n_instance);

int nthw_pcie3_trigger_sample_time(nthw_pcie3_t *p);

int nthw_pcie3_stat_req_enable(nthw_pcie3_t *p);
int nthw_pcie3_stat_req_disable(nthw_pcie3_t *p);

int nthw_pcie3_get_stat(nthw_pcie3_t *p, uint32_t *p_rx_cnt, uint32_t *p_tx_cnt,
		      uint32_t *p_ref_clk_cnt, uint32_t *p_tg_unit_size,
		      uint32_t *p_tg_ref_freq, uint32_t *p_tag_use_cnt,
		      uint32_t *p_rq_rdy_cnt, uint32_t *p_rq_vld_cnt);
int nthw_pcie3_get_stat_rate(nthw_pcie3_t *p, uint64_t *p_pci_rx_rate,
			  uint64_t *p_pci_tx_rate, uint64_t *p_ref_clk_cnt,
			  uint64_t *p_tag_use_cnt, uint64_t *p_pci_nt_bus_util,
			  uint64_t *p_pci_xil_bus_util);

int nthw_pcie3_end_point_counters_sample_pre(nthw_pcie3_t *p,
					struct nthw_hif_end_point_counters *epc);
int nthw_pcie3_end_point_counters_sample_post(nthw_pcie3_t *p,
		struct nthw_hif_end_point_counters *epc);

#endif /* __NTHW_PCIE3_H__ */

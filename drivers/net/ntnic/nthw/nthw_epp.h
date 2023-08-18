/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef NTHW_EPP_HPP_
#define NTHW_EPP_HPP_

/* VXLAN adds extra 50 bytes */
#define VXLANDATASIZEADJUST 50
#define VXLANDATASIZEADJUSTIPV6 70
#define MTUINITVAL 1500
#define NRECIPE 3

/* List of size adjust values to put in the recipe memory data register at startup */
static const int rcp_data_size_adjust_txp[NRECIPE] = { 0, VXLANDATASIZEADJUST,
						   VXLANDATASIZEADJUSTIPV6
						 };
static const int rcp_data_size_adjust_vport[NRECIPE] = { 0, VXLANDATASIZEADJUST,
						     VXLANDATASIZEADJUSTIPV6
						   };

struct nthw_epp_s {
	nt_fpga_t *mp_fpga;
	nt_module_t *mp_mod_epp;
	int mn_instance;
	int mn_epp_categories;

	nt_register_t *mp_reg_reciepe_memory_control;
	nt_field_t *mp_fld_reciepe_memory_control_adr;
	nt_field_t *mp_fld_reciepe_memory_control_cnt;

	nt_register_t *mp_reg_reciepe_memory_data;
	nt_field_t *mp_fld_reciepe_memory_data_tx_mtu_epp_enable;
	nt_field_t *mp_fld_reciepe_memory_data_queue_mtu_epp_enable;
	nt_field_t *mp_fld_reciepe_memory_data_size_adjust_tx_port;
	nt_field_t *mp_fld_reciepe_memory_data_size_adjust_virtual_port;
	nt_field_t *mp_fld_reciepe_memory_data_fixed18b_l2_mtu;
	nt_field_t *mp_fld_reciepe_memory_data_txp_qos_epp_enable;
	nt_field_t *mp_fld_reciepe_memory_data_queue_qos_epp_enable;

	nt_register_t *mp_reg_txp_port_mtu_control;
	nt_field_t *mp_fld_txp_port_mtu_control_adr;
	nt_field_t *mp_fld_txp_port_mtu_control_cnt;

	nt_register_t *mp_reg_txp_port_mtu_data;
	nt_field_t *mp_fld_txp_port_mtu_data_max_mtu;

	nt_register_t *mp_reg_queue_mtu_control;
	nt_field_t *mp_fld_queue_mtu_control_adr;
	nt_field_t *mp_fld_queue_mtu_control_cnt;

	nt_register_t *mp_reg_queue_mtu_data;
	nt_field_t *mp_fld_queue_mtu_data_max_mtu;

	nt_register_t *mp_reg_txp_qos_control;
	nt_field_t *mp_fld_txp_qos_control_adr;
	nt_field_t *mp_fld_txp_qos_control_cnt;

	nt_register_t *mp_reg_txp_qos_data;
	nt_field_t *mp_fld_txp_qos_data_enable;
	nt_field_t *mp_fld_txp_qos_data_information_rate;
	nt_field_t *mp_fld_txp_qos_data_information_rate_fractional;
	nt_field_t *mp_fld_txp_qos_data_burst_size;

	nt_register_t *mp_reg_vport_qos_control;
	nt_field_t *mp_fld_vport_qos_control_adr;
	nt_field_t *mp_fld_vport_qos_control_cnt;

	nt_register_t *mp_reg_vport_qos_data;
	nt_field_t *mp_fld_vport_qos_data_enable;
	nt_field_t *mp_fld_vport_qos_data_information_rate;
	nt_field_t *mp_fld_vport_qos_data_information_rate_fractional;
	nt_field_t *mp_fld_vport_qos_data_burst_size;

	nt_register_t *mp_reg_queue_vport_control;
	nt_field_t *mp_fld_queue_vport_control_adr;
	nt_field_t *mp_fld_queue_vport_control_cnt;

	nt_register_t *mp_reg_queue_vport_data;
	nt_field_t *mp_fld_queue_vport_data_vport;
};

typedef struct nthw_epp_s nthw_epp_t;

nthw_epp_t *nthw_epp_new(void);
void nthw_epp_delete(nthw_epp_t *p);

int nthw_epp_present(nt_fpga_t *p_fpga, int n_instance);
int nthw_epp_init(nthw_epp_t *p, nt_fpga_t *p_fpga, int n_instance);
int nthw_epp_setup(nthw_epp_t *p);
int nthw_epp_set_mtu(nthw_epp_t *p, uint32_t port, uint32_t max_mtu,
		   nt_meta_port_type_t port_type);
int nthw_epp_set_txp_qos(nthw_epp_t *p, uint32_t port, uint32_t information_rate,
		      uint32_t information_rate_fractional, uint32_t burst_size);
int nthw_epp_set_vport_qos(nthw_epp_t *p, uint32_t port, uint32_t information_rate,
			uint32_t information_rate_fractional, uint32_t burst_size);
int nthw_epp_set_queue_to_vport(nthw_epp_t *p, uint32_t qid, uint32_t vport);

#endif /* NTHW_EPP_HPP_ */

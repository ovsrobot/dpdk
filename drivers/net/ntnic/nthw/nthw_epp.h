/*
 * SPDX-License-Identifier: BSD-3-Clause
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
	nthw_fpga_t *mp_fpga;
	nthw_module_t *mp_mod_epp;
	int mn_instance;
	int mn_epp_categories;

	nthw_register_t *mp_reg_reciepe_memory_control;
	nthw_field_t *mp_fld_reciepe_memory_control_adr;
	nthw_field_t *mp_fld_reciepe_memory_control_cnt;

	nthw_register_t *mp_reg_reciepe_memory_data;
	nthw_field_t *mp_fld_reciepe_memory_data_tx_mtu_epp_enable;
	nthw_field_t *mp_fld_reciepe_memory_data_queue_mtu_epp_enable;
	nthw_field_t *mp_fld_reciepe_memory_data_size_adjust_tx_port;
	nthw_field_t *mp_fld_reciepe_memory_data_size_adjust_virtual_port;
	nthw_field_t *mp_fld_reciepe_memory_data_fixed18b_l2_mtu;
	nthw_field_t *mp_fld_reciepe_memory_data_txp_qos_epp_enable;
	nthw_field_t *mp_fld_reciepe_memory_data_queue_qos_epp_enable;

	nthw_register_t *mp_reg_txp_port_mtu_control;
	nthw_field_t *mp_fld_txp_port_mtu_control_adr;
	nthw_field_t *mp_fld_txp_port_mtu_control_cnt;

	nthw_register_t *mp_reg_txp_port_mtu_data;
	nthw_field_t *mp_fld_txp_port_mtu_data_max_mtu;

	nthw_register_t *mp_reg_queue_mtu_control;
	nthw_field_t *mp_fld_queue_mtu_control_adr;
	nthw_field_t *mp_fld_queue_mtu_control_cnt;

	nthw_register_t *mp_reg_queue_mtu_data;
	nthw_field_t *mp_fld_queue_mtu_data_max_mtu;

	nthw_register_t *mp_reg_txp_qos_control;
	nthw_field_t *mp_fld_txp_qos_control_adr;
	nthw_field_t *mp_fld_txp_qos_control_cnt;

	nthw_register_t *mp_reg_txp_qos_data;
	nthw_field_t *mp_fld_txp_qos_data_enable;
	nthw_field_t *mp_fld_txp_qos_data_information_rate;
	nthw_field_t *mp_fld_txp_qos_data_information_rate_fractional;
	nthw_field_t *mp_fld_txp_qos_data_burst_size;

	nthw_register_t *mp_reg_vport_qos_control;
	nthw_field_t *mp_fld_vport_qos_control_adr;
	nthw_field_t *mp_fld_vport_qos_control_cnt;

	nthw_register_t *mp_reg_vport_qos_data;
	nthw_field_t *mp_fld_vport_qos_data_enable;
	nthw_field_t *mp_fld_vport_qos_data_information_rate;
	nthw_field_t *mp_fld_vport_qos_data_information_rate_fractional;
	nthw_field_t *mp_fld_vport_qos_data_burst_size;

	nthw_register_t *mp_reg_queue_vport_control;
	nthw_field_t *mp_fld_queue_vport_control_adr;
	nthw_field_t *mp_fld_queue_vport_control_cnt;

	nthw_register_t *mp_reg_queue_vport_data;
	nthw_field_t *mp_fld_queue_vport_data_vport;
};

typedef struct nthw_epp_s nthw_epp_t;

nthw_epp_t *nthw_epp_new(void);

int nthw_epp_present(nthw_fpga_t *p_fpga, int n_instance);
int nthw_epp_init(nthw_epp_t *p, nthw_fpga_t *p_fpga, int n_instance);
int nthw_epp_setup(nthw_epp_t *p);

#endif	/* NTHW_EPP_HPP_ */

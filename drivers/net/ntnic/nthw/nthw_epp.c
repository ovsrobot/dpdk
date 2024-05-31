/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "ntlog.h"

#include "nthw_drv.h"
#include "nthw_register.h"

#include "nthw_epp.h"

#include <errno.h>	/* ENOTSUP */

nthw_epp_t *nthw_epp_new(void)
{
	nthw_epp_t *p = malloc(sizeof(nthw_epp_t));

	if (p)
		memset(p, 0, sizeof(nthw_epp_t));

	return p;
}

int nthw_epp_present(nthw_fpga_t *p_fpga, int n_instance)
{
	return nthw_epp_init(NULL, p_fpga, n_instance) == 0;
}

int nthw_epp_init(nthw_epp_t *p, nthw_fpga_t *p_fpga, int n_instance)
{
	nthw_module_t *mod = nthw_fpga_query_module(p_fpga, MOD_EPP, n_instance);

	if (p == NULL)
		return mod == NULL ? -1 : 0;

	if (mod == NULL) {
		NT_LOG(ERR, NTHW, "%s: EPP %d: no such instance\n",
			p_fpga->p_fpga_info->mp_adapter_id_str, n_instance);
		return -1;
	}

	p->mp_fpga = p_fpga;
	p->mn_instance = n_instance;
	p->mp_mod_epp = mod;

	p->mn_epp_categories = nthw_fpga_get_product_param(p_fpga, NT_EPP_CATEGORIES, 0);

	p->mp_reg_reciepe_memory_control = nthw_module_get_register(p->mp_mod_epp, EPP_RCP_CTRL);
	p->mp_fld_reciepe_memory_control_adr =
		nthw_register_get_field(p->mp_reg_reciepe_memory_control, EPP_RCP_CTRL_ADR);
	p->mp_fld_reciepe_memory_control_cnt =
		nthw_register_get_field(p->mp_reg_reciepe_memory_control, EPP_RCP_CTRL_CNT);

	p->mp_reg_reciepe_memory_data = nthw_module_get_register(p->mp_mod_epp, EPP_RCP_DATA);
	p->mp_fld_reciepe_memory_data_tx_mtu_epp_enable =
		nthw_register_get_field(p->mp_reg_reciepe_memory_data, EPP_RCP_DATA_TX_MTU_EPP_EN);
	p->mp_fld_reciepe_memory_data_queue_mtu_epp_enable =
		nthw_register_get_field(p->mp_reg_reciepe_memory_data,
			EPP_RCP_DATA_QUEUE_MTU_EPP_EN);
	p->mp_fld_reciepe_memory_data_size_adjust_tx_port =
		nthw_register_get_field(p->mp_reg_reciepe_memory_data,
			EPP_RCP_DATA_SIZE_ADJUST_TXP);
	p->mp_fld_reciepe_memory_data_size_adjust_virtual_port =
		nthw_register_get_field(p->mp_reg_reciepe_memory_data,
			EPP_RCP_DATA_SIZE_ADJUST_VPORT);
	p->mp_fld_reciepe_memory_data_fixed18b_l2_mtu =
		nthw_register_get_field(p->mp_reg_reciepe_memory_data,
			EPP_RCP_DATA_FIXED_18B_L2_MTU);
	p->mp_fld_reciepe_memory_data_txp_qos_epp_enable =
		nthw_register_get_field(p->mp_reg_reciepe_memory_data, EPP_RCP_DATA_TX_QOS_EPP_EN);
	p->mp_fld_reciepe_memory_data_queue_qos_epp_enable =
		nthw_register_get_field(p->mp_reg_reciepe_memory_data,
			EPP_RCP_DATA_QUEUE_QOS_EPP_EN);

	p->mp_reg_txp_port_mtu_control = nthw_module_get_register(p->mp_mod_epp, EPP_TXP_MTU_CTRL);
	p->mp_fld_txp_port_mtu_control_adr =
		nthw_register_get_field(p->mp_reg_txp_port_mtu_control, EPP_TXP_MTU_CTRL_ADR);
	p->mp_fld_txp_port_mtu_control_cnt =
		nthw_register_get_field(p->mp_reg_txp_port_mtu_control, EPP_TXP_MTU_CTRL_CNT);

	p->mp_reg_txp_port_mtu_data = nthw_module_get_register(p->mp_mod_epp, EPP_TXP_MTU_DATA);
	p->mp_fld_txp_port_mtu_data_max_mtu =
		nthw_register_get_field(p->mp_reg_txp_port_mtu_data, EPP_TXP_MTU_DATA_MAX_MTU);

	p->mp_reg_queue_mtu_control = nthw_module_get_register(p->mp_mod_epp, EPP_QUEUE_MTU_CTRL);
	p->mp_fld_queue_mtu_control_adr =
		nthw_register_get_field(p->mp_reg_queue_mtu_control, EPP_QUEUE_MTU_CTRL_ADR);
	p->mp_fld_queue_mtu_control_cnt =
		nthw_register_get_field(p->mp_reg_queue_mtu_control, EPP_QUEUE_MTU_CTRL_CNT);

	p->mp_reg_queue_mtu_data = nthw_module_get_register(p->mp_mod_epp, EPP_QUEUE_MTU_DATA);
	p->mp_fld_queue_mtu_data_max_mtu =
		nthw_register_get_field(p->mp_reg_queue_mtu_data, EPP_QUEUE_MTU_DATA_MAX_MTU);

	p->mp_reg_txp_qos_control = nthw_module_get_register(p->mp_mod_epp, EPP_TXP_QOS_CTRL);
	p->mp_fld_txp_qos_control_adr =
		nthw_register_get_field(p->mp_reg_txp_qos_control, EPP_TXP_QOS_CTRL_ADR);
	p->mp_fld_txp_qos_control_cnt =
		nthw_register_get_field(p->mp_reg_txp_qos_control, EPP_TXP_QOS_CTRL_CNT);

	p->mp_reg_txp_qos_data = nthw_module_get_register(p->mp_mod_epp, EPP_TXP_QOS_DATA);
	p->mp_fld_txp_qos_data_enable =
		nthw_register_get_field(p->mp_reg_txp_qos_data, EPP_TXP_QOS_DATA_EN);
	p->mp_fld_txp_qos_data_information_rate =
		nthw_register_get_field(p->mp_reg_txp_qos_data, EPP_TXP_QOS_DATA_IR);
	p->mp_fld_txp_qos_data_information_rate_fractional =
		nthw_register_get_field(p->mp_reg_txp_qos_data, EPP_TXP_QOS_DATA_IR_FRACTION);
	p->mp_fld_txp_qos_data_burst_size =
		nthw_register_get_field(p->mp_reg_txp_qos_data, EPP_TXP_QOS_DATA_BS);

	p->mp_reg_vport_qos_control = nthw_module_get_register(p->mp_mod_epp, EPP_VPORT_QOS_CTRL);
	p->mp_fld_vport_qos_control_adr =
		nthw_register_get_field(p->mp_reg_vport_qos_control, EPP_VPORT_QOS_CTRL_ADR);
	p->mp_fld_vport_qos_control_cnt =
		nthw_register_get_field(p->mp_reg_vport_qos_control, EPP_VPORT_QOS_CTRL_CNT);

	p->mp_reg_vport_qos_data = nthw_module_get_register(p->mp_mod_epp, EPP_VPORT_QOS_DATA);
	p->mp_fld_vport_qos_data_enable =
		nthw_register_get_field(p->mp_reg_vport_qos_data, EPP_VPORT_QOS_DATA_EN);
	p->mp_fld_vport_qos_data_information_rate =
		nthw_register_get_field(p->mp_reg_vport_qos_data, EPP_VPORT_QOS_DATA_IR);
	p->mp_fld_vport_qos_data_information_rate_fractional =
		nthw_register_get_field(p->mp_reg_vport_qos_data, EPP_VPORT_QOS_DATA_IR_FRACTION);
	p->mp_fld_vport_qos_data_burst_size =
		nthw_register_get_field(p->mp_reg_vport_qos_data, EPP_VPORT_QOS_DATA_BS);

	p->mp_reg_queue_vport_control =
		nthw_module_get_register(p->mp_mod_epp, EPP_QUEUE_VPORT_CTRL);
	p->mp_fld_queue_vport_control_adr =
		nthw_register_get_field(p->mp_reg_queue_vport_control, EPP_QUEUE_VPORT_CTRL_ADR);
	p->mp_fld_queue_vport_control_cnt =
		nthw_register_get_field(p->mp_reg_queue_vport_control, EPP_QUEUE_VPORT_CTRL_CNT);

	p->mp_reg_queue_vport_data = nthw_module_get_register(p->mp_mod_epp, EPP_QUEUE_VPORT_DATA);
	p->mp_fld_queue_vport_data_vport =
		nthw_register_get_field(p->mp_reg_queue_vport_data, EPP_QUEUE_VPORT_DATA_VPORT);

	return 0;
}

int nthw_epp_setup(nthw_epp_t *p)
{
	if (p == NULL)
		return 0;

	/* Set recieps for 2 first records */
	nthw_field_set_val32(p->mp_fld_reciepe_memory_control_cnt, 1);

	/* Zero all categories */
	for (int i = 0; i < p->mn_epp_categories; ++i) {
		nthw_field_set_val32(p->mp_fld_reciepe_memory_control_adr, i);
		nthw_register_flush(p->mp_reg_reciepe_memory_control, 1);

		nthw_field_set_val32(p->mp_fld_reciepe_memory_data_tx_mtu_epp_enable, 0);
		nthw_field_set_val32(p->mp_fld_reciepe_memory_data_queue_mtu_epp_enable, 0);
		nthw_field_set_val32(p->mp_fld_reciepe_memory_data_size_adjust_tx_port, 0);
		nthw_field_set_val32(p->mp_fld_reciepe_memory_data_size_adjust_virtual_port, 0);
		nthw_field_set_val32(p->mp_fld_reciepe_memory_data_fixed18b_l2_mtu, 0);
		nthw_field_set_val32(p->mp_fld_reciepe_memory_data_txp_qos_epp_enable, 0);
		nthw_field_set_val32(p->mp_fld_reciepe_memory_data_queue_qos_epp_enable, 0);
		nthw_register_flush(p->mp_reg_reciepe_memory_data, 1);
	}

	for (int i = 0; i < NRECIPE; ++i) {
		nthw_field_set_val32(p->mp_fld_reciepe_memory_control_adr, i);
		nthw_register_flush(p->mp_reg_reciepe_memory_control, 1);

		nthw_field_set_val32(p->mp_fld_reciepe_memory_data_tx_mtu_epp_enable, 1);
		nthw_field_set_val32(p->mp_fld_reciepe_memory_data_queue_mtu_epp_enable, 1);
		nthw_field_set_val32(p->mp_fld_reciepe_memory_data_size_adjust_tx_port,
			rcp_data_size_adjust_txp[i]);
		nthw_field_set_val32(p->mp_fld_reciepe_memory_data_size_adjust_virtual_port,
			rcp_data_size_adjust_vport[i]);
		nthw_field_set_val32(p->mp_fld_reciepe_memory_data_fixed18b_l2_mtu, 1);
		nthw_field_set_val32(p->mp_fld_reciepe_memory_data_txp_qos_epp_enable, 1);
		nthw_field_set_val32(p->mp_fld_reciepe_memory_data_queue_qos_epp_enable, 1);
		nthw_register_flush(p->mp_reg_reciepe_memory_data, 1);
	}

	/* phy mtu setup */
	nthw_field_set_val32(p->mp_fld_txp_port_mtu_control_cnt, 1);

	for (int i = 0; i < 2; ++i) {
		nthw_field_set_val32(p->mp_fld_txp_port_mtu_control_adr, i);
		nthw_register_flush(p->mp_reg_txp_port_mtu_control, 1);

		nthw_field_set_val32(p->mp_fld_txp_port_mtu_data_max_mtu, MTUINITVAL);
		nthw_register_flush(p->mp_reg_txp_port_mtu_data, 1);
	}

	/* phy QoS setup */
	nthw_field_set_val32(p->mp_fld_txp_qos_control_cnt, 1);

	for (int i = 0; i < 2; ++i) {
		nthw_field_set_val32(p->mp_fld_txp_qos_control_adr, i);
		nthw_register_flush(p->mp_reg_txp_qos_control, 1);

		nthw_field_set_val32(p->mp_fld_txp_qos_data_enable, 0);
		nthw_register_flush(p->mp_reg_txp_qos_data, 1);
	}

	/* virt mtu setup */
	nthw_field_set_val32(p->mp_fld_queue_mtu_control_cnt, 1);

	for (int i = 0; i < 128; ++i) {
		nthw_field_set_val32(p->mp_fld_queue_mtu_control_adr, i);
		nthw_register_flush(p->mp_reg_queue_mtu_control, 1);

		nthw_field_set_val32(p->mp_fld_queue_mtu_data_max_mtu, MTUINITVAL);
		nthw_register_flush(p->mp_reg_queue_mtu_data, 1);
	}

	/* virt QoS setup */
	nthw_field_set_val32(p->mp_fld_vport_qos_control_cnt, 1);

	for (int i = 0; i < 128; ++i) {
		nthw_field_set_val32(p->mp_fld_vport_qos_control_adr, i);
		nthw_register_flush(p->mp_reg_vport_qos_control, 1);

		nthw_field_set_val32(p->mp_fld_vport_qos_data_enable, 0);
		nthw_register_flush(p->mp_reg_vport_qos_data, 1);
	}

	return 0;
}

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "ntlog.h"

#include "nthw_drv.h"
#include "nthw_register.h"

#include "nthw_epp.h"

#include <errno.h> /* ENOTSUP */

nthw_epp_t *nthw_epp_new(void)
{
	nthw_epp_t *p = malloc(sizeof(nthw_epp_t));

	if (p)
		memset(p, 0, sizeof(nthw_epp_t));
	return p;
}

void nthw_epp_delete(nthw_epp_t *p)
{
	if (p) {
		memset(p, 0, sizeof(nthw_epp_t));
		free(p);
	}
}

int nthw_epp_present(nt_fpga_t *p_fpga, int n_instance)
{
	return nthw_epp_init(NULL, p_fpga, n_instance) == 0;
}

int nthw_epp_init(nthw_epp_t *p, nt_fpga_t *p_fpga, int n_instance)
{
	nt_module_t *mod = fpga_query_module(p_fpga, MOD_EPP, n_instance);

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

	p->mn_epp_categories = fpga_get_product_param(p_fpga, NT_EPP_CATEGORIES, 0);

	p->mp_reg_reciepe_memory_control =
		module_get_register(p->mp_mod_epp, EPP_RCP_CTRL);
	p->mp_fld_reciepe_memory_control_adr =
		register_get_field(p->mp_reg_reciepe_memory_control, EPP_RCP_CTRL_ADR);
	p->mp_fld_reciepe_memory_control_cnt =
		register_get_field(p->mp_reg_reciepe_memory_control, EPP_RCP_CTRL_CNT);

	p->mp_reg_reciepe_memory_data =
		module_get_register(p->mp_mod_epp, EPP_RCP_DATA);
	p->mp_fld_reciepe_memory_data_tx_mtu_epp_enable =
		register_get_field(p->mp_reg_reciepe_memory_data, EPP_RCP_DATA_TX_MTU_EPP_EN);
	p->mp_fld_reciepe_memory_data_queue_mtu_epp_enable =
		register_get_field(p->mp_reg_reciepe_memory_data, EPP_RCP_DATA_QUEUE_MTU_EPP_EN);
	p->mp_fld_reciepe_memory_data_size_adjust_tx_port =
		register_get_field(p->mp_reg_reciepe_memory_data, EPP_RCP_DATA_SIZE_ADJUST_TXP);
	p->mp_fld_reciepe_memory_data_size_adjust_virtual_port =
		register_get_field(p->mp_reg_reciepe_memory_data, EPP_RCP_DATA_SIZE_ADJUST_VPORT);
	p->mp_fld_reciepe_memory_data_fixed18b_l2_mtu =
		register_get_field(p->mp_reg_reciepe_memory_data, EPP_RCP_DATA_FIXED_18B_L2_MTU);
	p->mp_fld_reciepe_memory_data_txp_qos_epp_enable =
		register_get_field(p->mp_reg_reciepe_memory_data, EPP_RCP_DATA_TX_QOS_EPP_EN);
	p->mp_fld_reciepe_memory_data_queue_qos_epp_enable =
		register_get_field(p->mp_reg_reciepe_memory_data, EPP_RCP_DATA_QUEUE_QOS_EPP_EN);

	p->mp_reg_txp_port_mtu_control =
		module_get_register(p->mp_mod_epp, EPP_TXP_MTU_CTRL);
	p->mp_fld_txp_port_mtu_control_adr =
		register_get_field(p->mp_reg_txp_port_mtu_control, EPP_TXP_MTU_CTRL_ADR);
	p->mp_fld_txp_port_mtu_control_cnt =
		register_get_field(p->mp_reg_txp_port_mtu_control, EPP_TXP_MTU_CTRL_CNT);

	p->mp_reg_txp_port_mtu_data =
		module_get_register(p->mp_mod_epp, EPP_TXP_MTU_DATA);
	p->mp_fld_txp_port_mtu_data_max_mtu =
		register_get_field(p->mp_reg_txp_port_mtu_data, EPP_TXP_MTU_DATA_MAX_MTU);

	p->mp_reg_queue_mtu_control =
		module_get_register(p->mp_mod_epp, EPP_QUEUE_MTU_CTRL);
	p->mp_fld_queue_mtu_control_adr =
		register_get_field(p->mp_reg_queue_mtu_control, EPP_QUEUE_MTU_CTRL_ADR);
	p->mp_fld_queue_mtu_control_cnt =
		register_get_field(p->mp_reg_queue_mtu_control, EPP_QUEUE_MTU_CTRL_CNT);

	p->mp_reg_queue_mtu_data =
		module_get_register(p->mp_mod_epp, EPP_QUEUE_MTU_DATA);
	p->mp_fld_queue_mtu_data_max_mtu =
		register_get_field(p->mp_reg_queue_mtu_data, EPP_QUEUE_MTU_DATA_MAX_MTU);

	p->mp_reg_txp_qos_control =
		module_get_register(p->mp_mod_epp, EPP_TXP_QOS_CTRL);
	p->mp_fld_txp_qos_control_adr =
		register_get_field(p->mp_reg_txp_qos_control, EPP_TXP_QOS_CTRL_ADR);
	p->mp_fld_txp_qos_control_cnt =
		register_get_field(p->mp_reg_txp_qos_control, EPP_TXP_QOS_CTRL_CNT);

	p->mp_reg_txp_qos_data = module_get_register(p->mp_mod_epp, EPP_TXP_QOS_DATA);
	p->mp_fld_txp_qos_data_enable =
		register_get_field(p->mp_reg_txp_qos_data, EPP_TXP_QOS_DATA_EN);
	p->mp_fld_txp_qos_data_information_rate =
		register_get_field(p->mp_reg_txp_qos_data, EPP_TXP_QOS_DATA_IR);
	p->mp_fld_txp_qos_data_information_rate_fractional =
		register_get_field(p->mp_reg_txp_qos_data, EPP_TXP_QOS_DATA_IR_FRACTION);
	p->mp_fld_txp_qos_data_burst_size =
		register_get_field(p->mp_reg_txp_qos_data, EPP_TXP_QOS_DATA_BS);

	p->mp_reg_vport_qos_control =
		module_get_register(p->mp_mod_epp, EPP_VPORT_QOS_CTRL);
	p->mp_fld_vport_qos_control_adr =
		register_get_field(p->mp_reg_vport_qos_control, EPP_VPORT_QOS_CTRL_ADR);
	p->mp_fld_vport_qos_control_cnt =
		register_get_field(p->mp_reg_vport_qos_control, EPP_VPORT_QOS_CTRL_CNT);

	p->mp_reg_vport_qos_data =
		module_get_register(p->mp_mod_epp, EPP_VPORT_QOS_DATA);
	p->mp_fld_vport_qos_data_enable =
		register_get_field(p->mp_reg_vport_qos_data, EPP_VPORT_QOS_DATA_EN);
	p->mp_fld_vport_qos_data_information_rate =
		register_get_field(p->mp_reg_vport_qos_data, EPP_VPORT_QOS_DATA_IR);
	p->mp_fld_vport_qos_data_information_rate_fractional =
		register_get_field(p->mp_reg_vport_qos_data, EPP_VPORT_QOS_DATA_IR_FRACTION);
	p->mp_fld_vport_qos_data_burst_size =
		register_get_field(p->mp_reg_vport_qos_data, EPP_VPORT_QOS_DATA_BS);

	p->mp_reg_queue_vport_control =
		module_get_register(p->mp_mod_epp, EPP_QUEUE_VPORT_CTRL);
	p->mp_fld_queue_vport_control_adr =
		register_get_field(p->mp_reg_queue_vport_control, EPP_QUEUE_VPORT_CTRL_ADR);
	p->mp_fld_queue_vport_control_cnt =
		register_get_field(p->mp_reg_queue_vport_control, EPP_QUEUE_VPORT_CTRL_CNT);

	p->mp_reg_queue_vport_data =
		module_get_register(p->mp_mod_epp, EPP_QUEUE_VPORT_DATA);
	p->mp_fld_queue_vport_data_vport =
		register_get_field(p->mp_reg_queue_vport_data, EPP_QUEUE_VPORT_DATA_VPORT);

	return 0;
}

int nthw_epp_setup(nthw_epp_t *p)
{
	if (p == NULL)
		return 0;

	/* Set recieps for 2 first records */
	field_set_val32(p->mp_fld_reciepe_memory_control_cnt, 1);

	/* Zero all categories */
	for (int i = 0; i < p->mn_epp_categories; ++i) {
		field_set_val32(p->mp_fld_reciepe_memory_control_adr, i);
		register_flush(p->mp_reg_reciepe_memory_control, 1);

		field_set_val32(p->mp_fld_reciepe_memory_data_tx_mtu_epp_enable, 0);
		field_set_val32(p->mp_fld_reciepe_memory_data_queue_mtu_epp_enable, 0);
		field_set_val32(p->mp_fld_reciepe_memory_data_size_adjust_tx_port, 0);
		field_set_val32(p->mp_fld_reciepe_memory_data_size_adjust_virtual_port,
			       0);
		field_set_val32(p->mp_fld_reciepe_memory_data_fixed18b_l2_mtu, 0);
		field_set_val32(p->mp_fld_reciepe_memory_data_txp_qos_epp_enable, 0);
		field_set_val32(p->mp_fld_reciepe_memory_data_queue_qos_epp_enable, 0);
		register_flush(p->mp_reg_reciepe_memory_data, 1);
	}

	for (int i = 0; i < NRECIPE; ++i) {
		field_set_val32(p->mp_fld_reciepe_memory_control_adr, i);
		register_flush(p->mp_reg_reciepe_memory_control, 1);

		field_set_val32(p->mp_fld_reciepe_memory_data_tx_mtu_epp_enable, 1);
		field_set_val32(p->mp_fld_reciepe_memory_data_queue_mtu_epp_enable, 1);
		field_set_val32(p->mp_fld_reciepe_memory_data_size_adjust_tx_port,
			       rcp_data_size_adjust_txp[i]);
		field_set_val32(p->mp_fld_reciepe_memory_data_size_adjust_virtual_port,
			       rcp_data_size_adjust_vport[i]);
		field_set_val32(p->mp_fld_reciepe_memory_data_fixed18b_l2_mtu, 1);
		field_set_val32(p->mp_fld_reciepe_memory_data_txp_qos_epp_enable, 1);
		field_set_val32(p->mp_fld_reciepe_memory_data_queue_qos_epp_enable, 1);
		register_flush(p->mp_reg_reciepe_memory_data, 1);
	}
	/* phy mtu setup */
	field_set_val32(p->mp_fld_txp_port_mtu_control_cnt, 1);
	for (int i = 0; i < 2; ++i) {
		field_set_val32(p->mp_fld_txp_port_mtu_control_adr, i);
		register_flush(p->mp_reg_txp_port_mtu_control, 1);

		field_set_val32(p->mp_fld_txp_port_mtu_data_max_mtu, MTUINITVAL);
		register_flush(p->mp_reg_txp_port_mtu_data, 1);
	}
	/* phy QoS setup */
	field_set_val32(p->mp_fld_txp_qos_control_cnt, 1);
	for (int i = 0; i < 2; ++i) {
		field_set_val32(p->mp_fld_txp_qos_control_adr, i);
		register_flush(p->mp_reg_txp_qos_control, 1);

		field_set_val32(p->mp_fld_txp_qos_data_enable, 0);
		register_flush(p->mp_reg_txp_qos_data, 1);
	}

	/* virt mtu setup */
	field_set_val32(p->mp_fld_queue_mtu_control_cnt, 1);
	for (int i = 0; i < 128; ++i) {
		field_set_val32(p->mp_fld_queue_mtu_control_adr, i);
		register_flush(p->mp_reg_queue_mtu_control, 1);

		field_set_val32(p->mp_fld_queue_mtu_data_max_mtu, MTUINITVAL);
		register_flush(p->mp_reg_queue_mtu_data, 1);
	}

	/* virt QoS setup */
	field_set_val32(p->mp_fld_vport_qos_control_cnt, 1);
	for (int i = 0; i < 128; ++i) {
		field_set_val32(p->mp_fld_vport_qos_control_adr, i);
		register_flush(p->mp_reg_vport_qos_control, 1);

		field_set_val32(p->mp_fld_vport_qos_data_enable, 0);
		register_flush(p->mp_reg_vport_qos_data, 1);
	}

	return 0;
}

/*
 * Set the MTU registers in context with the current setMTU request.
 */
int nthw_epp_set_mtu(nthw_epp_t *p, uint32_t port, uint32_t max_mtu,
		   nt_meta_port_type_t port_type)
{
	if (p == NULL)
		return 0;

	if (port_type == PORT_TYPE_PHYSICAL) {
		/* Set the TXP Mtu control register */
		field_set_val32(p->mp_fld_txp_port_mtu_control_adr, port);
		field_set_val32(p->mp_fld_txp_port_mtu_control_cnt, 1);
		register_flush(p->mp_reg_txp_port_mtu_control, 1);

		/* Set the TXP Mtu control register */
		field_set_val32(p->mp_fld_txp_port_mtu_data_max_mtu, max_mtu);
		register_flush(p->mp_reg_txp_port_mtu_data, 1);
	} else if (port_type == PORT_TYPE_VIRTUAL) {
		/* Set the TXP Mtu control register */
		field_set_val32(p->mp_fld_queue_mtu_control_adr, port);
		field_set_val32(p->mp_fld_queue_mtu_control_cnt, 1);
		register_flush(p->mp_reg_queue_mtu_control, 1);

		/* Set the TXP Mtu control register */
		field_set_val32(p->mp_fld_queue_mtu_data_max_mtu, max_mtu);
		register_flush(p->mp_reg_queue_mtu_data, 1);
	} else {
		NT_LOG(DBG, NTHW, "NthwEpp::%s - port_type unsupported",
		       __func__);
		register_reset(p->mp_reg_queue_mtu_control);
		register_flush(p->mp_reg_queue_mtu_control, 1);
		register_reset(p->mp_reg_queue_mtu_data);
		register_flush(p->mp_reg_queue_mtu_data, 1);
		register_reset(p->mp_reg_txp_port_mtu_control);
		register_flush(p->mp_reg_txp_port_mtu_control, 1);
		register_reset(p->mp_reg_txp_port_mtu_data);
		register_flush(p->mp_reg_txp_port_mtu_data, 1);

		return -ENOTSUP;
	}

	return 0;
}

int nthw_epp_set_txp_qos(nthw_epp_t *p, uint32_t port, uint32_t information_rate,
		      uint32_t information_rate_fractional, uint32_t burst_size)
{
	if (p == NULL)
		return 0;

	field_set_val32(p->mp_fld_txp_qos_control_adr, port);
	field_set_val32(p->mp_fld_txp_qos_control_cnt, 1);
	register_flush(p->mp_reg_txp_qos_control, 1);

	uint32_t enable = ((information_rate | information_rate_fractional |
			    burst_size) != 0);
	field_set_val32(p->mp_fld_txp_qos_data_enable, enable);
	field_set_val32(p->mp_fld_txp_qos_data_information_rate, information_rate);
	field_set_val32(p->mp_fld_txp_qos_data_information_rate_fractional,
		       information_rate_fractional);
	field_set_val32(p->mp_fld_txp_qos_data_burst_size, burst_size);
	register_flush(p->mp_reg_txp_qos_data, 1);

	return 0;
}

int nthw_epp_set_vport_qos(nthw_epp_t *p, uint32_t port, uint32_t information_rate,
			uint32_t information_rate_fractional, uint32_t burst_size)
{
	if (p == NULL)
		return 0;

	field_set_val32(p->mp_fld_vport_qos_control_adr, port);
	field_set_val32(p->mp_fld_vport_qos_control_cnt, 1);
	register_flush(p->mp_reg_vport_qos_control, 1);

	uint32_t enable = ((information_rate | information_rate_fractional |
			    burst_size) != 0);
	field_set_val32(p->mp_fld_vport_qos_data_enable, enable);
	field_set_val32(p->mp_fld_vport_qos_data_information_rate, information_rate);
	field_set_val32(p->mp_fld_vport_qos_data_information_rate_fractional,
		       information_rate_fractional);
	field_set_val32(p->mp_fld_vport_qos_data_burst_size, burst_size);
	register_flush(p->mp_reg_vport_qos_data, 1);

	return 0;
}

int nthw_epp_set_queue_to_vport(nthw_epp_t *p, uint32_t qid, uint32_t vport)
{
	if (p == NULL)
		return 0;

	field_set_val32(p->mp_fld_queue_vport_control_adr, qid);
	field_set_val32(p->mp_fld_queue_vport_control_cnt, 1);
	register_flush(p->mp_reg_queue_vport_control, 1);

	field_set_val32(p->mp_fld_queue_vport_data_vport, vport);
	register_flush(p->mp_reg_queue_vport_data, 1);
	return 0;
}

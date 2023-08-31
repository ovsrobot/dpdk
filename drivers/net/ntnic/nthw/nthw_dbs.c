/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <errno.h>
#include "ntlog.h"

#include "nthw_drv.h"
#include "nthw_register.h"

#include "nthw_dbs.h"

#undef DBS_PRINT_REGS

static void set_shadow_tx_qos_data(nthw_dbs_t *p, uint32_t index, uint32_t enable,
				uint32_t ir, uint32_t bs);
static void flush_tx_qos_data(nthw_dbs_t *p, uint32_t index);
static void set_shadow_tx_qp_data(nthw_dbs_t *p, uint32_t index,
			       uint32_t virtual_port);
static void flush_tx_qp_data(nthw_dbs_t *p, uint32_t index);
static void set_shadow_tx_dr_data(nthw_dbs_t *p, uint32_t index,
			       uint64_t guest_physical_address, uint32_t host_id,
			       uint32_t queue_size, uint32_t port,
			       uint32_t header, uint32_t packed);
static void flush_tx_dr_data(nthw_dbs_t *p, uint32_t index);
static void set_shadow_rx_dr_data(nthw_dbs_t *p, uint32_t index,
			       uint64_t guest_physical_address, uint32_t host_id,
			       uint32_t queue_size, uint32_t header,
			       uint32_t packed);
static void flush_rx_dr_data(nthw_dbs_t *p, uint32_t index);
static void set_shadow_tx_uw_data(nthw_dbs_t *p, uint32_t index,
			       uint64_t guest_physical_address, uint32_t host_id,
			       uint32_t queue_size, uint32_t packed,
			       uint32_t int_enable, uint32_t vec, uint32_t istk,
			       uint32_t in_order);
static void flush_tx_uw_data(nthw_dbs_t *p, uint32_t index);
static void set_shadow_rx_uw_data(nthw_dbs_t *p, uint32_t index,
			       uint64_t guest_physical_address, uint32_t host_id,
			       uint32_t queue_size, uint32_t packed,
			       uint32_t int_enable, uint32_t vec,
			       uint32_t istk);
static void flush_rx_uw_data(nthw_dbs_t *p, uint32_t index);
static void set_shadow_rx_am_data(nthw_dbs_t *p, uint32_t index,
			       uint64_t guest_physical_address, uint32_t enable,
			       uint32_t host_id, uint32_t packed,
			       uint32_t int_enable);
static void flush_rx_am_data(nthw_dbs_t *p, uint32_t index);
static void set_shadow_tx_am_data(nthw_dbs_t *p, uint32_t index,
			       uint64_t guest_physical_address, uint32_t enable,
			       uint32_t host_id, uint32_t packed,
			       uint32_t int_enable);
static void flush_tx_am_data(nthw_dbs_t *p, uint32_t index);

nthw_dbs_t *nthw_dbs_new(void)
{
	nthw_dbs_t *p = malloc(sizeof(nthw_dbs_t));

	if (p)
		memset(p, 0, sizeof(nthw_dbs_t));
	return p;
}

void nthw_dbs_delete(nthw_dbs_t *p)
{
	if (p) {
		memset(p, 0, sizeof(nthw_dbs_t));
		free(p);
	}
}

int dbs_init(nthw_dbs_t *p, nt_fpga_t *p_fpga, int n_instance)
{
	nt_module_t *mod = fpga_query_module(p_fpga, MOD_DBS, n_instance);

	if (p == NULL)
		return mod == NULL ? -1 : 0;

	if (mod == NULL) {
		NT_LOG(ERR, NTHW, "%s: DBS %d: no such instance\n",
		       p_fpga->p_fpga_info->mp_adapter_id_str, n_instance);
		return -1;
	}

	p->mp_fpga = p_fpga;
	p->mn_instance = n_instance;
	p->mp_mod_dbs = mod;

	p->mn_param_dbs_present = fpga_get_product_param(p_fpga, NT_DBS_PRESENT, 0);
	if (p->mn_param_dbs_present == 0) {
		NT_LOG(WRN, NTHW,
		       "%s: DBS %d: logical error: module found but not flagged at present\n",
		       p->mp_fpga->p_fpga_info->mp_adapter_id_str, p->mn_instance);
	}

	p->mp_reg_rx_control = module_get_register(p->mp_mod_dbs, DBS_RX_CONTROL);
	p->mp_fld_rx_control_last_queue =
		register_get_field(p->mp_reg_rx_control, DBS_RX_CONTROL_LQ);
	p->mp_fld_rx_control_avail_monitor_enable =
		register_get_field(p->mp_reg_rx_control, DBS_RX_CONTROL_AME);
	p->mp_fld_rx_control_avail_monitor_scan_speed =
		register_get_field(p->mp_reg_rx_control, DBS_RX_CONTROL_AMS);
	p->mp_fld_rx_control_used_write_enable =
		register_get_field(p->mp_reg_rx_control, DBS_RX_CONTROL_UWE);
	p->mp_fld_rx_control_used_writer_update_speed =
		register_get_field(p->mp_reg_rx_control, DBS_RX_CONTROL_UWS);
	p->mp_fld_rx_control_rx_queues_enable =
		register_get_field(p->mp_reg_rx_control, DBS_RX_CONTROL_QE);

	p->mp_reg_tx_control = module_get_register(p->mp_mod_dbs, DBS_TX_CONTROL);
	p->mp_fld_tx_control_last_queue =
		register_get_field(p->mp_reg_tx_control, DBS_TX_CONTROL_LQ);
	p->mp_fld_tx_control_avail_monitor_enable =
		register_get_field(p->mp_reg_tx_control, DBS_TX_CONTROL_AME);
	p->mp_fld_tx_control_avail_monitor_scan_speed =
		register_get_field(p->mp_reg_tx_control, DBS_TX_CONTROL_AMS);
	p->mp_fld_tx_control_used_write_enable =
		register_get_field(p->mp_reg_tx_control, DBS_TX_CONTROL_UWE);
	p->mp_fld_tx_control_used_writer_update_speed =
		register_get_field(p->mp_reg_tx_control, DBS_TX_CONTROL_UWS);
	p->mp_fld_tx_control_tx_queues_enable =
		register_get_field(p->mp_reg_tx_control, DBS_TX_CONTROL_QE);

	p->mp_reg_rx_init = module_get_register(p->mp_mod_dbs, DBS_RX_INIT);
	p->mp_fld_rx_init_init =
		register_get_field(p->mp_reg_rx_init, DBS_RX_INIT_INIT);
	p->mp_fld_rx_init_queue =
		register_get_field(p->mp_reg_rx_init, DBS_RX_INIT_QUEUE);
	p->mp_fld_rx_init_busy =
		register_get_field(p->mp_reg_rx_init, DBS_RX_INIT_BUSY);

	p->mp_reg_rx_init_val = module_query_register(p->mp_mod_dbs, DBS_RX_INIT_VAL);
	if (p->mp_reg_rx_init_val) {
		p->mp_fld_rx_init_val_idx = register_query_field(p->mp_reg_rx_init_val,
				       DBS_RX_INIT_VAL_IDX);
		p->mp_fld_rx_init_val_ptr = register_query_field(p->mp_reg_rx_init_val,
				       DBS_RX_INIT_VAL_PTR);
	}

	p->mp_reg_rx_ptr = module_query_register(p->mp_mod_dbs, DBS_RX_PTR);
	if (p->mp_reg_rx_ptr) {
		p->mp_fld_rx_ptr_ptr =
			register_query_field(p->mp_reg_rx_ptr, DBS_RX_PTR_PTR);
		p->mp_fld_rx_ptr_queue =
			register_query_field(p->mp_reg_rx_ptr, DBS_RX_PTR_QUEUE);
		p->mp_fld_rx_ptr_valid =
			register_query_field(p->mp_reg_rx_ptr, DBS_RX_PTR_VALID);
	}

	p->mp_reg_tx_init = module_get_register(p->mp_mod_dbs, DBS_TX_INIT);
	p->mp_fld_tx_init_init =
		register_get_field(p->mp_reg_tx_init, DBS_TX_INIT_INIT);
	p->mp_fld_tx_init_queue =
		register_get_field(p->mp_reg_tx_init, DBS_TX_INIT_QUEUE);
	p->mp_fld_tx_init_busy =
		register_get_field(p->mp_reg_tx_init, DBS_TX_INIT_BUSY);

	p->mp_reg_tx_init_val = module_query_register(p->mp_mod_dbs, DBS_TX_INIT_VAL);
	if (p->mp_reg_tx_init_val) {
		p->mp_fld_tx_init_val_idx = register_query_field(p->mp_reg_tx_init_val,
				       DBS_TX_INIT_VAL_IDX);
		p->mp_fld_tx_init_val_ptr = register_query_field(p->mp_reg_tx_init_val,
				       DBS_TX_INIT_VAL_PTR);
	}

	p->mp_reg_tx_ptr = module_query_register(p->mp_mod_dbs, DBS_TX_PTR);
	if (p->mp_reg_tx_ptr) {
		p->mp_fld_tx_ptr_ptr =
			register_query_field(p->mp_reg_tx_ptr, DBS_TX_PTR_PTR);
		p->mp_fld_tx_ptr_queue =
			register_query_field(p->mp_reg_tx_ptr, DBS_TX_PTR_QUEUE);
		p->mp_fld_tx_ptr_valid =
			register_query_field(p->mp_reg_tx_ptr, DBS_TX_PTR_VALID);
	}

	p->mp_reg_rx_idle = module_query_register(p->mp_mod_dbs, DBS_RX_IDLE);
	if (p->mp_reg_rx_idle) {
		p->mp_fld_rx_idle_idle =
			register_query_field(p->mp_reg_rx_idle, DBS_RX_IDLE_IDLE);
		p->mp_fld_rx_idle_queue =
			register_query_field(p->mp_reg_rx_idle, DBS_RX_IDLE_QUEUE);
		p->mp_fld_rx_idle_busy =
			register_query_field(p->mp_reg_rx_idle, DBS_RX_IDLE_BUSY);
	}

	p->mp_reg_tx_idle = module_query_register(p->mp_mod_dbs, DBS_TX_IDLE);
	if (p->mp_reg_tx_idle) {
		p->mp_fld_tx_idle_idle =
			register_query_field(p->mp_reg_tx_idle, DBS_TX_IDLE_IDLE);
		p->mp_fld_tx_idle_queue =
			register_query_field(p->mp_reg_tx_idle, DBS_TX_IDLE_QUEUE);
		p->mp_fld_tx_idle_busy =
			register_query_field(p->mp_reg_tx_idle, DBS_TX_IDLE_BUSY);
	}

	p->mp_reg_rx_avail_monitor_control =
		module_get_register(p->mp_mod_dbs, DBS_RX_AM_CTRL);
	p->mp_fld_rx_avail_monitor_control_adr =
		register_get_field(p->mp_reg_rx_avail_monitor_control, DBS_RX_AM_CTRL_ADR);
	p->mp_fld_rx_avail_monitor_control_cnt =
		register_get_field(p->mp_reg_rx_avail_monitor_control, DBS_RX_AM_CTRL_CNT);

	p->mp_reg_rx_avail_monitor_data =
		module_get_register(p->mp_mod_dbs, DBS_RX_AM_DATA);
	p->mp_fld_rx_avail_monitor_data_guest_physical_address =
		register_get_field(p->mp_reg_rx_avail_monitor_data, DBS_RX_AM_DATA_GPA);
	p->mp_fld_rx_avail_monitor_data_enable =
		register_get_field(p->mp_reg_rx_avail_monitor_data, DBS_RX_AM_DATA_ENABLE);
	p->mp_fld_rx_avail_monitor_data_host_id =
		register_get_field(p->mp_reg_rx_avail_monitor_data, DBS_RX_AM_DATA_HID);
	p->mp_fld_rx_avail_monitor_data_packed =
		register_query_field(p->mp_reg_rx_avail_monitor_data, DBS_RX_AM_DATA_PCKED);
	p->mp_fld_rx_avail_monitor_data_int =
		register_query_field(p->mp_reg_rx_avail_monitor_data, DBS_RX_AM_DATA_INT);

	p->mp_reg_tx_avail_monitor_control =
		module_get_register(p->mp_mod_dbs, DBS_TX_AM_CTRL);
	p->mp_fld_tx_avail_monitor_control_adr =
		register_get_field(p->mp_reg_tx_avail_monitor_control, DBS_TX_AM_CTRL_ADR);
	p->mp_fld_tx_avail_monitor_control_cnt =
		register_get_field(p->mp_reg_tx_avail_monitor_control, DBS_TX_AM_CTRL_CNT);

	p->mp_reg_tx_avail_monitor_data =
		module_get_register(p->mp_mod_dbs, DBS_TX_AM_DATA);
	p->mp_fld_tx_avail_monitor_data_guest_physical_address =
		register_get_field(p->mp_reg_tx_avail_monitor_data, DBS_TX_AM_DATA_GPA);
	p->mp_fld_tx_avail_monitor_data_enable =
		register_get_field(p->mp_reg_tx_avail_monitor_data, DBS_TX_AM_DATA_ENABLE);
	p->mp_fld_tx_avail_monitor_data_host_id =
		register_get_field(p->mp_reg_tx_avail_monitor_data, DBS_TX_AM_DATA_HID);
	p->mp_fld_tx_avail_monitor_data_packed =
		register_query_field(p->mp_reg_tx_avail_monitor_data, DBS_TX_AM_DATA_PCKED);
	p->mp_fld_tx_avail_monitor_data_int =
		register_query_field(p->mp_reg_tx_avail_monitor_data, DBS_TX_AM_DATA_INT);

	p->mp_reg_rx_used_writer_control =
		module_get_register(p->mp_mod_dbs, DBS_RX_UW_CTRL);
	p->mp_fld_rx_used_writer_control_adr =
		register_get_field(p->mp_reg_rx_used_writer_control, DBS_RX_UW_CTRL_ADR);
	p->mp_fld_rx_used_writer_control_cnt =
		register_get_field(p->mp_reg_rx_used_writer_control, DBS_RX_UW_CTRL_CNT);

	p->mp_reg_rx_used_writer_data =
		module_get_register(p->mp_mod_dbs, DBS_RX_UW_DATA);
	p->mp_fld_rx_used_writer_data_guest_physical_address =
		register_get_field(p->mp_reg_rx_used_writer_data, DBS_RX_UW_DATA_GPA);
	p->mp_fld_rx_used_writer_data_host_id =
		register_get_field(p->mp_reg_rx_used_writer_data, DBS_RX_UW_DATA_HID);
	p->mp_fld_rx_used_writer_data_queue_size =
		register_get_field(p->mp_reg_rx_used_writer_data, DBS_RX_UW_DATA_QS);
	p->mp_fld_rx_used_writer_data_packed =
		register_query_field(p->mp_reg_rx_used_writer_data, DBS_RX_UW_DATA_PCKED);
	p->mp_fld_rx_used_writer_data_int =
		register_query_field(p->mp_reg_rx_used_writer_data, DBS_RX_UW_DATA_INT);
	p->mp_fld_rx_used_writer_data_vec =
		register_query_field(p->mp_reg_rx_used_writer_data, DBS_RX_UW_DATA_VEC);
	p->mp_fld_rx_used_writer_data_istk =
		register_query_field(p->mp_reg_rx_used_writer_data, DBS_RX_UW_DATA_ISTK);

	p->mp_reg_tx_used_writer_control =
		module_get_register(p->mp_mod_dbs, DBS_TX_UW_CTRL);
	p->mp_fld_tx_used_writer_control_adr =
		register_get_field(p->mp_reg_tx_used_writer_control, DBS_TX_UW_CTRL_ADR);
	p->mp_fld_tx_used_writer_control_cnt =
		register_get_field(p->mp_reg_tx_used_writer_control, DBS_TX_UW_CTRL_CNT);

	p->mp_reg_tx_used_writer_data =
		module_get_register(p->mp_mod_dbs, DBS_TX_UW_DATA);
	p->mp_fld_tx_used_writer_data_guest_physical_address =
		register_get_field(p->mp_reg_tx_used_writer_data, DBS_TX_UW_DATA_GPA);
	p->mp_fld_tx_used_writer_data_host_id =
		register_get_field(p->mp_reg_tx_used_writer_data, DBS_TX_UW_DATA_HID);
	p->mp_fld_tx_used_writer_data_queue_size =
		register_get_field(p->mp_reg_tx_used_writer_data, DBS_TX_UW_DATA_QS);
	p->mp_fld_tx_used_writer_data_packed =
		register_query_field(p->mp_reg_tx_used_writer_data, DBS_TX_UW_DATA_PCKED);
	p->mp_fld_tx_used_writer_data_int =
		register_query_field(p->mp_reg_tx_used_writer_data, DBS_TX_UW_DATA_INT);
	p->mp_fld_tx_used_writer_data_vec =
		register_query_field(p->mp_reg_tx_used_writer_data, DBS_TX_UW_DATA_VEC);
	p->mp_fld_tx_used_writer_data_istk =
		register_query_field(p->mp_reg_tx_used_writer_data, DBS_TX_UW_DATA_ISTK);
	p->mp_fld_tx_used_writer_data_in_order =
		register_query_field(p->mp_reg_tx_used_writer_data, DBS_TX_UW_DATA_INO);

	p->mp_reg_rx_descriptor_reader_control =
		module_get_register(p->mp_mod_dbs, DBS_RX_DR_CTRL);
	p->mp_fld_rx_descriptor_reader_control_adr =
		register_get_field(p->mp_reg_rx_descriptor_reader_control, DBS_RX_DR_CTRL_ADR);
	p->mp_fld_rx_descriptor_reader_control_cnt =
		register_get_field(p->mp_reg_rx_descriptor_reader_control, DBS_RX_DR_CTRL_CNT);

	p->mp_reg_rx_descriptor_reader_data =
		module_get_register(p->mp_mod_dbs, DBS_RX_DR_DATA);
	p->mp_fld_rx_descriptor_reader_data_guest_physical_address =
		register_get_field(p->mp_reg_rx_descriptor_reader_data, DBS_RX_DR_DATA_GPA);
	p->mp_fld_rx_descriptor_reader_data_host_id =
		register_get_field(p->mp_reg_rx_descriptor_reader_data, DBS_RX_DR_DATA_HID);
	p->mp_fld_rx_descriptor_reader_data_queue_size =
		register_get_field(p->mp_reg_rx_descriptor_reader_data, DBS_RX_DR_DATA_QS);
	p->mp_fld_rx_descriptor_reader_data_header =
		register_get_field(p->mp_reg_rx_descriptor_reader_data, DBS_RX_DR_DATA_HDR);
	p->mp_fld_rx_descriptor_reader_data_packed =
		register_query_field(p->mp_reg_rx_descriptor_reader_data, DBS_RX_DR_DATA_PCKED);

	p->mp_reg_tx_descriptor_reader_control =
		module_get_register(p->mp_mod_dbs, DBS_TX_DR_CTRL);
	p->mp_fld_tx_descriptor_reader_control_adr =
		register_get_field(p->mp_reg_tx_descriptor_reader_control, DBS_TX_DR_CTRL_ADR);
	p->mp_fld_tx_descriptor_reader_control_cnt =
		register_get_field(p->mp_reg_tx_descriptor_reader_control, DBS_TX_DR_CTRL_CNT);

	p->mp_reg_tx_descriptor_reader_data =
		module_get_register(p->mp_mod_dbs, DBS_TX_DR_DATA);
	p->mp_fld_tx_descriptor_reader_data_guest_physical_address =
		register_get_field(p->mp_reg_tx_descriptor_reader_data, DBS_TX_DR_DATA_GPA);
	p->mp_fld_tx_descriptor_reader_data_host_id =
		register_get_field(p->mp_reg_tx_descriptor_reader_data, DBS_TX_DR_DATA_HID);
	p->mp_fld_tx_descriptor_reader_data_queue_size =
		register_get_field(p->mp_reg_tx_descriptor_reader_data, DBS_TX_DR_DATA_QS);
	p->mp_fld_tx_descriptor_reader_data_header =
		register_get_field(p->mp_reg_tx_descriptor_reader_data, DBS_TX_DR_DATA_HDR);
	p->mp_fld_tx_descriptor_reader_data_port =
		register_get_field(p->mp_reg_tx_descriptor_reader_data, DBS_TX_DR_DATA_PORT);
	p->mp_fld_tx_descriptor_reader_data_packed =
		register_query_field(p->mp_reg_tx_descriptor_reader_data, DBS_TX_DR_DATA_PCKED);

	p->mp_reg_tx_queue_property_control =
		module_get_register(p->mp_mod_dbs, DBS_TX_QP_CTRL);
	p->mp_fld_tx_queue_property_control_adr =
		register_get_field(p->mp_reg_tx_queue_property_control, DBS_TX_QP_CTRL_ADR);
	p->mp_fld_tx_queue_property_control_cnt =
		register_get_field(p->mp_reg_tx_queue_property_control, DBS_TX_QP_CTRL_CNT);

	p->mp_reg_tx_queue_property_data =
		module_get_register(p->mp_mod_dbs, DBS_TX_QP_DATA);
	p->mp_fld_tx_queue_property_data_v_port =
		register_get_field(p->mp_reg_tx_queue_property_data, DBS_TX_QP_DATA_VPORT);

	/* HW QoS Tx rate limiting policing RFC2697/RFC4111 */
	p->mp_reg_tx_queue_qos_control =
		module_query_register(p->mp_mod_dbs, DBS_TX_QOS_CTRL);
	p->mp_reg_tx_queue_qos_data =
		module_query_register(p->mp_mod_dbs, DBS_TX_QOS_DATA);
	if (p->mp_reg_tx_queue_qos_control) {
		p->mp_reg_tx_queue_qos_control_adr =
			register_query_field(p->mp_reg_tx_queue_qos_control, DBS_TX_QOS_CTRL_ADR);
		p->mp_reg_tx_queue_qos_control_cnt =
			register_query_field(p->mp_reg_tx_queue_qos_control, DBS_TX_QOS_CTRL_CNT);

		if (p->mp_reg_tx_queue_qos_data) {
			p->mp_reg_tx_queue_qos_data_en =
				register_query_field(p->mp_reg_tx_queue_qos_data,
						     DBS_TX_QOS_DATA_EN);
			p->mp_reg_tx_queue_qos_data_ir =
				register_query_field(p->mp_reg_tx_queue_qos_data,
						     DBS_TX_QOS_DATA_IR);
			p->mp_reg_tx_queue_qos_data_bs =
				register_query_field(p->mp_reg_tx_queue_qos_data,
						     DBS_TX_QOS_DATA_BS);
		}
	}

	p->mp_reg_tx_queue_qos_rate =
		module_query_register(p->mp_mod_dbs, DBS_TX_QOS_RATE);
	if (p->mp_reg_tx_queue_qos_rate) {
		p->mp_reg_tx_queue_qos_rate_mul =
			register_query_field(p->mp_reg_tx_queue_qos_rate, DBS_TX_QOS_RATE_MUL);
		p->mp_reg_tx_queue_qos_rate_div =
			register_query_field(p->mp_reg_tx_queue_qos_rate, DBS_TX_QOS_RATE_DIV);
	}

	return 0;
}

int dbs_reset_rx_control(nthw_dbs_t *p)
{
	field_set_val32(p->mp_fld_rx_control_last_queue, 0);
	field_set_val32(p->mp_fld_rx_control_avail_monitor_enable, 0);
	field_set_val32(p->mp_fld_rx_control_avail_monitor_scan_speed, 8);
	field_set_val32(p->mp_fld_rx_control_used_write_enable, 0);
	field_set_val32(p->mp_fld_rx_control_used_writer_update_speed, 5);
	field_set_val32(p->mp_fld_rx_control_rx_queues_enable, 0);
	register_flush(p->mp_reg_rx_control, 1);
	return 0;
}

int dbs_reset_tx_control(nthw_dbs_t *p)
{
	field_set_val32(p->mp_fld_tx_control_last_queue, 0);
	field_set_val32(p->mp_fld_tx_control_avail_monitor_enable, 0);
	field_set_val32(p->mp_fld_tx_control_avail_monitor_scan_speed, 5);
	field_set_val32(p->mp_fld_tx_control_used_write_enable, 0);
	field_set_val32(p->mp_fld_tx_control_used_writer_update_speed, 8);
	field_set_val32(p->mp_fld_tx_control_tx_queues_enable, 0);
	register_flush(p->mp_reg_tx_control, 1);
	return 0;
}

void dbs_reset(nthw_dbs_t *p)
{
	uint32_t i;

	NT_LOG(DBG, NTHW, "NthwDbs::%s: resetting DBS", __func__);

	dbs_reset_rx_control(p);
	dbs_reset_tx_control(p);

	/* Reset RX memory banks and shado */
	for (i = 0; i < NT_DBS_RX_QUEUES_MAX; ++i) {
		set_shadow_rx_am_data(p, i, 0, 0, 0, 0, 0);
		flush_rx_am_data(p, i);

		set_shadow_rx_uw_data(p, i, 0, 0, 0, 0, 0, 0, 0);
		flush_rx_uw_data(p, i);

		set_shadow_rx_dr_data(p, i, 0, 0, 0, 0, 0);
		flush_rx_dr_data(p, i);
	}

	/* Reset TX memory banks and shado */
	for (i = 0; i < NT_DBS_TX_QUEUES_MAX; ++i) {
		set_shadow_tx_am_data(p, i, 0, 0, 0, 0, 0);
		flush_tx_am_data(p, i);

		set_shadow_tx_uw_data(p, i, 0, 0, 0, 0, 0, 0, 0, 0);
		flush_tx_uw_data(p, i);

		set_shadow_tx_dr_data(p, i, 0, 0, 0, 0, 0, 0);
		flush_tx_dr_data(p, i);

		set_shadow_tx_qp_data(p, i, 0);
		flush_tx_qp_data(p, i);

		set_shadow_tx_qos_data(p, i, 0, 0, 0);
		flush_tx_qos_data(p, i);
	}
}

int set_rx_control(nthw_dbs_t *p, uint32_t last_queue,
		   uint32_t avail_monitor_enable, uint32_t avail_monitor_speed,
		   uint32_t used_write_enable, uint32_t used_write_speed,
		   uint32_t rx_queue_enable)
{
#ifdef DBS_PRINT_REGS
	printf("last_queue %u\n", last_queue);
	printf("avail_monitor_enable %u\n", avail_monitor_enable);
	printf("avail_monitor_speed %u\n", avail_monitor_speed);
	printf("used_write_enable %u\n", used_write_enable);
	printf("used_write_speed %u\n", used_write_speed);
	printf("rx_queue_enable %u\n", rx_queue_enable);
#endif

	field_set_val32(p->mp_fld_rx_control_last_queue, last_queue);
	field_set_val32(p->mp_fld_rx_control_avail_monitor_enable, avail_monitor_enable);
	field_set_val32(p->mp_fld_rx_control_avail_monitor_scan_speed,
		       avail_monitor_speed);
	field_set_val32(p->mp_fld_rx_control_used_write_enable, used_write_enable);
	field_set_val32(p->mp_fld_rx_control_used_writer_update_speed, used_write_speed);
	field_set_val32(p->mp_fld_rx_control_rx_queues_enable, rx_queue_enable);
	register_flush(p->mp_reg_rx_control, 1);
	return 0;
}

int nthw_dbs_get_rx_control(nthw_dbs_t *p, uint32_t *last_queue,
			 uint32_t *avail_monitor_enable,
			 uint32_t *avail_monitor_speed, uint32_t *used_write_enable,
			 uint32_t *used_write_speed, uint32_t *rx_queue_enable)
{
	*last_queue = field_get_val32(p->mp_fld_rx_control_last_queue);
	*avail_monitor_enable =
		field_get_val32(p->mp_fld_rx_control_avail_monitor_enable);
	*avail_monitor_speed =
		field_get_val32(p->mp_fld_rx_control_avail_monitor_scan_speed);
	*used_write_enable = field_get_val32(p->mp_fld_rx_control_used_write_enable);
	*used_write_speed =
		field_get_val32(p->mp_fld_rx_control_used_writer_update_speed);
	*rx_queue_enable = field_get_val32(p->mp_fld_rx_control_rx_queues_enable);
	return 0;
}

int set_tx_control(nthw_dbs_t *p, uint32_t last_queue,
		   uint32_t avail_monitor_enable, uint32_t avail_monitor_speed,
		   uint32_t used_write_enable, uint32_t used_write_speed,
		   uint32_t tx_queue_enable)
{
#ifdef DBS_PRINT_REGS
	printf("last_queue %u\n", last_queue);
	printf("avail_monitor_enable %u\n", avail_monitor_enable);
	printf("avail_monitor_speed %u\n", avail_monitor_speed);
	printf("used_write_enable %u\n", used_write_enable);
	printf("used_write_speed %u\n", used_write_speed);
#endif

	field_set_val32(p->mp_fld_tx_control_last_queue, last_queue);
	field_set_val32(p->mp_fld_tx_control_avail_monitor_enable, avail_monitor_enable);
	field_set_val32(p->mp_fld_tx_control_avail_monitor_scan_speed,
		       avail_monitor_speed);
	field_set_val32(p->mp_fld_tx_control_used_write_enable, used_write_enable);
	field_set_val32(p->mp_fld_tx_control_used_writer_update_speed, used_write_speed);
	field_set_val32(p->mp_fld_tx_control_tx_queues_enable, tx_queue_enable);
	register_flush(p->mp_reg_tx_control, 1);
	return 0;
}

int nthw_dbs_get_tx_control(nthw_dbs_t *p, uint32_t *last_queue,
			 uint32_t *avail_monitor_enable,
			 uint32_t *avail_monitor_speed, uint32_t *used_write_enable,
			 uint32_t *used_write_speed, uint32_t *tx_queue_enable)
{
	*last_queue = field_get_val32(p->mp_fld_tx_control_last_queue);
	*avail_monitor_enable =
		field_get_val32(p->mp_fld_tx_control_avail_monitor_enable);
	*avail_monitor_speed =
		field_get_val32(p->mp_fld_tx_control_avail_monitor_scan_speed);
	*used_write_enable = field_get_val32(p->mp_fld_tx_control_used_write_enable);
	*used_write_speed =
		field_get_val32(p->mp_fld_tx_control_used_writer_update_speed);
	*tx_queue_enable = field_get_val32(p->mp_fld_tx_control_tx_queues_enable);
	return 0;
}

int set_rx_init(nthw_dbs_t *p, uint32_t start_idx, uint32_t start_ptr,
		uint32_t init, uint32_t queue)
{
	if (p->mp_reg_rx_init_val) {
		field_set_val32(p->mp_fld_rx_init_val_idx, start_idx);
		field_set_val32(p->mp_fld_rx_init_val_ptr, start_ptr);
		register_flush(p->mp_reg_rx_init_val, 1);
	}
	field_set_val32(p->mp_fld_rx_init_init, init);
	field_set_val32(p->mp_fld_rx_init_queue, queue);
	register_flush(p->mp_reg_rx_init, 1);
	return 0;
}

int get_rx_init(nthw_dbs_t *p, uint32_t *init, uint32_t *queue, uint32_t *busy)
{
	*init = field_get_val32(p->mp_fld_rx_init_init);
	*queue = field_get_val32(p->mp_fld_rx_init_queue);
	*busy = field_get_val32(p->mp_fld_rx_init_busy);
	return 0;
}

int set_tx_init(nthw_dbs_t *p, uint32_t start_idx, uint32_t start_ptr,
		uint32_t init, uint32_t queue)
{
	if (p->mp_reg_tx_init_val) {
		field_set_val32(p->mp_fld_tx_init_val_idx, start_idx);
		field_set_val32(p->mp_fld_tx_init_val_ptr, start_ptr);
		register_flush(p->mp_reg_tx_init_val, 1);
	}
	field_set_val32(p->mp_fld_tx_init_init, init);
	field_set_val32(p->mp_fld_tx_init_queue, queue);
	register_flush(p->mp_reg_tx_init, 1);
	return 0;
}

int get_tx_init(nthw_dbs_t *p, uint32_t *init, uint32_t *queue, uint32_t *busy)
{
	*init = field_get_val32(p->mp_fld_tx_init_init);
	*queue = field_get_val32(p->mp_fld_tx_init_queue);
	*busy = field_get_val32(p->mp_fld_tx_init_busy);
	return 0;
}

int set_rx_idle(nthw_dbs_t *p, uint32_t idle, uint32_t queue)

{
	if (!p->mp_reg_rx_idle)
		return -ENOTSUP;

	field_set_val32(p->mp_fld_rx_idle_idle, idle);
	field_set_val32(p->mp_fld_rx_idle_queue, queue);
	register_flush(p->mp_reg_rx_idle, 1);
	return 0;
}

int get_rx_idle(nthw_dbs_t *p, uint32_t *idle, uint32_t *queue, uint32_t *busy)
{
	if (!p->mp_reg_rx_idle)
		return -ENOTSUP;

	*idle = field_get_updated(p->mp_fld_rx_idle_idle);
	*queue = 0;
	*busy = field_get_updated(p->mp_fld_rx_idle_busy);
	return 0;
}

int set_tx_idle(nthw_dbs_t *p, uint32_t idle, uint32_t queue)

{
	if (!p->mp_reg_tx_idle)
		return -ENOTSUP;

	field_set_val32(p->mp_fld_tx_idle_idle, idle);
	field_set_val32(p->mp_fld_tx_idle_queue, queue);
	register_flush(p->mp_reg_tx_idle, 1);
	return 0;
}

int get_tx_idle(nthw_dbs_t *p, uint32_t *idle, uint32_t *queue, uint32_t *busy)
{
	if (!p->mp_reg_tx_idle)
		return -ENOTSUP;

	*idle = field_get_updated(p->mp_fld_tx_idle_idle);
	*queue = 0;
	*busy = field_get_updated(p->mp_fld_tx_idle_busy);
	return 0;
}

int set_rx_ptr_queue(nthw_dbs_t *p, uint32_t queue)
{
	if (!p->mp_reg_rx_ptr)
		return -ENOTSUP;

	field_set_val32(p->mp_fld_rx_ptr_queue, queue);
	register_flush(p->mp_reg_rx_ptr, 1);
	return 0;
}

int get_rx_ptr(nthw_dbs_t *p, uint32_t *ptr, uint32_t *queue, uint32_t *valid)
{
	if (!p->mp_reg_rx_ptr)
		return -ENOTSUP;

	*ptr = field_get_updated(p->mp_fld_rx_ptr_ptr);
	*queue = 0;
	*valid = field_get_updated(p->mp_fld_rx_ptr_valid);
	return 0;
}

int set_tx_ptr_queue(nthw_dbs_t *p, uint32_t queue)
{
	if (!p->mp_reg_tx_ptr)
		return -ENOTSUP;

	field_set_val32(p->mp_fld_tx_ptr_queue, queue);
	register_flush(p->mp_reg_tx_ptr, 1);
	return 0;
}

int get_tx_ptr(nthw_dbs_t *p, uint32_t *ptr, uint32_t *queue, uint32_t *valid)
{
	if (!p->mp_reg_tx_ptr)
		return -ENOTSUP;

	*ptr = field_get_updated(p->mp_fld_tx_ptr_ptr);
	*queue = 0;
	*valid = field_get_updated(p->mp_fld_tx_ptr_valid);
	return 0;
}

static void set_rx_am_data_index(nthw_dbs_t *p, uint32_t index)
{
	field_set_val32(p->mp_fld_rx_avail_monitor_control_adr, index);
	field_set_val32(p->mp_fld_rx_avail_monitor_control_cnt, 1);
	register_flush(p->mp_reg_rx_avail_monitor_control, 1);
}

static void
set_shadow_rx_am_data_guest_physical_address(nthw_dbs_t *p, uint32_t index,
				       uint64_t guest_physical_address)
{
	p->m_rx_am_shadow[index].guest_physical_address = guest_physical_address;
}

static void nthw_dbs_set_shadow_rx_am_data_enable(nthw_dbs_t *p, uint32_t index,
		uint32_t enable)
{
	p->m_rx_am_shadow[index].enable = enable;
}

static void set_shadow_rx_am_data_host_id(nthw_dbs_t *p, uint32_t index,
				     uint32_t host_id)
{
	p->m_rx_am_shadow[index].host_id = host_id;
}

static void set_shadow_rx_am_data_packed(nthw_dbs_t *p, uint32_t index,
				     uint32_t packed)
{
	p->m_rx_am_shadow[index].packed = packed;
}

static void set_shadow_rx_am_data_int_enable(nthw_dbs_t *p, uint32_t index,
					uint32_t int_enable)
{
	p->m_rx_am_shadow[index].int_enable = int_enable;
}

static void set_shadow_rx_am_data(nthw_dbs_t *p, uint32_t index,
			       uint64_t guest_physical_address, uint32_t enable,
			       uint32_t host_id, uint32_t packed,
			       uint32_t int_enable)
{
	set_shadow_rx_am_data_guest_physical_address(p, index, guest_physical_address);
	nthw_dbs_set_shadow_rx_am_data_enable(p, index, enable);
	set_shadow_rx_am_data_host_id(p, index, host_id);
	set_shadow_rx_am_data_packed(p, index, packed);
	set_shadow_rx_am_data_int_enable(p, index, int_enable);
}

static void flush_rx_am_data(nthw_dbs_t *p, uint32_t index)
{
	field_set_val(p->mp_fld_rx_avail_monitor_data_guest_physical_address,
		     (uint32_t *)&p->m_rx_am_shadow[index].guest_physical_address,
		     2);
	field_set_val32(p->mp_fld_rx_avail_monitor_data_enable,
		       p->m_rx_am_shadow[index].enable);
	field_set_val32(p->mp_fld_rx_avail_monitor_data_host_id,
		       p->m_rx_am_shadow[index].host_id);
	if (p->mp_fld_rx_avail_monitor_data_packed) {
		field_set_val32(p->mp_fld_rx_avail_monitor_data_packed,
			       p->m_rx_am_shadow[index].packed);
	}
	if (p->mp_fld_rx_avail_monitor_data_int) {
		field_set_val32(p->mp_fld_rx_avail_monitor_data_int,
			       p->m_rx_am_shadow[index].int_enable);
	}

	set_rx_am_data_index(p, index);
	register_flush(p->mp_reg_rx_avail_monitor_data, 1);
}

int set_rx_am_data(nthw_dbs_t *p, uint32_t index, uint64_t guest_physical_address,
		   uint32_t enable, uint32_t host_id, uint32_t packed,
		   uint32_t int_enable)
{
	if (!p->mp_reg_rx_avail_monitor_data)
		return -ENOTSUP;

	set_shadow_rx_am_data(p, index, guest_physical_address, enable, host_id,
			   packed, int_enable);
	flush_rx_am_data(p, index);
	return 0;
}

static void set_tx_am_data_index(nthw_dbs_t *p, uint32_t index)
{
	field_set_val32(p->mp_fld_tx_avail_monitor_control_adr, index);
	field_set_val32(p->mp_fld_tx_avail_monitor_control_cnt, 1);
	register_flush(p->mp_reg_tx_avail_monitor_control, 1);
}

static void set_shadow_tx_am_data(nthw_dbs_t *p, uint32_t index,
			       uint64_t guest_physical_address, uint32_t enable,
			       uint32_t host_id, uint32_t packed,
			       uint32_t int_enable)
{
	p->m_tx_am_shadow[index].guest_physical_address = guest_physical_address;
	p->m_tx_am_shadow[index].enable = enable;
	p->m_tx_am_shadow[index].host_id = host_id;
	p->m_tx_am_shadow[index].packed = packed;
	p->m_tx_am_shadow[index].int_enable = int_enable;
}

static void flush_tx_am_data(nthw_dbs_t *p, uint32_t index)
{
	field_set_val(p->mp_fld_tx_avail_monitor_data_guest_physical_address,
		     (uint32_t *)&p->m_tx_am_shadow[index].guest_physical_address,
		     2);
	field_set_val32(p->mp_fld_tx_avail_monitor_data_enable,
		       p->m_tx_am_shadow[index].enable);
	field_set_val32(p->mp_fld_tx_avail_monitor_data_host_id,
		       p->m_tx_am_shadow[index].host_id);
	if (p->mp_fld_tx_avail_monitor_data_packed) {
		field_set_val32(p->mp_fld_tx_avail_monitor_data_packed,
			       p->m_tx_am_shadow[index].packed);
	}
	if (p->mp_fld_tx_avail_monitor_data_int) {
		field_set_val32(p->mp_fld_tx_avail_monitor_data_int,
			       p->m_tx_am_shadow[index].int_enable);
	}

	set_tx_am_data_index(p, index);
	register_flush(p->mp_reg_tx_avail_monitor_data, 1);
}

int set_tx_am_data(nthw_dbs_t *p, uint32_t index, uint64_t guest_physical_address,
		   uint32_t enable, uint32_t host_id, uint32_t packed,
		   uint32_t int_enable)
{
	if (!p->mp_reg_tx_avail_monitor_data)
		return -ENOTSUP;

	set_shadow_tx_am_data(p, index, guest_physical_address, enable, host_id,
			   packed, int_enable);
	flush_tx_am_data(p, index);
	return 0;
}

static void set_rx_uw_data_index(nthw_dbs_t *p, uint32_t index)
{
	field_set_val32(p->mp_fld_rx_used_writer_control_adr, index);
	field_set_val32(p->mp_fld_rx_used_writer_control_cnt, 1);
	register_flush(p->mp_reg_rx_used_writer_control, 1);
}

static void
set_shadow_rx_uw_data_guest_physical_address(nthw_dbs_t *p, uint32_t index,
				       uint64_t guest_physical_address)
{
	p->m_rx_uw_shadow[index].guest_physical_address = guest_physical_address;
}

static void set_shadow_rx_uw_data_host_id(nthw_dbs_t *p, uint32_t index,
				     uint32_t host_id)
{
	p->m_rx_uw_shadow[index].host_id = host_id;
}

static void set_shadow_rx_uw_data_queue_size(nthw_dbs_t *p, uint32_t index,
					uint32_t queue_size)
{
	p->m_rx_uw_shadow[index].queue_size = queue_size;
}

static void set_shadow_rx_uw_data_packed(nthw_dbs_t *p, uint32_t index,
				     uint32_t packed)
{
	p->m_rx_uw_shadow[index].packed = packed;
}

static void set_shadow_rx_uw_data_int_enable(nthw_dbs_t *p, uint32_t index,
					uint32_t int_enable)
{
	p->m_rx_uw_shadow[index].int_enable = int_enable;
}

static void set_shadow_rx_uw_data_vec(nthw_dbs_t *p, uint32_t index, uint32_t vec)
{
	p->m_rx_uw_shadow[index].vec = vec;
}

static void set_shadow_rx_uw_data_istk(nthw_dbs_t *p, uint32_t index, uint32_t istk)
{
	p->m_rx_uw_shadow[index].istk = istk;
}

static void set_shadow_rx_uw_data(nthw_dbs_t *p, uint32_t index,
			       uint64_t guest_physical_address, uint32_t host_id,
			       uint32_t queue_size, uint32_t packed,
			       uint32_t int_enable, uint32_t vec, uint32_t istk)
{
	set_shadow_rx_uw_data_guest_physical_address(p, index, guest_physical_address);
	set_shadow_rx_uw_data_host_id(p, index, host_id);
	set_shadow_rx_uw_data_queue_size(p, index, queue_size);
	set_shadow_rx_uw_data_packed(p, index, packed);
	set_shadow_rx_uw_data_int_enable(p, index, int_enable);
	set_shadow_rx_uw_data_vec(p, index, vec);
	set_shadow_rx_uw_data_istk(p, index, istk);
}

static void flush_rx_uw_data(nthw_dbs_t *p, uint32_t index)
{
	field_set_val(p->mp_fld_rx_used_writer_data_guest_physical_address,
		     (uint32_t *)&p->m_rx_uw_shadow[index].guest_physical_address,
		     2);
	field_set_val32(p->mp_fld_rx_used_writer_data_host_id,
		       p->m_rx_uw_shadow[index].host_id);
	if (module_is_version_newer(p->mp_mod_dbs, 0, 8)) {
		field_set_val32(p->mp_fld_rx_used_writer_data_queue_size,
			       (1U << p->m_rx_uw_shadow[index].queue_size) - 1U);
	} else {
		field_set_val32(p->mp_fld_rx_used_writer_data_queue_size,
			       p->m_rx_uw_shadow[index].queue_size);
	}
	if (p->mp_fld_rx_used_writer_data_packed) {
		field_set_val32(p->mp_fld_rx_used_writer_data_packed,
			       p->m_rx_uw_shadow[index].packed);
	}
	if (p->mp_fld_rx_used_writer_data_int) {
		field_set_val32(p->mp_fld_rx_used_writer_data_int,
			       p->m_rx_uw_shadow[index].int_enable);
		field_set_val32(p->mp_fld_rx_used_writer_data_vec,
			       p->m_rx_uw_shadow[index].vec);
		field_set_val32(p->mp_fld_rx_used_writer_data_istk,
			       p->m_rx_uw_shadow[index].istk);
	}

	set_rx_uw_data_index(p, index);
	register_flush(p->mp_reg_rx_used_writer_data, 1);
}

int set_rx_uw_data(nthw_dbs_t *p, uint32_t index, uint64_t guest_physical_address,
		   uint32_t host_id, uint32_t queue_size, uint32_t packed,
		   uint32_t int_enable, uint32_t vec, uint32_t istk)
{
	if (!p->mp_reg_rx_used_writer_data)
		return -ENOTSUP;

	set_shadow_rx_uw_data(p, index, guest_physical_address, host_id, queue_size,
			   packed, int_enable, vec, istk);
	flush_rx_uw_data(p, index);
	return 0;
}

static void set_tx_uw_data_index(nthw_dbs_t *p, uint32_t index)
{
	field_set_val32(p->mp_fld_tx_used_writer_control_adr, index);
	field_set_val32(p->mp_fld_tx_used_writer_control_cnt, 1);
	register_flush(p->mp_reg_tx_used_writer_control, 1);
}

static void
set_shadow_tx_uw_data_guest_physical_address(nthw_dbs_t *p, uint32_t index,
				       uint64_t guest_physical_address)
{
	p->m_tx_uw_shadow[index].guest_physical_address = guest_physical_address;
}

static void set_shadow_tx_uw_data_host_id(nthw_dbs_t *p, uint32_t index,
				     uint32_t host_id)
{
	p->m_tx_uw_shadow[index].host_id = host_id;
}

static void set_shadow_tx_uw_data_queue_size(nthw_dbs_t *p, uint32_t index,
					uint32_t queue_size)
{
	p->m_tx_uw_shadow[index].queue_size = queue_size;
}

static void set_shadow_tx_uw_data_packed(nthw_dbs_t *p, uint32_t index,
				     uint32_t packed)
{
	p->m_tx_uw_shadow[index].packed = packed;
}

static void set_shadow_tx_uw_data_int_enable(nthw_dbs_t *p, uint32_t index,
					uint32_t int_enable)
{
	p->m_tx_uw_shadow[index].int_enable = int_enable;
}

static void set_shadow_tx_uw_data_vec(nthw_dbs_t *p, uint32_t index, uint32_t vec)
{
	p->m_tx_uw_shadow[index].vec = vec;
}

static void set_shadow_tx_uw_data_istk(nthw_dbs_t *p, uint32_t index, uint32_t istk)
{
	p->m_tx_uw_shadow[index].istk = istk;
}

static void set_shadow_tx_uw_data_in_order(nthw_dbs_t *p, uint32_t index,
				      uint32_t in_order)
{
	p->m_tx_uw_shadow[index].in_order = in_order;
}

static void set_shadow_tx_uw_data(nthw_dbs_t *p, uint32_t index,
			       uint64_t guest_physical_address, uint32_t host_id,
			       uint32_t queue_size, uint32_t packed,
			       uint32_t int_enable, uint32_t vec, uint32_t istk,
			       uint32_t in_order)
{
	set_shadow_tx_uw_data_guest_physical_address(p, index, guest_physical_address);
	set_shadow_tx_uw_data_host_id(p, index, host_id);
	set_shadow_tx_uw_data_queue_size(p, index, queue_size);
	set_shadow_tx_uw_data_packed(p, index, packed);
	set_shadow_tx_uw_data_int_enable(p, index, int_enable);
	set_shadow_tx_uw_data_vec(p, index, vec);
	set_shadow_tx_uw_data_istk(p, index, istk);
	set_shadow_tx_uw_data_in_order(p, index, in_order);
}

static void flush_tx_uw_data(nthw_dbs_t *p, uint32_t index)
{
	field_set_val(p->mp_fld_tx_used_writer_data_guest_physical_address,
		     (uint32_t *)&p->m_tx_uw_shadow[index].guest_physical_address,
		     2);
	field_set_val32(p->mp_fld_tx_used_writer_data_host_id,
		       p->m_tx_uw_shadow[index].host_id);
	if (module_is_version_newer(p->mp_mod_dbs, 0, 8)) {
		field_set_val32(p->mp_fld_tx_used_writer_data_queue_size,
			       (1U << p->m_tx_uw_shadow[index].queue_size) - 1U);
	} else {
		field_set_val32(p->mp_fld_tx_used_writer_data_queue_size,
			       p->m_tx_uw_shadow[index].queue_size);
	}
	if (p->mp_fld_tx_used_writer_data_packed) {
		field_set_val32(p->mp_fld_tx_used_writer_data_packed,
			       p->m_tx_uw_shadow[index].packed);
	}
	if (p->mp_fld_tx_used_writer_data_int) {
		field_set_val32(p->mp_fld_tx_used_writer_data_int,
			       p->m_tx_uw_shadow[index].int_enable);
		field_set_val32(p->mp_fld_tx_used_writer_data_vec,
			       p->m_tx_uw_shadow[index].vec);
		field_set_val32(p->mp_fld_tx_used_writer_data_istk,
			       p->m_tx_uw_shadow[index].istk);
	}
	if (p->mp_fld_tx_used_writer_data_in_order) {
		field_set_val32(p->mp_fld_tx_used_writer_data_in_order,
			       p->m_tx_uw_shadow[index].in_order);
	}

	set_tx_uw_data_index(p, index);
	register_flush(p->mp_reg_tx_used_writer_data, 1);
}

int set_tx_uw_data(nthw_dbs_t *p, uint32_t index, uint64_t guest_physical_address,
		   uint32_t host_id, uint32_t queue_size, uint32_t packed,
		   uint32_t int_enable, uint32_t vec, uint32_t istk,
		   uint32_t in_order)
{
	if (!p->mp_reg_tx_used_writer_data)
		return -ENOTSUP;

	set_shadow_tx_uw_data(p, index, guest_physical_address, host_id, queue_size,
			   packed, int_enable, vec, istk, in_order);
	flush_tx_uw_data(p, index);
	return 0;
}

static void set_rx_dr_data_index(nthw_dbs_t *p, uint32_t index)
{
	field_set_val32(p->mp_fld_rx_descriptor_reader_control_adr, index);
	field_set_val32(p->mp_fld_rx_descriptor_reader_control_cnt, 1);
	register_flush(p->mp_reg_rx_descriptor_reader_control, 1);
}

static void
set_shadow_rx_dr_data_guest_physical_address(nthw_dbs_t *p, uint32_t index,
				       uint64_t guest_physical_address)
{
	p->m_rx_dr_shadow[index].guest_physical_address = guest_physical_address;
}

static void set_shadow_rx_dr_data_host_id(nthw_dbs_t *p, uint32_t index,
				     uint32_t host_id)
{
	p->m_rx_dr_shadow[index].host_id = host_id;
}

static void set_shadow_rx_dr_data_queue_size(nthw_dbs_t *p, uint32_t index,
					uint32_t queue_size)
{
	p->m_rx_dr_shadow[index].queue_size = queue_size;
}

static void set_shadow_rx_dr_data_header(nthw_dbs_t *p, uint32_t index,
				     uint32_t header)
{
	p->m_rx_dr_shadow[index].header = header;
}

static void set_shadow_rx_dr_data_packed(nthw_dbs_t *p, uint32_t index,
				     uint32_t packed)
{
	p->m_rx_dr_shadow[index].packed = packed;
}

static void set_shadow_rx_dr_data(nthw_dbs_t *p, uint32_t index,
			       uint64_t guest_physical_address, uint32_t host_id,
			       uint32_t queue_size, uint32_t header,
			       uint32_t packed)
{
	set_shadow_rx_dr_data_guest_physical_address(p, index, guest_physical_address);
	set_shadow_rx_dr_data_host_id(p, index, host_id);
	set_shadow_rx_dr_data_queue_size(p, index, queue_size);
	set_shadow_rx_dr_data_header(p, index, header);
	set_shadow_rx_dr_data_packed(p, index, packed);
}

static void flush_rx_dr_data(nthw_dbs_t *p, uint32_t index)
{
	field_set_val(p->mp_fld_rx_descriptor_reader_data_guest_physical_address,
		     (uint32_t *)&p->m_rx_dr_shadow[index].guest_physical_address,
		     2);
	field_set_val32(p->mp_fld_rx_descriptor_reader_data_host_id,
		       p->m_rx_dr_shadow[index].host_id);
	if (module_is_version_newer(p->mp_mod_dbs, 0, 8)) {
		field_set_val32(p->mp_fld_rx_descriptor_reader_data_queue_size,
			       (1U << p->m_rx_dr_shadow[index].queue_size) - 1U);
	} else {
		field_set_val32(p->mp_fld_rx_descriptor_reader_data_queue_size,
			       p->m_rx_dr_shadow[index].queue_size);
	}
	field_set_val32(p->mp_fld_rx_descriptor_reader_data_header,
		       p->m_rx_dr_shadow[index].header);
	if (p->mp_fld_rx_descriptor_reader_data_packed) {
		field_set_val32(p->mp_fld_rx_descriptor_reader_data_packed,
			       p->m_rx_dr_shadow[index].packed);
	}

	set_rx_dr_data_index(p, index);
	register_flush(p->mp_reg_rx_descriptor_reader_data, 1);
}

int set_rx_dr_data(nthw_dbs_t *p, uint32_t index, uint64_t guest_physical_address,
		   uint32_t host_id, uint32_t queue_size, uint32_t header,
		   uint32_t packed)
{
	if (!p->mp_reg_rx_descriptor_reader_data)
		return -ENOTSUP;

	set_shadow_rx_dr_data(p, index, guest_physical_address, host_id, queue_size,
			   header, packed);
	flush_rx_dr_data(p, index);
	return 0;
}

static void set_tx_dr_data_index(nthw_dbs_t *p, uint32_t index)
{
	field_set_val32(p->mp_fld_tx_descriptor_reader_control_adr, index);
	field_set_val32(p->mp_fld_tx_descriptor_reader_control_cnt, 1);
	register_flush(p->mp_reg_tx_descriptor_reader_control, 1);
}

static void
set_shadow_tx_dr_data_guest_physical_address(nthw_dbs_t *p, uint32_t index,
				       uint64_t guest_physical_address)
{
	p->m_tx_dr_shadow[index].guest_physical_address = guest_physical_address;
}

static void set_shadow_tx_dr_data_host_id(nthw_dbs_t *p, uint32_t index,
				     uint32_t host_id)
{
	p->m_tx_dr_shadow[index].host_id = host_id;
}

static void set_shadow_tx_dr_data_queue_size(nthw_dbs_t *p, uint32_t index,
					uint32_t queue_size)
{
	p->m_tx_dr_shadow[index].queue_size = queue_size;
}

static void set_shadow_tx_dr_data_header(nthw_dbs_t *p, uint32_t index,
				     uint32_t header)
{
	p->m_tx_dr_shadow[index].header = header;
}

static void set_shadow_tx_dr_data_port(nthw_dbs_t *p, uint32_t index, uint32_t port)
{
	p->m_tx_dr_shadow[index].port = port;
}

static void set_shadow_tx_dr_data_packed(nthw_dbs_t *p, uint32_t index,
				     uint32_t packed)
{
	p->m_tx_dr_shadow[index].packed = packed;
}

static void set_shadow_tx_dr_data(nthw_dbs_t *p, uint32_t index,
			       uint64_t guest_physical_address, uint32_t host_id,
			       uint32_t queue_size, uint32_t port,
			       uint32_t header, uint32_t packed)
{
	set_shadow_tx_dr_data_guest_physical_address(p, index, guest_physical_address);
	set_shadow_tx_dr_data_host_id(p, index, host_id);
	set_shadow_tx_dr_data_queue_size(p, index, queue_size);
	set_shadow_tx_dr_data_header(p, index, header);
	set_shadow_tx_dr_data_port(p, index, port);
	set_shadow_tx_dr_data_packed(p, index, packed);
}

static void flush_tx_dr_data(nthw_dbs_t *p, uint32_t index)
{
	field_set_val(p->mp_fld_tx_descriptor_reader_data_guest_physical_address,
		     (uint32_t *)&p->m_tx_dr_shadow[index].guest_physical_address,
		     2);
	field_set_val32(p->mp_fld_tx_descriptor_reader_data_host_id,
		       p->m_tx_dr_shadow[index].host_id);
	if (module_is_version_newer(p->mp_mod_dbs, 0, 8)) {
		field_set_val32(p->mp_fld_tx_descriptor_reader_data_queue_size,
			       (1U << p->m_tx_dr_shadow[index].queue_size) - 1U);
	} else {
		field_set_val32(p->mp_fld_tx_descriptor_reader_data_queue_size,
			       p->m_tx_dr_shadow[index].queue_size);
	}
	field_set_val32(p->mp_fld_tx_descriptor_reader_data_header,
		       p->m_tx_dr_shadow[index].header);
	field_set_val32(p->mp_fld_tx_descriptor_reader_data_port,
		       p->m_tx_dr_shadow[index].port);
	if (p->mp_fld_tx_descriptor_reader_data_packed) {
		field_set_val32(p->mp_fld_tx_descriptor_reader_data_packed,
			       p->m_tx_dr_shadow[index].packed);
	}

	set_tx_dr_data_index(p, index);
	register_flush(p->mp_reg_tx_descriptor_reader_data, 1);
}

int set_tx_dr_data(nthw_dbs_t *p, uint32_t index, uint64_t guest_physical_address,
		   uint32_t host_id, uint32_t queue_size, uint32_t port,
		   uint32_t header, uint32_t packed)
{
	if (!p->mp_reg_tx_descriptor_reader_data)
		return -ENOTSUP;

	set_shadow_tx_dr_data(p, index, guest_physical_address, host_id, queue_size,
			   port, header, packed);
	flush_tx_dr_data(p, index);
	return 0;
}

static void set_tx_qp_data_index(nthw_dbs_t *p, uint32_t index)
{
	field_set_val32(p->mp_fld_tx_queue_property_control_adr, index);
	field_set_val32(p->mp_fld_tx_queue_property_control_cnt, 1);
	register_flush(p->mp_reg_tx_queue_property_control, 1);
}

static void set_shadow_tx_qp_data_virtual_port(nthw_dbs_t *p, uint32_t index,
		uint32_t virtual_port)
{
	p->m_tx_qp_shadow[index].virtual_port = virtual_port;
}

static void set_shadow_tx_qp_data(nthw_dbs_t *p, uint32_t index,
			       uint32_t virtual_port)
{
	set_shadow_tx_qp_data_virtual_port(p, index, virtual_port);
}

static void flush_tx_qp_data(nthw_dbs_t *p, uint32_t index)
{
	field_set_val32(p->mp_fld_tx_queue_property_data_v_port,
		       p->m_tx_qp_shadow[index].virtual_port);

	set_tx_qp_data_index(p, index);
	register_flush(p->mp_reg_tx_queue_property_data, 1);
}

int nthw_dbs_set_tx_qp_data(nthw_dbs_t *p, uint32_t index, uint32_t virtual_port)
{
	if (!p->mp_reg_tx_queue_property_data)
		return -ENOTSUP;

	set_shadow_tx_qp_data(p, index, virtual_port);
	flush_tx_qp_data(p, index);
	return 0;
}

static void set_tx_qos_data_index(nthw_dbs_t *p, uint32_t index)
{
	field_set_val32(p->mp_reg_tx_queue_qos_control_adr, index);
	field_set_val32(p->mp_reg_tx_queue_qos_control_cnt, 1);
	register_flush(p->mp_reg_tx_queue_qos_control, 1);
}

static void set_shadow_tx_qos_data_enable(nthw_dbs_t *p, uint32_t index,
				      uint32_t enable)
{
	p->m_tx_qos_shadow[index].enable = enable;
}

static void set_shadow_tx_qos_data_ir(nthw_dbs_t *p, uint32_t index, uint32_t ir)
{
	p->m_tx_qos_shadow[index].ir = ir;
}

static void set_shadow_tx_qos_data_bs(nthw_dbs_t *p, uint32_t index, uint32_t bs)
{
	p->m_tx_qos_shadow[index].bs = bs;
}

static void set_shadow_tx_qos_data(nthw_dbs_t *p, uint32_t index, uint32_t enable,
				uint32_t ir, uint32_t bs)
{
	set_shadow_tx_qos_data_enable(p, index, enable);
	set_shadow_tx_qos_data_ir(p, index, ir);
	set_shadow_tx_qos_data_bs(p, index, bs);
}

static void flush_tx_qos_data(nthw_dbs_t *p, uint32_t index)
{
	field_set_val32(p->mp_reg_tx_queue_qos_data_en, p->m_tx_qos_shadow[index].enable);
	field_set_val32(p->mp_reg_tx_queue_qos_data_ir, p->m_tx_qos_shadow[index].ir);
	field_set_val32(p->mp_reg_tx_queue_qos_data_bs, p->m_tx_qos_shadow[index].bs);

	set_tx_qos_data_index(p, index);
	register_flush(p->mp_reg_tx_queue_qos_data, 1);
}

int set_tx_qos_data(nthw_dbs_t *p, uint32_t index, uint32_t enable, uint32_t ir,
		    uint32_t bs)
{
	if (!p->mp_reg_tx_queue_qos_data)
		return -ENOTSUP;

	set_shadow_tx_qos_data(p, index, enable, ir, bs);
	flush_tx_qos_data(p, index);
	return 0;
}

int set_tx_qos_rate(nthw_dbs_t *p, uint32_t mul, uint32_t div)
{
	if (!p->mp_reg_tx_queue_qos_rate)
		return -ENOTSUP;

	field_set_val32(p->mp_reg_tx_queue_qos_rate_mul, mul);
	field_set_val32(p->mp_reg_tx_queue_qos_rate_div, div);
	register_flush(p->mp_reg_tx_queue_qos_rate, 1);
	return 0;
}

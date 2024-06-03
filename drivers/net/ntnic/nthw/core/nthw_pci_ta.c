/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "ntlog.h"

#include "nthw_drv.h"
#include "nthw_register.h"

#include "nthw_pci_ta.h"

nthw_pci_ta_t *nthw_pci_ta_new(void)
{
	nthw_pci_ta_t *p = malloc(sizeof(nthw_pci_ta_t));

	if (p)
		memset(p, 0, sizeof(nthw_pci_ta_t));

	return p;
}

int nthw_pci_ta_init(nthw_pci_ta_t *p, nthw_fpga_t *p_fpga, int n_instance)
{
	nthw_module_t *mod = nthw_fpga_query_module(p_fpga, MOD_PCI_TA, n_instance);

	if (p == NULL)
		return mod == NULL ? -1 : 0;

	if (mod == NULL) {
		NT_LOG(ERR, NTHW, "%s: PCI_TA %d: no such instance\n",
			p_fpga->p_fpga_info->mp_adapter_id_str, n_instance);
		return -1;
	}

	p->mp_fpga = p_fpga;
	p->mn_instance = n_instance;
	p->mp_mod_pci_ta = mod;

	p->mn_param_pci_ta_tg_present =
		nthw_fpga_get_product_param(p_fpga, NT_PCI_TA_TG_PRESENT, 1);

	p->mp_reg_pci_ta_ctrl = nthw_module_get_register(p->mp_mod_pci_ta, PCI_TA_CONTROL);
	p->mp_fld_pci_ta_ctrl_enable =
		nthw_register_get_field(p->mp_reg_pci_ta_ctrl, PCI_TA_CONTROL_ENABLE);

	p->mp_reg_pci_ta_packet_good =
		nthw_module_get_register(p->mp_mod_pci_ta, PCI_TA_PACKET_GOOD);
	p->mp_fld_pci_ta_packet_good_amount =
		nthw_register_get_field(p->mp_reg_pci_ta_packet_good, PCI_TA_PACKET_GOOD_AMOUNT);

	p->mp_reg_pci_ta_packet_bad =
		nthw_module_get_register(p->mp_mod_pci_ta, PCI_TA_PACKET_BAD);
	p->mp_fld_pci_ta_packet_bad_amount =
		nthw_register_get_field(p->mp_reg_pci_ta_packet_bad, PCI_TA_PACKET_BAD_AMOUNT);

	p->mp_reg_pci_ta_length_error =
		nthw_module_get_register(p->mp_mod_pci_ta, PCI_TA_LENGTH_ERROR);
	p->mp_fld_pci_ta_length_error_amount =
		nthw_register_get_field(p->mp_reg_pci_ta_length_error, PCI_TA_LENGTH_ERROR_AMOUNT);

	p->mp_reg_pci_ta_payload_error =
		nthw_module_get_register(p->mp_mod_pci_ta, PCI_TA_PAYLOAD_ERROR);
	p->mp_fld_pci_ta_payload_error_amount =
		nthw_register_get_field(p->mp_reg_pci_ta_payload_error,
			PCI_TA_PAYLOAD_ERROR_AMOUNT);

	return 0;
}

void nthw_pci_ta_set_control_enable(nthw_pci_ta_t *p, uint32_t val)
{
	nthw_field_set_val_flush32(p->mp_fld_pci_ta_ctrl_enable, val);
}

void nthw_pci_ta_get_packet_good(nthw_pci_ta_t *p, uint32_t *val)
{
	*val = nthw_field_get_updated(p->mp_fld_pci_ta_packet_good_amount);
}

void nthw_pci_ta_get_packet_bad(nthw_pci_ta_t *p, uint32_t *val)
{
	*val = nthw_field_get_updated(p->mp_fld_pci_ta_packet_bad_amount);
}

void nthw_pci_ta_get_length_error(nthw_pci_ta_t *p, uint32_t *val)
{
	*val = nthw_field_get_updated(p->mp_fld_pci_ta_length_error_amount);
}

void nthw_pci_ta_get_payload_error(nthw_pci_ta_t *p, uint32_t *val)
{
	*val = nthw_field_get_updated(p->mp_fld_pci_ta_payload_error_amount);
}

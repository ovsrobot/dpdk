/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __NTHW_PCI_TA_H__
#define __NTHW_PCI_TA_H__

struct nthw_pci_ta {
	nthw_fpga_t *mp_fpga;
	nthw_module_t *mp_mod_pci_ta;
	int mn_instance;

	int mn_param_pci_ta_tg_present;

	nthw_register_t *mp_reg_pci_ta_ctrl;
	nthw_field_t *mp_fld_pci_ta_ctrl_enable;
	nthw_register_t *mp_reg_pci_ta_packet_good;
	nthw_field_t *mp_fld_pci_ta_packet_good_amount;
	nthw_register_t *mp_reg_pci_ta_packet_bad;
	nthw_field_t *mp_fld_pci_ta_packet_bad_amount;
	nthw_register_t *mp_reg_pci_ta_length_error;
	nthw_field_t *mp_fld_pci_ta_length_error_amount;
	nthw_register_t *mp_reg_pci_ta_payload_error;
	nthw_field_t *mp_fld_pci_ta_payload_error_amount;
};

typedef struct nthw_pci_ta nthw_pci_ta_t;
typedef struct nthw_pci_ta nthw_pci_ta;

nthw_pci_ta_t *nthw_pci_ta_new(void);
int nthw_pci_ta_init(nthw_pci_ta_t *p, nthw_fpga_t *p_fpga, int n_instance);

void nthw_pci_ta_set_control_enable(nthw_pci_ta_t *p, uint32_t val);
void nthw_pci_ta_get_packet_good(nthw_pci_ta_t *p, uint32_t *val);
void nthw_pci_ta_get_packet_bad(nthw_pci_ta_t *p, uint32_t *val);
void nthw_pci_ta_get_length_error(nthw_pci_ta_t *p, uint32_t *val);
void nthw_pci_ta_get_payload_error(nthw_pci_ta_t *p, uint32_t *val);

#endif	/* __NTHW_PCI_TA_H__ */

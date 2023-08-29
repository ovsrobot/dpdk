/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __NTHW_PCI_TA_H__
#define __NTHW_PCI_TA_H__

struct nthw_pci_ta {
	nt_fpga_t *mp_fpga;
	nt_module_t *mp_mod_pci_ta;
	int mn_instance;

	int mn_param_pci_ta_tg_present;

	nt_register_t *mp_reg_pci_ta_ctrl;
	nt_field_t *mp_fld_pci_ta_ctrl_enable;
	nt_register_t *mp_reg_pci_ta_packet_good;
	nt_field_t *mp_fld_pci_ta_packet_good_amount;
	nt_register_t *mp_reg_pci_ta_packet_bad;
	nt_field_t *mp_fld_pci_ta_packet_bad_amount;
	nt_register_t *mp_reg_pci_ta_length_error;
	nt_field_t *mp_fld_pci_ta_length_error_amount;
	nt_register_t *mp_reg_pci_ta_payload_error;
	nt_field_t *mp_fld_pci_ta_payload_error_amount;
};

typedef struct nthw_pci_ta nthw_pci_ta_t;
typedef struct nthw_pci_ta nthw_pci_ta;

nthw_pci_ta_t *nthw_pci_ta_new(void);
void nthw_pci_ta_delete(nthw_pci_ta_t *p);
int nthw_pci_ta_init(nthw_pci_ta_t *p, nt_fpga_t *p_fpga, int n_instance);

void nthw_pci_ta_set_control_enable(nthw_pci_ta_t *p, uint32_t val);
void nthw_pci_ta_get_packet_good(nthw_pci_ta_t *p, uint32_t *val);
void nthw_pci_ta_get_packet_bad(nthw_pci_ta_t *p, uint32_t *val);
void nthw_pci_ta_get_length_error(nthw_pci_ta_t *p, uint32_t *val);
void nthw_pci_ta_get_payload_error(nthw_pci_ta_t *p, uint32_t *val);

#endif /* __NTHW_PCI_TA_H__ */

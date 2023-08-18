/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __NTHW_PCI_WR_TG_H__
#define __NTHW_PCI_WR_TG_H__

struct nthw_pci_wr_tg {
	nt_fpga_t *mp_fpga;
	nt_module_t *mp_mod_pci_wr_tg;
	int mn_instance;

	int mn_param_pci_ta_tg_present;

	nt_register_t *mp_reg_pci_wr_tg_data0;
	nt_field_t *mp_fld_pci_wr_tg_phys_addr_low;

	nt_register_t *mp_reg_pci_wr_tg_data1;
	nt_field_t *mp_fld_pci_wr_tg_phys_addr_high;

	nt_register_t *mp_reg_pci_wr_tg_data2;
	nt_field_t *mp_fld_pci_wr_tg_req_size;
	nt_field_t *mp_fld_pci_wr_tg_req_hid;
	nt_field_t *mp_fld_pci_wr_tg_inc_mode;
	nt_field_t *mp_fld_pci_wr_tg_wait;
	nt_field_t *mp_fld_pci_wr_tg_wrap;

	nt_register_t *mp_reg_pci_wr_tg_addr;
	nt_field_t *mp_fld_pci_wr_tg_ram_addr;

	nt_register_t *mp_reg_pci_wr_tg_run;
	nt_field_t *mp_fld_pci_wr_tg_run_iteration;

	nt_register_t *mp_reg_pci_wr_tg_ctrl;
	nt_field_t *mp_fld_pci_wr_tg_ctrl_rdy;

	nt_register_t *mp_reg_pci_wr_tg_seq;
	nt_field_t *mp_fld_pci_wr_tg_seq_sequence;
};

typedef struct nthw_pci_wr_tg nthw_pci_wr_tg_t;
typedef struct nthw_pci_wr_tg nthw_pci_wr_tg;

nthw_pci_wr_tg_t *nthw_pci_wr_tg_new(void);
void nthw_pci_wr_tg_delete(nthw_pci_wr_tg_t *p);
int nthw_pci_wr_tg_init(nthw_pci_wr_tg_t *p, nt_fpga_t *p_fpga, int n_instance);

void nthw_pci_wr_tg_set_phys_addr(nthw_pci_wr_tg_t *p, uint64_t n_phys_addr);
void nthw_pci_wr_tg_set_ram_addr(nthw_pci_wr_tg_t *p, int n_ram_addr);
void nthw_pci_wr_tg_set_ram_data(nthw_pci_wr_tg_t *p, uint32_t req_size, bool wait,
			    bool wrap, bool inc);
void nthw_pci_wr_tg_set_run(nthw_pci_wr_tg_t *p, int n_iterations);
uint32_t nthw_pci_wr_tg_get_ctrl_rdy(nthw_pci_wr_tg_t *p);

#endif /* __NTHW_PCI_WR_TG_H__ */

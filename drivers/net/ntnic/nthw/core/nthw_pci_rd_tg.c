/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "ntlog.h"

#include "nthw_drv.h"
#include "nthw_register.h"

#include "nthw_pci_rd_tg.h"

nthw_pci_rd_tg_t *nthw_pci_rd_tg_new(void)
{
	nthw_pci_rd_tg_t *p = malloc(sizeof(nthw_pci_rd_tg_t));

	if (p)
		memset(p, 0, sizeof(nthw_pci_rd_tg_t));

	return p;
}

int nthw_pci_rd_tg_init(nthw_pci_rd_tg_t *p, nthw_fpga_t *p_fpga, int n_instance)
{
	nthw_module_t *mod = nthw_fpga_query_module(p_fpga, MOD_PCI_RD_TG, n_instance);

	if (p == NULL)
		return mod == NULL ? -1 : 0;

	if (mod == NULL) {
		NT_LOG(ERR, NTHW, "%s: PCI_RD_TG %d: no such instance\n",
			p_fpga->p_fpga_info->mp_adapter_id_str, n_instance);
		return -1;
	}

	p->mp_fpga = p_fpga;
	p->mn_instance = n_instance;
	p->mp_mod_pci_rd_tg = mod;

	p->mn_param_pci_ta_tg_present =
		nthw_fpga_get_product_param(p_fpga, NT_PCI_TA_TG_PRESENT, 1);

	p->mp_reg_pci_rd_tg_rd_data0 =
		nthw_module_get_register(p->mp_mod_pci_rd_tg, PCI_RD_TG_TG_RDDATA0);
	p->mp_fld_pci_rd_tg_phys_addr_low =
		nthw_register_get_field(p->mp_reg_pci_rd_tg_rd_data0,
			PCI_RD_TG_TG_RDDATA0_PHYS_ADDR_LOW);

	p->mp_reg_pci_rd_tg_rd_data1 =
		nthw_module_get_register(p->mp_mod_pci_rd_tg, PCI_RD_TG_TG_RDDATA1);
	p->mp_fld_pci_rd_tg_phys_addr_high =
		nthw_register_get_field(p->mp_reg_pci_rd_tg_rd_data1,
			PCI_RD_TG_TG_RDDATA1_PHYS_ADDR_HIGH);

	p->mp_reg_pci_rd_tg_rd_data2 =
		nthw_module_get_register(p->mp_mod_pci_rd_tg, PCI_RD_TG_TG_RDDATA2);
	p->mp_fld_pci_rd_tg_req_size = nthw_register_get_field(p->mp_reg_pci_rd_tg_rd_data2,
			PCI_RD_TG_TG_RDDATA2_REQ_SIZE);
	p->mp_fld_pci_rd_tg_wait =
		nthw_register_get_field(p->mp_reg_pci_rd_tg_rd_data2, PCI_RD_TG_TG_RDDATA2_WAIT);
	p->mp_fld_pci_rd_tg_wrap =
		nthw_register_get_field(p->mp_reg_pci_rd_tg_rd_data2, PCI_RD_TG_TG_RDDATA2_WRAP);
	/* optional VF host id */
	p->mp_fld_pci_rd_tg_req_hid = nthw_register_query_field(p->mp_reg_pci_rd_tg_rd_data2,
			PCI_RD_TG_TG_RDDATA2_REQ_HID);

	p->mp_reg_pci_rd_tg_rd_addr =
		nthw_module_get_register(p->mp_mod_pci_rd_tg, PCI_RD_TG_TG_RDADDR);
	p->mp_fld_pci_rd_tg_ram_addr =
		nthw_register_get_field(p->mp_reg_pci_rd_tg_rd_addr, PCI_RD_TG_TG_RDADDR_RAM_ADDR);

	p->mp_reg_pci_rd_tg_rd_run =
		nthw_module_get_register(p->mp_mod_pci_rd_tg, PCI_RD_TG_TG_RD_RUN);
	p->mp_fld_pci_rd_tg_run_iteration =
		nthw_register_get_field(p->mp_reg_pci_rd_tg_rd_run,
			PCI_RD_TG_TG_RD_RUN_RD_ITERATION);

	p->mp_reg_pci_rd_tg_rd_ctrl =
		nthw_module_get_register(p->mp_mod_pci_rd_tg, PCI_RD_TG_TG_CTRL);
	p->mp_fld_pci_rd_tg_ctrl_rdy =
		nthw_register_get_field(p->mp_reg_pci_rd_tg_rd_ctrl, PCI_RD_TG_TG_CTRL_TG_RD_RDY);

	return 0;
}

void nthw_pci_rd_tg_set_phys_addr(nthw_pci_rd_tg_t *p, uint64_t n_phys_addr)
{
	nthw_field_set_val_flush32(p->mp_fld_pci_rd_tg_phys_addr_low,
		(uint32_t)(n_phys_addr & ((1UL << 32) - 1)));
	nthw_field_set_val_flush32(p->mp_fld_pci_rd_tg_phys_addr_high,
		(uint32_t)((n_phys_addr >> 32) & ((1UL << 32) - 1)));
}

void nthw_pci_rd_tg_set_ram_addr(nthw_pci_rd_tg_t *p, int n_ram_addr)
{
	nthw_field_set_val_flush32(p->mp_fld_pci_rd_tg_ram_addr, n_ram_addr);
}

void nthw_pci_rd_tg_set_ram_data(nthw_pci_rd_tg_t *p, uint32_t req_size, bool wait, bool wrap)
{
	nthw_field_set_val32(p->mp_fld_pci_rd_tg_req_size, req_size);
	nthw_field_set_val32(p->mp_fld_pci_rd_tg_wait, wait);
	nthw_field_set_val32(p->mp_fld_pci_rd_tg_wrap, wrap);
	nthw_field_flush_register(p->mp_fld_pci_rd_tg_wrap);
}

void nthw_pci_rd_tg_set_run(nthw_pci_rd_tg_t *p, int n_iterations)
{
	nthw_field_set_val_flush32(p->mp_fld_pci_rd_tg_run_iteration, n_iterations);
}

uint32_t nthw_pci_rd_tg_get_ctrl_rdy(nthw_pci_rd_tg_t *p)
{
	return nthw_field_get_updated(p->mp_fld_pci_rd_tg_ctrl_rdy);
}
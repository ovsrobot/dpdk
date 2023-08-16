/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __NTHW_RAC_H__
#define __NTHW_RAC_H__

#include "nt_util.h"
#include "nthw_bus.h"

struct nthw_rac {
	nt_fpga_t *mp_fpga;
	nt_module_t *mp_mod_rac;

	pthread_mutex_t m_mutex;

	int mn_param_rac_rab_interfaces;
	int mn_param_rac_rab_ob_update;

	nt_register_t *mp_reg_dummy0;
	nt_register_t *mp_reg_dummy1;
	nt_register_t *mp_reg_dummy2;

	nt_register_t *mp_reg_rab_init;
	nt_field_t *mp_fld_rab_init;

	int mn_fld_rab_init_bw;
	uint32_t mn_fld_rab_init_mask;

	nt_register_t *mp_reg_dbg_ctrl;
	nt_field_t *mp_fld_dbg_ctrl;

	nt_register_t *mp_reg_dbg_data;
	nt_field_t *mp_fld_dbg_data;

	nt_register_t *mp_reg_rab_ib_data;
	nt_field_t *mp_fld_rab_ib_data;

	nt_register_t *mp_reg_rab_ob_data;
	nt_field_t *mp_fld_rab_ob_data;

	nt_register_t *mp_reg_rab_buf_free;
	nt_field_t *mp_fld_rab_buf_free_ib_free;
	nt_field_t *mp_fld_rab_buf_free_ib_ovf;
	nt_field_t *mp_fld_rab_buf_free_ob_free;
	nt_field_t *mp_fld_rab_buf_free_ob_ovf;
	nt_field_t *mp_fld_rab_buf_free_timeout;

	nt_register_t *mp_reg_rab_buf_used;
	nt_field_t *mp_fld_rab_buf_used_ib_used;
	nt_field_t *mp_fld_rab_buf_used_ob_used;
	nt_field_t *mp_fld_rab_buf_used_flush;

	nt_register_t *mp_reg_rab_dma_ib_lo;
	nt_field_t *mp_fld_rab_dma_ib_lo_phy_addr;

	nt_register_t *mp_reg_rab_dma_ib_hi;
	nt_field_t *mp_fld_rab_dma_ib_hi_phy_addr;

	nt_register_t *mp_reg_rab_dma_ob_hi;
	nt_field_t *mp_fld_rab_dma_ob_hi_phy_addr;

	nt_register_t *mp_reg_rab_dma_ob_lo;
	nt_field_t *mp_fld_rab_dma_ob_lo_phy_addr;

	nt_register_t *mp_reg_rab_dma_ib_wr;
	nt_field_t *mp_fld_rab_dma_ib_wr_ptr;

	nt_register_t *mp_reg_rab_dma_ib_rd;
	nt_field_t *mp_fld_rab_dma_ib_rd_ptr;

	nt_register_t *mp_reg_rab_dma_ob_wr;
	nt_field_t *mp_fld_rab_dma_ob_wr_ptr;

	nt_register_t *mp_reg_rab_nmb_rd;
	nt_register_t *mp_reg_rab_nmb_data;
	nt_register_t *mp_reg_rab_nmb_wr;
	nt_register_t *mp_reg_rab_nmb_status;

	uint32_t rac_rab_init_addr;
	uint32_t rac_rab_ib_data_addr;
	uint32_t rac_rab_ob_data_addr;
	uint32_t rac_rab_buf_free_addr;
	uint32_t rac_rab_buf_used_addr;

	uint32_t rac_rab_dma_ib_lo_addr;
	uint32_t rac_rab_dma_ib_hi_addr;
	uint32_t rac_rab_dma_ob_lo_addr;
	uint32_t rac_rab_dma_ob_hi_addr;
	uint32_t rac_rab_dma_ib_rd_addr;
	uint32_t rac_rab_dma_ob_wr_addr;
	uint32_t rac_rab_dma_ib_wr_addr;

	uint32_t rac_rab_buf_free_ib_free_mask;
	uint32_t rac_rab_buf_free_ob_free_mask;
	uint32_t rac_rab_buf_used_ib_used_mask;
	uint32_t rac_rab_buf_used_ob_used_mask;
	uint32_t rac_rab_buf_used_flush_mask;

	uint32_t rac_rab_buf_used_ob_used_low;

	uint32_t rac_nmb_rd_adr_addr;
	uint32_t rac_nmb_data_addr;
	uint32_t rac_nmb_wr_adr_addr;
	uint32_t rac_nmb_status_addr;

	bool m_dma_active;

	struct nt_dma_s *m_dma;

	volatile uint32_t *m_dma_in_buf;
	volatile uint32_t *m_dma_out_buf;

	uint16_t m_dma_out_ptr_rd;
	uint16_t m_dma_in_ptr_wr;
	uint32_t m_in_free;
};

typedef struct nthw_rac nthw_rac_t;
typedef struct nthw_rac nthw_rac;

struct dma_buf_ptr {
	uint32_t size;
	uint32_t index;
	volatile uint32_t *base;
};

nthw_rac_t *nthw_rac_new(void);
void nthw_rac_delete(nthw_rac_t *p);
int nthw_rac_init(nthw_rac_t *p, nt_fpga_t *p_fpga, struct fpga_info_s *p_fpga_info);

int nthw_rac_get_rab_interface_count(const nthw_rac_t *p);

int nthw_rac_rab_init(nthw_rac_t *p, uint32_t rab_intf_mask);

int nthw_rac_rab_setup(nthw_rac_t *p);

int nthw_rac_rab_reset(nthw_rac_t *p);

int nthw_rac_rab_write32(nthw_rac_t *p, uint32_t address, rab_bus_id_t bus_id,
			uint32_t word_cnt, const uint32_t *p_data);
int nthw_rac_rab_write32_dma(nthw_rac_t *p, uint32_t address, rab_bus_id_t bus_id,
			    uint32_t word_cnt, const uint32_t *p_data);
int nthw_rac_rab_read32(nthw_rac_t *p, uint32_t address, rab_bus_id_t bus_id,
		       uint32_t word_cnt, uint32_t *p_data);
int nthw_rac_rab_read32_dma(nthw_rac_t *p, uint32_t address, rab_bus_id_t bus_id,
			   uint32_t word_cnt, struct dma_buf_ptr *buf_ptr);

int nthw_rac_rab_flush(nthw_rac_t *p);

int nthw_rac_rab_dma_begin(nthw_rac_t *p);
int nthw_rac_rab_dma_commit(nthw_rac_t *p);

void nthw_rac_reg_read32(const struct fpga_info_s *p_fpga_info, uint32_t reg_addr,
		       uint32_t *p_data);
void nthw_rac_reg_write32(const struct fpga_info_s *p_fpga_info, uint32_t reg_addr,
			uint32_t p_data);

#endif /* __NTHW_RAC_H__ */

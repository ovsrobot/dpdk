/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __NTHW_FPGA_H__
#define __NTHW_FPGA_H__

#include "nthw_drv.h"

#include "nthw_fpga_model.h"

#include "nthw_rac.h"
#include "nthw_iic.h"

#include "nthw_stat.h"

#include "nthw_fpga_rst.h"

#include "nthw_fpga_nt200a0x.h"

#include "nthw_dbs.h"

int nthw_fpga_init(struct fpga_info_s *p_fpga_info);
int nthw_fpga_shutdown(struct fpga_info_s *p_fpga_info);

int nthw_fpga_get_param_info(struct fpga_info_s *p_fpga_info, nt_fpga_t *p_fpga);

int nthw_fpga_avr_probe(nt_fpga_t *p_fpga, const int n_instance_no);

int nthw_fpga_iic_scan(nt_fpga_t *p_fpga, const int n_instance_no_begin,
		       const int n_instance_no_end);

int nthw_fpga_iic_read_byte(nt_fpga_t *p_fpga, const int n_instance_no,
			    const uint8_t n_dev_addr, const uint8_t n_reg_addr);
int nthw_fpga_iic_write_byte(nt_fpga_t *p_fpga, const int n_instance_no,
			     const uint8_t n_dev_addr, const uint8_t n_reg_addr,
			     uint8_t val);

int nthw_fpga_silabs_detect(nt_fpga_t *p_fpga, const int n_instance_no,
			    const int n_dev_addr, const int n_page_reg_addr);

int nthw_fpga_si5340_clock_synth_init_fmt2(nt_fpga_t *p_fpga,
	const uint8_t n_iic_addr,
	const clk_profile_data_fmt2_t *p_clk_profile,
	const int n_clk_profile_rec_cnt);

#endif /* __NTHW_FPGA_H__ */

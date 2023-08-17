/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __NTHW_FPGA_NT200A0X_H__
#define __NTHW_FPGA_NT200A0X_H__

int nthw_fpga_nt200a0x_init(struct fpga_info_s *p_fpga_info);

/* NT200A02: 9563 */
int nthw_fpga_rst9563_init(struct fpga_info_s *p_fpga_info,
			  struct nthw_fpga_rst_nt200a0x *const p);

#endif /* __NTHW_FPGA_NT200A0X_H__ */

/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __NTHW_PROFILE_H__
#define __NTHW_PROFILE_H__

enum fpga_info_profile {
	FPGA_INFO_PROFILE_UNKNOWN = 0,
	FPGA_INFO_PROFILE_VSWITCH = 1,
	FPGA_INFO_PROFILE_INLINE = 2,
	FPGA_INFO_PROFILE_CAPTURE = 3,
};

#endif	/* __NTHW_PROFILE_H__ */

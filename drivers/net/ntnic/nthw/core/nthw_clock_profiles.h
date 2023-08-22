/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __NTHW_CLOCK_PROFILES_H__
#define __NTHW_CLOCK_PROFILES_H__

#include <stdint.h>

#include "nthw_helper.h"

#define clk_profile_size_error_msg "size test failed"

typedef struct {
	unsigned char reg_addr;
	unsigned char reg_val;
	unsigned char reg_mask;
} clk_profile_data_fmt0_t;

typedef struct {
	uint16_t reg_addr;
	uint8_t reg_val;
} clk_profile_data_fmt1_t;

typedef struct {
	unsigned int reg_addr;
	unsigned char reg_val;
} clk_profile_data_fmt2_t;

typedef enum {
	CLK_PROFILE_DATA_FMT_0,
	CLK_PROFILE_DATA_FMT_1,
	CLK_PROFILE_DATA_FMT_2
} clk_profile_data_fmt_t;

extern const int n_data_si5340_nt200a02_u23_v5;
extern const  clk_profile_data_fmt2_t *p_data_si5340_nt200a02_u23_v5;

#endif /* __NTHW_CLOCK_PROFILES_H__ */

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "nthw_clock_profiles.h"

/* Clock profile for NT200A02 2x40G, 2x100G */
#define si5340_revd_register_t type_si5340_nt200a02_u23_v5
#define si5340_revd_registers data_si5340_nt200a02_u23_v5
#include "nthw_nt200a02_u23_si5340_v5.h"
const int n_data_si5340_nt200a02_u23_v5 = SI5340_REVD_REG_CONFIG_NUM_REGS;
const clk_profile_data_fmt2_t *p_data_si5340_nt200a02_u23_v5 =
	(const clk_profile_data_fmt2_t *)&data_si5340_nt200a02_u23_v5[0];
#undef si5340_revd_registers
#undef si5340_revd_register_t
#undef SI5340_REVD_REG_CONFIG_HEADER /*Disable the include once protection */

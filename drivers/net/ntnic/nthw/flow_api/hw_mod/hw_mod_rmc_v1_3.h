/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _HW_MOD_RMC_V1_3_H_
#define _HW_MOD_RMC_V1_3_H_

struct rmc_v1_3_ctrl_s {
	uint32_t block_statt;
	uint32_t block_keepa;
	uint32_t block_rpp_slice;
	uint32_t block_mac_port;
	uint32_t lag_phy_odd_even;
};

struct hw_mod_rmc_v1_3_s {
	struct rmc_v1_3_ctrl_s *ctrl;
};

#endif /* _HW_MOD_RMC_V1_3_H_ */

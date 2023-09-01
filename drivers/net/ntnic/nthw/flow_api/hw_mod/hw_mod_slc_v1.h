/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _HW_MOD_SLC_V1_H_
#define _HW_MOD_SLC_V1_H_

struct slc_v1_rcp_s {
	uint32_t tail_slc_en;
	uint32_t tail_dyn;
	int32_t tail_ofs;
	uint32_t pcap;
};

struct hw_mod_slc_v1_s {
	struct slc_v1_rcp_s *rcp;
};

#endif /* _HW_MOD_SLC_V1_H_ */

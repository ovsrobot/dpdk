/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _HW_MOD_BACKEND_H_
#define _HW_MOD_BACKEND_H_

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "ntlog.h"

#ifdef __cplusplus
extern "C" {
#endif

#define COMMON_FUNC_INFO_S                                                                        \
	int ver;                                                                                  \
	void *base;                                                                               \
	unsigned int alloced_size;                                                                \
	int debug

struct common_func_s {
	COMMON_FUNC_INFO_S;
};

struct flm_func_s {
	COMMON_FUNC_INFO_S;
	uint32_t nb_categories;
	uint32_t nb_size_mb;
	uint32_t nb_entry_size;
	uint32_t nb_variant;
	uint32_t nb_prios;
	uint32_t nb_pst_profiles;
	uint32_t nb_scrub_profiles;
	uint32_t nb_rpp_clock_in_ps;
	uint32_t nb_load_aps_max;
};

struct tpe_func_s {
	COMMON_FUNC_INFO_S;
	uint32_t nb_rcp_categories;
	uint32_t nb_ifr_categories;
	uint32_t nb_cpy_writers;
	uint32_t nb_rpl_depth;
	uint32_t nb_rpl_ext_categories;
};

struct flow_api_backend_s {
	void *be_dev;
	/* flow filter FPGA modules */
	struct flm_func_s flm;
	struct tpe_func_s tpe;

	/* NIC attributes */
	unsigned int num_phy_ports;
	unsigned int num_rx_ports;

	/* flow filter resource capacities */
	unsigned int max_categories;
	unsigned int max_queues;
};

#ifdef __cplusplus
}
#endif

#endif	/* _HW_MOD_BACKEND_H_ */

/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __NTOS_SYSTEM_H__
#define __NTOS_SYSTEM_H__

#include "include/ntdrv_4ga.h"

/*
 * struct drv_s for DPDK (clone of kernel struct)
 * keep it as close as possible to original kernel struct
 */
struct drv_s {
	int adapter_no;
	struct rte_pci_device *p_dev;
	struct ntdrv_4ga_s ntdrv;

	int n_eth_dev_init_count;
	int probe_finished;
	int setup_finished;
};

#endif	/* __NTOS_SYSTEM_H__ */
/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __NTNIC_ETHDEV_H__
#define __NTNIC_ETHDEV_H__

#include <rte_ether.h>
#include <rte_version.h>/* RTE_VERSION, RTE_VERSION_NUM */
#include <rte_mbuf.h>
#include <rte_pci.h>
#include <ethdev_pci.h>

#include "ntos_drv.h"
#include "ntos_system.h"
#include "ntoss_virt_queue.h"
#include "ntnic_stat.h"
#include "nt_util.h"
#include "stream_binary_flow_api.h"

/* Total max ports per NT NFV NIC */
#define MAX_NTNIC_PORTS 2

/* Functions: */
struct drv_s *get_pdrv(uint8_t adapter_no);

extern uint64_t rte_tsc_freq;
extern rte_spinlock_t hwlock;


#endif	/* __NTNIC_ETHDEV_H__ */

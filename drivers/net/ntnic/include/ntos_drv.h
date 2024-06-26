/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __NTOS_DRV_H__
#define __NTOS_DRV_H__

#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>

#include <rte_ether.h>

#include "nthw_drv.h"

#define NUM_MAC_ADDRS_PER_PORT (16U)
#define NUM_MULTICAST_ADDRS_PER_PORT (16U)

#define NUM_ADAPTER_MAX (8)
#define NUM_ADAPTER_PORTS_MAX (128)

struct pmd_internals {
	const struct rte_pci_device *pci_dev;
	char name[20];
	int n_intf_no;
	int if_index;
	int lpbk_mode;
	uint8_t ts_multiplier;
	uint16_t min_tx_pkt_size;
	uint16_t max_tx_pkt_size;
	unsigned int nb_rx_queues;
	unsigned int nb_tx_queues;
	uint32_t port;
	uint32_t port_id;
	/* Offset of the VF from the PF */
	uint8_t vf_offset;
	nt_meta_port_type_t type;
	/* if a virtual port type - the vhid */
	int vhid;
	struct drv_s *p_drv;
	/* Ethernet (MAC) addresses. Element number zero denotes default address. */
	struct rte_ether_addr eth_addrs[NUM_MAC_ADDRS_PER_PORT];
	/* Multicast ethernet (MAC) addresses. */
	struct rte_ether_addr mc_addrs[NUM_MULTICAST_ADDRS_PER_PORT];
	struct pmd_internals *next;
};

#endif	/* __NTOS_DRV_H__ */

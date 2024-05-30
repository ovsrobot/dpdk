/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __NTOS_DRV_H__
#define __NTOS_DRV_H__

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

#include <rte_version.h>/* RTE_VERSION, RTE_VERSION_NUM */
#include <rte_mtr_driver.h>

#include "stream_binary_flow_api.h"
#include "nthw_drv.h"
#include "nthw_profile.h"

#define NUM_MAC_ADDRS_PER_PORT (16U)
#define NUM_MULTICAST_ADDRS_PER_PORT (16U)

/* Max RSS queues */
#define MAX_QUEUES 125

/* Structs: */
#define SG_HDR_SIZE 12

struct _pkt_hdr_rx {
	uint32_t cap_len : 14;
	uint32_t fid : 10;
	uint32_t ofs1 : 8;
	uint32_t ip_prot : 8;
	uint32_t port : 13;
	uint32_t descr : 8;
	uint32_t descr_12b : 1;
	uint32_t color_type : 2;
	uint32_t color : 32;
};

struct _pkt_hdr_tx {
	uint32_t cap_len : 14;
	uint32_t lso_cso0 : 9;
	uint32_t lso_cso1 : 9;
	uint32_t lso_cso2 : 8;
	/* all 1's : use implicit in-port. 0-127 queue index. 0x80 + phy-port to phy */
	uint32_t bypass_port : 13;
	uint32_t descr : 8;
	uint32_t descr_12b : 1;
	uint32_t color_type : 2;
	uint32_t color : 32;
};

/* Total max ports per NT NFV NIC */
#define MAX_NTNIC_PORTS 2

/* Total max VDPA ports */
#define MAX_VDPA_PORTS 128UL

struct nthw_memory_descriptor {
	void *phys_addr;
	void *virt_addr;
	uint32_t len;
};

struct hwq_s {
	int vf_num;
	struct nthw_memory_descriptor virt_queues_ctrl;
	struct nthw_memory_descriptor *pkt_buffers;
};

struct ntnic_rx_queue {
	struct flow_queue_id_s queue;	/* queue info - user id and hw queue index */

	struct rte_mempool *mb_pool;	/* mbuf memory pool */
	uint16_t buf_size;	/* Size of data area in mbuf */
	unsigned long rx_pkts;	/* Rx packet statistics */
	unsigned long rx_bytes;	/* Rx bytes statistics */
	unsigned long err_pkts;	/* Rx error packet statistics */
	int enabled;	/* Enabling/disabling of this queue */

	struct hwq_s hwq;
	struct nthw_virt_queue *vq;
	int nb_hw_rx_descr;
	nt_meta_port_type_t type;
	uint32_t port;	/* Rx port for this queue */
	enum fpga_info_profile profile;	/* Vswitch / Inline / Capture */

} __rte_cache_aligned;

struct ntnic_tx_queue {
	struct flow_queue_id_s queue;	/* queue info - user id and hw queue index */
	struct hwq_s hwq;
	struct nthw_virt_queue *vq;
	int nb_hw_tx_descr;
	/* Used for bypass in NTDVIO0 header on  Tx - pre calculated */
	int target_id;
	nt_meta_port_type_t type;
	/* only used for exception tx queue from OVS SW switching */
	int rss_target_id;

	uint32_t port;	/* Tx port for this queue */
	unsigned long tx_pkts;	/* Tx packet statistics */
	unsigned long tx_bytes;	/* Tx bytes statistics */
	unsigned long err_pkts;	/* Tx error packet stat */
	int enabled;	/* Enabling/disabling of this queue */
	enum fpga_info_profile profile;	/* Vswitch / Inline / Capture */
} __rte_cache_aligned;

struct nt_mtr_profile {
	LIST_ENTRY(nt_mtr_profile) next;
	uint32_t profile_id;
	struct rte_mtr_meter_profile profile;
};

struct nt_mtr {
	LIST_ENTRY(nt_mtr) next;
	uint32_t mtr_id;
	int shared;
	struct nt_mtr_profile *profile;
};

enum virt_port_comm {
	VIRT_PORT_NEGOTIATED_NONE,
	VIRT_PORT_NEGOTIATED_SPLIT,
	VIRT_PORT_NEGOTIATED_PACKED,
	VIRT_PORT_USE_RELAY
};

struct pmd_internals {
	const struct rte_pci_device *pci_dev;

	struct flow_eth_dev *flw_dev;

	char name[20];
	char vhost_path[MAX_PATH_LEN];

	int n_intf_no;
	int if_index;

	int lpbk_mode;

	uint8_t ts_multiplier;
	uint16_t min_tx_pkt_size;
	uint16_t max_tx_pkt_size;

	unsigned int nb_rx_queues;	/* Number of Rx queues configured */
	unsigned int nb_tx_queues;	/* Number of Tx queues configured */
	uint32_t port;
	uint32_t port_id;
	uint8_t vf_offset;	/* Offset of the VF from the PF */

	nt_meta_port_type_t type;
	struct flow_queue_id_s vpq[MAX_QUEUES];
	unsigned int vpq_nb_vq;
	int vhid;	/* if a virtual port type - the vhid */
	enum virt_port_comm vport_comm;	/* link and how split,packed,relay */
	uint32_t vlan;

	struct ntnic_rx_queue rxq_scg[MAX_QUEUES];	/* Array of Rx queues */
	struct ntnic_tx_queue txq_scg[MAX_QUEUES];	/* Array of Tx queues */

	struct drv_s *p_drv;
	/* Ethernet (MAC) addresses. Element number zero denotes default address. */
	struct rte_ether_addr eth_addrs[NUM_MAC_ADDRS_PER_PORT];
	/* Multicast ethernet (MAC) addresses. */
	struct rte_ether_addr mc_addrs[NUM_MULTICAST_ADDRS_PER_PORT];

	LIST_HEAD(_profiles, nt_mtr_profile) mtr_profiles;
	LIST_HEAD(_mtrs, nt_mtr) mtrs;

	uint64_t last_stat_rtc;
	uint64_t rx_missed;

	struct pmd_internals *next;
};

#endif	/* __NTOS_DRV_H__ */

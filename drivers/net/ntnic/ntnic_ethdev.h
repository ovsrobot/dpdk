/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __NTNIC_ETHDEV_H__
#define __NTNIC_ETHDEV_H__

#include <stdatomic.h>

#include <rte_ether.h>
#include <rte_version.h> /* RTE_VERSION, RTE_VERSION_NUM */
#include <rte_mtr_driver.h>
#include <rte_mbuf.h>
#include <rte_pci.h>
#include <ethdev_pci.h>

#include "ntos_system.h"
#include "ntnic_dbsconfig.h"
#include "stream_binary_flow_api.h"

#if (RTE_VERSION_NUM(22, 07, 0, 0) <= RTE_VERSION)
#undef ETH_LINK_HALF_DUPLEX
#undef ETH_LINK_FULL_DUPLEX
#undef ETH_LINK_DOWN
#undef ETH_LINK_UP
#undef ETH_LINK_FIXED
#undef ETH_LINK_AUTONEG
#undef ETH_SPEED_NUM_NONE
#undef ETH_SPEED_NUM_10M
#undef ETH_SPEED_NUM_100M
#undef ETH_SPEED_NUM_1G
#undef ETH_SPEED_NUM_2_5G
#undef ETH_SPEED_NUM_5G
#undef ETH_SPEED_NUM_10G
#undef ETH_SPEED_NUM_20G
#undef ETH_SPEED_NUM_25G
#undef ETH_SPEED_NUM_40G
#undef ETH_SPEED_NUM_50G
#undef ETH_SPEED_NUM_56G
#undef ETH_SPEED_NUM_100G
#undef ETH_SPEED_NUM_200G
#undef ETH_SPEED_NUM_UNKNOWN
#undef ETH_LINK_SPEED_AUTONEG
#undef ETH_LINK_SPEED_FIXED
#undef ETH_LINK_SPEED_10M_HD
#undef ETH_LINK_SPEED_10M
#undef ETH_LINK_SPEED_100M_HD
#undef ETH_LINK_SPEED_100M
#undef ETH_LINK_SPEED_1G
#undef ETH_LINK_SPEED_2_5G
#undef ETH_LINK_SPEED_5G
#undef ETH_LINK_SPEED_10G
#undef ETH_LINK_SPEED_20G
#undef ETH_LINK_SPEED_25G
#undef ETH_LINK_SPEED_40G
#undef ETH_LINK_SPEED_50G
#undef ETH_LINK_SPEED_56G
#undef ETH_LINK_SPEED_100G
#undef ETH_LINK_SPEED_200G
#undef ETH_RSS_IP
#undef ETH_RSS_UDP
#undef ETH_RSS_TCP
#undef ETH_RSS_SCTP
#define ETH_LINK_HALF_DUPLEX RTE_ETH_LINK_HALF_DUPLEX
#define ETH_LINK_FULL_DUPLEX RTE_ETH_LINK_FULL_DUPLEX
#define ETH_LINK_DOWN RTE_ETH_LINK_DOWN
#define ETH_LINK_UP RTE_ETH_LINK_UP
#define ETH_LINK_FIXED RTE_ETH_LINK_FIXED
#define ETH_LINK_AUTONEG RTE_ETH_LINK_AUTONEG
#define ETH_SPEED_NUM_NONE RTE_ETH_SPEED_NUM_NONE
#define ETH_SPEED_NUM_10M RTE_ETH_SPEED_NUM_10M
#define ETH_SPEED_NUM_100M RTE_ETH_SPEED_NUM_100M
#define ETH_SPEED_NUM_1G RTE_ETH_SPEED_NUM_1G
#define ETH_SPEED_NUM_2_5G RTE_ETH_SPEED_NUM_2_5G
#define ETH_SPEED_NUM_5G RTE_ETH_SPEED_NUM_5G
#define ETH_SPEED_NUM_10G RTE_ETH_SPEED_NUM_10G
#define ETH_SPEED_NUM_20G RTE_ETH_SPEED_NUM_20G
#define ETH_SPEED_NUM_25G RTE_ETH_SPEED_NUM_25G
#define ETH_SPEED_NUM_40G RTE_ETH_SPEED_NUM_40G
#define ETH_SPEED_NUM_50G RTE_ETH_SPEED_NUM_50G
#define ETH_SPEED_NUM_56G RTE_ETH_SPEED_NUM_56G
#define ETH_SPEED_NUM_100G RTE_ETH_SPEED_NUM_100G
#define ETH_SPEED_NUM_200G RTE_ETH_SPEED_NUM_200G
#define ETH_SPEED_NUM_UNKNOWN RTE_ETH_SPEED_NUM_UNKNOWN
#define ETH_LINK_SPEED_AUTONEG RTE_ETH_LINK_SPEED_AUTONEG
#define ETH_LINK_SPEED_FIXED RTE_ETH_LINK_SPEED_FIXED
#define ETH_LINK_SPEED_10M_HD RTE_ETH_LINK_SPEED_10M_HD
#define ETH_LINK_SPEED_10M RTE_ETH_LINK_SPEED_10M
#define ETH_LINK_SPEED_100M_HD RTE_ETH_LINK_SPEED_100M_HD
#define ETH_LINK_SPEED_100M RTE_ETH_LINK_SPEED_100M
#define ETH_LINK_SPEED_1G RTE_ETH_LINK_SPEED_1G
#define ETH_LINK_SPEED_2_5G RTE_ETH_LINK_SPEED_2_5G
#define ETH_LINK_SPEED_5G RTE_ETH_LINK_SPEED_5G
#define ETH_LINK_SPEED_10G RTE_ETH_LINK_SPEED_10G
#define ETH_LINK_SPEED_20G RTE_ETH_LINK_SPEED_20G
#define ETH_LINK_SPEED_25G RTE_ETH_LINK_SPEED_25G
#define ETH_LINK_SPEED_40G RTE_ETH_LINK_SPEED_40G
#define ETH_LINK_SPEED_50G RTE_ETH_LINK_SPEED_50G
#define ETH_LINK_SPEED_56G RTE_ETH_LINK_SPEED_56G
#define ETH_LINK_SPEED_100G RTE_ETH_LINK_SPEED_100G
#define ETH_LINK_SPEED_200G RTE_ETH_LINK_SPEED_200G
#define ETH_RSS_IP RTE_ETH_RSS_IP
#define ETH_RSS_UDP RTE_ETH_RSS_UDP
#define ETH_RSS_TCP RTE_ETH_RSS_TCP
#define ETH_RSS_SCTP RTE_ETH_RSS_SCTP
#define ETH_RSS_IPV4 RTE_ETH_RSS_IPV4
#define ETH_RSS_FRAG_IPV4 RTE_ETH_RSS_FRAG_IPV4
#define ETH_RSS_NONFRAG_IPV4_OTHER RTE_ETH_RSS_NONFRAG_IPV4_OTHER
#define ETH_RSS_IPV6 RTE_ETH_RSS_IPV6
#define ETH_RSS_FRAG_IPV6 RTE_ETH_RSS_FRAG_IPV6
#define ETH_RSS_NONFRAG_IPV6_OTHER RTE_ETH_RSS_NONFRAG_IPV6_OTHER
#define ETH_RSS_IPV6_EX RTE_ETH_RSS_IPV6_EX
#define ETH_RSS_C_VLAN RTE_ETH_RSS_C_VLAN
#define ETH_RSS_L3_DST_ONLY RTE_ETH_RSS_L3_DST_ONLY
#define ETH_RSS_L3_SRC_ONLY RTE_ETH_RSS_L3_SRC_ONLY
#endif

#define NUM_MAC_ADDRS_PER_PORT (16U)
#define NUM_MULTICAST_ADDRS_PER_PORT (16U)

#define MAX_FPGA_VIRTUAL_PORTS_SUPPORTED 256

/* Total max ports per NT NFV NIC */
#define MAX_NTNIC_PORTS 2

/* Max RSS queues */
#define MAX_QUEUES 125

#define SG_NB_HW_RX_DESCRIPTORS 1024
#define SG_NB_HW_TX_DESCRIPTORS 1024
#define SG_HW_RX_PKT_BUFFER_SIZE (1024 << 1)
#define SG_HW_TX_PKT_BUFFER_SIZE (1024 << 1)

#define SG_HDR_SIZE 12

/* VQ buffers needed to fit all data in packet + header */
#define NUM_VQ_SEGS(_data_size_) \
	({ \
		size_t _size = (_data_size_); \
		size_t _segment_count = ((_size + SG_HDR_SIZE) > SG_HW_TX_PKT_BUFFER_SIZE) ? \
		(((_size + SG_HDR_SIZE) + SG_HW_TX_PKT_BUFFER_SIZE - 1) / \
		SG_HW_TX_PKT_BUFFER_SIZE) : 1; \
		_segment_count; \
	})


#define VIRTQ_DESCR_IDX(_tx_pkt_idx_) \
	(((_tx_pkt_idx_) + first_vq_descr_idx) % SG_NB_HW_TX_DESCRIPTORS)

#define VIRTQ_DESCR_IDX_NEXT(_vq_descr_idx_) \
	(((_vq_descr_idx_) + 1) % SG_NB_HW_TX_DESCRIPTORS)

#define MAX_REL_VQS 128

/* Functions: */
struct pmd_internals *vp_vhid_instance_ready(int vhid);
struct pmd_internals *vp_path_instance_ready(const char *path);
int setup_virtual_pf_representor_base(struct rte_pci_device *dev);
int nthw_create_vf_interface_dpdk(struct rte_pci_device *pci_dev);
int nthw_remove_vf_interface_dpdk(struct rte_pci_device *pci_dev);
nthw_dbs_t *get_pdbs_from_pci(struct rte_pci_addr pci_addr);
enum fpga_info_profile get_fpga_profile_from_pci(struct rte_pci_addr pci_addr);
int register_release_virtqueue_info(struct nthw_virt_queue *vq, int rx,
				    int managed);
int de_register_release_virtqueue_info(struct nthw_virt_queue *vq);
int copy_mbuf_to_virtqueue(struct nthw_cvirtq_desc *cvq_desc,
			   uint16_t vq_descr_idx,
			   struct nthw_memory_descriptor *vq_bufs, int max_segs,
			   struct rte_mbuf *mbuf);

extern int lag_active;
extern uint64_t rte_tsc_freq;
extern rte_spinlock_t hwlock;

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

/* Compile time verification of scatter gather header size. */
typedef char check_sg_pkt_rx_hdr_size
[(sizeof(struct _pkt_hdr_rx) == SG_HDR_SIZE) ? 1 : -1];
typedef char check_sg_pkt_tx_hdr_size
[(sizeof(struct _pkt_hdr_tx) == SG_HDR_SIZE) ? 1 : -1];

typedef void *handle_t;

struct hwq_s {
	int vf_num;
	struct nthw_memory_descriptor virt_queues_ctrl;
	struct nthw_memory_descriptor *pkt_buffers;
};

struct ntnic_rx_queue {
	struct flow_queue_id_s
		queue; /* queue info - user id and hw queue index */

	struct rte_mempool *mb_pool; /* mbuf memory pool */
	uint16_t buf_size; /* size of data area in mbuf */
	unsigned long rx_pkts; /* Rx packet statistics */
	unsigned long rx_bytes; /* Rx bytes statistics */
	unsigned long err_pkts; /* Rx error packet statistics */
	int enabled; /* Enabling/disabling of this queue */

	struct hwq_s hwq;
	struct nthw_virt_queue *vq;
	int nb_hw_rx_descr;
	nt_meta_port_type_t type;
	uint32_t port; /* Rx port for this queue */
	enum fpga_info_profile profile; /* Vswitch / Inline / Capture */

} __rte_cache_aligned;

struct ntnic_tx_queue {
	struct flow_queue_id_s
		queue; /* queue info - user id and hw queue index */
	struct hwq_s hwq;
	struct nthw_virt_queue *vq;
	int nb_hw_tx_descr;
	/* Used for bypass in NTDVIO0 header on  Tx - pre calculated */
	int target_id;
	nt_meta_port_type_t type;
	/* only used for exception tx queue from OVS SW switching */
	int rss_target_id;

	uint32_t port; /* Tx port for this queue */
	unsigned long tx_pkts; /* Tx packet statistics */
	unsigned long tx_bytes; /* Tx bytes statistics */
	unsigned long err_pkts; /* Tx error packet stat */
	int enabled; /* Enabling/disabling of this queue */
	enum fpga_info_profile profile; /* Vswitch / Inline / Capture */
} __rte_cache_aligned;

#define MAX_ARRAY_ENTRIES MAX_QUEUES
struct array_s {
	uint32_t value[MAX_ARRAY_ENTRIES];
	int count;
};

/* Configuerations related to LAG management */
typedef struct {
	uint8_t mode;

	int8_t primary_port;
	int8_t backup_port;

	uint32_t ntpl_rx_id;

	pthread_t lag_tid;
	uint8_t lag_thread_active;

	struct pmd_internals *internals;
} lag_config_t;

#define BONDING_MODE_ACTIVE_BACKUP (1)
#define BONDING_MODE_8023AD (4)
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

#define MAX_PATH_LEN 128

struct pmd_internals {
	const struct rte_pci_device *pci_dev;

	struct flow_eth_dev *flw_dev;

	char name[20];
	char vhost_path[MAX_PATH_LEN];

	int n_intf_no;
	int if_index;

	int lpbk_mode;

	uint8_t nb_ports_on_adapter;
	uint8_t ts_multiplier;
	uint16_t min_tx_pkt_size;
	uint16_t max_tx_pkt_size;

	unsigned int nb_rx_queues; /* Number of Rx queues configured */
	unsigned int nb_tx_queues; /* Number of Tx queues configured */
	uint32_t port;
	uint8_t port_id;

	nt_meta_port_type_t type;
	struct flow_queue_id_s vpq[MAX_QUEUES];
	unsigned int vpq_nb_vq;
	volatile atomic_int vhid; /* if a virtual port type - the vhid */
	enum virt_port_comm vport_comm; /* link and how split,packed,relay */
	uint32_t vlan;

	lag_config_t *lag_config;

	struct ntnic_rx_queue rxq_scg[MAX_QUEUES]; /* Array of Rx queues */
	struct ntnic_tx_queue txq_scg[MAX_QUEUES]; /* Array of Tx queues */

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

void cleanup_flows(struct pmd_internals *internals);
int poll_statistics(struct pmd_internals *internals);
int debug_adapter_show_info(uint32_t pciident, FILE *pfh);

#endif /* __NTNIC_ETHDEV_H__ */

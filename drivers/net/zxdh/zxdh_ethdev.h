/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#ifndef _ZXDH_ETHDEV_H_
#define _ZXDH_ETHDEV_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "ethdev_pci.h"

extern struct zxdh_dtb_shared_data g_dtb_data;
#define PF_PCIE_ID(pcie_id)         ((pcie_id & 0xff00) | 1 << 11)
#define VF_PCIE_ID(pcie_id, vf_idx) ((pcie_id & 0xff00) | (1 << 11) | (vf_idx & 0xff))

#define ZXDH_QUEUES_NUM_MAX          256

/* ZXDH PCI vendor/device ID. */
#define PCI_VENDOR_ID_ZTE        0x1cf2

#define ZXDH_E310_PF_DEVICEID     0x8061
#define ZXDH_E310_VF_DEVICEID     0x8062
#define ZXDH_E312_PF_DEVICEID     0x8049
#define ZXDH_E312_VF_DEVICEID     0x8060

#define ZXDH_MAX_UC_MAC_ADDRS  32
#define ZXDH_MAX_MC_MAC_ADDRS  32
#define ZXDH_MAX_MAC_ADDRS     (ZXDH_MAX_UC_MAC_ADDRS + ZXDH_MAX_MC_MAC_ADDRS)

/* BAR definitions */
#define ZXDH_NUM_BARS    2
#define ZXDH_BAR0_INDEX  0

#define ZXDH_MIN_QUEUE_DEPTH 1024
#define ZXDH_MAX_QUEUE_DEPTH 32768

#define ZXDH_MAX_VF 256

#define ZXDH_TBL_ERAM_DUMP_SIZE  (4 * 1024 * 1024)
#define ZXDH_TBL_ZCAM_DUMP_SIZE  (5 * 1024 * 1024)

#define INVALID_DTBQUE  0xFFFF
#define ZXDH_MAX_BASE_DTB_TABLE_COUNT 30
#define ZXDH_DTB_TABLE_CONF_SIZE  (32 * (16 + 16 * 1024))
#define ZXDH_DTB_TABLE_DUMP_SIZE  (32 * (16 + 16 * 1024))

/*
 * Process  dev config changed interrupt. Call the callback
 * if link state changed, generate gratuitous RARP packet if
 * the status indicates an ANNOUNCE.
 */
#define ZXDH_NET_S_LINK_UP   1 /* Link is up */
#define ZXDH_NET_S_ANNOUNCE  2 /* Announcement is needed */

struct pfinfo {
	uint16_t pcieid;
	uint16_t vf_nums;
};
struct vfinfo {
	uint16_t vf_idx;
	uint16_t pcieid;
	uint16_t vport;
	uint8_t flag;
	uint8_t state;
	uint8_t rsv;
	struct rte_ether_addr mac_addr;
	struct rte_ether_addr vf_mac[ZXDH_MAX_MAC_ADDRS];
};

union VPORT {
	uint16_t vport;

	__extension__
	struct {
		uint16_t vfid:8;
		uint16_t pfid:3;
		uint16_t vf_flag:1;
		uint16_t epid:3;
		uint16_t direct_flag:1;
	};
};

struct chnl_context {
	uint16_t valid;
	uint16_t ph_chno;
}; /* 4B */

struct zxdh_hw {
	uint64_t host_features;
	uint64_t guest_features;
	uint32_t max_queue_pairs;
	uint16_t max_mtu;
	uint8_t  vtnet_hdr_size;
	uint8_t  vlan_strip;
	uint8_t  use_msix;
	uint8_t  intr_enabled;
	uint8_t  started;
	uint8_t  weak_barriers;

	bool has_tx_offload;
	bool has_rx_offload;

	uint8_t  mac_addr[RTE_ETHER_ADDR_LEN];
	uint16_t port_id;

	uint32_t  notify_off_multiplier;
	uint32_t  speed;  /* link speed in MB */
	uint32_t  speed_mode;  /* link speed in 1x 2x 3x */
	uint8_t   duplex;
	uint8_t  *isr;
	uint16_t *notify_base;

	struct zxdh_pci_common_cfg *common_cfg;
	struct zxdh_net_config     *dev_cfg;

	uint16_t queue_num;
	uint16_t device_id;

	uint16_t pcie_id;
	uint8_t  phyport;
	bool     msg_chan_init;

	uint8_t panel_id;
	uint8_t rsv[1];

	/**
	 * App management thread and virtio interrupt handler
	 * thread both can change device state,
	 * this lock is meant to avoid such a contention.
	 */
	rte_spinlock_t     state_lock;
	struct rte_mbuf  **inject_pkts;
	struct virtqueue **vqs;

	uint64_t bar_addr[ZXDH_NUM_BARS];
	struct rte_intr_handle *risc_intr;  /* Interrupt handle of rsic_v to host */
	struct rte_intr_handle *dtb_intr;  /* Interrupt handle of rsic_v to host */

	struct chnl_context channel_context[ZXDH_QUEUES_NUM_MAX];
	union VPORT vport;

	uint8_t is_pf         : 1,
			switchoffload : 1;
	uint8_t hash_search_index;
	uint8_t admin_status;

	uint16_t vfid;
	uint16_t q_depth;
	uint64_t *vlan_fiter;
	struct pfinfo pfinfo;
	struct vfinfo *vfinfo;
	struct rte_eth_dev *eth_dev;
};

/* Shared data between primary and secondary processes. */
struct zxdh_shared_data {
	rte_spinlock_t lock; /* Global spinlock for primary and secondary processes. */
	int init_done;       /* Whether primary has done initialization. */
	unsigned int secondary_cnt; /* Number of secondary processes init'd. */

	int npsdk_init_done;
	uint32_t  dev_refcnt;
	struct zxdh_dtb_shared_data *dtb_data;
};

struct zxdh_dtb_shared_data {
	int init_done;
	char name[32];
	uint16_t queueid;
	uint16_t vport;
	uint32_t vector;
	const struct rte_memzone *dtb_table_conf_mz;
	const struct rte_memzone *dtb_table_dump_mz;
	const struct rte_memzone *dtb_table_bulk_dump_mz[ZXDH_MAX_BASE_DTB_TABLE_COUNT];
	struct rte_eth_dev *bind_device;
	uint32_t dev_refcnt;
};

struct zxdh_dtb_bulk_dump_info {
	const char *mz_name;
	uint32_t mz_size;
	uint32_t sdt_no;        /** <@brief sdt no 0~255 */
	const struct rte_memzone *mz;
};

void zxdh_interrupt_handler(void *param);
int32_t zxdh_dev_pause(struct rte_eth_dev *dev);
void zxdh_dev_resume(struct rte_eth_dev *dev);
int32_t zxdh_inject_pkts(struct rte_eth_dev *dev, struct rte_mbuf **tx_pkts, int32_t nb_pkts);
void zxdh_notify_peers(struct rte_eth_dev *dev);

int32_t zxdh_eth_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
			struct rte_pci_device *pci_dev);
int32_t zxdh_eth_pci_remove(struct rte_pci_device *pci_dev);

#ifdef __cplusplus
}
#endif

#endif /* _ZXDH_ETHDEV_H_ */

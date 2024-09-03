/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#ifndef _ZXDH_PCI_H_
#define _ZXDH_PCI_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <rte_pci.h>
#include <rte_bus_pci.h>
#include <bus_pci_driver.h>
#include <ethdev_driver.h>

#include "zxdh_ethdev.h"

/* The bit of the ISR which indicates a device has an interrupt. */
#define ZXDH_PCI_ISR_INTR    0x1
/* The bit of the ISR which indicates a device configuration change. */
#define ZXDH_PCI_ISR_CONFIG  0x2
/* Vector value used to disable MSI for queue. */
#define ZXDH_MSI_NO_VECTOR   0x7F

/* Status byte for guest to report progress. */
#define ZXDH_CONFIG_STATUS_RESET           0x00
#define ZXDH_CONFIG_STATUS_ACK             0x01
#define ZXDH_CONFIG_STATUS_DRIVER          0x02
#define ZXDH_CONFIG_STATUS_DRIVER_OK       0x04
#define ZXDH_CONFIG_STATUS_FEATURES_OK     0x08
#define ZXDH_CONFIG_STATUS_DEV_NEED_RESET  0x40
#define ZXDH_CONFIG_STATUS_FAILED          0x80

/* The feature bitmap for net */
#define ZXDH_NET_F_CSUM              0   /* Host handles pkts w/ partial csum */
#define ZXDH_NET_F_GUEST_CSUM        1   /* Guest handles pkts w/ partial csum */
#define ZXDH_NET_F_MTU               3   /* Initial MTU advice. */
#define ZXDH_NET_F_MAC               5   /* Host has given MAC address. */
#define ZXDH_NET_F_GUEST_TSO4        7   /* Guest can handle TSOv4 in. */
#define ZXDH_NET_F_GUEST_TSO6        8   /* Guest can handle TSOv6 in. */
#define ZXDH_NET_F_GUEST_ECN         9   /* Guest can handle TSO[6] w/ ECN in. */
#define ZXDH_NET_F_GUEST_UFO         10  /* Guest can handle UFO in. */
#define ZXDH_NET_F_HOST_TSO4         11  /* Host can handle TSOv4 in. */
#define ZXDH_NET_F_HOST_TSO6         12  /* Host can handle TSOv6 in. */
#define ZXDH_NET_F_HOST_ECN          13  /* Host can handle TSO[6] w/ ECN in. */
#define ZXDH_NET_F_HOST_UFO          14  /* Host can handle UFO in. */
#define ZXDH_NET_F_MRG_RXBUF         15  /* Host can merge receive buffers. */
#define ZXDH_NET_F_STATUS            16  /* zxdh_net_config.status available */
#define ZXDH_NET_F_CTRL_VQ           17  /* Control channel available */
#define ZXDH_NET_F_CTRL_RX           18  /* Control channel RX mode support */
#define ZXDH_NET_F_CTRL_VLAN         19  /* Control channel VLAN filtering */
#define ZXDH_NET_F_CTRL_RX_EXTRA     20  /* Extra RX mode control support */
#define ZXDH_NET_F_GUEST_ANNOUNCE    21  /* Guest can announce device on the network */
#define ZXDH_NET_F_MQ                22  /* Device supports Receive Flow Steering */
#define ZXDH_NET_F_CTRL_MAC_ADDR     23  /* Set MAC address */
/* Do we get callbacks when the ring is completely used, even if we've suppressed them? */
#define ZXDH_F_NOTIFY_ON_EMPTY       24
#define ZXDH_F_ANY_LAYOUT            27 /* Can the device handle any descriptor layout? */
#define VIRTIO_RING_F_INDIRECT_DESC  28 /* We support indirect buffer descriptors */
#define ZXDH_F_VERSION_1             32
#define ZXDH_F_IOMMU_PLATFORM        33
#define ZXDH_F_RING_PACKED           34
/* Inorder feature indicates that all buffers are used by the device
 * in the same order in which they have been made available.
 */
#define ZXDH_F_IN_ORDER              35
/** This feature indicates that memory accesses by the driver
 * and the device are ordered in a way described by the platform.
 */
#define ZXDH_F_ORDER_PLATFORM        36
/**
 * This feature indicates that the driver passes extra data
 * (besides identifying the virtqueue) in its device notifications.
 */
#define ZXDH_F_NOTIFICATION_DATA     38
#define ZXDH_NET_F_SPEED_DUPLEX      63 /* Device set linkspeed and duplex */

/* The Guest publishes the used index for which it expects an interrupt
 * at the end of the avail ring. Host should ignore the avail->flags field.
 */
/* The Host publishes the avail index for which it expects a kick
 * at the end of the used ring. Guest should ignore the used->flags field.
 */
#define ZXDH_RING_F_EVENT_IDX                       29

/* Maximum number of virtqueues per device. */
#define ZXDH_MAX_VIRTQUEUE_PAIRS  8
#define ZXDH_MAX_VIRTQUEUES       (ZXDH_MAX_VIRTQUEUE_PAIRS * 2 + 1)


#define ZXDH_PCI_CAP_COMMON_CFG  1 /* Common configuration */
#define ZXDH_PCI_CAP_NOTIFY_CFG  2 /* Notifications */
#define ZXDH_PCI_CAP_ISR_CFG     3 /* ISR Status */
#define ZXDH_PCI_CAP_DEVICE_CFG  4 /* Device specific configuration */
#define ZXDH_PCI_CAP_PCI_CFG     5 /* PCI configuration access */

#define VTPCI_OPS(hw)  (zxdh_hw_internal[(hw)->port_id].vtpci_ops)
#define VTPCI_IO(hw)   (&zxdh_hw_internal[(hw)->port_id].io)

/*
 * How many bits to shift physical queue address written to QUEUE_PFN.
 * 12 is historical, and due to x86 page size.
 */
#define ZXDH_PCI_QUEUE_ADDR_SHIFT                   12

/* The alignment to use between consumer and producer parts of vring. */
#define ZXDH_PCI_VRING_ALIGN                        4096

/******BAR0  SPACE********************************************************************/
#define ZXDH_VQMREG_OFFSET    0x0000
#define ZXDH_FWCAP_OFFSET     0x1000
#define ZXDH_CTRLCH_OFFSET    0x2000
#define ZXDH_MAC_OFFSET       0x24000
#define ZXDH_SPINLOCK_OFFSET  0x4000
#define ZXDH_FWSHRD_OFFSET    0x5000
#define ZXDH_QUERES_SHARE_BASE   (ZXDH_FWSHRD_OFFSET)
#define ZXDH_QUERES_SHARE_SIZE   512

enum zxdh_msix_status {
	ZXDH_MSIX_NONE     = 0,
	ZXDH_MSIX_DISABLED = 1,
	ZXDH_MSIX_ENABLED  = 2
};

static inline int32_t vtpci_with_feature(struct zxdh_hw *hw, uint64_t bit)
{
	return (hw->guest_features & (1ULL << bit)) != 0;
}

static inline int32_t vtpci_packed_queue(struct zxdh_hw *hw)
{
	return vtpci_with_feature(hw, ZXDH_F_RING_PACKED);
}

/*
 * While zxdh_hw is stored in shared memory, this structure stores
 * some infos that may vary in the multiple process model locally.
 * For example, the vtpci_ops pointer.
 */
struct zxdh_hw_internal {
	const struct zxdh_pci_ops *vtpci_ops;
	struct rte_pci_ioport io;
};

/* Fields in ZXDH_PCI_CAP_COMMON_CFG: */
struct zxdh_pci_common_cfg {
	/* About the whole device. */
	uint32_t device_feature_select; /* read-write */
	uint32_t device_feature;    /* read-only */
	uint32_t guest_feature_select;  /* read-write */
	uint32_t guest_feature;     /* read-write */
	uint16_t msix_config;       /* read-write */
	uint16_t num_queues;        /* read-only */
	uint8_t  device_status;     /* read-write */
	uint8_t  config_generation; /* read-only */

	/* About a specific virtqueue. */
	uint16_t queue_select;      /* read-write */
	uint16_t queue_size;        /* read-write, power of 2. */
	uint16_t queue_msix_vector; /* read-write */
	uint16_t queue_enable;      /* read-write */
	uint16_t queue_notify_off;  /* read-only */
	uint32_t queue_desc_lo;     /* read-write */
	uint32_t queue_desc_hi;     /* read-write */
	uint32_t queue_avail_lo;    /* read-write */
	uint32_t queue_avail_hi;    /* read-write */
	uint32_t queue_used_lo;     /* read-write */
	uint32_t queue_used_hi;     /* read-write */
};

/*
 * This structure is just a reference to read
 * net device specific config space; it just a chodu structure
 *
 */
struct zxdh_net_config {
	/* The config defining mac address (if ZXDH_NET_F_MAC) */
	uint8_t    mac[RTE_ETHER_ADDR_LEN];
	/* See ZXDH_NET_F_STATUS and ZXDH_NET_S_* above */
	uint16_t   status;
	uint16_t   max_virtqueue_pairs;
	uint16_t   mtu;
	/*
	 * speed, in units of 1Mb. All values 0 to INT_MAX are legal.
	 * Any other value stands for unknown.
	 */
	uint32_t   speed;
	/* 0x00 - half duplex
	 * 0x01 - full duplex
	 * Any other value stands for unknown.
	 */
	uint8_t    duplex;
} __rte_packed;

/* This is the PCI capability header: */
struct zxdh_pci_cap {
	uint8_t  cap_vndr;   /* Generic PCI field: PCI_CAP_ID_VNDR */
	uint8_t  cap_next;   /* Generic PCI field: next ptr. */
	uint8_t  cap_len;    /* Generic PCI field: capability length */
	uint8_t  cfg_type;   /* Identifies the structure. */
	uint8_t  bar;        /* Where to find it. */
	uint8_t  padding[3]; /* Pad to full dword. */
	uint32_t offset;     /* Offset within bar. */
	uint32_t length;     /* Length of the structure, in bytes. */
};
struct zxdh_pci_notify_cap {
	struct zxdh_pci_cap cap;
	uint32_t notify_off_multiplier;  /* Multiplier for queue_notify_off. */
};

struct zxdh_pci_ops {
	void     (*read_dev_cfg)(struct zxdh_hw *hw, size_t offset, void *dst, int32_t len);
	void     (*write_dev_cfg)(struct zxdh_hw *hw, size_t offset, const void *src, int32_t len);

	uint8_t  (*get_status)(struct zxdh_hw *hw);
	void     (*set_status)(struct zxdh_hw *hw, uint8_t status);

	uint64_t (*get_features)(struct zxdh_hw *hw);
	void     (*set_features)(struct zxdh_hw *hw, uint64_t features);

	uint8_t  (*get_isr)(struct zxdh_hw *hw);

	uint16_t (*set_config_irq)(struct zxdh_hw *hw, uint16_t vec);

	uint16_t (*set_queue_irq)(struct zxdh_hw *hw, struct virtqueue *vq, uint16_t vec);

	uint16_t (*get_queue_num)(struct zxdh_hw *hw, uint16_t queue_id);
	void     (*set_queue_num)(struct zxdh_hw *hw, uint16_t queue_id, uint16_t vq_size);

	int32_t  (*setup_queue)(struct zxdh_hw *hw, struct virtqueue *vq);
	void     (*del_queue)(struct zxdh_hw *hw, struct virtqueue *vq);
	void     (*notify_queue)(struct zxdh_hw *hw, struct virtqueue *vq);
};

extern struct zxdh_hw_internal zxdh_hw_internal[RTE_MAX_ETHPORTS];
extern const struct zxdh_pci_ops zxdh_modern_ops;

void zxdh_vtpci_reset(struct zxdh_hw *hw);
void zxdh_vtpci_reinit_complete(struct zxdh_hw *hw);
uint8_t zxdh_vtpci_get_status(struct zxdh_hw *hw);
void zxdh_vtpci_set_status(struct zxdh_hw *hw, uint8_t status);
uint16_t zxdh_vtpci_get_features(struct zxdh_hw *hw);
void zxdh_vtpci_write_dev_config(struct zxdh_hw *hw, size_t offset,
		const void *src, int32_t length);
void zxdh_vtpci_read_dev_config(struct zxdh_hw *hw, size_t offset,
		void *dst, int32_t length);
uint8_t zxdh_vtpci_isr(struct zxdh_hw *hw);
enum zxdh_msix_status zxdh_vtpci_msix_detect(struct rte_pci_device *dev);

int32_t zxdh_read_pci_caps(struct rte_pci_device *dev, struct zxdh_hw *hw);

#ifdef __cplusplus
}
#endif

#endif /* _ZXDH_PCI_H_ */

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#ifndef _ZXDH_QUEUE_H_
#define _ZXDH_QUEUE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include <rte_common.h>

#include "zxdh_ethdev.h"
#include "zxdh_rxtx.h"

/** ring descriptors: 16 bytes.
 * These can chain together via "next".
 **/
struct vring_desc {
	uint64_t addr;  /*  Address (guest-physical). */
	uint32_t len;   /* Length. */
	uint16_t flags; /* The flags as indicated above. */
	uint16_t next;  /* We chain unused descriptors via this. */
};

struct vring_avail {
	uint16_t flags;
	uint16_t idx;
	uint16_t ring[0];
};

struct vring_packed_desc {
	uint64_t addr;
	uint32_t len;
	uint16_t id;
	uint16_t flags;
};

struct vring_packed_desc_event {
	uint16_t desc_event_off_wrap;
	uint16_t desc_event_flags;
};

struct vring_packed {
	uint32_t num;
	struct vring_packed_desc *desc;
	struct vring_packed_desc_event *driver;
	struct vring_packed_desc_event *device;
};

struct vq_desc_extra {
	void *cookie;
	uint16_t ndescs;
	uint16_t next;
};

struct virtqueue {
	struct zxdh_hw  *hw; /**< zxdh_hw structure pointer. */
	struct {
		/**< vring keeping descs and events */
		struct vring_packed ring;
		uint8_t used_wrap_counter;
		uint8_t rsv;
		uint16_t cached_flags; /**< cached flags for descs */
		uint16_t event_flags_shadow;
		uint16_t rsv1;
	} __rte_packed vq_packed;
	uint16_t vq_used_cons_idx; /**< last consumed descriptor */
	uint16_t vq_nentries;  /**< vring desc numbers */
	uint16_t vq_free_cnt;  /**< num of desc available */
	uint16_t vq_avail_idx; /**< sync until needed */
	uint16_t vq_free_thresh; /**< free threshold */
	uint16_t rsv2;

	void *vq_ring_virt_mem;  /**< linear address of vring*/
	uint32_t vq_ring_size;

	union {
		struct virtnet_rx rxq;
		struct virtnet_tx txq;
	};

	/** < physical address of vring,
	 * or virtual address for virtio_user.
	 **/
	rte_iova_t vq_ring_mem;

	/**
	 * Head of the free chain in the descriptor table. If
	 * there are no free descriptors, this will be set to
	 * VQ_RING_DESC_CHAIN_END.
	 **/
	uint16_t  vq_desc_head_idx;
	uint16_t  vq_desc_tail_idx;
	uint16_t  vq_queue_index;   /**< PCI queue index */
	uint16_t  offset; /**< relative offset to obtain addr in mbuf */
	uint16_t *notify_addr;
	struct rte_mbuf **sw_ring;  /**< RX software ring. */
	struct vq_desc_extra vq_descx[0];
};

#endif /* _ZXDH_QUEUE_H_ */

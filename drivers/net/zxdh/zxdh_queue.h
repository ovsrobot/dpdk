/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 ZTE Corporation
 */

#ifndef _ZXDH_QUEUE_H_
#define _ZXDH_QUEUE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include <rte_atomic.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_net.h>
#include <ethdev_driver.h>

#include "zxdh_pci.h"
#include "zxdh_ring.h"
#include "zxdh_rxtx.h"


enum {
	VTNET_RQ = 0,
	VTNET_TQ = 1
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
		bool used_wrap_counter;
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

struct rte_mbuf *zxdh_virtqueue_detach_unused(struct virtqueue *vq);
int32_t zxdh_free_queues(struct rte_eth_dev *dev);
int32_t get_queue_type(uint16_t vtpci_queue_idx);

#endif

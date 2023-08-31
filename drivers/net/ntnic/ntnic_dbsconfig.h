/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef NTNIC_DBS_CONFIG_H
#define NTNIC_DBS_CONFIG_H

#include <stdint.h>
#include "nthw_drv.h"

struct nthw_virt_queue;

struct nthw_memory_descriptor {
	void *phys_addr;
	void *virt_addr;
	uint32_t len;
};

#define ule64 uint64_t
#define ule32 uint32_t
#define ule16 uint16_t

#define MAX_MSIX_VECTORS_PR_VF 8

#define SPLIT_RING 0
#define PACKED_RING 1
#define IN_ORDER 1
#define NO_ORDER_REQUIRED 0

/*
 * SPLIT : This marks a buffer as continuing via the next field.
 * PACKED: This marks a buffer as continuing. (packed does not have a next field, so must be
 * contiguous) In Used descriptors it must be ignored
 */
#define VIRTQ_DESC_F_NEXT 1
/*
 * SPLIT : This marks a buffer as device write-only (otherwise device read-only).
 * PACKED: This marks a descriptor as device write-only (otherwise device read-only).
 * PACKED: In a used descriptor, this bit is used to specify whether any data has been written by
 * the device into any parts of the buffer.
 */
#define VIRTQ_DESC_F_WRITE 2
/*
 * SPLIT : This means the buffer contains a list of buffer descriptors.
 * PACKED: This means the element contains a table of descriptors.
 */
#define VIRTQ_DESC_F_INDIRECT 4

/*
 * Split Ring virtq Descriptor
 */
#pragma pack(1)
struct virtq_desc {
	/* Address (guest-physical). */
	ule64 addr;
	/* Length. */
	ule32 len;
	/* The flags as indicated above. */
	ule16 flags;
	/* Next field if flags & NEXT */
	ule16 next;
};

#pragma pack()

/*
 * Packed Ring special structures and defines
 *
 */

#define MAX_PACKED_RING_ELEMENTS (1 << 15) /* 32768 */

/* additional packed ring flags */
#define VIRTQ_DESC_F_AVAIL (1 << 7)
#define VIRTQ_DESC_F_USED (1 << 15)

/* descr phys address must be 16 byte aligned */
#pragma pack(push, 16)
struct pvirtq_desc {
	/* Buffer Address. */
	ule64 addr;
	/* Buffer Length. */
	ule32 len;
	/* Buffer ID. */
	ule16 id;
	/* The flags depending on descriptor type. */
	ule16 flags;
};

#pragma pack(pop)

/* Enable events */
#define RING_EVENT_FLAGS_ENABLE 0x0
/* Disable events */
#define RING_EVENT_FLAGS_DISABLE 0x1
/*
 * Enable events for a specific descriptor
 * (as specified by Descriptor Ring Change Event offset/Wrap Counter).
 * Only valid if VIRTIO_F_RING_EVENT_IDX has been negotiated.
 */
#define RING_EVENT_FLAGS_DESC 0x2
/* The value 0x3 is reserved */

struct pvirtq_event_suppress {
	union {
		struct {
			ule16 desc_event_off : 15; /* Descriptor Ring Change Event offset */
			ule16 desc_event_wrap : 1; /* Descriptor Ring Change Event Wrap Counter */
		};
		ule16 desc; /* If desc_event_flags set to RING_EVENT_FLAGS_DESC */
	};

	/* phys address must be 4 byte aligned */
#pragma pack(push, 16)
	union {
		struct {
			ule16 desc_event_flags : 2; /* Descriptor Ring Change Event Flags */
			ule16 reserved : 14; /* Reserved, set to 0 */
		};
		ule16 flags;
	};
};

#pragma pack(pop)

/*
 * Common virtq descr
 */
#define vq_set_next(_vq, index, nxt)                \
	do {                                       \
		__typeof__(_vq) (vq) = (_vq); \
		if ((vq)->vq_type == SPLIT_RING)   \
			(vq)->s[index].next = nxt; \
	} while (0)
#define vq_add_flags(_vq, _index, _flgs)                  \
	do {                                           \
		__typeof__(_vq) (vq) = (_vq); \
		__typeof__(_index) (index) = (_index); \
		__typeof__(_flgs) (flgs) = (_flgs); \
		if ((vq)->vq_type == SPLIT_RING)       \
			(vq)->s[index].flags |= flgs;  \
		else if ((vq)->vq_type == PACKED_RING) \
			(vq)->p[index].flags |= flgs;  \
	} while (0)
#define vq_set_flags(_vq, _index, _flgs)                  \
	do {                                           \
		__typeof__(_vq) (vq) = (_vq); \
		__typeof__(_index) (index) = (_index); \
		__typeof__(_flgs) (flgs) = (_flgs); \
		if ((vq)->vq_type == SPLIT_RING)       \
			(vq)->s[index].flags = flgs;   \
		else if ((vq)->vq_type == PACKED_RING) \
			(vq)->p[index].flags = flgs;   \
	} while (0)

struct nthw_virtq_desc_buf {
	/* Address (guest-physical). */
	ule64 addr;
	/* Length. */
	ule32 len;
} __rte_aligned(16);

struct nthw_cvirtq_desc {
	union {
		struct nthw_virtq_desc_buf *b; /* buffer part as is common */
		struct virtq_desc *s; /* SPLIT */
		struct pvirtq_desc *p; /* PACKED */
	};
	uint16_t vq_type;
};

/* Setup a virt_queue for a VM */
struct nthw_virt_queue *nthw_setup_rx_virt_queue(nthw_dbs_t *p_nthw_dbs,
	uint32_t index, uint16_t start_idx,
	uint16_t start_ptr, void *avail_struct_phys_addr, void *used_struct_phys_addr,
	void *desc_struct_phys_addr, uint16_t queue_size, uint32_t host_id,
	uint32_t header, uint32_t vq_type, int irq_vector);

int nthw_enable_rx_virt_queue(struct nthw_virt_queue *rx_vq);
int nthw_disable_rx_virt_queue(struct nthw_virt_queue *rx_vq);
int nthw_release_rx_virt_queue(struct nthw_virt_queue *rxvq);

struct nthw_virt_queue *nthw_setup_tx_virt_queue(nthw_dbs_t *p_nthw_dbs,
	uint32_t index, uint16_t start_idx,
	uint16_t start_ptr, void *avail_struct_phys_addr, void *used_struct_phys_addr,
	void *desc_struct_phys_addr, uint16_t queue_size, uint32_t host_id,
	uint32_t port, uint32_t virtual_port, uint32_t header, uint32_t vq_type,
	int irq_vector, uint32_t in_order);

int nthw_enable_tx_virt_queue(struct nthw_virt_queue *tx_vq);
int nthw_disable_tx_virt_queue(struct nthw_virt_queue *tx_vq);
int nthw_release_tx_virt_queue(struct nthw_virt_queue *txvq);
int nthw_enable_and_change_port_tx_virt_queue(struct nthw_virt_queue *tx_vq,
		uint32_t outport);

struct nthw_virt_queue *nthw_setup_managed_rx_virt_queue(nthw_dbs_t *p_nthw_dbs,
	uint32_t index, uint32_t queue_size,
	uint32_t host_id, uint32_t header,
	struct nthw_memory_descriptor *
	p_virt_struct_area,
	struct nthw_memory_descriptor *
	p_packet_buffers,
	uint32_t vq_type, int irq_vector);

int nthw_release_managed_rx_virt_queue(struct nthw_virt_queue *rxvq);

struct nthw_virt_queue *nthw_setup_managed_tx_virt_queue(nthw_dbs_t *p_nthw_dbs,
	uint32_t index, uint32_t queue_size,
	uint32_t host_id, uint32_t port, uint32_t virtual_port, uint32_t header,
	struct nthw_memory_descriptor *
	p_virt_struct_area,
	struct nthw_memory_descriptor *
	p_packet_buffers,
	uint32_t vq_type, int irq_vector, uint32_t in_order);

int nthw_release_managed_tx_virt_queue(struct nthw_virt_queue *txvq);

int nthw_set_tx_qos_config(nthw_dbs_t *p_nthw_dbs, uint32_t port, uint32_t enable,
			   uint32_t ir, uint32_t bs);

int nthw_set_tx_qos_rate_global(nthw_dbs_t *p_nthw_dbs, uint32_t multiplier,
				uint32_t divider);

struct nthw_received_packets {
	void *addr;
	uint32_t len;
};

/*
 * These functions handles both Split and Packed including merged buffers (jumbo)
 */
uint16_t nthw_get_rx_packets(struct nthw_virt_queue *rxvq, uint16_t n,
			     struct nthw_received_packets *rp,
			     uint16_t *nb_pkts);

void nthw_release_rx_packets(struct nthw_virt_queue *rxvq, uint16_t n);

uint16_t nthw_get_tx_buffers(struct nthw_virt_queue *txvq, uint16_t n,
			     uint16_t *first_idx, struct nthw_cvirtq_desc *cvq,
			     struct nthw_memory_descriptor **p_virt_addr);

void nthw_release_tx_buffers(struct nthw_virt_queue *txvq, uint16_t n,
			     uint16_t n_segs[]);

int nthw_get_rx_queue_ptr(struct nthw_virt_queue *rxvq, uint16_t *index);

int nthw_get_tx_queue_ptr(struct nthw_virt_queue *txvq, uint16_t *index);

int nthw_virt_queue_init(struct fpga_info_s *p_fpga_info);

#endif

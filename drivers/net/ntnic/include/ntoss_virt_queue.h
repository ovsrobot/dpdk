/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __NTOSS_VIRT_QUEUE_H__
#define __NTOSS_VIRT_QUEUE_H__

#include <stdint.h>
#include <stdalign.h>

#include "ntos_drv.h"
struct nthw_virt_queue;

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
 */

#define MAX_PACKED_RING_ELEMENTS (1 << 15)	/* 32768 */

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
 * (as specified by Descriptor Ring Change Event Offset/Wrap Counter).
 * Only valid if VIRTIO_F_RING_EVENT_IDX has been negotiated.
 */
#define RING_EVENT_FLAGS_DESC 0x2
/* The value 0x3 is reserved */

struct pvirtq_event_suppress {
	union {
		struct {
			/* Descriptor Ring Change Event Offset */
			ule16 desc_event_off : 15;
			/* Descriptor Ring Change Event Wrap Counter */
			ule16 desc_event_wrap : 1;
		};
		/* If desc_event_flags set to RING_EVENT_FLAGS_DESC */
		ule16 desc;
	};

	/* phys address must be 4 byte aligned */
#pragma pack(push, 16)
	union {
		struct {
			ule16 desc_event_flags : 2;	/* Descriptor Ring Change Event Flags */
			ule16 reserved : 14;	/* Reserved, set to 0 */
		};
		ule16 flags;
	};
};
#pragma pack(pop)

/*
 * Common virtq descr
 */
#define vq_set_next(vq, index, nxt)                                                               \
	do {                                                                                      \
		struct nthw_cvirtq_desc *temp_vq = (vq);                                          \
		if (temp_vq->vq_type == SPLIT_RING)                                               \
			temp_vq->s[index].next = nxt;                                             \
	} while (0)

#define vq_set_flags(vq, index, flgs)                                                             \
	do {                                                                                      \
		struct nthw_cvirtq_desc *temp_vq = (vq);                                          \
		uint32_t temp_flags = (flgs);                                                     \
		uint32_t temp_index = (index);                                                    \
		if ((temp_vq)->vq_type == SPLIT_RING)                                             \
			(temp_vq)->s[temp_index].flags = temp_flags;                              \
		else if ((temp_vq)->vq_type == PACKED_RING)                                       \
			(temp_vq)->p[temp_index].flags = temp_flags;                              \
	} while (0)

struct nthw_virtq_desc_buf {
	/* Address (guest-physical). */
	alignas(16) ule64 addr;
	/* Length. */
	ule32 len;
};

struct nthw_cvirtq_desc {
	union {
		struct nthw_virtq_desc_buf *b;	/* buffer part as is common */
		struct virtq_desc *s;	/* SPLIT */
		struct pvirtq_desc *p;	/* PACKED */
	};
	uint16_t vq_type;
};

struct nthw_received_packets {
	void *addr;
	uint32_t len;
};

#endif	/* __NTOSS_VIRT_QUEUE_H__ */

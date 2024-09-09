/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 ZTE Corporation
 */

#ifndef _ZXDH_RING_H_
#define _ZXDH_RING_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <rte_common.h>

/* This marks a buffer as continuing via the next field. */
#define VRING_DESC_F_NEXT                                   1

/* This marks a buffer as write-only (otherwise read-only). */
#define VRING_DESC_F_WRITE                                  2

/* This means the buffer contains a list of buffer descriptors. */
#define VRING_DESC_F_INDIRECT                               4

/* This flag means the descriptor was made available by the driver */
#define VRING_PACKED_DESC_F_AVAIL                           (1 << (7))
/* This flag means the descriptor was used by the device */
#define VRING_PACKED_DESC_F_USED                            (1 << (15))

/* Frequently used combinations */
#define VRING_PACKED_DESC_F_AVAIL_USED \
			(VRING_PACKED_DESC_F_AVAIL | VRING_PACKED_DESC_F_USED)

/* The Host uses this in used->flags to advise the Guest: don't kick me
 * when you add a buffer.  It's unreliable, so it's simply an
 * optimization.  Guest will still kick if it's out of buffers.
 **/
#define VRING_USED_F_NO_NOTIFY                              1

/** The Guest uses this in avail->flags to advise the Host: don't
 * interrupt me when you consume a buffer.  It's unreliable, so it's
 * simply an optimization.
 **/
#define VRING_AVAIL_F_NO_INTERRUPT                          1

#define RING_EVENT_FLAGS_ENABLE                             0x0
#define RING_EVENT_FLAGS_DISABLE                            0x1
#define RING_EVENT_FLAGS_DESC                               0x2

/** VirtIO ring descriptors: 16 bytes.
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

/** For support of packed virtqueues in Virtio 1.1 the format of descriptors
 * looks like this.
 **/
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

#endif

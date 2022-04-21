/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Intel Corporation
 */

#ifndef _VDPA_BLK_COMPACT_H_
#define _VDPA_BLK_COMPACT_H_

/**
 * @file
 *
 * Device specific vhost lib
 */

#include <stdbool.h>

#include <rte_pci.h>
#include <rte_vhost.h>

/* Feature bits */
#define VIRTIO_BLK_F_SIZE_MAX     1    /* Indicates maximum segment size */
#define VIRTIO_BLK_F_SEG_MAX      2    /* Indicates maximum # of segments */
#define VIRTIO_BLK_F_GEOMETRY     4    /* Legacy geometry available  */
#define VIRTIO_BLK_F_RO           5    /* Disk is read-only */
#define VIRTIO_BLK_F_BLK_SIZE     6    /* Block size of disk is available */
#define VIRTIO_BLK_F_TOPOLOGY     10   /* Topology information is available */
#define VIRTIO_BLK_F_MQ           12   /* support more than one vq */
#define VIRTIO_BLK_F_DISCARD      13   /* DISCARD is supported */
#define VIRTIO_BLK_F_WRITE_ZEROES 14   /* WRITE ZEROES is supported */

/* Legacy feature bits */
#ifndef VIRTIO_BLK_NO_LEGACY
#define VIRTIO_BLK_F_BARRIER      0    /* Does host support barriers? */
#define VIRTIO_BLK_F_SCSI         7    /* Supports scsi command passthru */
#define VIRTIO_BLK_F_FLUSH        9    /* Flush command supported */
#define VIRTIO_BLK_F_CONFIG_WCE   11   /* Writeback mode available in config */

/* Old (deprecated) name for VIRTIO_BLK_F_FLUSH. */
#define VIRTIO_BLK_F_WCE VIRTIO_BLK_F_FLUSH
#endif /* !VIRTIO_BLK_NO_LEGACY */

#ifndef VHOST_USER_F_PROTOCOL_FEATURES
#define VHOST_USER_F_PROTOCOL_FEATURES 30
#endif

#define VHOST_BLK_FEATURES ((1ULL << VHOST_F_LOG_ALL) | \
	(1ULL << VHOST_USER_F_PROTOCOL_FEATURES) | \
	(1ULL << VIRTIO_F_VERSION_1) | \
	(1ULL << VIRTIO_F_NOTIFY_ON_EMPTY) | \
	(1ULL << VIRTIO_RING_F_EVENT_IDX) | \
	(1ULL << VIRTIO_RING_F_INDIRECT_DESC))

#define VHOST_BLK_DISABLED_FEATURES ((1ULL << VIRTIO_RING_F_EVENT_IDX) | \
	(1ULL << VIRTIO_F_NOTIFY_ON_EMPTY))

#define VHOST_BLK_FEATURES_BASE (VHOST_BLK_FEATURES | \
	(1ULL << VIRTIO_BLK_F_SIZE_MAX) | (1ULL << VIRTIO_BLK_F_SEG_MAX) | \
	(1ULL << VIRTIO_BLK_F_GEOMETRY) | (1ULL << VIRTIO_BLK_F_BLK_SIZE) | \
	(1ULL << VIRTIO_BLK_F_TOPOLOGY) | (1ULL << VIRTIO_BLK_F_BARRIER)  | \
	(1ULL << VIRTIO_BLK_F_SCSI)     | (1ULL << VIRTIO_BLK_F_CONFIG_WCE) | \
	(1ULL << VIRTIO_BLK_F_MQ))

/* Not supported features */
#define VHOST_VDPA_BLK_DISABLED_FEATURES (VHOST_BLK_DISABLED_FEATURES | \
	(1ULL << VIRTIO_BLK_F_GEOMETRY) | (1ULL << VIRTIO_BLK_F_CONFIG_WCE) | \
	(1ULL << VIRTIO_BLK_F_BARRIER)  | (1ULL << VIRTIO_BLK_F_SCSI))

/* Vhost-blk support protocol features */
#define VHOST_BLK_PROTOCOL_FEATURES \
	((1ULL << VHOST_USER_PROTOCOL_F_CONFIG) | \
	(1ULL << VHOST_USER_PROTOCOL_F_INFLIGHT_SHMFD))

#endif /* _VDPA_BLK_COMPACT_H_ */

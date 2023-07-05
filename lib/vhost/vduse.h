/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Red Hat, Inc.
 */

#ifndef _VDUSE_H
#define _VDUSE_H

#include "vhost.h"

#define VDUSE_NET_SUPPORTED_FEATURES ((1ULL << VIRTIO_NET_F_MRG_RXBUF) | \
				(1ULL << VIRTIO_F_ANY_LAYOUT) | \
				(1ULL << VIRTIO_F_VERSION_1)   | \
				(1ULL << VIRTIO_NET_F_GSO) | \
				(1ULL << VIRTIO_NET_F_HOST_TSO4) | \
				(1ULL << VIRTIO_NET_F_HOST_TSO6) | \
				(1ULL << VIRTIO_NET_F_HOST_UFO) | \
				(1ULL << VIRTIO_NET_F_HOST_ECN) | \
				(1ULL << VIRTIO_NET_F_CSUM)    | \
				(1ULL << VIRTIO_NET_F_GUEST_CSUM) | \
				(1ULL << VIRTIO_NET_F_GUEST_TSO4) | \
				(1ULL << VIRTIO_NET_F_GUEST_TSO6) | \
				(1ULL << VIRTIO_NET_F_GUEST_UFO) | \
				(1ULL << VIRTIO_NET_F_GUEST_ECN) | \
				(1ULL << VIRTIO_RING_F_INDIRECT_DESC) | \
				(1ULL << VIRTIO_F_IN_ORDER) | \
				(1ULL << VIRTIO_F_IOMMU_PLATFORM) | \
				(1ULL << VIRTIO_NET_F_CTRL_VQ) | \
				(1ULL << VIRTIO_NET_F_MQ))

#ifdef VHOST_HAS_VDUSE

int vduse_device_create(const char *path);
int vduse_device_destroy(const char *path);

#else

static inline int
vduse_device_create(const char *path)
{
	VHOST_LOG_CONFIG(path, ERR, "VDUSE support disabled at build time\n");
	return -1;
}

static inline int
vduse_device_destroy(const char *path)
{
	VHOST_LOG_CONFIG(path, ERR, "VDUSE support disabled at build time\n");
	return -1;
}

#endif /* VHOST_HAS_VDUSE */

#endif /* _VDUSE_H */

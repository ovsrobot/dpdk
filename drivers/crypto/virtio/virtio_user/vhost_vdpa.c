/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Marvell
 */

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include <rte_memory.h>

#include "virtio_user/vhost.h"

#include "virtio_user_dev.h"
#include "../virtio_pci.h"

struct vhost_vdpa_data {
	int vhostfd;
	uint64_t protocol_features;
};

#define VHOST_VDPA_SUPPORTED_BACKEND_FEATURES		\
	(1ULL << VHOST_BACKEND_F_IOTLB_MSG_V2	|	\
	1ULL << VHOST_BACKEND_F_IOTLB_BATCH)

/* vhost kernel & vdpa ioctls */
#define VHOST_VIRTIO 0xAF
#define VHOST_GET_FEATURES _IOR(VHOST_VIRTIO, 0x00, __u64)
#define VHOST_SET_FEATURES _IOW(VHOST_VIRTIO, 0x00, __u64)
#define VHOST_SET_OWNER _IO(VHOST_VIRTIO, 0x01)
#define VHOST_RESET_OWNER _IO(VHOST_VIRTIO, 0x02)
#define VHOST_SET_LOG_BASE _IOW(VHOST_VIRTIO, 0x04, __u64)
#define VHOST_SET_LOG_FD _IOW(VHOST_VIRTIO, 0x07, int)
#define VHOST_SET_VRING_NUM _IOW(VHOST_VIRTIO, 0x10, struct vhost_vring_state)
#define VHOST_SET_VRING_ADDR _IOW(VHOST_VIRTIO, 0x11, struct vhost_vring_addr)
#define VHOST_SET_VRING_BASE _IOW(VHOST_VIRTIO, 0x12, struct vhost_vring_state)
#define VHOST_GET_VRING_BASE _IOWR(VHOST_VIRTIO, 0x12, struct vhost_vring_state)
#define VHOST_SET_VRING_KICK _IOW(VHOST_VIRTIO, 0x20, struct vhost_vring_file)
#define VHOST_SET_VRING_CALL _IOW(VHOST_VIRTIO, 0x21, struct vhost_vring_file)
#define VHOST_SET_VRING_ERR _IOW(VHOST_VIRTIO, 0x22, struct vhost_vring_file)
#define VHOST_NET_SET_BACKEND _IOW(VHOST_VIRTIO, 0x30, struct vhost_vring_file)
#define VHOST_VDPA_GET_DEVICE_ID _IOR(VHOST_VIRTIO, 0x70, __u32)
#define VHOST_VDPA_GET_STATUS _IOR(VHOST_VIRTIO, 0x71, __u8)
#define VHOST_VDPA_SET_STATUS _IOW(VHOST_VIRTIO, 0x72, __u8)
#define VHOST_VDPA_GET_CONFIG _IOR(VHOST_VIRTIO, 0x73, struct vhost_vdpa_config)
#define VHOST_VDPA_SET_CONFIG _IOW(VHOST_VIRTIO, 0x74, struct vhost_vdpa_config)
#define VHOST_VDPA_SET_VRING_ENABLE _IOW(VHOST_VIRTIO, 0x75, struct vhost_vring_state)
#define VHOST_SET_BACKEND_FEATURES _IOW(VHOST_VIRTIO, 0x25, __u64)
#define VHOST_GET_BACKEND_FEATURES _IOR(VHOST_VIRTIO, 0x26, __u64)

/* no alignment requirement */
struct vhost_iotlb_msg {
	uint64_t iova;
	uint64_t size;
	uint64_t uaddr;
#define VHOST_ACCESS_RO      0x1
#define VHOST_ACCESS_WO      0x2
#define VHOST_ACCESS_RW      0x3
	uint8_t perm;
#define VHOST_IOTLB_MISS           1
#define VHOST_IOTLB_UPDATE         2
#define VHOST_IOTLB_INVALIDATE     3
#define VHOST_IOTLB_ACCESS_FAIL    4
#define VHOST_IOTLB_BATCH_BEGIN    5
#define VHOST_IOTLB_BATCH_END      6
	uint8_t type;
};

#define VHOST_IOTLB_MSG_V2 0x2

struct vhost_vdpa_config {
	uint32_t off;
	uint32_t len;
	uint8_t buf[];
};

struct vhost_msg {
	uint32_t type;
	uint32_t reserved;
	union {
		struct vhost_iotlb_msg iotlb;
		uint8_t padding[64];
	};
};


static int
vhost_vdpa_ioctl(int fd, uint64_t request, void *arg)
{
	int ret;

	ret = ioctl(fd, request, arg);
	if (ret) {
		PMD_DRV_LOG(ERR, "Vhost-vDPA ioctl %"PRIu64" failed (%s)",
				request, strerror(errno));
		return -1;
	}

	return 0;
}

static int
vhost_vdpa_get_protocol_features(struct virtio_user_dev *dev, uint64_t *features)
{
	struct vhost_vdpa_data *data = dev->backend_data;

	return vhost_vdpa_ioctl(data->vhostfd, VHOST_GET_BACKEND_FEATURES, features);
}

static int
vhost_vdpa_set_protocol_features(struct virtio_user_dev *dev, uint64_t features)
{
	struct vhost_vdpa_data *data = dev->backend_data;

	return vhost_vdpa_ioctl(data->vhostfd, VHOST_SET_BACKEND_FEATURES, &features);
}

static int
vhost_vdpa_get_features(struct virtio_user_dev *dev, uint64_t *features)
{
	struct vhost_vdpa_data *data = dev->backend_data;
	int ret;

	ret = vhost_vdpa_ioctl(data->vhostfd, VHOST_GET_FEATURES, features);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failed to get features");
		return -1;
	}

	/* Negotiated vDPA backend features */
	ret = vhost_vdpa_get_protocol_features(dev, &data->protocol_features);
	if (ret < 0) {
		PMD_DRV_LOG(ERR, "Failed to get backend features");
		return -1;
	}

	data->protocol_features &= VHOST_VDPA_SUPPORTED_BACKEND_FEATURES;

	ret = vhost_vdpa_set_protocol_features(dev, data->protocol_features);
	if (ret < 0) {
		PMD_DRV_LOG(ERR, "Failed to set backend features");
		return -1;
	}

	return 0;
}

static int
vhost_vdpa_set_vring_enable(struct virtio_user_dev *dev, struct vhost_vring_state *state)
{
	struct vhost_vdpa_data *data = dev->backend_data;

	return vhost_vdpa_ioctl(data->vhostfd, VHOST_VDPA_SET_VRING_ENABLE, state);
}

/**
 * Set up environment to talk with a vhost vdpa backend.
 *
 * @return
 *   - (-1) if fail to set up;
 *   - (>=0) if successful.
 */
static int
vhost_vdpa_setup(struct virtio_user_dev *dev)
{
	struct vhost_vdpa_data *data;
	uint32_t did = (uint32_t)-1;

	data = malloc(sizeof(*data));
	if (!data) {
		PMD_DRV_LOG(ERR, "(%s) Faidle to allocate backend data", dev->path);
		return -1;
	}

	data->vhostfd = open(dev->path, O_RDWR);
	if (data->vhostfd < 0) {
		PMD_DRV_LOG(ERR, "Failed to open %s: %s",
				dev->path, strerror(errno));
		free(data);
		return -1;
	}

	if (ioctl(data->vhostfd, VHOST_VDPA_GET_DEVICE_ID, &did) < 0 ||
			did != VIRTIO_ID_CRYPTO) {
		PMD_DRV_LOG(ERR, "Invalid vdpa device ID: %u", did);
		close(data->vhostfd);
		free(data);
		return -1;
	}

	dev->backend_data = data;

	return 0;
}

static int
vhost_vdpa_cvq_enable(struct virtio_user_dev *dev, int enable)
{
	struct vhost_vring_state state = {
		.index = dev->max_queue_pairs,
		.num   = enable,
	};

	return vhost_vdpa_set_vring_enable(dev, &state);
}

static int
vhost_vdpa_enable_queue_pair(struct virtio_user_dev *dev,
				uint16_t pair_idx,
				int enable)
{
	struct vhost_vring_state state = {
		.index = pair_idx,
		.num   = enable,
	};

	if (dev->qp_enabled[pair_idx] == enable)
		return 0;

	if (vhost_vdpa_set_vring_enable(dev, &state))
		return -1;

	dev->qp_enabled[pair_idx] = enable;
	return 0;
}

static int
vhost_vdpa_update_link_state(struct virtio_user_dev *dev)
{
	dev->crypto_status = VIRTIO_CRYPTO_S_HW_READY;
	return 0;
}

static int
vhost_vdpa_get_nr_vrings(struct virtio_user_dev *dev)
{
	int nr_vrings = dev->max_queue_pairs;

	return nr_vrings;
}

static int
vhost_vdpa_unmap_notification_area(struct virtio_user_dev *dev)
{
	int i, nr_vrings;

	nr_vrings = vhost_vdpa_get_nr_vrings(dev);

	for (i = 0; i < nr_vrings; i++) {
		if (dev->notify_area[i])
			munmap(dev->notify_area[i], getpagesize());
	}
	free(dev->notify_area);
	dev->notify_area = NULL;

	return 0;
}

static int
vhost_vdpa_map_notification_area(struct virtio_user_dev *dev)
{
	struct vhost_vdpa_data *data = dev->backend_data;
	int nr_vrings, i, page_size = getpagesize();
	uint16_t **notify_area;

	nr_vrings = vhost_vdpa_get_nr_vrings(dev);

	/* CQ is another vring */
	nr_vrings++;

	notify_area = malloc(nr_vrings * sizeof(*notify_area));
	if (!notify_area) {
		PMD_DRV_LOG(ERR, "(%s) Failed to allocate notify area array", dev->path);
		return -1;
	}

	for (i = 0; i < nr_vrings; i++) {
		notify_area[i] = mmap(NULL, page_size, PROT_WRITE, MAP_SHARED | MAP_FILE,
					data->vhostfd, i * page_size);
		if (notify_area[i] == MAP_FAILED) {
			PMD_DRV_LOG(ERR, "(%s) Map failed for notify address of queue %d",
					dev->path, i);
			i--;
			goto map_err;
		}
	}
	dev->notify_area = notify_area;

	return 0;

map_err:
	for (; i >= 0; i--)
		munmap(notify_area[i], page_size);
	free(notify_area);

	return -1;
}

struct virtio_user_backend_ops virtio_crypto_ops_vdpa = {
	.setup = vhost_vdpa_setup,
	.get_features = vhost_vdpa_get_features,
	.cvq_enable = vhost_vdpa_cvq_enable,
	.enable_qp = vhost_vdpa_enable_queue_pair,
	.update_link_state = vhost_vdpa_update_link_state,
	.map_notification_area = vhost_vdpa_map_notification_area,
	.unmap_notification_area = vhost_vdpa_unmap_notification_area,
};

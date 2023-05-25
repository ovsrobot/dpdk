/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Red Hat, Inc.
 */

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>


#include <linux/vduse.h>
#include <linux/virtio_net.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <rte_common.h>

#include "fd_man.h"
#include "iotlb.h"
#include "vduse.h"
#include "vhost.h"

#define VHOST_VDUSE_API_VERSION 0
#define VDUSE_CTRL_PATH "/dev/vduse/control"

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
				(1ULL << VIRTIO_F_IOMMU_PLATFORM))

struct vduse {
	struct fdset fdset;
};

static struct vduse vduse = {
	.fdset = {
		.fd = { [0 ... MAX_FDS - 1] = {-1, NULL, NULL, NULL, 0} },
		.fd_mutex = PTHREAD_MUTEX_INITIALIZER,
		.fd_pooling_mutex = PTHREAD_MUTEX_INITIALIZER,
		.num = 0
	},
};

static bool vduse_events_thread;

static const char * const vduse_reqs_str[] = {
	"VDUSE_GET_VQ_STATE",
	"VDUSE_SET_STATUS",
	"VDUSE_UPDATE_IOTLB",
};

#define vduse_req_id_to_str(id) \
	(id < RTE_DIM(vduse_reqs_str) ? \
	vduse_reqs_str[id] : "Unknown")

static int
vduse_inject_irq(struct virtio_net *dev, struct vhost_virtqueue *vq)
{
	return ioctl(dev->vduse_dev_fd, VDUSE_VQ_INJECT_IRQ, &vq->index);
}

static void
vduse_iotlb_remove_notify(uint64_t addr, uint64_t offset, uint64_t size)
{
	munmap((void *)(uintptr_t)addr, offset + size);
}

static int
vduse_iotlb_miss(struct virtio_net *dev, uint64_t iova, uint8_t perm __rte_unused)
{
	struct vduse_iotlb_entry entry;
	uint64_t size, page_size;
	struct stat stat;
	void *mmap_addr;
	int fd, ret;

	entry.start = iova;
	entry.last = iova + 1;

	ret = ioctl(dev->vduse_dev_fd, VDUSE_IOTLB_GET_FD, &entry);
	if (ret < 0) {
		VHOST_LOG_CONFIG(dev->ifname, ERR, "Failed to get IOTLB entry for 0x%" PRIx64 "\n",
				iova);
		return -1;
	}

	fd = ret;

	VHOST_LOG_CONFIG(dev->ifname, DEBUG, "New IOTLB entry:\n");
	VHOST_LOG_CONFIG(dev->ifname, DEBUG, "\tIOVA: %" PRIx64 " - %" PRIx64 "\n",
			(uint64_t)entry.start, (uint64_t)entry.last);
	VHOST_LOG_CONFIG(dev->ifname, DEBUG, "\toffset: %" PRIx64 "\n", (uint64_t)entry.offset);
	VHOST_LOG_CONFIG(dev->ifname, DEBUG, "\tfd: %d\n", fd);
	VHOST_LOG_CONFIG(dev->ifname, DEBUG, "\tperm: %x\n", entry.perm);

	size = entry.last - entry.start + 1;
	mmap_addr = mmap(0, size + entry.offset, entry.perm, MAP_SHARED, fd, 0);
	if (!mmap_addr) {
		VHOST_LOG_CONFIG(dev->ifname, ERR,
				"Failed to mmap IOTLB entry for 0x%" PRIx64 "\n", iova);
		ret = -1;
		goto close_fd;
	}

	ret = fstat(fd, &stat);
	if (ret < 0) {
		VHOST_LOG_CONFIG(dev->ifname, ERR, "Failed to get page size.\n");
		munmap(mmap_addr, entry.offset + size);
		goto close_fd;
	}
	page_size = (uint64_t)stat.st_blksize;

	vhost_user_iotlb_cache_insert(dev, entry.start, (uint64_t)(uintptr_t)mmap_addr,
		entry.offset, size, page_size, entry.perm);

	ret = 0;
close_fd:
	close(fd);

	return ret;
}

static struct vhost_backend_ops vduse_backend_ops = {
	.iotlb_miss = vduse_iotlb_miss,
	.iotlb_remove_notify = vduse_iotlb_remove_notify,
	.inject_irq = vduse_inject_irq,
};

static void
vduse_events_handler(int fd, void *arg, int *remove __rte_unused)
{
	struct virtio_net *dev = arg;
	struct vduse_dev_request req;
	struct vduse_dev_response resp;
	struct vhost_virtqueue *vq;
	int ret;

	memset(&resp, 0, sizeof(resp));

	ret = read(fd, &req, sizeof(req));
	if (ret < 0) {
		VHOST_LOG_CONFIG(dev->ifname, ERR, "Failed to read request: %s\n",
				strerror(errno));
		return;
	} else if (ret < (int)sizeof(req)) {
		VHOST_LOG_CONFIG(dev->ifname, ERR, "Incomplete to read request %d\n", ret);
		return;
	}

	VHOST_LOG_CONFIG(dev->ifname, INFO, "New request: %s (%u)\n",
			vduse_req_id_to_str(req.type), req.type);

	switch (req.type) {
	case VDUSE_GET_VQ_STATE:
		vq = dev->virtqueue[req.vq_state.index];
		VHOST_LOG_CONFIG(dev->ifname, INFO, "\tvq index: %u, avail_index: %u\n",
				req.vq_state.index, vq->last_avail_idx);
		resp.vq_state.split.avail_index = vq->last_avail_idx;
		resp.result = VDUSE_REQ_RESULT_OK;
		break;
	case VDUSE_SET_STATUS:
		VHOST_LOG_CONFIG(dev->ifname, INFO, "\tnew status: 0x%08x\n",
				req.s.status);
		dev->status = req.s.status;
		resp.result = VDUSE_REQ_RESULT_OK;
		break;
	case VDUSE_UPDATE_IOTLB:
		VHOST_LOG_CONFIG(dev->ifname, INFO, "\tIOVA range: %" PRIx64 " - %" PRIx64 "\n",
				(uint64_t)req.iova.start, (uint64_t)req.iova.last);
		vhost_user_iotlb_cache_remove(dev, req.iova.start,
				req.iova.last - req.iova.start + 1);
		resp.result = VDUSE_REQ_RESULT_OK;
		break;
	default:
		resp.result = VDUSE_REQ_RESULT_FAILED;
		break;
	}

	resp.request_id = req.request_id;

	ret = write(dev->vduse_dev_fd, &resp, sizeof(resp));
	if (ret != sizeof(resp)) {
		VHOST_LOG_CONFIG(dev->ifname, ERR, "Failed to write response %s\n",
				strerror(errno));
		return;
	}
	VHOST_LOG_CONFIG(dev->ifname, INFO, "Request %s (%u) handled successfully\n",
			vduse_req_id_to_str(req.type), req.type);
}

int
vduse_device_create(const char *path)
{
	int control_fd, dev_fd, vid, ret;
	pthread_t fdset_tid;
	uint32_t i;
	struct virtio_net *dev;
	uint64_t ver = VHOST_VDUSE_API_VERSION;
	struct vduse_dev_config *dev_config = NULL;
	const char *name = path + strlen("/dev/vduse/");

	/* If first device, create events dispatcher thread */
	if (vduse_events_thread == false) {
		/**
		 * create a pipe which will be waited by poll and notified to
		 * rebuild the wait list of poll.
		 */
		if (fdset_pipe_init(&vduse.fdset) < 0) {
			VHOST_LOG_CONFIG(path, ERR, "failed to create pipe for vduse fdset\n");
			return -1;
		}

		ret = rte_ctrl_thread_create(&fdset_tid, "vduse-events", NULL,
				fdset_event_dispatch, &vduse.fdset);
		if (ret != 0) {
			VHOST_LOG_CONFIG(path, ERR, "failed to create vduse fdset handling thread\n");
			fdset_pipe_uninit(&vduse.fdset);
			return -1;
		}

		vduse_events_thread = true;
	}

	control_fd = open(VDUSE_CTRL_PATH, O_RDWR);
	if (control_fd < 0) {
		VHOST_LOG_CONFIG(name, ERR, "Failed to open %s: %s\n",
				VDUSE_CTRL_PATH, strerror(errno));
		return -1;
	}

	if (ioctl(control_fd, VDUSE_SET_API_VERSION, &ver)) {
		VHOST_LOG_CONFIG(name, ERR, "Failed to set API version: %" PRIu64 ": %s\n",
				ver, strerror(errno));
		ret = -1;
		goto out_ctrl_close;
	}

	dev_config = malloc(offsetof(struct vduse_dev_config, config));
	if (!dev_config) {
		VHOST_LOG_CONFIG(name, ERR, "Failed to allocate VDUSE config\n");
		ret = -1;
		goto out_ctrl_close;
	}

	memset(dev_config, 0, sizeof(struct vduse_dev_config));

	strncpy(dev_config->name, name, VDUSE_NAME_MAX - 1);
	dev_config->device_id = VIRTIO_ID_NET;
	dev_config->vendor_id = 0;
	dev_config->features = VDUSE_NET_SUPPORTED_FEATURES;
	dev_config->vq_num = 2;
	dev_config->vq_align = sysconf(_SC_PAGE_SIZE);
	dev_config->config_size = 0;

	ret = ioctl(control_fd, VDUSE_CREATE_DEV, dev_config);
	if (ret < 0) {
		VHOST_LOG_CONFIG(name, ERR, "Failed to create VDUSE device: %s\n",
				strerror(errno));
		goto out_free;
	}

	dev_fd = open(path, O_RDWR);
	if (dev_fd < 0) {
		VHOST_LOG_CONFIG(name, ERR, "Failed to open device %s: %s\n",
				path, strerror(errno));
		ret = -1;
		goto out_dev_close;
	}

	ret = fcntl(dev_fd, F_SETFL, O_NONBLOCK);
	if (ret < 0) {
		VHOST_LOG_CONFIG(name, ERR, "Failed to set chardev as non-blocking: %s\n",
				strerror(errno));
		goto out_dev_close;
	}

	vid = vhost_new_device(&vduse_backend_ops);
	if (vid < 0) {
		VHOST_LOG_CONFIG(name, ERR, "Failed to create new Vhost device\n");
		ret = -1;
		goto out_dev_close;
	}

	dev = get_device(vid);
	if (!dev) {
		ret = -1;
		goto out_dev_close;
	}

	strncpy(dev->ifname, path, IF_NAME_SZ - 1);
	dev->vduse_ctrl_fd = control_fd;
	dev->vduse_dev_fd = dev_fd;
	vhost_setup_virtio_net(dev->vid, true, true, true, true);

	for (i = 0; i < 2; i++) {
		struct vduse_vq_config vq_cfg = { 0 };

		ret = alloc_vring_queue(dev, i);
		if (ret) {
			VHOST_LOG_CONFIG(name, ERR, "Failed to alloc vring %d metadata\n", i);
			goto out_dev_destroy;
		}

		vq_cfg.index = i;
		vq_cfg.max_size = 1024;

		ret = ioctl(dev->vduse_dev_fd, VDUSE_VQ_SETUP, &vq_cfg);
		if (ret) {
			VHOST_LOG_CONFIG(name, ERR, "Failed to set-up VQ %d\n", i);
			goto out_dev_destroy;
		}
	}

	ret = fdset_add(&vduse.fdset, dev->vduse_dev_fd, vduse_events_handler, NULL, dev);
	if (ret) {
		VHOST_LOG_CONFIG(name, ERR, "Failed to add fd %d to vduse fdset\n",
				dev->vduse_dev_fd);
		goto out_dev_destroy;
	}
	fdset_pipe_notify(&vduse.fdset);

	free(dev_config);

	return 0;

out_dev_destroy:
	vhost_destroy_device(vid);
out_dev_close:
	if (dev_fd >= 0)
		close(dev_fd);
	ioctl(control_fd, VDUSE_DESTROY_DEV, name);
out_free:
	free(dev_config);
out_ctrl_close:
	close(control_fd);

	return ret;
}

int
vduse_device_destroy(const char *path)
{
	const char *name = path + strlen("/dev/vduse/");
	struct virtio_net *dev;
	int vid, ret;

	for (vid = 0; vid < RTE_MAX_VHOST_DEVICE; vid++) {
		dev = vhost_devices[vid];

		if (dev == NULL)
			continue;

		if (!strcmp(path, dev->ifname))
			break;
	}

	if (vid == RTE_MAX_VHOST_DEVICE)
		return -1;

	fdset_del(&vduse.fdset, dev->vduse_dev_fd);
	fdset_pipe_notify(&vduse.fdset);

	if (dev->vduse_dev_fd >= 0) {
		close(dev->vduse_dev_fd);
		dev->vduse_dev_fd = -1;
	}

	if (dev->vduse_ctrl_fd >= 0) {
		ret = ioctl(dev->vduse_ctrl_fd, VDUSE_DESTROY_DEV, name);
		if (ret)
			VHOST_LOG_CONFIG(name, ERR, "Failed to destroy VDUSE device: %s\n",
					strerror(errno));
		close(dev->vduse_ctrl_fd);
		dev->vduse_ctrl_fd = -1;
	}

	vhost_destroy_device(vid);

	return 0;
}

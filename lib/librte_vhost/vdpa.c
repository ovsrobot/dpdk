/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Intel Corporation
 */

/**
 * @file
 *
 * Device specific vhost lib
 */

#include <stdbool.h>
#include <sys/queue.h>

#include <rte_class.h>
#include <rte_malloc.h>
#include <rte_spinlock.h>
#include <rte_tailq.h>

#include "rte_vdpa.h"
#include "vhost.h"

/** Double linked list of vDPA devices. */
TAILQ_HEAD(vdpa_device_list, rte_vdpa_device);

static struct vdpa_device_list vdpa_device_list =
		TAILQ_HEAD_INITIALIZER(vdpa_device_list);
static rte_spinlock_t vdpa_device_list_lock = RTE_SPINLOCK_INITIALIZER;
static uint32_t vdpa_device_num;


/* Unsafe, needs to be called with vdpa_device_list_lock held */
static struct rte_vdpa_device *
__vdpa_find_device_by_name(const char *name)
{
	struct rte_vdpa_device *dev, *ret = NULL;

	if (name == NULL)
		return NULL;

	TAILQ_FOREACH(dev, &vdpa_device_list, next) {
		if (strcmp(dev->device->name, name) == 0) {
			ret = dev;
			break;
		}
	}

	return ret;
}

struct rte_vdpa_device *
rte_vdpa_find_device_by_name(const char *name)
{
	struct rte_vdpa_device *dev;

	rte_spinlock_lock(&vdpa_device_list_lock);
	dev = __vdpa_find_device_by_name(name);
	rte_spinlock_unlock(&vdpa_device_list_lock);

	return dev;
}

struct rte_device *
rte_vdpa_get_rte_device(struct rte_vdpa_device *vdpa_dev)
{
	if (vdpa_dev == NULL)
		return NULL;

	return vdpa_dev->device;
}

struct rte_vdpa_device *
rte_vdpa_register_device(struct rte_device *rte_dev,
		struct rte_vdpa_dev_ops *ops)
{
	struct rte_vdpa_device *dev;

	if (ops == NULL)
		return NULL;

	rte_spinlock_lock(&vdpa_device_list_lock);
	/* Check the device hasn't been register already */
	dev = __vdpa_find_device_by_name(rte_dev->name);
	if (dev) {
		dev = NULL;
		goto out_unlock;
	}

	dev = rte_zmalloc(NULL, sizeof(*dev), 0);
	if (!dev)
		goto out_unlock;

	dev->device = rte_dev;
	dev->ops = ops;
	TAILQ_INSERT_TAIL(&vdpa_device_list, dev, next);
	vdpa_device_num++;
out_unlock:
	rte_spinlock_unlock(&vdpa_device_list_lock);

	return dev;
}

int
rte_vdpa_unregister_device(struct rte_vdpa_device *dev)
{
	struct rte_vdpa_device *cur_dev, *tmp_dev;
	int ret = -1;

	rte_spinlock_lock(&vdpa_device_list_lock);
	TAILQ_FOREACH_SAFE(cur_dev, &vdpa_device_list, next, tmp_dev) {
		if (dev != cur_dev)
			continue;

		TAILQ_REMOVE(&vdpa_device_list, dev, next);
		rte_free(dev);
		vdpa_device_num--;
		ret = 0;
		break;
	}
	rte_spinlock_lock(&vdpa_device_list_lock);

	return ret;
}

int
rte_vdpa_get_device_num(void)
{
	return vdpa_device_num;
}

int
rte_vdpa_relay_vring_used(int vid, uint16_t qid, void *vring_m)
{
	struct virtio_net *dev = get_device(vid);
	uint16_t idx, idx_m, desc_id;
	struct vhost_virtqueue *vq;
	struct vring_desc desc;
	struct vring_desc *desc_ring;
	struct vring_desc *idesc = NULL;
	struct vring *s_vring;
	uint64_t dlen;
	uint32_t nr_descs;
	int ret;

	if (!dev || !vring_m)
		return -1;

	if (qid >= dev->nr_vring)
		return -1;

	if (vq_is_packed(dev))
		return -1;

	s_vring = (struct vring *)vring_m;
	vq = dev->virtqueue[qid];
	idx = vq->used->idx;
	idx_m = s_vring->used->idx;
	ret = (uint16_t)(idx_m - idx);

	while (idx != idx_m) {
		/* copy used entry, used ring logging is not covered here */
		vq->used->ring[idx & (vq->size - 1)] =
			s_vring->used->ring[idx & (vq->size - 1)];

		desc_id = vq->used->ring[idx & (vq->size - 1)].id;
		desc_ring = vq->desc;
		nr_descs = vq->size;

		if (unlikely(desc_id >= vq->size))
			return -1;

		if (vq->desc[desc_id].flags & VRING_DESC_F_INDIRECT) {
			dlen = vq->desc[desc_id].len;
			nr_descs = dlen / sizeof(struct vring_desc);
			if (unlikely(nr_descs > vq->size))
				return -1;

			desc_ring = (struct vring_desc *)(uintptr_t)
				vhost_iova_to_vva(dev, vq,
						vq->desc[desc_id].addr, &dlen,
						VHOST_ACCESS_RO);
			if (unlikely(!desc_ring))
				return -1;

			if (unlikely(dlen < vq->desc[desc_id].len)) {
				idesc = vhost_alloc_copy_ind_table(dev, vq,
						vq->desc[desc_id].addr,
						vq->desc[desc_id].len);
				if (unlikely(!idesc))
					return -1;

				desc_ring = idesc;
			}

			desc_id = 0;
		}

		/* dirty page logging for DMA writeable buffer */
		do {
			if (unlikely(desc_id >= vq->size))
				goto fail;
			if (unlikely(nr_descs-- == 0))
				goto fail;
			desc = desc_ring[desc_id];
			if (desc.flags & VRING_DESC_F_WRITE)
				vhost_log_write_iova(dev, vq, desc.addr,
						     desc.len);
			desc_id = desc.next;
		} while (desc.flags & VRING_DESC_F_NEXT);

		if (unlikely(idesc)) {
			free_ind_table(idesc);
			idesc = NULL;
		}

		idx++;
	}

	rte_smp_wmb();
	vq->used->idx = idx_m;

	if (dev->features & (1ULL << VIRTIO_RING_F_EVENT_IDX))
		vring_used_event(s_vring) = idx_m;

	return ret;

fail:
	if (unlikely(idesc))
		free_ind_table(idesc);
	return -1;
}

static int
vdpa_dev_match(struct rte_vdpa_device *dev,
	      const struct rte_device *rte_dev)
{
	if (dev->device == rte_dev)
		return 0;

	return -1;
}

/* Generic rte_vdpa_dev comparison function. */
typedef int (*rte_vdpa_cmp_t)(struct rte_vdpa_device *,
		const struct rte_device *rte_dev);

static struct rte_vdpa_device *
vdpa_find_device(const struct rte_vdpa_device *start, rte_vdpa_cmp_t cmp,
		struct rte_device *rte_dev)
{
	struct rte_vdpa_device *dev;

	rte_spinlock_lock(&vdpa_device_list_lock);
	if (start == NULL)
		dev = TAILQ_FIRST(&vdpa_device_list);
	else
		dev = TAILQ_NEXT(start, next);

	while (dev != NULL) {
		if (cmp(dev, rte_dev) == 0)
			break;

		dev = TAILQ_NEXT(dev, next);
	}
	rte_spinlock_unlock(&vdpa_device_list_lock);

	return dev;
}

static void *
vdpa_dev_iterate(const void *start,
		const char *str,
		const struct rte_dev_iterator *it)
{
	struct rte_vdpa_device *vdpa_dev = NULL;

	RTE_SET_USED(str);

	vdpa_dev = vdpa_find_device(start, vdpa_dev_match, it->device);

	return vdpa_dev;
}

static struct rte_class rte_class_vdpa = {
	.dev_iterate = vdpa_dev_iterate,
};

RTE_REGISTER_CLASS(vdpa, rte_class_vdpa);

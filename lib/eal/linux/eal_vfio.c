/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2018 Intel Corporation
 */

#include <uapi/linux/vfio.h>

#include <inttypes.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <dirent.h>

#include <rte_errno.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_eal_memconfig.h>
#include <rte_vfio.h>

#include <eal_export.h>
#include "eal_filesystem.h"
#include "eal_memcfg.h"
#include "eal_vfio.h"
#include "eal_private.h"
#include "eal_internal_cfg.h"

/*
 * rte_errno convention:
 *
 * - EINVAL: invalid parameters
 * - ENOTSUP: current mode does not support this operation
 * - ENOXIO: VFIO not initialized
 * - ENODEV: device not managed by VFIO
 * - ENOSPC: no space in config
 * - EEXIST: device already assigned
 * - ENOENT: group or device not found
 * - EIO: underlying VFIO operation failed
 */

/* functions can fail for multiple reasons, and errno is tedious */
enum vfio_result {
	VFIO_SUCCESS,
	VFIO_ERROR,
	VFIO_EXISTS,
	VFIO_NOT_SUPPORTED,
	VFIO_NOT_MANAGED,
	VFIO_NOT_FOUND,
	VFIO_NO_SPACE,
};

struct container containers[RTE_MAX_VFIO_CONTAINERS] = {0};
struct vfio_config global_cfg = {
	.mode = RTE_VFIO_MODE_NONE,
	.default_cfg = &containers[0]
};

static int vfio_dma_mem_map(struct container *cfg, uint64_t vaddr,
		uint64_t iova, uint64_t len, int do_map);

static int
is_null_map(const struct user_mem_map *map)
{
	return map->addr == 0 && map->iova == 0 &&
			map->len == 0 && map->chunk == 0;
}

/* we may need to merge user mem maps together in case of user mapping/unmapping
 * chunks of memory, so we'll need a comparator function to sort segments.
 */
static int
user_mem_map_cmp(const void *a, const void *b)
{
	const struct user_mem_map *umm_a = a;
	const struct user_mem_map *umm_b = b;

	/* move null entries to end */
	if (is_null_map(umm_a))
		return 1;
	if (is_null_map(umm_b))
		return -1;

	/* sort by iova first */
	if (umm_a->iova < umm_b->iova)
		return -1;
	if (umm_a->iova > umm_b->iova)
		return 1;

	if (umm_a->addr < umm_b->addr)
		return -1;
	if (umm_a->addr > umm_b->addr)
		return 1;

	if (umm_a->len < umm_b->len)
		return -1;
	if (umm_a->len > umm_b->len)
		return 1;

	if (umm_a->chunk < umm_b->chunk)
		return -1;
	if (umm_a->chunk > umm_b->chunk)
		return 1;

	return 0;
}

/*
 * Take in an address range and list of current mappings, and produce a list of
 * mappings that will be kept.
 */
static int
process_maps(struct user_mem_map *src, size_t src_len,
		struct user_mem_map newmap[2], uint64_t vaddr, uint64_t len)
{
	struct user_mem_map *src_first = &src[0];
	struct user_mem_map *src_last = &src[src_len - 1];
	struct user_mem_map *dst_first = &newmap[0];
	/* we can get at most two new segments */
	struct user_mem_map *dst_last = &newmap[1];
	uint64_t first_off = vaddr - src_first->addr;
	uint64_t last_off = (src_last->addr + src_last->len) - (vaddr + len);
	int newmap_len = 0;

	if (first_off != 0) {
		dst_first->addr = src_first->addr;
		dst_first->iova = src_first->iova;
		dst_first->len = first_off;
		dst_first->chunk = src_first->chunk;

		newmap_len++;
	}
	if (last_off != 0) {
		/* if we had start offset, we have two segments */
		struct user_mem_map *last =
				first_off == 0 ? dst_first : dst_last;
		last->addr = (src_last->addr + src_last->len) - last_off;
		last->iova = (src_last->iova + src_last->len) - last_off;
		last->len = last_off;
		last->chunk = src_last->chunk;

		newmap_len++;
	}
	return newmap_len;
}

/* erase certain maps from the list */
static void
delete_maps(struct user_mem_maps *user_mem_maps, struct user_mem_map *del_maps,
		size_t n_del)
{
	unsigned int i;
	size_t j;

	for (i = 0, j = 0; i < RTE_DIM(user_mem_maps->maps) && j < n_del; i++) {
		struct user_mem_map *left = &user_mem_maps->maps[i];
		struct user_mem_map *right = &del_maps[j];

		if (user_mem_map_cmp(left, right) == 0) {
			memset(left, 0, sizeof(*left));
			j++;
			user_mem_maps->n_maps--;
		}
	}
}

static void
copy_maps(struct user_mem_maps *user_mem_maps, struct user_mem_map *add_maps,
		size_t n_add)
{
	unsigned int i;
	size_t j;

	for (i = 0, j = 0; i < RTE_DIM(user_mem_maps->maps) && j < n_add; i++) {
		struct user_mem_map *left = &user_mem_maps->maps[i];
		struct user_mem_map *right = &add_maps[j];

		/* insert into empty space */
		if (is_null_map(left)) {
			memcpy(left, right, sizeof(*left));
			j++;
			user_mem_maps->n_maps++;
		}
	}
}

/* try merging two maps into one, return 1 if succeeded */
static int
merge_map(struct user_mem_map *left, struct user_mem_map *right)
{
	/* merge the same maps into one */
	if (memcmp(left, right, sizeof(struct user_mem_map)) == 0)
		goto out;

	if (left->addr + left->len != right->addr)
		return 0;
	if (left->iova + left->len != right->iova)
		return 0;
	if (left->chunk != right->chunk)
		return 0;
	left->len += right->len;

out:
	memset(right, 0, sizeof(*right));

	return 1;
}

static bool
addr_is_chunk_aligned(struct user_mem_map *maps, size_t n_maps,
		uint64_t vaddr, uint64_t iova)
{
	unsigned int i;

	for (i = 0; i < n_maps; i++) {
		struct user_mem_map *map = &maps[i];
		uint64_t map_va_end = map->addr + map->len;
		uint64_t map_iova_end = map->iova + map->len;
		uint64_t map_va_off = vaddr - map->addr;
		uint64_t map_iova_off = iova - map->iova;

		/* we include end of the segment in comparison as well */
		bool addr_in_map = (vaddr >= map->addr) && (vaddr <= map_va_end);
		bool iova_in_map = (iova >= map->iova) && (iova <= map_iova_end);
		/* chunk may not be power of two, so use modulo */
		bool addr_is_aligned = (map_va_off % map->chunk) == 0;
		bool iova_is_aligned = (map_iova_off % map->chunk) == 0;

		if (addr_in_map && iova_in_map &&
				addr_is_aligned && iova_is_aligned)
			return true;
	}
	return false;
}

static int
find_user_mem_maps(struct user_mem_maps *user_mem_maps, uint64_t addr,
		uint64_t iova, uint64_t len, struct user_mem_map *dst,
		size_t dst_len)
{
	uint64_t va_end = addr + len;
	uint64_t iova_end = iova + len;
	bool found = false;
	size_t j;
	int i, ret;

	for (i = 0, j = 0; i < user_mem_maps->n_maps; i++) {
		struct user_mem_map *map = &user_mem_maps->maps[i];
		uint64_t map_va_end = map->addr + map->len;
		uint64_t map_iova_end = map->iova + map->len;

		bool start_addr_in_map = (addr >= map->addr) &&
				(addr < map_va_end);
		bool end_addr_in_map = (va_end > map->addr) &&
				(va_end <= map_va_end);
		bool start_iova_in_map = (iova >= map->iova) &&
				(iova < map_iova_end);
		bool end_iova_in_map = (iova_end > map->iova) &&
				(iova_end <= map_iova_end);

		/* do we have space in temporary map? */
		if (j == dst_len) {
			ret = -ENOSPC;
			goto err;
		}
		/* check if current map is start of our segment */
		if (!found && start_addr_in_map && start_iova_in_map)
			found = true;
		/* if we have previously found a segment, add it to the map */
		if (found) {
			/* copy the segment into our temporary map */
			memcpy(&dst[j++], map, sizeof(*map));

			/* if we match end of segment, quit */
			if (end_addr_in_map && end_iova_in_map)
				return j;
		}
	}
	/* we didn't find anything */
	ret = -ENOENT;
err:
	memset(dst, 0, sizeof(*dst) * dst_len);
	return ret;
}

/* this will sort all user maps, and merge/compact any adjacent maps */
static void
compact_user_maps(struct user_mem_maps *user_mem_maps)
{
	unsigned int i;

	qsort(user_mem_maps->maps, RTE_DIM(user_mem_maps->maps),
			sizeof(user_mem_maps->maps[0]), user_mem_map_cmp);

	/* we'll go over the list backwards when merging */
	for (i = RTE_DIM(user_mem_maps->maps) - 2; i != 0; i--) {
		struct user_mem_map *l, *r;

		l = &user_mem_maps->maps[i];
		r = &user_mem_maps->maps[i + 1];

		if (is_null_map(l) || is_null_map(r))
			continue;

		/* try and merge the maps */
		if (merge_map(l, r))
			user_mem_maps->n_maps--;
	}

	/* the entries are still sorted, but now they have holes in them, so
	 * sort the list again.
	 */
	qsort(user_mem_maps->maps, RTE_DIM(user_mem_maps->maps),
			sizeof(user_mem_maps->maps[0]), user_mem_map_cmp);
}

/*
 * we will rely on kernel to not allow user to assign the same device to different containers, but
 * kernel will not prevent mapping the same device twice using two different fd's, so we need to
 * deduplicate our internal config to make sure we only store unique device fd's.
 */
static bool
fd_is_same(int fd1, int fd2)
{
	struct stat st1, st2;

	if (fd1 < 0 || fd2 < 0)
		return false;

	if (fstat(fd1, &st1) < 0)
		return false;
	if (fstat(fd2, &st2) < 0)
		return false;

	return st1.st_dev == st2.st_dev && st1.st_ino == st2.st_ino;
}

bool
vfio_container_is_default(struct container *cfg)
{
	return cfg == global_cfg.default_cfg;
}

static struct container *
vfio_container_get_by_fd(int container_fd)
{
	struct container *cfg;

	if (container_fd == RTE_VFIO_DEFAULT_CONTAINER_FD)
		return global_cfg.default_cfg;

	CONTAINER_FOREACH_ACTIVE(cfg) {
		if (cfg->container_fd == container_fd)
			return cfg;
	}
	return NULL;
}

static struct container *
vfio_container_get_by_group_num(int group_num)
{
	struct container *cfg;
	struct vfio_group *grp;

	CONTAINER_FOREACH_ACTIVE(cfg) {
		GROUP_FOREACH_ACTIVE(cfg, grp)
			if (grp->group_num == group_num)
				return cfg;
	}
	return NULL;
}

static struct container *
vfio_container_create(void)
{
	struct container *cfg;

	/* find an unused container config */
	CONTAINER_FOREACH(cfg) {
		if (!cfg->active) {
			*cfg = CONTAINER_INITIALIZER;
			cfg->active = true;
			return cfg;
		}
	}
	/* no space */
	return NULL;
}

static void
vfio_container_erase(struct container *cfg)
{
	if (cfg->container_fd >= 0 && close(cfg->container_fd))
		EAL_LOG(ERR, "Error when closing container, %d (%s)", errno, strerror(errno));

	*cfg = (struct container){0};
}

static struct vfio_device *
vfio_device_create(struct container *cfg)
{
	struct vfio_device *dev;

	/* is there space? */
	if (cfg->n_devices == RTE_DIM(cfg->devices))
		return NULL;

	DEVICE_FOREACH(cfg, dev) {
		if (dev->active)
			continue;
		dev->active = true;
		/* set to invalid fd */
		dev->fd = -1;

		cfg->n_devices++;
		return dev;
	}
	/* should not happen */
	EAL_LOG(WARNING, "Could not find space in device list for container");
	return NULL;
}

static void
vfio_device_erase(struct container *cfg, struct vfio_device *dev)
{
	if (dev->fd >= 0 && close(dev->fd))
		EAL_LOG(ERR, "Error when closing device, %d (%s)", errno, strerror(errno));

	*dev = (struct vfio_device){0};
	cfg->n_devices--;
}

RTE_EXPORT_SYMBOL(rte_vfio_get_group_fd)
int
rte_vfio_get_group_fd(int iommu_group_num)
{
	struct container *cfg;
	struct vfio_group *grp;

	if (global_cfg.mode == RTE_VFIO_MODE_NONE) {
		EAL_LOG(ERR, "VFIO support not initialized");
		rte_errno = ENXIO;
		return -1;
	}
	if (global_cfg.mode != RTE_VFIO_MODE_GROUP &&
			global_cfg.mode != RTE_VFIO_MODE_NOIOMMU) {
		EAL_LOG(ERR, "VFIO not initialized in group mode");
		rte_errno = ENOTSUP;
		return -1;
	}

	CONTAINER_FOREACH_ACTIVE(cfg) {
		GROUP_FOREACH_ACTIVE(cfg, grp)
			if (grp->group_num == iommu_group_num)
				return grp->fd;
	}

	/* group doesn't exist */
	EAL_LOG(ERR, "IOMMU group %d not bound to any VFIO container", iommu_group_num);
	rte_errno = ENOENT;
	return -1;
}

static void
vfio_mem_event_callback(enum rte_mem_event type, const void *addr, size_t len,
		void *arg __rte_unused)
{
	struct container *cfg = global_cfg.default_cfg;
	struct rte_memseg_list *msl;
	struct rte_memseg *ms;
	size_t cur_len = 0;

	msl = rte_mem_virt2memseg_list(addr);

	/* for IOVA as VA mode, no need to care for IOVA addresses */
	if (rte_eal_iova_mode() == RTE_IOVA_VA && msl->external == 0) {
		uint64_t vfio_va = (uint64_t)(uintptr_t)addr;
		uint64_t page_sz = msl->page_sz;

		/* Maintain granularity of DMA map/unmap to memseg size */
		for (; cur_len < len; cur_len += page_sz) {
			if (type == RTE_MEM_EVENT_ALLOC)
				vfio_dma_mem_map(cfg, vfio_va, vfio_va, page_sz, 1);
			else
				vfio_dma_mem_map(cfg, vfio_va, vfio_va, page_sz, 0);
			vfio_va += page_sz;
		}

		return;
	}

	/* memsegs are contiguous in memory */
	ms = rte_mem_virt2memseg(addr, msl);
	while (cur_len < len) {
		/* some memory segments may have invalid IOVA */
		if (ms->iova == RTE_BAD_IOVA) {
			EAL_LOG(DEBUG,
				"Memory segment at %p has bad IOVA, skipping",
				ms->addr);
			goto next;
		}
		if (type == RTE_MEM_EVENT_ALLOC)
			vfio_dma_mem_map(cfg, ms->addr_64, ms->iova, ms->len, 1);
		else
			vfio_dma_mem_map(cfg, ms->addr_64, ms->iova, ms->len, 0);
next:
		cur_len += ms->len;
		++ms;
	}
}

RTE_EXPORT_SYMBOL(rte_vfio_clear_group)
int
rte_vfio_clear_group(int vfio_group_fd)
{
	struct container *cfg;
	struct vfio_group *grp;
	struct vfio_device *dev;

	if (global_cfg.mode == RTE_VFIO_MODE_NONE) {
		EAL_LOG(ERR, "VFIO support not initialized");
		rte_errno = ENXIO;
		return -1;
	}

	if (global_cfg.mode != RTE_VFIO_MODE_GROUP &&
			global_cfg.mode != RTE_VFIO_MODE_NOIOMMU) {
		EAL_LOG(ERR, "VFIO not initialized in group mode");
		rte_errno = ENOTSUP;
		return -1;
	}

	/* find our group */
	CONTAINER_FOREACH_ACTIVE(cfg) {
		GROUP_FOREACH_ACTIVE(cfg, grp) {
			if (grp->fd != vfio_group_fd)
				continue;
			/* clear out all devices within this group */
			DEVICE_FOREACH_ACTIVE(cfg, dev) {
				if (dev->group != grp->group_num)
					continue;
				vfio_device_erase(cfg, dev);
			}
			/* clear out group itself */
			vfio_group_erase(cfg, grp);
			return 0;
		}
	}

	rte_errno = ENOENT;
	return -1;
}

static int
vfio_register_mem_event_callback(void)
{
	int ret;

	ret = rte_mem_event_callback_register(VFIO_MEM_EVENT_CLB_NAME,
			vfio_mem_event_callback, NULL);

	if (ret && rte_errno != ENOTSUP) {
		EAL_LOG(ERR, "Could not install memory event callback for VFIO");
		return -1;
	}
	if (ret)
		EAL_LOG(DEBUG, "Memory event callbacks not supported");
	else
		EAL_LOG(DEBUG, "Installed memory event callback for VFIO");

	return 0;
}

static int
vfio_setup_dma_mem(struct container *cfg)
{
	struct user_mem_maps *user_mem_maps = &cfg->mem_maps;
	int i, ret;

	/* do we need to map DPDK-managed memory? */
	if (vfio_container_is_default(cfg) && rte_eal_process_type() == RTE_PROC_PRIMARY)
		ret = global_cfg.ops->dma_map_func(cfg);
	else
		ret = 0;
	if (ret) {
		EAL_LOG(ERR, "DMA remapping failed, error %i (%s)",
			errno, strerror(errno));
		return -1;
	}

	/*
	 * not all IOMMU types support DMA mapping, but if we have mappings in the list - that
	 * means we have previously mapped something successfully, so we can be sure that DMA
	 * mapping is supported.
	 */
	for (i = 0; i < user_mem_maps->n_maps; i++) {
		struct user_mem_map *map;
		map = &user_mem_maps->maps[i];

		ret = global_cfg.ops->dma_user_map_func(cfg, map->addr, map->iova, map->len, 1);
		if (ret) {
			EAL_LOG(ERR, "Couldn't map user memory for DMA: "
					"va: 0x%" PRIx64 " "
					"iova: 0x%" PRIx64 " "
					"len: 0x%" PRIu64,
					map->addr, map->iova,
					map->len);
			return -1;
		}
	}

	return 0;
}

static enum vfio_result
vfio_group_assign_device(struct container *cfg, const char *sysfs_base,
		const char *dev_addr, struct vfio_device **out_dev)
{
	struct vfio_group_config *group_cfg = &cfg->group_cfg;
	struct vfio_group *grp;
	struct vfio_device *idev, *dev;
	int iommu_group_num;
	enum vfio_result res;
	int ret;

	/* allocate new device in config */
	dev = vfio_device_create(cfg);
	if (dev == NULL) {
		EAL_LOG(ERR, "No space to track new VFIO device");
		return VFIO_NO_SPACE;
	}

	/* remember to register mem event callback for default container in primary */
	bool need_clb = vfio_container_is_default(cfg) &&
			rte_eal_process_type() == RTE_PROC_PRIMARY;

	/* get group number for this device */
	ret = vfio_group_get_num(sysfs_base, dev_addr, &iommu_group_num);
	if (ret < 0) {
		EAL_LOG(ERR, "Cannot get IOMMU group for %s", dev_addr);
		res = VFIO_ERROR;
		goto device_erase;
	} else if (ret == 0) {
		res = VFIO_NOT_MANAGED;
		goto device_erase;
	}

	/* group may already exist as multiple devices may share group */
	grp = vfio_group_get_by_num(cfg, iommu_group_num);
	if (grp == NULL) {
		/* no device currently uses this group, create it */
		grp = vfio_group_create(cfg, iommu_group_num);
		if (grp == NULL) {
			EAL_LOG(ERR, "Cannot allocate group for device %s", dev_addr);
			res = VFIO_NO_SPACE;
			goto device_erase;
		}

		/* open group fd */
		ret = vfio_group_open_fd(cfg, grp);
		if (ret == -ENOENT) {
			EAL_LOG(DEBUG, "Device %s (IOMMU group %d) not managed by VFIO",
					dev_addr, iommu_group_num);
			res = VFIO_NOT_MANAGED;
			goto group_erase;
		} else if (ret < 0) {
			EAL_LOG(ERR, "Cannot open VFIO group %d for device %s",
				iommu_group_num, dev_addr);
			res = VFIO_ERROR;
			goto group_erase;
		}

		/* prepare group (viability + container attach) */
		ret = vfio_group_prepare(cfg, grp);
		if (ret < 0) {
			res = VFIO_ERROR;
			goto group_erase;
		}

		/* set up IOMMU type once per container */
		if (!group_cfg->iommu_type_set) {
			ret = vfio_group_setup_iommu(cfg);
			if (ret < 0) {
				res = VFIO_ERROR;
				goto group_erase;
			}
			group_cfg->iommu_type_set = true;
		}

		/* set up DMA memory once per container */
		if (!group_cfg->dma_setup_done) {
			rte_spinlock_recursive_lock(&cfg->mem_maps.lock);
			ret = vfio_setup_dma_mem(cfg);
			rte_spinlock_recursive_unlock(&cfg->mem_maps.lock);
			if (ret < 0) {
				EAL_LOG(ERR, "DMA remapping for %s failed", dev_addr);
				res = VFIO_ERROR;
				goto group_erase;
			}
			group_cfg->dma_setup_done = true;
		}

		/* set up mem event callback if needed */
		if (need_clb && !group_cfg->mem_event_clb_set) {
			ret = vfio_register_mem_event_callback();
			if (ret < 0) {
				res = VFIO_ERROR;
				goto group_erase;
			}
			group_cfg->mem_event_clb_set = true;
		}
	}

	/* open dev fd */
	ret = vfio_group_setup_device_fd(dev_addr, grp, dev);
	if (ret < 0) {
		EAL_LOG(ERR, "Cannot open VFIO device %s, error %i (%s)",
				dev_addr, errno, strerror(errno));
		res = VFIO_ERROR;
		goto group_erase;
	}

	/*
	 * we want to prevent user from assigning devices twice to prevent resource leaks, but for
	 * group mode this is not trivial, as there is no direct way to know which fd belongs to
	 * which group/device, except for directly comparing fd's with stat. so, that's what we're
	 * going to do. we do not need to look in other configs as if we were to attempt to use a
	 * different container, the kernel wouldn't have allowed us to bind the group to the
	 * container in the first place.
	 */
	DEVICE_FOREACH_ACTIVE(cfg, idev) {
		if (fd_is_same(idev->fd, dev->fd)) {
			EAL_LOG(ERR, "Device %s already assigned to this container",
					dev_addr);
			res = VFIO_EXISTS;
			*out_dev = idev;
			goto dev_remove;
		}
	}
	*out_dev = dev;
	return VFIO_SUCCESS;
dev_remove:
	/* device will be closed, but we still need to keep the group consistent */
	grp->n_devices--;
group_erase:
	/* this may be a pre-existing group so only erase it if it has no devices */
	if (grp->n_devices == 0)
		vfio_group_erase(cfg, grp);
	/* if we registered callback, unregister it */
	if (group_cfg->n_groups == 0 && group_cfg->mem_event_clb_set) {
		rte_mem_event_callback_unregister(VFIO_MEM_EVENT_CLB_NAME, NULL);
		group_cfg->mem_event_clb_set = false;
	}
device_erase:
	vfio_device_erase(cfg, dev);
	return res;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_vfio_container_assign_device, 26.03)
int
rte_vfio_container_assign_device(int container_fd, const char *sysfs_base, const char *dev_addr)
{
	struct container *cfg;
	enum vfio_result res;
	struct vfio_device *dev;

	if (sysfs_base == NULL || dev_addr == NULL) {
		rte_errno = EINVAL;
		return -1;
	}

	if (global_cfg.mode == RTE_VFIO_MODE_NONE) {
		EAL_LOG(ERR, "VFIO support not initialized");
		rte_errno = ENXIO;
		return -1;
	}

	cfg = vfio_container_get_by_fd(container_fd);
	if (cfg == NULL) {
		EAL_LOG(ERR, "Invalid VFIO container fd");
		rte_errno = EINVAL;
		return -1;
	}
	/* protect memory configuration while setting up IOMMU/DMA */
	rte_mcfg_mem_read_lock();

	switch (global_cfg.mode) {
	case RTE_VFIO_MODE_GROUP:
	case RTE_VFIO_MODE_NOIOMMU:
		res = vfio_group_assign_device(cfg, sysfs_base, dev_addr, &dev);
		break;
	default:
		EAL_LOG(ERR, "Unsupported VFIO mode");
		res = VFIO_NOT_SUPPORTED;
		break;
	}
	rte_mcfg_mem_read_unlock();

	switch (res) {
	case VFIO_SUCCESS:
		return 0;
	case VFIO_EXISTS:
		rte_errno = EEXIST;
		return -1;
	case VFIO_NOT_MANAGED:
		EAL_LOG(DEBUG, "Device %s not managed by VFIO", dev_addr);
		rte_errno = ENODEV;
		return -1;
	case VFIO_NO_SPACE:
		EAL_LOG(ERR, "No space in VFIO container to assign device %s", dev_addr);
		rte_errno = ENOSPC;
		return -1;
	default:
		EAL_LOG(ERR, "Error assigning device %s to container", dev_addr);
		rte_errno = EIO;
		return -1;
	}
}

RTE_EXPORT_SYMBOL(rte_vfio_setup_device)
int
rte_vfio_setup_device(const char *sysfs_base, const char *dev_addr,
		int *vfio_dev_fd, struct vfio_device_info *device_info)
{
	struct container *cfg;
	struct vfio_device *dev;
	enum vfio_result res;
	int ret;

	if (sysfs_base == NULL || dev_addr == NULL || vfio_dev_fd == NULL) {
		rte_errno = EINVAL;
		return -1;
	}

	if (global_cfg.mode == RTE_VFIO_MODE_NONE) {
		EAL_LOG(ERR, "VFIO support not initialized");
		rte_errno = ENXIO;
		return -1;
	}

	rte_mcfg_mem_read_lock();

	switch (global_cfg.mode) {
	case RTE_VFIO_MODE_GROUP:
	case RTE_VFIO_MODE_NOIOMMU:
	{
		int iommu_group_num;

		/* find group number */
		ret = vfio_group_get_num(sysfs_base, dev_addr, &iommu_group_num);
		if (ret < 0) {
			EAL_LOG(ERR, "Cannot get IOMMU group for %s", dev_addr);
			goto unlock;
		} else if (ret == 0) {
			EAL_LOG(DEBUG, "Device %s not managed by VFIO", dev_addr);
			ret = 1;
			goto unlock;
		}

		/* find config by group */
		cfg = vfio_container_get_by_group_num(iommu_group_num);
		if (cfg == NULL)
			cfg = global_cfg.default_cfg;

		res = vfio_group_assign_device(cfg, sysfs_base, dev_addr, &dev);
		break;
	}
	default:
		EAL_LOG(ERR, "Unsupported VFIO mode");
		rte_errno = ENOTSUP;
		ret = -1;
		goto unlock;
	}

	switch (res) {
	case VFIO_NOT_MANAGED:
		EAL_LOG(DEBUG, "Device %s not managed by VFIO", dev_addr);
		rte_errno = ENODEV;
		ret = -1;
		goto unlock;
	case VFIO_SUCCESS:
	case VFIO_EXISTS:
		break;
	case VFIO_NO_SPACE:
		EAL_LOG(ERR, "No space in VFIO container to assign device %s", dev_addr);
		rte_errno = ENOSPC;
		ret = -1;
		goto unlock;
	default:
		EAL_LOG(ERR, "Error assigning device %s to container", dev_addr);
		rte_errno = EIO;
		ret = -1;
		goto unlock;
	}

	/* populate device info */
	if (device_info != NULL) {
		ret = rte_vfio_get_device_info(dev->fd, device_info);
		if (ret < 0) {
			EAL_LOG(ERR, "Could not get VFIO device info for %s", dev_addr);
			/* if device didn't exist before we entered this function, release it */
			if (res == VFIO_SUCCESS)
				rte_vfio_release_device(sysfs_base, dev_addr, dev->fd);
			goto unlock;
		}
	}
	*vfio_dev_fd = dev->fd;

	/* success */
	ret = 0;

unlock:
	rte_mcfg_mem_read_unlock();

	return ret;
}

RTE_EXPORT_SYMBOL(rte_vfio_release_device)
int
rte_vfio_release_device(const char *sysfs_base __rte_unused,
		const char *dev_addr, int vfio_dev_fd)
{
	struct container *cfg = NULL, *icfg;
	struct vfio_device *dev = NULL, *idev;
	int ret;

	if (sysfs_base == NULL || dev_addr == NULL) {
		rte_errno = EINVAL;
		return -1;
	}

	if (global_cfg.mode == RTE_VFIO_MODE_NONE) {
		EAL_LOG(ERR, "VFIO support not initialized");
		rte_errno = ENXIO;
		return -1;
	}

	rte_mcfg_mem_read_lock();

	/* we need to find both config and device */
	CONTAINER_FOREACH_ACTIVE(icfg) {
		DEVICE_FOREACH_ACTIVE(icfg, idev) {
			if (idev->fd != vfio_dev_fd)
				continue;
			cfg = icfg;
			dev = idev;
			goto found;
		}
	}
found:
	if (dev == NULL) {
		EAL_LOG(ERR, "Device %s not managed by any container", dev_addr);
		rte_errno = ENOENT;
		ret = -1;
		goto unlock;
	}

	switch (global_cfg.mode) {
	case RTE_VFIO_MODE_GROUP:
	case RTE_VFIO_MODE_NOIOMMU:
	{
		int iommu_group_num = dev->group;
		struct vfio_group_config *group_cfg = &cfg->group_cfg;
		struct vfio_group *grp;

		bool need_clb = vfio_container_is_default(cfg) &&
				rte_eal_process_type() == RTE_PROC_PRIMARY;

		/* find the group */
		grp = vfio_group_get_by_num(cfg, iommu_group_num);
		if (grp == NULL) {
			/* shouldn't happen because we already know the device is valid */
			EAL_LOG(ERR, "IOMMU group %d not found in container",
					iommu_group_num);
			rte_errno = EIO;
			ret = -1;
			goto unlock;
		}

		/* close device handle */
		vfio_device_erase(cfg, dev);

		/* remove device from group */
		grp->n_devices--;

		/* was this the last device? */
		if (grp->n_devices == 0)
			vfio_group_erase(cfg, grp);

		/* if no more groups left, remove callback */
		if (need_clb && group_cfg->n_groups == 0 && group_cfg->mem_event_clb_set) {
			rte_mem_event_callback_unregister(VFIO_MEM_EVENT_CLB_NAME, NULL);
			group_cfg->mem_event_clb_set = false;
		}
		break;
	}
	default:
		EAL_LOG(ERR, "Unsupported VFIO mode");
		rte_errno = ENOTSUP;
		ret = -1;
		goto unlock;
	}
	ret = 0;
unlock:
	rte_mcfg_mem_read_unlock();

	return ret;
}

static int
vfio_sync_mode(struct container *cfg, enum rte_vfio_mode *mode)
{
	struct vfio_mp_param *p;
	struct rte_mp_msg mp_req = {0};
	struct rte_mp_reply mp_reply = {0};
	struct timespec ts = {5, 0};

	/* request iommufd from primary via mp_sync */
	rte_strscpy(mp_req.name, EAL_VFIO_MP, sizeof(mp_req.name));
	mp_req.len_param = sizeof(*p);
	mp_req.num_fds = 0;
	p = (struct vfio_mp_param *)mp_req.param;
	p->req = SOCKET_REQ_CONTAINER;

	if (rte_mp_request_sync(&mp_req, &mp_reply, &ts) == 0 &&
			mp_reply.nb_received == 1) {
		struct rte_mp_msg *mp_rep;
		mp_rep = &mp_reply.msgs[0];
		p = (struct vfio_mp_param *)mp_rep->param;
		if (p->result == SOCKET_OK && mp_rep->num_fds == 1) {
			cfg->container_fd = mp_rep->fds[0];
			*mode = p->mode;
			free(mp_reply.msgs);
			return 0;
		}
	}

	free(mp_reply.msgs);
	EAL_LOG(ERR, "Cannot request container_fd");
	return -1;
}

static enum rte_vfio_mode
vfio_select_mode(void)
{
	struct container *cfg;
	enum rte_vfio_mode mode = RTE_VFIO_MODE_NONE;

	cfg = vfio_container_create();
	/* cannot happen */
	if (cfg == NULL || cfg != global_cfg.default_cfg) {
		EAL_LOG(ERR, "Unexpected VFIO config structure");
		return RTE_VFIO_MODE_NONE;
	}

	/* for secondary, just ask the primary for the container and mode */
	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		struct vfio_group_config *group_cfg = &cfg->group_cfg;

		if (vfio_sync_mode(cfg, &mode) < 0)
			goto err;

		/* primary handles DMA setup for default containers */
		group_cfg->dma_setup_done = true;
		return mode;
	}
	/* if we failed mp sync setup, we cannot initialize VFIO */
	if (vfio_mp_sync_setup() < 0)
		return RTE_VFIO_MODE_NONE;

	/* try group mode first */
	if (vfio_group_enable(cfg) == 0) {
		/* check for noiommu */
		int ret = vfio_group_noiommu_is_enabled();
		if (ret < 0)
			goto err_mpsync;
		else if (ret == 1)
			return RTE_VFIO_MODE_NOIOMMU;
		return RTE_VFIO_MODE_GROUP;
	}
err_mpsync:
	vfio_mp_sync_cleanup();
err:
	vfio_container_erase(cfg);

	return RTE_VFIO_MODE_NONE;
}

static const char *
vfio_mode_to_str(enum rte_vfio_mode mode)
{
	switch (mode) {
	case RTE_VFIO_MODE_GROUP: return "group";
	case RTE_VFIO_MODE_NOIOMMU: return "noiommu";
	default: return "not initialized";
	}
}

RTE_EXPORT_SYMBOL(rte_vfio_enable)
int
rte_vfio_enable(const char *modname)
{
	int vfio_available;
	enum rte_vfio_mode mode = RTE_VFIO_MODE_NONE;

	if (modname == NULL) {
		rte_errno = EINVAL;
		return -1;
	}

	EAL_LOG(DEBUG, "Probing VFIO support...");

	/* check if vfio module is loaded */
	vfio_available = rte_eal_check_module(modname);

	/* return error directly */
	if (vfio_available == -1) {
		EAL_LOG(INFO, "Could not get loaded module details!");
		return -1;
	}

	/* return 0 if VFIO modules not loaded */
	if (vfio_available == 0) {
		EAL_LOG(DEBUG,
			"VFIO modules not loaded, skipping VFIO support...");
		return 0;
	}
	EAL_LOG(DEBUG, "VFIO module '%s' loaded, attempting to initialize VFIO...", modname);
	mode = vfio_select_mode();

	/* have we initialized anything? */
	if (mode == RTE_VFIO_MODE_NONE)
		EAL_LOG(NOTICE, "VFIO support could not be initialized");
	else
		EAL_LOG(NOTICE, "VFIO support initialized: %s mode", vfio_mode_to_str(mode));

	global_cfg.mode = mode;

	return 0;
}

RTE_EXPORT_SYMBOL(rte_vfio_is_enabled)
int
rte_vfio_is_enabled(const char *modname)
{
	const int mod_available = modname ? rte_eal_check_module(modname) > 0 : 0;
	return global_cfg.default_cfg->active && mod_available;
}

int
vfio_get_iommu_type(void)
{
	if (global_cfg.ops == NULL)
		return -1;

	return global_cfg.ops->type_id;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_vfio_get_device_info, 26.03)
int
rte_vfio_get_device_info(int vfio_dev_fd, struct vfio_device_info *device_info)
{
	int ret;

	if (device_info == NULL) {
		rte_errno = EINVAL;
		return -1;
	}

	if (global_cfg.mode == RTE_VFIO_MODE_NONE) {
		EAL_LOG(ERR, "VFIO support not initialized");
		rte_errno = ENXIO;
		return -1;
	}

	ret = ioctl(vfio_dev_fd, VFIO_DEVICE_GET_INFO, device_info);
	if (ret) {
		EAL_LOG(ERR, "Cannot get device info, error %d (%s)", errno, strerror(errno));
		rte_errno = errno;
		return -1;
	}

	return 0;
}

RTE_EXPORT_SYMBOL(rte_vfio_get_container_fd)
int
rte_vfio_get_container_fd(void)
{
	if (global_cfg.mode != RTE_VFIO_MODE_NONE)
		return global_cfg.default_cfg->container_fd;

	EAL_LOG(ERR, "VFIO support not initialized");
	rte_errno = ENXIO;
	return -1;
}

RTE_EXPORT_SYMBOL(rte_vfio_get_group_num)
int
rte_vfio_get_group_num(const char *sysfs_base, const char *dev_addr, int *iommu_group_num)
{
	int ret;

	if (sysfs_base == NULL || dev_addr == NULL || iommu_group_num == NULL) {
		rte_errno = EINVAL;
		return -1;
	}

	if (global_cfg.mode == RTE_VFIO_MODE_NONE) {
		EAL_LOG(ERR, "VFIO support not initialized");
		rte_errno = ENXIO;
		return -1;
	}
	if (global_cfg.mode != RTE_VFIO_MODE_GROUP && global_cfg.mode != RTE_VFIO_MODE_NOIOMMU) {
		EAL_LOG(ERR, "VFIO not initialized in group mode");
		rte_errno = ENOTSUP;
		return -1;
	}
	ret = vfio_group_get_num(sysfs_base, dev_addr, iommu_group_num);
	if (ret < 0) {
		rte_errno = EINVAL;
		return -1;
	} else if (ret == 0) {
		rte_errno = ENODEV;
		return -1;
	}
	return 0;
}

static int
vfio_dma_mem_map(struct container *cfg, uint64_t vaddr, uint64_t iova,
		uint64_t len, int do_map)
{
	const struct vfio_iommu_ops *t = global_cfg.ops;

	if (!t) {
		EAL_LOG(ERR, "VFIO support not initialized");
		return -1;
	}

	if (!t->dma_user_map_func) {
		EAL_LOG(ERR,
			"VFIO custom DMA region mapping not supported by IOMMU %s",
			t->name);
		return -1;
	}

	return t->dma_user_map_func(cfg, vaddr, iova, len, do_map);
}

static int
container_dma_map(struct container *cfg, uint64_t vaddr, uint64_t iova,
		uint64_t len)
{
	struct user_mem_map *new_map;
	struct user_mem_maps *user_mem_maps;
	bool has_partial_unmap;
	int ret = 0;

	user_mem_maps = &cfg->mem_maps;
	rte_spinlock_recursive_lock(&user_mem_maps->lock);
	if (user_mem_maps->n_maps == RTE_DIM(user_mem_maps->maps)) {
		EAL_LOG(ERR, "No more space for user mem maps");
		ret = -1;
		goto out;
	}
	/* map the entry */
	if (vfio_dma_mem_map(cfg, vaddr, iova, len, 1)) {
		/* technically, this will fail if there are currently no devices
		 * plugged in, even if a device were added later, this mapping
		 * might have succeeded. however, since we cannot verify if this
		 * is a valid mapping without having a device attached, consider
		 * this to be unsupported, because we can't just store any old
		 * mapping and pollute list of active mappings willy-nilly.
		 */
		EAL_LOG(ERR, "Couldn't map new region for DMA");
		ret = -1;
		goto out;
	}
	/* do we have partial unmap support? */
	has_partial_unmap = global_cfg.ops->partial_unmap;

	/* create new user mem map entry */
	new_map = &user_mem_maps->maps[user_mem_maps->n_maps++];
	new_map->addr = vaddr;
	new_map->iova = iova;
	new_map->len = len;
	/* for IOMMU types supporting partial unmap, we don't need chunking */
	new_map->chunk = has_partial_unmap ? 0 : len;

	compact_user_maps(user_mem_maps);
out:
	rte_spinlock_recursive_unlock(&user_mem_maps->lock);
	return ret;
}

static int
container_dma_unmap(struct container *cfg, uint64_t vaddr, uint64_t iova,
		uint64_t len)
{
	struct user_mem_map orig_maps[RTE_DIM(cfg->mem_maps.maps)];
	struct user_mem_map new_maps[2]; /* can be at most 2 */
	struct user_mem_maps *user_mem_maps;
	int n_orig, n_new, ret = 0;
	bool has_partial_unmap;
	unsigned int newlen;

	user_mem_maps = &cfg->mem_maps;
	rte_spinlock_recursive_lock(&user_mem_maps->lock);

	/*
	 * Previously, we had adjacent mappings entirely contained within one
	 * mapping entry. Since we now store original mapping length in some
	 * cases, this is no longer the case, so unmapping can potentially go
	 * over multiple segments and split them in any number of ways.
	 *
	 * To complicate things further, some IOMMU types support arbitrary
	 * partial unmapping, while others will only support unmapping along the
	 * chunk size, so there are a lot of cases we need to handle. To make
	 * things easier code wise, instead of trying to adjust existing
	 * mappings, let's just rebuild them using information we have.
	 */

	/*
	 * first thing to do is check if there exists a mapping that includes
	 * the start and the end of our requested unmap. We need to collect all
	 * maps that include our unmapped region.
	 */
	n_orig = find_user_mem_maps(user_mem_maps, vaddr, iova, len,
			orig_maps, RTE_DIM(orig_maps));
	/* did we find anything? */
	if (n_orig < 0) {
		EAL_LOG(ERR, "Couldn't find previously mapped region");
		ret = -1;
		goto out;
	}

	/* do we have partial unmap capability? */
	has_partial_unmap = global_cfg.ops->partial_unmap;

	/*
	 * if we don't support partial unmap, we must check if start and end of
	 * current unmap region are chunk-aligned.
	 */
	if (!has_partial_unmap) {
		bool start_aligned, end_aligned;

		start_aligned = addr_is_chunk_aligned(orig_maps, n_orig,
				vaddr, iova);
		end_aligned = addr_is_chunk_aligned(orig_maps, n_orig,
				vaddr + len, iova + len);

		if (!start_aligned || !end_aligned) {
			EAL_LOG(DEBUG, "DMA partial unmap unsupported");
			ret = -1;
			goto out;
		}
	}

	/*
	 * now we know we can potentially unmap the region, but we still have to
	 * figure out if there is enough space in our list to store remaining
	 * maps. for this, we will figure out how many segments we are going to
	 * remove, and how many new segments we are going to create.
	 */
	n_new = process_maps(orig_maps, n_orig, new_maps, vaddr, len);

	/* can we store the new maps in our list? */
	newlen = (user_mem_maps->n_maps - n_orig) + n_new;
	if (newlen >= RTE_DIM(user_mem_maps->maps)) {
		EAL_LOG(ERR, "Not enough space to store partial mapping");
		ret = -1;
		goto out;
	}

	/* unmap the entry */
	if (vfio_dma_mem_map(cfg, vaddr, iova, len, 0)) {
		/* there may not be any devices plugged in, so unmapping will
		 * fail, but that doesn't stop us from removing the mapping,
		 * as the assumption is we won't be needing this memory any
		 * more and thus will want to prevent it from being remapped
		 * again on hotplug. Ignore the error and proceed with
		 * removing the mapping from our records.
		 */
		EAL_LOG(DEBUG, "DMA unmapping failed, but removing mappings anyway");
	}

	/* we have unmapped the region, so now update the maps */
	delete_maps(user_mem_maps, orig_maps, n_orig);
	copy_maps(user_mem_maps, new_maps, n_new);
	compact_user_maps(user_mem_maps);
out:
	rte_spinlock_recursive_unlock(&user_mem_maps->lock);
	return ret;
}

RTE_EXPORT_SYMBOL(rte_vfio_noiommu_is_enabled)
int
rte_vfio_noiommu_is_enabled(void)
{
	return global_cfg.mode == RTE_VFIO_MODE_NOIOMMU;
}

RTE_EXPORT_SYMBOL(rte_vfio_container_create)
int
rte_vfio_container_create(void)
{
	struct container *cfg;
	int container_fd;

	if (global_cfg.mode == RTE_VFIO_MODE_NONE) {
		EAL_LOG(ERR, "VFIO not initialized");
		rte_errno = ENXIO;
		return -1;
	}
	cfg = vfio_container_create();
	if (cfg == NULL) {
		EAL_LOG(ERR, "Reached VFIO container limit");
		rte_errno = ENOSPC;
		return -1;
	}

	switch (global_cfg.mode) {
	case RTE_VFIO_MODE_GROUP:
	case RTE_VFIO_MODE_NOIOMMU:
	{
		container_fd = vfio_group_open_container_fd();
		if (container_fd < 0) {
			EAL_LOG(ERR, "Fail to create a new VFIO container");
			rte_errno = EIO;
			goto err;
		}
		cfg->container_fd = container_fd;
		break;
	}
	default:
		EAL_LOG(NOTICE, "Unsupported VFIO mode");
		rte_errno = ENOTSUP;
		goto err;
	}
	return container_fd;
err:
	vfio_container_erase(cfg);
	return -1;
}

RTE_EXPORT_SYMBOL(rte_vfio_container_destroy)
int
rte_vfio_container_destroy(int container_fd)
{
	struct container *cfg;
	struct vfio_device *dev;

	if (global_cfg.mode == RTE_VFIO_MODE_NONE) {
		EAL_LOG(ERR, "VFIO not initialized");
		rte_errno = ENXIO;
		return -1;
	}

	cfg = vfio_container_get_by_fd(container_fd);
	if (cfg == NULL) {
		EAL_LOG(ERR, "VFIO container fd not managed by VFIO");
		rte_errno = ENODEV;
		return -1;
	}
	/* forbid destroying default container */
	if (vfio_container_is_default(cfg)) {
		EAL_LOG(ERR, "Cannot destroy default VFIO container");
		rte_errno = EINVAL;
		return -1;
	}

	switch (global_cfg.mode) {
	case RTE_VFIO_MODE_GROUP:
	case RTE_VFIO_MODE_NOIOMMU:
		/* erase all devices */
		DEVICE_FOREACH_ACTIVE(cfg, dev) {
			EAL_LOG(DEBUG, "Device in IOMMU group %d still open, closing", dev->group);
			/*
			 * technically we could've done back-reference lookup and closed our groups
			 * following a device close, but since we're closing and erasing all groups
			 * anyway, we can afford to not bother.
			 */
			vfio_device_erase(cfg, dev);
		}

		/* erase all groups */
		struct vfio_group *grp;
		GROUP_FOREACH_ACTIVE(cfg, grp) {
			EAL_LOG(DEBUG, "IOMMU group %d still open, closing", grp->group_num);
			vfio_group_erase(cfg, grp);
		}
		break;
	default:
		EAL_LOG(ERR, "Unsupported VFIO mode");
		rte_errno = ENOTSUP;
		return -1;
	}

	/* erase entire config */
	vfio_container_erase(cfg);

	return 0;
}

RTE_EXPORT_SYMBOL(rte_vfio_container_group_bind)
int
rte_vfio_container_group_bind(int container_fd, int iommu_group_num)
{
	struct container *cfg;
	struct vfio_group *grp;
	int ret;

	if (global_cfg.mode == RTE_VFIO_MODE_NONE) {
		EAL_LOG(ERR, "VFIO support not initialized");
		rte_errno = ENXIO;
		return -1;
	}
	if (global_cfg.mode != RTE_VFIO_MODE_GROUP && global_cfg.mode != RTE_VFIO_MODE_NOIOMMU) {
		EAL_LOG(ERR, "VFIO not initialized in group mode");
		rte_errno = ENOTSUP;
		return -1;
	}

	cfg = vfio_container_get_by_fd(container_fd);
	if (cfg == NULL) {
		EAL_LOG(ERR, "Invalid VFIO container fd");
		rte_errno = EINVAL;
		return -1;
	}

	/* does the group already exist and already bound? */
	grp = vfio_group_get_by_num(cfg, iommu_group_num);
	if (grp != NULL)
		return 0;

	/* group doesn't exist, create it */
	grp = vfio_group_create(cfg, iommu_group_num);
	if (grp == NULL) {
		EAL_LOG(ERR, "Failed to bind VFIO group %d", iommu_group_num);
		rte_errno = ENOSPC;
		return -1;
	}

	/* group created, now open fd */
	ret = vfio_group_open_fd(cfg, grp);
	if (ret == -ENOENT) {
		EAL_LOG(ERR, "IOMMU group %d not managed by VFIO", iommu_group_num);
		vfio_group_erase(cfg, grp);
		rte_errno = ENODEV;
		return -1;
	} else if (ret < 0) {
		EAL_LOG(ERR, "Cannot open VFIO group %d", iommu_group_num);
		rte_errno = errno;
		vfio_group_erase(cfg, grp);
		return -1;
	}

	/* we're done */
	return 0;
}

RTE_EXPORT_SYMBOL(rte_vfio_container_group_unbind)
int
rte_vfio_container_group_unbind(int container_fd, int iommu_group_num)
{
	struct container *cfg;
	struct vfio_group *grp;
	struct vfio_device *dev;

	if (global_cfg.mode == RTE_VFIO_MODE_NONE) {
		EAL_LOG(ERR, "VFIO support not initialized");
		rte_errno = ENODEV;
		return -1;
	}

	if (global_cfg.mode != RTE_VFIO_MODE_GROUP && global_cfg.mode != RTE_VFIO_MODE_NOIOMMU) {
		EAL_LOG(ERR, "VFIO not initialized in group mode");
		rte_errno = ENOTSUP;
		return -1;
	}

	/* find container */
	cfg = vfio_container_get_by_fd(container_fd);
	if (cfg == NULL) {
		EAL_LOG(ERR, "Invalid VFIO container fd");
		rte_errno = EINVAL;
		return -1;
	}

	/* find the group */
	grp = vfio_group_get_by_num(cfg, iommu_group_num);
	if (grp == NULL) {
		EAL_LOG(ERR, "VFIO group %d not found in container", iommu_group_num);
		rte_errno = ENOENT;
		return -1;
	}

	/* remove all devices from this group */
	DEVICE_FOREACH_ACTIVE(cfg, dev) {
		if (dev->group != grp->group_num)
			continue;
		vfio_device_erase(cfg, dev);
	}

	vfio_group_erase(cfg, grp);

	return 0;
}

RTE_EXPORT_SYMBOL(rte_vfio_container_dma_map)
int
rte_vfio_container_dma_map(int container_fd, uint64_t vaddr, uint64_t iova, uint64_t len)
{
	struct container *cfg;

	if (len == 0) {
		rte_errno = EINVAL;
		return -1;
	}

	if (global_cfg.mode == RTE_VFIO_MODE_NONE) {
		EAL_LOG(ERR, "VFIO support not initialized");
		rte_errno = ENXIO;
		return -1;
	}

	cfg = vfio_container_get_by_fd(container_fd);
	if (cfg == NULL) {
		EAL_LOG(ERR, "Invalid VFIO container fd");
		rte_errno = EINVAL;
		return -1;
	}

	if (container_dma_map(cfg, vaddr, iova, len) < 0) {
		rte_errno = EIO;
		return -1;
	}

	return 0;
}

RTE_EXPORT_SYMBOL(rte_vfio_container_dma_unmap)
int
rte_vfio_container_dma_unmap(int container_fd, uint64_t vaddr, uint64_t iova, uint64_t len)
{
	struct container *cfg;

	if (len == 0) {
		rte_errno = EINVAL;
		return -1;
	}

	if (global_cfg.mode == RTE_VFIO_MODE_NONE) {
		EAL_LOG(ERR, "VFIO support not initialized");
		rte_errno = ENXIO;
		return -1;
	}

	cfg = vfio_container_get_by_fd(container_fd);
	if (cfg == NULL) {
		EAL_LOG(ERR, "Invalid VFIO container fd");
		rte_errno = EINVAL;
		return -1;
	}

	if (container_dma_unmap(cfg, vaddr, iova, len) < 0) {
		rte_errno = EIO;
		return -1;
	}

	return 0;
}

RTE_EXPORT_SYMBOL(rte_vfio_get_mode)
enum rte_vfio_mode
rte_vfio_get_mode(void)
{
	return global_cfg.mode;
}

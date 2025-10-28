/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#ifndef EAL_VFIO_H_
#define EAL_VFIO_H_

#include <rte_common.h>
#include <rte_spinlock.h>

#include <stdint.h>

#include <rte_vfio.h>

/* hot plug/unplug of VFIO groups may cause all DMA maps to be dropped. we can
 * recreate the mappings for DPDK segments, but we cannot do so for memory that
 * was registered by the user themselves, so we need to store the user mappings
 * somewhere, to recreate them later.
 */
#define EAL_VFIO_MAX_USER_MEM_MAPS 256

/* user memory map entry */
struct user_mem_map {
	uint64_t addr;  /**< start VA */
	uint64_t iova;  /**< start IOVA */
	uint64_t len;   /**< total length of the mapping */
	uint64_t chunk; /**< this mapping can be split in chunks of this size */
};

/* user memory maps container (common for all API modes) */
struct user_mem_maps {
	rte_spinlock_recursive_t lock;
	int n_maps;
	struct user_mem_map maps[EAL_VFIO_MAX_USER_MEM_MAPS];
};

/*
 * we don't need to store device fd's anywhere since they can be obtained from
 * the group fd via an ioctl() call.
 */
struct vfio_group {
	bool active;
	int group_num;
	int fd;
	int n_devices;
};

/* device tracking (common for group and cdev modes) */
struct vfio_device {
	bool active;
	union {
		int group; /**< back-reference to group list (group mode) */
		int dev_num;   /**< device number, e.g., X in /dev/vfio/devices/vfioX (cdev mode) */
	};
	int fd;
};

/* group mode specific configuration */
struct vfio_group_config {
	bool dma_setup_done;
	bool iommu_type_set;
	bool mem_event_clb_set;
	size_t n_groups;
	struct vfio_group groups[RTE_MAX_VFIO_GROUPS];
};

/* cdev mode specific configuration */
struct vfio_cdev_config {
	uint32_t ioas_id;
};

/* per-container configuration */
struct container {
	bool active;
	int container_fd;
	struct user_mem_maps mem_maps;
	union {
		struct vfio_group_config group_cfg;
		struct vfio_cdev_config cdev_cfg;
	};
	int n_devices;
	struct vfio_device devices[RTE_MAX_VFIO_DEVICES];
};

/* DMA mapping function prototype.
 * Takes VFIO container config as a parameter.
 * Returns 0 on success, -1 on error.
 */
typedef int (*dma_func_t)(struct container *cfg);

/* Custom memory region DMA mapping function prototype.
 * Takes VFIO container config, virtual address, physical address, length and
 * operation type (0 to unmap 1 for map) as a parameters.
 * Returns 0 on success, -1 on error.
 */
typedef int (*dma_user_func_t)(struct container *cfg, uint64_t vaddr,
		uint64_t iova, uint64_t len, int do_map);

/* mode-independent ops */
struct vfio_iommu_ops {
	int type_id;
	const char *name;
	bool partial_unmap;
	dma_user_func_t dma_user_map_func;
	dma_func_t dma_map_func;
};

/* global configuration */
struct vfio_config {
	struct container *default_cfg;
	enum rte_vfio_mode mode;
	const struct vfio_iommu_ops *ops;
};

/* per-process, per-container data */
extern struct container containers[RTE_MAX_VFIO_CONTAINERS];

/* current configuration */
extern struct vfio_config global_cfg;

#define CONTAINER_FOREACH(cfg) \
	for ((cfg) = &containers[0]; \
		(cfg) < &containers[RTE_DIM(containers)]; \
		(cfg)++)

#define CONTAINER_FOREACH_ACTIVE(cfg) \
	CONTAINER_FOREACH((cfg)) \
		if (((cfg)->active))

#define GROUP_FOREACH(cfg, grp) \
	for ((grp) = &((cfg)->group_cfg.groups[0]); \
		(grp) < &((cfg)->group_cfg.groups[RTE_DIM((cfg)->group_cfg.groups)]); \
		(grp)++)

#define GROUP_FOREACH_ACTIVE(cfg, grp) \
	GROUP_FOREACH((cfg), (grp)) \
		if (((grp)->active))

#define DEVICE_FOREACH(cfg, dev) \
	for ((dev) = &((cfg)->devices[0]); \
		(dev) < &((cfg)->devices[RTE_DIM((cfg)->devices)]); \
		(dev)++)

#define DEVICE_FOREACH_ACTIVE(cfg, dev) \
	DEVICE_FOREACH((cfg), (dev)) \
		if (((dev)->active))

/* for containers, we only need to initialize the lock in mem maps */
#define CONTAINER_INITIALIZER \
	((struct container){ \
		.mem_maps = {.lock = RTE_SPINLOCK_RECURSIVE_INITIALIZER,}, \
	})

int vfio_get_iommu_type(void);
int vfio_mp_sync_setup(void);
void vfio_mp_sync_cleanup(void);
bool vfio_container_is_default(struct container *cfg);

/* group mode functions */
int vfio_group_enable(struct container *cfg);
int vfio_group_open_container_fd(void);
int vfio_group_noiommu_is_enabled(void);
int vfio_group_get_num(const char *sysfs_base, const char *dev_addr,
		int *iommu_group_num);
struct vfio_group *vfio_group_get_by_num(struct container *cfg, int iommu_group);
struct vfio_group *vfio_group_create(struct container *cfg, int iommu_group);
void vfio_group_erase(struct container *cfg, struct vfio_group *grp);
int vfio_group_open_fd(struct container *cfg, struct vfio_group *grp);
int vfio_group_prepare(struct container *cfg, struct vfio_group *grp);
int vfio_group_setup_iommu(struct container *cfg);
int vfio_group_setup_device_fd(const char *dev_addr,
		struct vfio_group *grp, struct vfio_device *dev);

/* cdev mode functions */
int vfio_cdev_enable(struct container *cfg);
int vfio_cdev_setup_ioas(struct container *cfg);
int vfio_cdev_sync_ioas(struct container *cfg);
int vfio_cdev_get_iommufd(void);
int vfio_cdev_get_device_num(const char *sysfs_base, const char *dev_addr,
		int *cdev_dev_num);
struct vfio_device *vfio_cdev_get_dev_by_num(struct container *cfg, int cdev_dev_num);
int vfio_cdev_setup_device(struct container *cfg, struct vfio_device *dev);

#define VFIO_MEM_EVENT_CLB_NAME "vfio_mem_event_clb"
#define EAL_VFIO_MP "eal_vfio_mp_sync"

#define SOCKET_REQ_CONTAINER 0x100
#define SOCKET_REQ_GROUP 0x200
#define SOCKET_REQ_IOMMU_TYPE 0x400
#define SOCKET_REQ_CDEV 0x800
#define SOCKET_REQ_IOAS_ID 0x1000
#define SOCKET_OK 0x0
#define SOCKET_NO_FD 0x1
#define SOCKET_ERR 0xFF

struct vfio_mp_param {
	int req;
	int result;
	union {
		int group_num;
		int iommu_type_id;
		int cdev_dev_num;
		int ioas_id;
		enum rte_vfio_mode mode;
	};
};

#endif /* EAL_VFIO_H_ */

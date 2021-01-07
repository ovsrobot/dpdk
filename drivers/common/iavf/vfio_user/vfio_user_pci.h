/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#ifndef _VFIO_USER_PCI_H_
#define _VFIO_USER_PCI_H_

#include <linux/vfio.h>
#include <linux/limits.h>

#define IAVF_CLIENT_MAX_VECTORS			17
#define VFIO_MAXIMUM_SPARSE_MMAP_REGISONS	8

struct vfio_memory_region {
	TAILQ_ENTRY(vfio_memory_region) link;
	uint64_t iova;
	uint64_t size; /* bytes */
	uint64_t vaddr;
	uint64_t offset;
	int fd;
};

struct vfio_sparse_mmaps {
	void *mem;
	uint64_t offset;
	size_t size;
};

struct vfio_pci_region {
	uint64_t offset;
	size_t size;
	uint64_t flags;
	uint32_t nr_mmaps;
	struct vfio_sparse_mmaps mmaps[VFIO_MAXIMUM_SPARSE_MMAP_REGISONS];
};

TAILQ_HEAD(vfio_memory_region_list, vfio_memory_region);

struct vfio_device {
	int dev_id;
	char name[64];
	char path[PATH_MAX];
	uint64_t flags;
	uint32_t pci_regions;
	uint32_t nb_mrs;
	uint32_t nb_irqs;
	struct vfio_pci_region regions[VFIO_PCI_NUM_REGIONS];
	int irqfds[IAVF_CLIENT_MAX_VECTORS];
	struct vfio_memory_region_list mrs_list;
};

extern int iavf_common_logger;
#define CLIENT_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, iavf_common_logger, "%s(): " fmt "\n", \
		__func__, ## args)

__rte_internal
struct vfio_device *client_vfio_user_setup(const char *path, int socket);
__rte_internal
void client_vfio_user_release(struct vfio_device *dev);
__rte_internal
void *client_vfio_user_get_bar_addr(struct vfio_device *dev, uint32_t index,
				    uint64_t offset, uint32_t len);
int client_vfio_user_pci_bar_access(struct vfio_device *dev, uint32_t index,
				    uint64_t offset, size_t len, void *buf,
				    bool is_write);

#endif /* _VFIO_USER_PCI_H_ */

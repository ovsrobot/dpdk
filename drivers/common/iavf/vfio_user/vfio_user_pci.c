/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>

#include <sys/queue.h>
#include <sys/mman.h>
#include <sys/eventfd.h>

#include <rte_common.h>
#include <rte_memory.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_tailq.h>
#include <rte_errno.h>
#include <rte_vfio_user.h>

#include "vfio_user_pci.h"

#define IAVF_MEM_EVENT_CLB_NAME "iavf_mem_event_clb"

/* buffer length for irq set */
#define MSIX_IRQ_SET_BUF_LEN (sizeof(struct vfio_irq_set) + \
				sizeof(int) * IAVF_CLIENT_MAX_VECTORS)
/* buffer length for region infor get */
#define REG_INFO_GET_BUF_LEN (sizeof(struct vfio_region_info) + \
			sizeof(struct vfio_region_info_cap_sparse_mmap) \
			+ 2 * sizeof(struct vfio_region_sparse_mmap_area))

static inline int
vfio_add_mr(struct vfio_device *dev, struct vfio_memory_region *mr)
{
	if (dev->nb_mrs == RTE_VUSER_MAX_DMA) {
		CLIENT_LOG(ERR, "Exceed Maximum supported memory regions %d",
			RTE_VUSER_MAX_DMA);
		return -EINVAL;
	}

	TAILQ_INSERT_HEAD(&dev->mrs_list, mr, link);
	dev->nb_mrs++;

	CLIENT_LOG(DEBUG, "Add memory region: FD %d, VADDR 0x%lx,"
			  " IOVA 0x%lx, Size 0x%lx",
			  mr->fd, mr->vaddr, mr->iova, mr->size);
	return 0;
}

static inline void
vfio_remove_mr(struct vfio_device *dev, struct vfio_memory_region *mr)
{
	if (dev->nb_mrs == 0)
		return;

	CLIENT_LOG(DEBUG, "Remove memory region: FD %d, VADDR 0x%lx,"
			  " IOVA 0x%lx, Size 0x%lx",
			  mr->fd, mr->vaddr, mr->iova, mr->size);
	TAILQ_REMOVE(&dev->mrs_list, mr, link);
	dev->nb_mrs--;
	rte_free(mr);
}

static int
update_vfio_memory_region(const struct rte_memseg_list *msl __rte_unused,
		const struct rte_memseg *ms, void *arg)
{
	int ret = 0;
	struct vfio_device *dev = arg;
	struct vfio_memory_region *mr;
	struct rte_vfio_user_mem_reg mem;
	uint64_t offset;

	mr = rte_zmalloc_socket("iavf_client_vfio_user", sizeof(*mr),
				0, SOCKET_ID_ANY);
	if (mr == NULL)
		return -ENOMEM;

	mr->vaddr = (uint64_t)(uintptr_t)ms->addr;
	mr->iova = ms->iova;
	mr->size = ms->len;
	mr->fd = rte_memseg_get_fd_thread_unsafe(ms);
	if (mr->fd == -1) {
		CLIENT_LOG(ERR, "Error to get the memory fd");
		rte_free(mr);
		return -EFAULT;
	}
	if (rte_memseg_get_fd_offset_thread_unsafe(ms, &offset) < 0) {
		CLIENT_LOG(ERR, "Error to get the memory map offset");
		rte_free(mr);
		return -EFAULT;
	}
	mr->offset = offset;

	ret = vfio_add_mr(dev, mr);
	if (ret) {
		CLIENT_LOG(ERR, "Error to add memory region");
		rte_free(mr);
		return ret;
	}

	mem.gpa = mr->iova;
	mem.size = mr->size;
	mem.fd_offset = mr->offset;
	mem.protection = PROT_WRITE | PROT_READ;
	mem.flags = RTE_VUSER_MEM_MAPPABLE;

	ret = rte_vfio_user_dma_map(dev->dev_id, &mem, &mr->fd, 1);
	if (ret) {
		CLIENT_LOG(ERR, "Error to send dma map request");
		vfio_remove_mr(dev, mr);
		rte_free(mr);
		return ret;
	}
	return ret;

}

static int
vfio_device_dma_map(struct vfio_device *dev)
{
	if (rte_memseg_walk_thread_unsafe(update_vfio_memory_region, dev) < 0)
		return -1;

	return 0;
}


static void
vfio_device_dma_unmap(struct vfio_device *dev)
{
	int ret;
	struct vfio_memory_region *mr;

	if (dev->nb_mrs == 0)
		return;

	while ((mr = TAILQ_FIRST(&dev->mrs_list))) {
		struct rte_vfio_user_mem_reg mem;

		mem.gpa = mr->iova;
		mem.size = mr->size;
		mem.fd_offset = mr->offset;
		mem.protection = PROT_WRITE | PROT_READ;
		ret = rte_vfio_user_dma_unmap(dev->dev_id, &mem, 1);
		if (ret)
			CLIENT_LOG(ERR, "Error to send dma unmap request for"
				" mr FD %d, VADDR 0x%lx, IOVA 0x%lx, Size 0x%lx",
				 mr->fd, mr->vaddr, mr->iova, mr->size);
		TAILQ_REMOVE(&dev->mrs_list, mr, link);
		dev->nb_mrs--;
		rte_free(mr);
	}
	return;
}

static void
iavf_mem_event_cb(enum rte_mem_event type __rte_unused,
			 const void *addr,
			 size_t len __rte_unused,
			 void *arg)
{
	struct vfio_device *dev = arg;
	struct rte_memseg_list *msl;
	uint16_t ret;

	/* ignore externally allocated memory */
	msl = rte_mem_virt2memseg_list(addr);
	if (msl->external)
		return;
	ret = vfio_device_dma_map(dev);
	if (ret)
		CLIENT_LOG(ERR, "DMA map failed");
}

static inline struct vfio_info_cap_header *
vfio_device_get_info_cap(struct vfio_region_info *info, int cap)
{
	struct vfio_info_cap_header *h;
	size_t offset;

	offset = info->cap_offset;
	while (offset != 0 && offset < info->argsz) {
		h = (struct vfio_info_cap_header *)((uintptr_t)info + offset);
		if (h->id == cap) {
			return h;
		}
		offset = h->next;
	}

	return NULL;
}

static int
vfio_device_setup_sparse_mmaps(struct vfio_device *device, int index,
			       struct vfio_region_info *info, int *fds)
{
	struct vfio_info_cap_header *hdr;
	struct vfio_region_info_cap_sparse_mmap *sparse;
	struct vfio_pci_region *region = &device->regions[index];
	uint32_t i, j = 0;
	int prot = 0;

	hdr = vfio_device_get_info_cap(info, VFIO_REGION_INFO_CAP_SPARSE_MMAP);
	if (!hdr) {
		CLIENT_LOG(ERR, "Device doesn't have sparse mmap");
		return -EEXIST;
	}

	sparse = container_of(hdr, struct vfio_region_info_cap_sparse_mmap, header);
	for (i = 0; i < sparse->nr_areas; i++) {
		if (sparse->areas[i].size == 0)
			continue;
		region->mmaps[j].offset = sparse->areas[i].offset;
		region->mmaps[j].size = sparse->areas[i].size;
		prot |= info->flags & VFIO_REGION_INFO_FLAG_READ ? PROT_READ : 0;
		prot |= info->flags & VFIO_REGION_INFO_FLAG_WRITE ? PROT_WRITE : 0;
		if (*fds) {
			/* Use single fd for now*/
			region->mmaps[j].mem = mmap(NULL, region->mmaps[j].size,
						prot, MAP_SHARED, fds[0],
						region->offset + region->mmaps[j].offset);
			if (region->mmaps[j].mem == MAP_FAILED) {
				CLIENT_LOG(ERR, "Device SPARSE MMAP failed");
				return -EIO;
			}
		} else {
			CLIENT_LOG(ERR, "No valid fd, skip mmap for"
					" bar %d region %u", index, i);
		}
		CLIENT_LOG(DEBUG, "Sparse region %u, Size 0x%llx,"
				  " Offset 0x%llx, Map addr %p",
				  i, sparse->areas[i].size,
				  sparse->areas[i].offset, region->mmaps[j].mem);
		j++;
	}
	device->regions[index].nr_mmaps = j;

	return 0;
}

static int
vfio_device_map_region(struct vfio_device *device __rte_unused,
			struct vfio_pci_region *region, int fd)
{
	int prot = 0;

	prot |= region->flags & VFIO_REGION_INFO_FLAG_READ ? PROT_READ : 0;
	prot |= region->flags & VFIO_REGION_INFO_FLAG_WRITE ? PROT_WRITE : 0;

	region->mmaps[0].offset = 0;
	region->mmaps[0].size = region->size;

	region->mmaps[0].mem = mmap(NULL, region->size, prot, MAP_SHARED,
				    fd, region->offset);
	if (region->mmaps[0].mem == MAP_FAILED) {
		CLIENT_LOG(ERR, "Device Region MMAP failed");
		return -EFAULT;
	}
	CLIENT_LOG(DEBUG, "Memory mapped to %p", region->mmaps[0].mem);
	region->nr_mmaps = 1;

	return 0;
}

static void
vfio_device_unmap_bars(struct vfio_device *dev)
{
	uint32_t i, j;
	struct vfio_pci_region *region;

	for (i = 0; i < dev->pci_regions; i++) {
		region = &dev->regions[i];
		for (j = 0; j < region->nr_mmaps; j++) {
			if (region->mmaps[j].mem)
				munmap(region->mmaps[j].mem, region->mmaps[j].size);
		}
	}
	memset(dev->regions, 0, sizeof(dev->regions));
}

static int
vfio_user_create_irqfd(struct vfio_device *device, uint32_t count)
{
	uint32_t i;

	for (i = 0; i < count; i++) {
		device->irqfds[i] = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
		if (device->irqfds[i] < 0) {
			CLIENT_LOG(ERR, "Failed to create irqfd");
			return -1;
		}
	}
	return 0;
}

struct vfio_device *
client_vfio_user_setup(const char *path, int socket)
{
	struct vfio_device *device = NULL;
	char irq_set_buf[MSIX_IRQ_SET_BUF_LEN];
	char reg_get_buf[REG_INFO_GET_BUF_LEN];
	int fds[VFIO_MAXIMUM_SPARSE_MMAP_REGISONS];
	struct vfio_device_info dev_info = {};
	struct vfio_irq_info irq_info = {};
	struct vfio_irq_set *irq_set;
	struct vfio_region_info *reg_info;
	uint32_t i;
	int dev_id;
	int ret;

	device = rte_zmalloc_socket("iavf_client_vfio_user",
				    sizeof(struct vfio_device),
				    0, socket);
	if (!device)
		return NULL;

	TAILQ_INIT(&device->mrs_list);

	dev_id = rte_vfio_user_attach_dev(path);
	if (dev_id < 0) {
		rte_free(device);
		CLIENT_LOG(ERR, "Error to setup vfio-user via path %s", path);
		return NULL;
	}

	device->dev_id = dev_id;
	snprintf(device->name, sizeof(device->name), "vfio-user%u", dev_id);
	snprintf(device->path, PATH_MAX, "%s", path);

	ret = rte_vfio_user_get_dev_info(dev_id, &dev_info);
	if (ret) {
		CLIENT_LOG(ERR, "Device get info failed");
		goto cleanup;
	}
	device->pci_regions = dev_info.num_regions;
	device->flags = dev_info.flags;

	irq_info.argsz = sizeof(struct vfio_irq_info);
	irq_info.index = VFIO_PCI_MSIX_IRQ_INDEX;
	ret = rte_vfio_user_get_irq_info(dev_id, &irq_info);
	if (ret) {
		CLIENT_LOG(ERR, "IRQ get info failed");
		goto cleanup;
	}

	if (irq_info.count) {
		if (vfio_user_create_irqfd(device, irq_info.count))
			goto cleanup;

		irq_set = (struct vfio_irq_set *)irq_set_buf;
		irq_set->argsz = sizeof(irq_set_buf);
		irq_set->count = RTE_MIN(irq_info.count,
					 (uint32_t)IAVF_CLIENT_MAX_VECTORS);
		irq_set->flags = VFIO_IRQ_SET_DATA_EVENTFD |
				 VFIO_IRQ_SET_ACTION_TRIGGER;
		irq_set->index = VFIO_PCI_MSIX_IRQ_INDEX;
		irq_set->start = 0;
		rte_memcpy(irq_set->data, device->irqfds,
			   sizeof(int) * IAVF_CLIENT_MAX_VECTORS);
		ret = rte_vfio_user_set_irqs(dev_id, irq_set);
		if (ret) {
			CLIENT_LOG(ERR, "IRQ set failed");
			goto cleanup;
		}
	}

	reg_info = (struct vfio_region_info *)reg_get_buf;

	for (i = 0; i < device->pci_regions; i++) {
		memset(reg_info, 0, REG_INFO_GET_BUF_LEN);
		memset(fds, 0, sizeof(fds));

		reg_info->index = i;
		reg_info->argsz = sizeof(struct vfio_region_info);
		ret = rte_vfio_user_get_reg_info(dev_id, reg_info, fds);
		if (reg_info->argsz > sizeof(struct vfio_region_info))
			ret = rte_vfio_user_get_reg_info(dev_id, reg_info, fds);
		if (ret) {
			CLIENT_LOG(ERR, "Device setup bar %d failed", i);
			goto cleanup;
		}

		device->regions[i].size = reg_info->size;
		device->regions[i].offset = reg_info->offset;
		device->regions[i].flags = reg_info->flags;

		CLIENT_LOG(DEBUG, "Bar %d, Size 0x%llx, Offset 0x%llx,"
			" Flags 0x%x, Cap offset %u",
			i, reg_info->size, reg_info->offset,
			reg_info->flags, reg_info->cap_offset);

		/* Setup MMAP if any */
		if (reg_info->size &&
		    (reg_info->flags & VFIO_REGION_INFO_FLAG_MMAP)) {
			/* Try to map sparse region first */
			if (reg_info->flags & VFIO_REGION_INFO_FLAG_CAPS)
				ret = vfio_device_setup_sparse_mmaps(device, i,
							     reg_info, fds);
			else
				ret = vfio_device_map_region(device,
						&device->regions[i], fds[0]);

			if (ret != 0) {
				CLIENT_LOG(ERR, "Setup Device %s region %d failed",
					   device->name, i);
				goto cleanup;
			}
		}
	}

	/* Register DMA Region */
	ret = vfio_device_dma_map(device);
	if (ret) {
		CLIENT_LOG(ERR, "Container DMA map failed");
		goto cleanup;
	}

	CLIENT_LOG(DEBUG, "Device %s, Path %s Setup Successfully",
		   device->name, device->path);

	if (rte_mem_event_callback_register(IAVF_MEM_EVENT_CLB_NAME,
				iavf_mem_event_cb, device)) {
		if (rte_errno != ENOTSUP) {
			CLIENT_LOG(ERR, "Failed to register mem event"
					" callback");
			goto cleanup;
		}
	}

	return device;

cleanup:
	rte_vfio_user_detach_dev(dev_id);
	rte_free(device);
	return NULL;
}

void
client_vfio_user_release(struct vfio_device *dev)
{
	vfio_device_unmap_bars(dev);
	vfio_device_dma_unmap(dev);
	rte_vfio_user_detach_dev(dev->dev_id);

	rte_free(dev);
}

void *
client_vfio_user_get_bar_addr(struct vfio_device *dev, uint32_t index,
			      uint64_t offset, uint32_t len)
{
	struct vfio_pci_region *region = &dev->regions[index];
	uint32_t i;

	if (!region->size || !(region->flags & VFIO_REGION_INFO_FLAG_MMAP))
		return NULL;

	for (i = 0; i < region->nr_mmaps; i++) {
		if (region->mmaps[i].mem &&
		    (region->mmaps[i].offset <= offset) &&
		    ((offset + len) <= (region->mmaps[i].offset + region->mmaps[i].size))) {
			return (void *)((uintptr_t)region->mmaps[i].mem + \
					offset - region->mmaps[i].offset);
		}
	}

	return NULL;
}

int
client_vfio_user_pci_bar_access(struct vfio_device *dev, uint32_t index,
				uint64_t offset, size_t len,
				void *buf, bool is_write)
{
	struct vfio_pci_region *region = &dev->regions[index];
	uint64_t sparse_size, sparse_offset, bar_addr;
	uint32_t i;
	int ret;

	if ((offset + len > region->size) ||
	    (is_write && !(region->flags & VFIO_REGION_INFO_FLAG_WRITE)) ||
	    (!is_write && !(region->flags & VFIO_REGION_INFO_FLAG_READ)))
		return -EINVAL;

	/* Read/write through MMAP */
	for (i = 0; i < region->nr_mmaps; i++) {
		sparse_offset = region->mmaps[i].offset;
		sparse_size = region->mmaps[i].offset + region->mmaps[i].size;

		if ((offset >= sparse_offset) &&
		    (offset + len <= sparse_size)) {
			bar_addr = (uint64_t)(uintptr_t)region->mmaps[i].mem +
				offset - sparse_offset;
			if (is_write)
				rte_memcpy((void *)bar_addr, buf, len);
			else
				rte_memcpy(buf, (void *)bar_addr, len);

			return 0;
		}
	}

	/* Read/write through message */
	if (is_write)
		ret = rte_vfio_user_region_write(dev->dev_id, index,
						 offset, len, buf);
	else
		ret = rte_vfio_user_region_read(dev->dev_id, index,
						 offset, len, buf);
	return ret;
}

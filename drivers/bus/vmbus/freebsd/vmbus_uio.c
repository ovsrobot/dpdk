/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018, Microsoft Corporation.
 * All Rights Reserved.
 */

#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/ioctl.h>

#include <rte_log.h>
#include <rte_bus.h>
#include <rte_malloc.h>
#include <rte_bus_vmbus.h>

#include "private.h"

const char *driver_name = "hv_uio";
static void *vmbus_map_addr;

/* Check map names with kernel names */
static const char *map_names[VMBUS_MAX_RESOURCE] = {
	[HV_TXRX_RING_MAP] = "txrx_rings",
	[HV_INT_PAGE_MAP]  = "int_page",
	[HV_MON_PAGE_MAP]  = "monitor_page",
	[HV_RECV_BUF_MAP]  = "recv_buf",
	[HV_SEND_BUF_MAP]  = "send_buf",
};

void
vmbus_uio_free_resource(struct rte_vmbus_device *dev,
		struct mapped_vmbus_resource *uio_res)
{
	rte_free(uio_res);

	if (dev->intr_handle.uio_cfg_fd >= 0) {
		close(dev->intr_handle.uio_cfg_fd);
		dev->intr_handle.uio_cfg_fd = -1;
	}

	if (dev->intr_handle.fd >= 0) {
		close(dev->intr_handle.fd);
		dev->intr_handle.fd = -1;
		dev->intr_handle.type = RTE_INTR_HANDLE_UNKNOWN;
	}
}

static int
sysctl_get_vmbus_device_info(struct rte_vmbus_device *dev)
{
	char sysctlBuffer[PATH_MAX];
	char sysctlVar[PATH_MAX];
	size_t len = PATH_MAX, sysctl_len;
	unsigned long tmp;
	int i;

	snprintf(sysctlBuffer, len, "dev.%s.%d", driver_name, dev->uio_num);

	sysctl_len = sizeof(unsigned long);
	/* get relid */
	snprintf(sysctlVar, len, "%s.channel.ch_id", sysctlBuffer);
	if (sysctlbyname(sysctlVar, &tmp, &sysctl_len, NULL, 0) < 0) {
		VMBUS_LOG(ERR, "could not read %s", sysctlVar);
		goto error;
	}
	dev->relid = tmp;

	/* get monitor id */
	snprintf(sysctlVar, len, "%s.channel.%u.monitor_id", sysctlBuffer,
		 dev->relid);
	if (sysctlbyname(sysctlVar, &tmp, &sysctl_len, NULL, 0) < 0) {
		VMBUS_LOG(ERR, "could not read %s", sysctlVar);
		goto error;
	}
	dev->monitor_id = tmp;

	/* Extract resource value */
	for (i = 0; i < VMBUS_MAX_RESOURCE; i++) {
		struct rte_mem_resource *res = &dev->resource[i];
		unsigned long size, gpad = 0;
		size_t sizelen = sizeof(len);

		snprintf(sysctlVar, sizeof(sysctlVar), "%s.%s.size",
			 sysctlBuffer, map_names[i]);
		if (sysctlbyname(sysctlVar, &size, &sizelen, NULL, 0) < 0) {
			VMBUS_LOG(ERR,
				"could not read %s", sysctlVar);
			goto error;
		}
		res->len = size;

		if (i == HV_RECV_BUF_MAP || i == HV_SEND_BUF_MAP) {
			snprintf(sysctlVar, sizeof(sysctlVar), "%s.%s.gpadl",
				 sysctlBuffer, map_names[i]);
			if (sysctlbyname(sysctlVar, &gpad, &sizelen, NULL, 0) < 0) {
				VMBUS_LOG(ERR,
					"could not read %s", sysctlVar);
				goto error;
			}
			/* put the GPAD value in physical address */
			res->phys_addr = gpad;
		}
	}
	return 0;
error:
	return -1;
}

int
vmbus_uio_alloc_resource(struct rte_vmbus_device *dev,
			 struct mapped_vmbus_resource **uio_res)
{
	char devname[PATH_MAX]; /* contains the /dev/hv_uioX */

	/* save fd if in primary process */
	snprintf(devname, sizeof(devname), "/dev/hv_uio%u", dev->uio_num);
	dev->intr_handle.fd = open(devname, O_RDWR);
	if (dev->intr_handle.fd < 0) {
		VMBUS_LOG(ERR, "Cannot open %s: %s",
			devname, strerror(errno));
		goto error;
	}
	dev->intr_handle.type = RTE_INTR_HANDLE_UIO_INTX;

	/* allocate the mapping details for secondary processes*/
	*uio_res = rte_zmalloc("UIO_RES", sizeof(**uio_res), 0);
	if (*uio_res == NULL) {
		VMBUS_LOG(ERR, "cannot store uio mmap details");
		goto error;
	}

	strlcpy((*uio_res)->path, devname, PATH_MAX);
	rte_uuid_copy((*uio_res)->id, dev->device_id);

	if (sysctl_get_vmbus_device_info(dev) < 0)
		goto error;

	return 0;
error:
	vmbus_uio_free_resource(dev, *uio_res);
	return -1;
}

static int
find_max_end_va(const struct rte_memseg_list *msl, void *arg)
{
	size_t sz = msl->memseg_arr.len * msl->page_sz;
	void *end_va = RTE_PTR_ADD(msl->base_va, sz);
	void **max_va = arg;

	if (*max_va < end_va)
		*max_va = end_va;
	return 0;
}

/*
 * TODO: this should be part of memseg api.
 *       code is duplicated from PCI.
 */
static void *
vmbus_find_max_end_va(void)
{
	void *va = NULL;

	rte_memseg_list_walk(find_max_end_va, &va);
	return va;
}

int
vmbus_uio_map_resource_by_index(struct rte_vmbus_device *dev, int idx,
				struct mapped_vmbus_resource *uio_res,
				int flags)
{
	size_t size = dev->resource[idx].len;
	struct vmbus_map *maps = uio_res->maps;
	void *mapaddr;
	off_t offset;
	int fd;

	/* devname for mmap  */
	fd = open(uio_res->path, O_RDWR);
	if (fd < 0) {
		VMBUS_LOG(ERR, "Cannot open %s: %s",
			  uio_res->path, strerror(errno));
		return -1;
	}

	/* try mapping somewhere close to the end of hugepages */
	if (vmbus_map_addr == NULL)
		vmbus_map_addr = vmbus_find_max_end_va();

	/* offset is special in uio it indicates which resource */
	offset = idx * rte_mem_page_size();

	mapaddr = vmbus_map_resource(vmbus_map_addr, fd, offset, size, flags);
	close(fd);

	if (mapaddr == MAP_FAILED)
		return -1;

	dev->resource[idx].addr = mapaddr;
	vmbus_map_addr = RTE_PTR_ADD(mapaddr, size);

	/* Record result of successful mapping for use by secondary */
	maps[idx].addr = mapaddr;
	maps[idx].size = size;

	return 0;
}


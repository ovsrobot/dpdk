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

/* Macros to distinguish mmap request
 * [7-0] - Device memory region
 * [15-8]- Sub-channel id
 */
#define UH_SUBCHAN_MASK_SHIFT  8

/* ioctl */
#define HVIOOPENSUBCHAN     _IOW('h', 14, uint32_t)

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

static int vmbus_uio_map_primary(struct vmbus_channel *chan,
				 void **ring_buf, uint32_t *ring_size)
{
	struct mapped_vmbus_resource *uio_res;

	uio_res = vmbus_uio_find_resource(chan->device);
	if (!uio_res) {
		VMBUS_LOG(ERR, "can not find resources!");
		return -ENOMEM;
	}

	if (uio_res->nb_maps < VMBUS_MAX_RESOURCE) {
		VMBUS_LOG(ERR, "VMBUS: only %u resources found!",
			  uio_res->nb_maps);
		return -EINVAL;
	}

	*ring_size = uio_res->maps[HV_TXRX_RING_MAP].size / 2;
	*ring_buf  = uio_res->maps[HV_TXRX_RING_MAP].addr;
	return 0;
}

static int vmbus_uio_map_subchan(const struct rte_vmbus_device *dev,
				 struct vmbus_channel *chan,
				 void **ring_buf, uint32_t *ring_size)
{
	char ring_path[PATH_MAX];
	size_t size;
	void *mapaddr;
	off_t offset;
	int fd;

	snprintf(ring_path, sizeof(ring_path),
		 "/dev/hv_uio%d", dev->uio_num);

	fd = open(ring_path, O_RDWR);
	if (fd < 0) {
		VMBUS_LOG(ERR, "Cannot open %s: %s",
			  ring_path, strerror(errno));
		return -errno;
	}

	/* subchannel rings are of the same size as primary */
	size = dev->resource[HV_TXRX_RING_MAP].len;
	offset = (chan->relid << UH_SUBCHAN_MASK_SHIFT) * PAGE_SIZE;

	mapaddr = vmbus_map_resource(vmbus_map_addr, fd,
				     offset, size, 0);
	close(fd);

	if (mapaddr == MAP_FAILED)
		return -EIO;

	*ring_size = size / 2;
	*ring_buf = mapaddr;

	vmbus_map_addr = RTE_PTR_ADD(mapaddr, size);
	return 0;
}

int vmbus_uio_map_rings(struct vmbus_channel *chan)
{
	const struct rte_vmbus_device *dev = chan->device;
	uint32_t ring_size;
	void *ring_buf;
	int ret;

	/* Primary channel */
	if (chan->subchannel_id == 0)
		ret = vmbus_uio_map_primary(chan, &ring_buf, &ring_size);
	else
		ret = vmbus_uio_map_subchan(dev, chan, &ring_buf, &ring_size);

	if (ret)
		return ret;

	vmbus_br_setup(&chan->txbr, ring_buf, ring_size);
	vmbus_br_setup(&chan->rxbr, (char *)ring_buf + ring_size, ring_size);
	return 0;
}

bool vmbus_uio_subchannels_supported(const struct rte_vmbus_device *dev,
				     const struct vmbus_channel *chan)
{
	RTE_SET_USED(dev);
	RTE_SET_USED(chan);
	return true;
}

static bool vmbus_isnew_subchannel(struct vmbus_channel *primary,
				   uint16_t id)
{
	const struct vmbus_channel *c;

	STAILQ_FOREACH(c, &primary->subchannel_list, next) {
		if (c->relid == id)
			return false;
	}
	return true;
}

int vmbus_uio_get_subchan(struct vmbus_channel *primary,
			  struct vmbus_channel **subchan)
{
	const struct rte_vmbus_device *dev = primary->device;
	char sysctlBuffer[PATH_MAX], sysctlVar[PATH_MAX];
	size_t len = PATH_MAX, sysctl_len;
	/* nr_schan, relid, subid & monid datatype must match kernel's for sysctl */
	uint32_t relid, subid, nr_schan, i;
	uint8_t monid;
	int err;

	/* get no. of sub-channels opened by hv_uio
	 * dev.hv_uio.0.subchan_cnt
	 */
	snprintf(sysctlVar, len, "dev.%s.%d.subchan_cnt", driver_name,
		 dev->uio_num);
	sysctl_len = sizeof(nr_schan);
	if (sysctlbyname(sysctlVar, &nr_schan, &sysctl_len, NULL, 0) < 0) {
		VMBUS_LOG(ERR, "could not read %s : %s", sysctlVar,
				strerror(errno));
		return -1;
	}

	/* dev.hv_uio.0.channel.14.sub */
	snprintf(sysctlBuffer, len, "dev.%s.%d.channel.%u.sub", driver_name,
		 dev->uio_num, primary->relid);
	for (i = 1; i <= nr_schan; i++) {
		/* get relid */
		snprintf(sysctlVar, len, "%s.%u.chanid", sysctlBuffer, i);
		sysctl_len = sizeof(relid);
		if (sysctlbyname(sysctlVar, &relid, &sysctl_len, NULL, 0) < 0) {
			VMBUS_LOG(ERR, "could not read %s : %s", sysctlVar,
					strerror(errno));
			goto error;
		}

		if (!vmbus_isnew_subchannel(primary, (uint16_t)relid)) {
			VMBUS_LOG(DEBUG, "skip already found channel: %u",
					relid);
			continue;
		}

		/* get sub-channel id */
		snprintf(sysctlVar, len, "%s.%u.ch_subidx", sysctlBuffer, i);
		sysctl_len = sizeof(subid);
		if (sysctlbyname(sysctlVar, &subid, &sysctl_len, NULL, 0) < 0) {
			VMBUS_LOG(ERR, "could not read %s : %s", sysctlVar,
					strerror(errno));
			goto error;
		}

		/* get monitor id */
		snprintf(sysctlVar, len, "%s.%u.monitor_id", sysctlBuffer, i);
		sysctl_len = sizeof(monid);
		if (sysctlbyname(sysctlVar, &monid, &sysctl_len, NULL, 0) < 0) {
			VMBUS_LOG(ERR, "could not read %s : %s", sysctlVar,
					strerror(errno));
			goto error;
		}

		err = vmbus_chan_create(dev, (uint16_t)relid, (uint16_t)subid,
					monid, subchan);
		if (err) {
			VMBUS_LOG(ERR, "subchannel setup failed");
			return err;
		}
		break;
	}
	return 0;
error:
	return -1;
}

int vmbus_uio_subchan_open(struct rte_vmbus_device *dev, uint32_t subchan)
{
	struct mapped_vmbus_resource *uio_res;
	int fd, err = 0;

	uio_res = vmbus_uio_find_resource(dev);
	if (!uio_res) {
		VMBUS_LOG(ERR, "cannot find uio resource");
		return -EINVAL;
	}

	fd = open(uio_res->path, O_RDWR);
	if (fd < 0) {
		VMBUS_LOG(ERR, "Cannot open %s: %s",
				uio_res->path, strerror(errno));
		return -1;
	}

	if (ioctl(fd, HVIOOPENSUBCHAN, &subchan)) {
		VMBUS_LOG(ERR, "open subchan ioctl failed %s: %s",
				uio_res->path, strerror(errno));
		err = -1;
	}
	close(fd);
	return err;
}

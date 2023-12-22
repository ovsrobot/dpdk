/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Intel Corporation
 */

#include <inttypes.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include <rte_errno.h>
#include <rte_vfio.h>

#include "eal_private.h"
#include "eal_internal_cfg.h"

#ifdef VFIO_IOMMUFD_PRESENT
#include <linux/iommufd.h>
#include "eal_iommufd.h"

#define VFIO_IOMMUFD_MEM_EVENT_CLB_NAME "vfio_iommufd_mem_event_clb"

struct ioas_info {
	int iommufd;
	uint32_t ioas_id;
};

static int
vfio_iommufd_add_device(const char *dev_addr, int vfio_dev_fd)
{
	struct iommufd_config *iommufd_cfg;
	int iommufd;
	uint32_t ioas_id;
	struct vfio_device_bind_iommufd bind = {};
	struct vfio_device_attach_iommufd_pt attach = {};
	int ret = 0;

	iommufd_cfg = default_iommufd_cfg;
	iommufd = iommufd_cfg->iommufd;
	ioas_id = iommufd_cfg->ioas_id;

	bind.argsz = sizeof(bind);
	bind.iommufd = iommufd;
	bind.flags = 0;

	ret = ioctl(vfio_dev_fd, VFIO_DEVICE_BIND_IOMMUFD, &bind);
	if (ret) {
		RTE_LOG(ERR, EAL, "Device %s cannot bind to iommufd\n", dev_addr);
		return ret;
	}

	attach.argsz = sizeof(attach);
	attach.flags = 0;
	attach.pt_id = ioas_id;

	ret = ioctl(vfio_dev_fd, VFIO_DEVICE_ATTACH_IOMMUFD_PT, &attach);
	if (ret) {
		RTE_LOG(ERR, EAL, "Device %s cannot attach to ioas\n", dev_addr);
		return ret;
	}

	return 0;
}

static int
vfio_iommufd_map_contig(const struct rte_memseg_list *msl, const struct rte_memseg *ms,
			size_t len, void *arg)
{
	struct ioas_info *info = arg;

	if (msl->external)
		return 0;

	return iommufd_dma_mem_map(info->iommufd, info->ioas_id, ms->addr_64,
				   ms->iova, len, 1);
}

static int
vfio_iommufd_map(const struct rte_memseg_list *msl, const struct rte_memseg *ms,
		 void *arg)
{
	struct ioas_info *info = arg;

	/* skip external memory that isn't a heap */
	if (msl->external && !msl->heap)
		return 0;

	/* skip any segments with invalid IOVA addresses */
	if (ms->iova == RTE_BAD_IOVA)
		return 0;

	/* if IOVA mode is VA, we've already mapped the internal segments */
	if (!msl->external && rte_eal_iova_mode() == RTE_IOVA_VA)
		return 0;

	return iommufd_dma_mem_map(info->iommufd, info->ioas_id, ms->addr_64,
				   ms->iova,  ms->len, 1);
}

static int
vfio_iommufd_dma_map(int iommufd, uint32_t ioasid)
{
	struct ioas_info info = {.iommufd = iommufd, .ioas_id = ioasid};
	if (rte_eal_iova_mode() == RTE_IOVA_VA) {
		/* with IOVA as VA mode, we can get away with mapping contiguous
		 * chunks rather than going page-by-page.
		 */
		int ret = rte_memseg_contig_walk(vfio_iommufd_map_contig,
						 &info);
		if (ret)
			return ret;
		/* we have to continue the walk because we've skipped the
		 * external segments during the config walk.
		 */
	}
	return rte_memseg_walk(vfio_iommufd_map, &info);
}

static void
vfio_iommufd_mem_event_callback(enum rte_mem_event type, const void *addr,
				size_t len, void *arg __rte_unused)
{
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
				iommufd_dma_mem_map(default_iommufd_cfg->iommufd,
						    default_iommufd_cfg->ioas_id,
						    vfio_va, vfio_va, page_sz, 1);
			else
				iommufd_dma_mem_map(default_iommufd_cfg->iommufd,
						    default_iommufd_cfg->ioas_id,
						    vfio_va, vfio_va, page_sz, 0);
			vfio_va += page_sz;
		}

		return;
	}

	/* memsegs are contiguous in memory */
	ms = rte_mem_virt2memseg(addr, msl);
	while (cur_len < len) {
		/* some memory segments may have invalid IOVA */
		if (ms->iova == RTE_BAD_IOVA) {
			RTE_LOG(DEBUG, EAL,
				"Memory segment at %p has bad IOVA, skipping\n",
				ms->addr);
			goto next;
		}
		if (type == RTE_MEM_EVENT_ALLOC)
			iommufd_dma_mem_map(default_iommufd_cfg->iommufd,
					    default_iommufd_cfg->ioas_id,
					    ms->addr_64, ms->iova, ms->len, 1);
		else
			iommufd_dma_mem_map(default_iommufd_cfg->iommufd,
					    default_iommufd_cfg->ioas_id,
					    ms->addr_64, ms->iova, ms->len, 0);
next:
		cur_len += ms->len;
		++ms;
	}
}

static int
vfio_iommufd_get_fd(const char *sysfs_base, const char *dev_addr)
{
	char vfio_cdev_path[PATH_MAX];
	char vfio_path[PATH_MAX];
	char dirname[PATH_MAX];
	int vfio_dev_fd;
	struct dirent *dent;
	unsigned int major, minor;
	struct stat st;
	dev_t cdev;
	DIR *dir;
	FILE *f;
	int ret = 0;

	memset(vfio_cdev_path, 0, sizeof(vfio_cdev_path));
	memset(vfio_path, 0, sizeof(vfio_path));
	memset(dirname, 0, sizeof(dirname));

	snprintf(dirname, sizeof(dirname), "%s/%s/vfio-dev",
		 sysfs_base, dev_addr);

	dir = opendir(dirname);
	if (dir == NULL) {
		RTE_LOG(ERR, EAL, "%s(): opendir failed: %s\n",
			__func__, strerror(errno));
		return -1;
	}

	while ((dent = readdir(dir)) != NULL) {
		if (!strncmp(dent->d_name, "vfio", 4)) {
			snprintf(vfio_cdev_path, sizeof(vfio_cdev_path),
				 "%s/%s/vfio-dev/%s/dev", sysfs_base,
				 dev_addr, dent->d_name);
			break;
		}
	}

	f = fopen(vfio_cdev_path, "r");
	if (f == NULL) {
		RTE_LOG(ERR, EAL, "%s(): cannot open sysfs to get major:minor\n",
			__func__);
		ret = -1;
		goto err_fopen;
	}

	ret = fscanf(f, "%u:%u", &major, &minor);
	if (ret != 2) {
		RTE_LOG(ERR, EAL, "%s(): cannot parse sysfs to get major:minor\n",
			__func__);
		ret = -1;
		goto err_fscanf;
	}

	cdev = makedev(major, minor);

	snprintf(vfio_path, sizeof(vfio_path), "/dev/vfio/devices/%s", dent->d_name);
	vfio_dev_fd = open(vfio_path, O_RDWR);
	if (vfio_dev_fd == -1) {
		RTE_LOG(ERR, EAL, "%s(): can't open %s: %s\n",
			__func__, vfio_path, strerror(errno));
		ret = -1;
		goto err_fscanf;
	}

	if (fstat(vfio_dev_fd, &st) || !S_ISCHR(st.st_mode) ||
	    (cdev != 0 && st.st_rdev != cdev)) {
		RTE_LOG(ERR, EAL, "%s(): vfio char device is not matched\n",
			__func__);
		ret = -1;
	}

	ret = vfio_dev_fd;

err_fscanf:
	fclose(f);
err_fopen:
	closedir(dir);
	return ret;
}

int
rte_vfio_iommufd_setup_device(const char *sysfs_base, const char *dev_addr,
			      int *vfio_dev_fd, struct vfio_device_info *device_info)
{
	struct iommufd_config *iommufd_cfg;
	int iommufd;
	uint32_t ioas_id;
	int ret = 0;
	const struct internal_config *internal_conf =
		eal_get_internal_configuration();

	iommufd_cfg = default_iommufd_cfg;
	iommufd = iommufd_cfg->iommufd;
	ioas_id = iommufd_cfg->ioas_id;

	*vfio_dev_fd = vfio_iommufd_get_fd(sysfs_base, dev_addr);
	if (*vfio_dev_fd < 0) {
		RTE_LOG(ERR, EAL, "Failed to get device fd for device %s\n", dev_addr);
		return -1;
	}

	if (vfio_iommufd_add_device(dev_addr, *vfio_dev_fd)) {
		RTE_LOG(ERR, EAL, "Failed to add device %s to iommufd\n", dev_addr);
		ret = -1;
		goto err_add_dev;
	}

	if (!iommufd_cfg->dma_init &&
	    internal_conf->process_type == RTE_PROC_PRIMARY &&
	    iommufd != -1) {
		/* lock memory hotplug before mapping and release it
		 * after registering callback, to prevent races
		 */
		rte_mcfg_mem_read_lock();
		ret = vfio_iommufd_dma_map(iommufd, ioas_id);
		if (ret) {
			RTE_LOG(ERR, EAL,
				"%s DMA remapping failed, error "
				"%i (%s)\n",
				dev_addr, errno, strerror(errno));
			rte_mcfg_mem_read_unlock();
			ret = -1;
			goto err_dma_map;
		}

		/* register callback for mem events */
		ret = rte_mem_event_callback_register(
			VFIO_IOMMUFD_MEM_EVENT_CLB_NAME,
			vfio_iommufd_mem_event_callback, NULL);

		/* unlock memory hotplug */
		rte_mcfg_mem_read_unlock();

		if (ret && rte_errno != ENOTSUP) {
			RTE_LOG(ERR, EAL, "Could not install memory event callback for VFIO\n");
			ret = -1;
			goto err_dma_map;
		}
		if (ret)
			RTE_LOG(DEBUG, EAL, "Memory event callbacks not supported\n");
		else
			RTE_LOG(DEBUG, EAL, "Installed memory event callback for VFIO\n");

		iommufd_cfg->dma_init = true;
	}

	ret = ioctl(*vfio_dev_fd, VFIO_DEVICE_GET_INFO, device_info);
	if (ret) {
		RTE_LOG(ERR, EAL, "%s cannot get device info, "
			"error %i (%s)\n", dev_addr, errno,
			strerror(errno));
		ret = -1;
		goto err_dma_map;
	}

	return 0;

err_dma_map:
	rte_vfio_iommufd_release_device(dev_addr, *vfio_dev_fd);
err_add_dev:
	close(*vfio_dev_fd);
	return ret;
}

int
rte_vfio_iommufd_release_device(const char *dev_addr, int vfio_dev_fd)
{
	struct vfio_device_detach_iommufd_pt detach = {};
	int ret = 0;

	rte_mcfg_mem_read_lock();

	detach.argsz = sizeof(detach);
	detach.flags = 0;

	ret = ioctl(vfio_dev_fd, VFIO_DEVICE_DETACH_IOMMUFD_PT, &detach);
	if (ret) {
		RTE_LOG(ERR, EAL, "Device %s cannot detach from iommufd\n", dev_addr);
		goto err;
	}

	close(vfio_dev_fd);

	rte_mem_event_callback_unregister(VFIO_IOMMUFD_MEM_EVENT_CLB_NAME,
					  NULL);

err:
	rte_mcfg_mem_read_unlock();
	return ret;
}

#else
int
rte_vfio_iommufd_setup_device(__rte_unused const char *sysfs_base,
			      __rte_unused const char *dev_addr,
			      __rte_unused int *vfio_dev_fd,
			      __rte_unused struct vfio_device_info *device_info)
{
	return -1;
}

int
rte_vfio_iommufd_release_device(__rte_unused const char *dev_addr,
				__rte_unused int vfio_dev_fd)
{
	return -1;
}

#endif /* VFIO_IOMMUFD_PRESENT */

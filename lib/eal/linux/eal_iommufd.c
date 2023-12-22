/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Intel Corporation
 */

#include <inttypes.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include <rte_iommufd.h>
#include <rte_spinlock.h>
#include <rte_errno.h>

#include "eal_iommufd.h"
#include "eal_private.h"

#ifdef IOMMUFD_PRESENT
#include <linux/iommufd.h>

/* per-process IOMMUFD config */
static struct iommufd_config iommufd_cfgs[IOMMUFD_MAX_FD];
struct iommufd_config *default_iommufd_cfg = &iommufd_cfgs[0];

static void
iommufd_get_ioas(int *iommufd, uint32_t *ioas_id)
{
	int iommu_fd, ret;
	struct iommu_ioas_alloc alloc_data = {};

	*iommufd = -1;
	iommu_fd = open(IOMMUFD_PATH, O_RDWR);
	if (iommu_fd < 0) {
		RTE_LOG(ERR, EAL, "Failed to open iommufd!\n");
		return;
	}

	alloc_data.size = sizeof(alloc_data);
	ret = ioctl(iommu_fd, IOMMU_IOAS_ALLOC, &alloc_data);
	if (ret) {
		RTE_LOG(ERR, EAL, "Failed to alloc ioas!\n");
		return;
	}

	*iommufd = iommu_fd;
	*ioas_id = alloc_data.out_ioas_id;
}

int
rte_iommufd_enable(const char *modname)
{
	/* initialize device list */
	int i;
	int iommufd_available;
	const struct internal_config *internal_conf =
		eal_get_internal_configuration();

	for (i = 0; i < IOMMUFD_MAX_FD; i++) {
		iommufd_cfgs[i].iommufd_enabled = 0;
		iommufd_cfgs[i].iommufd = -1;
		iommufd_cfgs[i].ioas_id = 0;
		iommufd_cfgs[i].dma_init = false;
	}

	RTE_LOG(DEBUG, EAL, "Probing IOMMUFD support...\n");

	/* check if iommufd module is loaded */
	iommufd_available = rte_eal_check_module(modname);

	/* return error directly */
	if (iommufd_available == -1) {
		RTE_LOG(INFO, EAL, "Could not get loaded module details!\n");
		return -1;
	}

	/* return 0 if IOMMUFD modules not loaded */
	if (iommufd_available == 0) {
		RTE_LOG(DEBUG, EAL,
			"IOMMUFD modules not loaded, skipping IOMMUFD support...\n");
		return 0;
	}

	if (internal_conf->process_type == RTE_PROC_PRIMARY)
		iommufd_get_ioas(&default_iommufd_cfg->iommufd, &default_iommufd_cfg->ioas_id);

	/* check if we have IOMMUFD driver enabled */
	if (default_iommufd_cfg->iommufd != -1) {
		RTE_LOG(INFO, EAL, "IOMMUFD support initialized\n");
		default_iommufd_cfg->iommufd_enabled = 1;
	} else {
		RTE_LOG(NOTICE, EAL, "IOMMUFD support could not be initialized\n");
	}

	return 0;
}

int
rte_iommufd_is_enabled(const char *modname)
{
	const int mod_available = rte_eal_check_module(modname) > 0;
	return default_iommufd_cfg->iommufd_enabled && mod_available;
}

int
iommufd_dma_mem_map(int iommufd, uint32_t ioasid, uint64_t vaddr,
			uint64_t iova, uint64_t len, int do_map)
{
	struct iommu_ioas_map dma_map;
	struct iommu_ioas_unmap dma_unmap;
	int ret;

	if (do_map != 0) {
		memset(&dma_map, 0, sizeof(dma_map));
		dma_map.ioas_id = ioasid;
		dma_map.size = sizeof(struct iommu_ioas_map);
		dma_map.user_va = vaddr;
		dma_map.length = len;
		dma_map.iova = iova;
		dma_map.flags = IOMMU_IOAS_MAP_READABLE |
				IOMMU_IOAS_MAP_WRITEABLE |
				IOMMU_IOAS_MAP_FIXED_IOVA;

		ret = ioctl(iommufd, IOMMU_IOAS_MAP, &dma_map);
		if (ret) {
			/**
			 * In case the mapping was already done EEXIST will be
			 * returned from kernel.
			 */
			if (errno == EEXIST) {
				RTE_LOG(DEBUG, EAL,
					"Memory segment is already mapped, skipping");
			} else {
				RTE_LOG(ERR, EAL,
					"Cannot set up DMA remapping, error "
					"%i (%s)\n", errno, strerror(errno));
				return -1;
			}
		}
	} else {
		memset(&dma_unmap, 0, sizeof(dma_unmap));
		dma_unmap.ioas_id = ioasid;
		dma_unmap.size = sizeof(struct iommu_ioas_unmap);
		dma_unmap.length = len;
		dma_unmap.iova = iova;

		ret = ioctl(iommufd, IOMMU_IOAS_UNMAP, &dma_unmap);
		if (ret) {
			RTE_LOG(ERR, EAL, "Cannot clear DMA remapping, error "
					"%i (%s)\n", errno, strerror(errno));
			return -1;
		} else if (dma_unmap.length != len) {
			RTE_LOG(ERR, EAL, "Unexpected size %"PRIu64
				" of DMA remapping cleared instead of %"PRIu64"\n",
				(uint64_t)dma_unmap.size, len);
			rte_errno = EIO;
			return -1;
		}
	}

	return 0;
}

#else /* not IOMMUFD_PRESENT */

int
rte_iommufd_enable(__rte_unused const char *modname)
{
	return -1;
}

int
rte_iommufd_is_enabled(__rte_unused const char *modname)
{
	return -1;
}

int
iommufd_dma_mem_map(__rte_unused int iommufd, __rte_unused uint32_t ioasid,
		    __rte_unused uint64_t vaddr, __rte_unused  uint64_t iova,
		    __rte_unused uint64_t len, __rte_unused int do_map)
{
	return -1;
}

#endif /* IOMMUFD_PRESENT */

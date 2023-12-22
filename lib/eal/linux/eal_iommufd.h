/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Intel Corporation
 */

#ifndef EAL_IOMMUFD_H_
#define EAL_IOMMUFD_H_

#include <rte_common.h>
#include <stdbool.h>

/*
 * determine if IOMMUFD is present on the system
 */
#if !defined(IOMMUFD_PRESENT) && defined(RTE_EAL_IOMMUFD)
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
#define IOMMUFD_PRESENT
#else
#pragma message("IOMMUFD configured but not supported by this kernel, disabling.")
#endif /* kernel version >= 6.6.0 */
#endif /* RTE_EAL_IOMMUFD */

#ifdef IOMMUFD_PRESENT

#define IOMMUFD_MAX_FD RTE_MAX_IOMMUFD_FD

struct iommufd_config {
	int iommufd_enabled;
	int iommufd;
	uint32_t ioas_id;
	bool dma_init;
};

/* per-process IOMMUFD config */
extern struct iommufd_config *default_iommufd_cfg;

#endif /* IOMMUFD_PRESENT */

int
iommufd_dma_mem_map(int iommufd, uint32_t ioasid, uint64_t vaddr,
		    uint64_t iova, uint64_t len, int do_map);

#endif /* EAL_IOMMUFD_H_ */

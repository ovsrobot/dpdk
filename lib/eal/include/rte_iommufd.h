/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Intel Corporation
 */

#ifndef _RTE_IOMMUFD_H_
#define _RTE_IOMMUFD_H_

/**
 * @file
 * RTE IOMMUFD. This library provides various IOMMUFD related utility functions.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

#include <rte_compat.h>
/*
 * determine if IOMMUFD is present on the system
 */
#if !defined(IOMMUFD_PRESENT) && defined(RTE_EAL_IOMMUFD)
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
#define IOMMUFD_PRESENT
#endif /* kernel version >= 6.6.0 */
#endif /* RTE_EAL_IOMMUFD */

#ifdef IOMMUFD_PRESENT

#define IOMMUFD_PATH "/dev/iommu"

#else /* not IOMMUFD_PRESENT */
#endif /* IOMMUFD_PRESENT */

/**
 * Enable a IOMMUFD-related kmod.
 *
 * This function is only relevant to linux and will return
 * an error on BSD.
 *
 * @param modname
 *   kernel module name.
 *
 * @return
 *   0 on success.
 *   <0 on failure.
 */
__rte_experimental
int rte_iommufd_enable(const char *modname);

/**
 * Check whether a IOMMUFD-related kmod is enabled.
 *
 * This function is only relevant to Linux.
 *
 * @param modname
 *   kernel module name.
 *
 * @return
 *   1 if true.
 *   0 otherwise.
 */
__rte_experimental
int rte_iommufd_is_enabled(const char *modname);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_IOMMUFD_H_ */

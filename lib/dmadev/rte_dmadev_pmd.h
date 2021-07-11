/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 HiSilicon Limited.
 */

#ifndef _RTE_DMADEV_PMD_H_
#define _RTE_DMADEV_PMD_H_

/**
 * @file
 *
 * RTE DMA Device PMD APIs
 *
 * Driver facing APIs for a DMA device. These are not to be called directly by
 * any application.
 */

#include "rte_dmadev.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @internal
 * Allocates a new dmadev slot for an DMA device and returns the pointer
 * to that slot for the driver to use.
 *
 * @param name
 *   DMA device name.
 *
 * @return
 *   A pointer to the DMA device slot case of success,
 *   NULL otherwise.
 */
__rte_internal
struct rte_dmadev *
rte_dmadev_pmd_allocate(const char *name);

/**
 * @internal
 * Release the specified dmadev.
 *
 * @param dev
 *   Device to be released.
 *
 * @return
 *   - 0 on success, negative on error
 */
__rte_internal
int
rte_dmadev_pmd_release(struct rte_dmadev *dev);

/**
 * @internal
 * Return the DMA device based on the device name.
 *
 * @param name
 *   DMA device name.
 *
 * @return
 *   A pointer to the DMA device slot case of success,
 *   NULL otherwise.
 */
__rte_internal
struct rte_dmadev *
rte_dmadev_get_device_by_name(const char *name);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_DMADEV_PMD_H_ */

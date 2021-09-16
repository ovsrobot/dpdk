/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 HiSilicon Limited
 */

#ifndef RTE_DMADEV_PMD_H
#define RTE_DMADEV_PMD_H

/**
 * @file
 *
 * DMA Device PMD APIs
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
 * @param numa_node
 *   Driver's private data's numa node.
 * @param private_data_size
 *   Driver's private data size.
 *
 * @return
 *   A pointer to the DMA device slot case of success,
 *   NULL otherwise.
 */
__rte_internal
struct rte_dma_dev *rte_dma_pmd_allocate(const char *name, int numa_node,
					 size_t private_data_size);

/**
 * @internal
 * Release the specified dmadev.
 *
 * @param name
 *   DMA device name.
 *
 * @return
 *   - 0 on success, negative on error.
 */
__rte_internal
int rte_dma_pmd_release(const char *name);

#ifdef __cplusplus
}
#endif

#endif /* RTE_DMADEV_PMD_H */

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 HiSilicon Limited
 * Copyright(c) 2021 Intel Corporation
 * Copyright(c) 2021 Marvell International Ltd
 * Copyright(c) 2021 SmartShare Systems
 */

#ifndef RTE_DMADEV_H
#define RTE_DMADEV_H

/**
 * @file rte_dmadev.h
 *
 * DMA (Direct Memory Access) device API.
 *
 * The DMA framework is built on the following model:
 *
 *     ---------------   ---------------       ---------------
 *     | virtual DMA |   | virtual DMA |       | virtual DMA |
 *     | channel     |   | channel     |       | channel     |
 *     ---------------   ---------------       ---------------
 *            |                |                      |
 *            ------------------                      |
 *                     |                              |
 *               ------------                    ------------
 *               |  dmadev  |                    |  dmadev  |
 *               ------------                    ------------
 *                     |                              |
 *            ------------------               ------------------
 *            | HW DMA channel |               | HW DMA channel |
 *            ------------------               ------------------
 *                     |                              |
 *                     --------------------------------
 *                                     |
 *                           ---------------------
 *                           | HW DMA Controller |
 *                           ---------------------
 *
 * The DMA controller could have multiple HW-DMA-channels (aka. HW-DMA-queues),
 * each HW-DMA-channel should be represented by a dmadev.
 *
 * The dmadev could create multiple virtual DMA channels, each virtual DMA
 * channel represents a different transfer context. The DMA operation request
 * must be submitted to the virtual DMA channel. e.g. Application could create
 * virtual DMA channel 0 for memory-to-memory transfer scenario, and create
 * virtual DMA channel 1 for memory-to-device transfer scenario.
 *
 * The dmadev are dynamically allocated by rte_dma_pmd_allocate() during the
 * PCI/SoC device probing phase performed at EAL initialization time. And could
 * be released by rte_dma_pmd_release() during the PCI/SoC device removing
 * phase.
 *
 * This framework uses 'int16_t dev_id' as the device identifier of a dmadev,
 * and 'uint16_t vchan' as the virtual DMA channel identifier in one dmadev.
 *
 */

#include <stdint.h>

#include <rte_bitops.h>
#include <rte_common.h>
#include <rte_compat.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Configure the maximum number of dmadevs.
 * @note This function can be invoked before the primary process rte_eal_init()
 * to change the maximum number of dmadevs.
 *
 * @param dev_max
 *   maximum number of dmadevs.
 *
 * @return
 *   0 on success. Otherwise negative value is returned.
 */
__rte_experimental
int rte_dma_dev_max(size_t dev_max);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Get the device identifier for the named DMA device.
 *
 * @param name
 *   DMA device name.
 *
 * @return
 *   Returns DMA device identifier on success.
 *   - <0: Failure to find named DMA device.
 */
__rte_experimental
int rte_dma_get_dev_id(const char *name);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * @param dev_id
 *   DMA device index.
 *
 * @return
 *   - If the device index is valid (true) or not (false).
 */
__rte_experimental
bool rte_dma_is_valid(int16_t dev_id);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Get the total number of DMA devices that have been successfully
 * initialised.
 *
 * @return
 *   The total number of usable DMA devices.
 */
__rte_experimental
uint16_t rte_dma_count_avail(void);

#include "rte_dmadev_core.h"

#ifdef __cplusplus
}
#endif

#endif /* RTE_DMADEV_H */

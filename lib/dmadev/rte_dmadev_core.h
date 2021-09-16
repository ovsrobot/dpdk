/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 HiSilicon Limited
 * Copyright(c) 2021 Intel Corporation
 */

#ifndef RTE_DMADEV_CORE_H
#define RTE_DMADEV_CORE_H

/**
 * @file
 *
 * DMA Device internal header.
 *
 * This header contains internal data types, that are used by the DMA devices
 * in order to expose their ops to the class.
 *
 * Applications should not use these API directly.
 *
 */

#include <rte_dev.h>

/**
 * Possible states of a DMA device.
 *
 * @see struct rte_dmadev::state
 */
enum rte_dma_dev_state {
	RTE_DMA_DEV_UNUSED = 0, /**< Device is unused. */
	/** Device is registered, but not ready to be used. */
	RTE_DMA_DEV_REGISTERED,
	/** Device is ready for use. This is set by the PMD. */
	RTE_DMA_DEV_READY,

};

/**
 * @internal
 * The data part, with no function pointers, associated with each DMA device.
 *
 * This structure is safe to place in shared memory to be common among different
 * processes in a multi-process configuration.
 *
 * @see struct rte_dmadev::data
 */
struct rte_dma_dev_data {
	char dev_name[RTE_DEV_NAME_MAX_LEN]; /**< Unique identifier name */
	int16_t dev_id; /**< Device [external] identifier. */
	int16_t numa_node; /**< Local NUMA memory ID. -1 if unknown. */
	/** PMD-specific private data.
	 * This is a copy of the 'dev_private' field in the 'struct rte_dmadev'
	 * from primary process, it is used by the secondary process to get
	 * dev_private information.
	 */
	void *dev_private;
	uint8_t dev_started : 1; /**< Device state: STARTED(1)/STOPPED(0). */
	uint64_t reserved[2]; /**< Reserved for future fields */
} __rte_cache_aligned;

/**
 * @internal
 * The generic data structure associated with each DMA device.
 *
 * The dataplane APIs are located at the beginning of the structure, along
 * with the pointer to where all the data elements for the particular device
 * are stored in shared memory. This split scheme allows the function pointer
 * and driver data to be per-process, while the actual configuration data for
 * the device is shared.
 * And the 'dev_private' field was placed in the first cache line to optimize
 * performance because the PMD driver mainly depends on this field.
 */
struct rte_dma_dev {
	void *dev_private; /**< PMD-specific private data. */
	struct rte_dma_dev_data *data; /**< Pointer to device data. */
	/** Device info which supplied during device initialization. */
	struct rte_device *device;
	enum rte_dma_dev_state state; /**< Flag indicating the device state. */
	uint64_t reserved[2]; /**< Reserved for future fields. */
} __rte_cache_aligned;

extern struct rte_dma_dev *rte_dma_devices;

#endif /* RTE_DMADEV_CORE_H */

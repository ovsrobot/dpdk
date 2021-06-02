/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 NVIDIA Corporation & Affiliates
 */

#ifndef RTE_GPUDEV_H
#define RTE_GPUDEV_H

#include <stdint.h>
#include <stdbool.h>

#include <rte_common.h>

/**
 * @file
 * Generic library to interact with a GPU.
 *
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 */

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum number of GPU engines. */
#define RTE_GPU_MAX_DEVS UINT16_C(32)
/** Maximum length of device name. */
#define RTE_GPU_NAME_MAX_LEN 128

/** Flags indicate current state of GPU device. */
enum rte_gpu_state {
	RTE_GPU_STATE_UNUSED,        /**< not initialized */
	RTE_GPU_STATE_INITIALIZED,   /**< initialized */
};

/** Store a list of info for a given GPU. */
struct rte_gpu_info {
	/** GPU device ID. */
	uint16_t gpu_id;
	/** Unique identifier name. */
	char name[RTE_GPU_NAME_MAX_LEN];
	/** Total memory available on device. */
	size_t total_memory;
	/** Total processors available on device. */
	int processor_count;
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Returns the number of GPUs detected and associated to DPDK.
 *
 * @return
 *   The number of available GPUs.
 */
__rte_experimental
uint16_t rte_gpu_dev_count_avail(void);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Check if the device is valid and initialized in DPDK.
 *
 * @param gpu_id
 *   The input GPU ID.
 *
 * @return
 *   - True if gpu_id is a valid and initialized GPU.
 *   - False otherwise.
 */
__rte_experimental
bool rte_gpu_dev_is_valid(uint16_t gpu_id);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Get the GPU ID of the next valid GPU initialized in DPDK.
 *
 * @param gpu_id
 *   The initial GPU ID to start the research.
 *
 * @return
 *   Next GPU ID corresponding to a valid and initialized GPU device.
 */
__rte_experimental
uint16_t rte_gpu_dev_find_next(uint16_t gpu_id);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Macro to iterate over all valid GPUs.
 *
 * @param gpu_id
 *   The ID of the next possible valid GPU.
 * @return
 *   Next valid GPU ID, RTE_GPU_MAX_DEVS if there is none.
 */
#define RTE_GPU_FOREACH_DEV(gpu_id) \
	for (gpu_id = rte_gpu_find_next(0); \
	     gpu_id < RTE_GPU_MAX_DEVS; \
	     gpu_id = rte_gpu_find_next(gpu_id + 1))

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Return GPU specific info.
 *
 * @param gpu_id
 *   GPU ID to get info.
 * @param info
 *   Memory structure to fill with the info.
 *
 * @return
 *   0 on success, -1 otherwise.
 */
__rte_experimental
int rte_gpu_dev_info_get(uint16_t gpu_id, struct rte_gpu_info **info);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Allocate a chunk of memory on the GPU.
 *
 * @param gpu_id
 *   GPU ID to allocate memory.
 * @param size
 *   Number of bytes to allocate.
 * @param ptr
 *   Pointer to store the address of the allocated memory.
 *
 * @return
 *   0 on success, -1 otherwise.
 */
__rte_experimental
int rte_gpu_malloc(uint16_t gpu_id, size_t size, void **ptr);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Allocate a chunk of memory on the CPU that is visible from the GPU.
 *
 * @param gpu_id
 *   Reference GPU ID.
 * @param size
 *   Number of bytes to allocate.
 * @param ptr
 *   Pointer to store the address of the allocated memory.
 *
 * @return
 *   0 on success, -1 otherwise.
 */
__rte_experimental
int rte_gpu_malloc_visible(uint16_t gpu_id, size_t size, void **ptr);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Deallocate a chunk of memory allocated with rte_gpu_malloc*.
 *
 * @param gpu_id
 *   Reference GPU ID.
 * @param ptr
 *   Pointer to the memory area to be deallocated.
 *
 * @return
 *   0 on success, -1 otherwise.
 */
__rte_experimental
int rte_gpu_free(uint16_t gpu_id, void *ptr);

#ifdef __cplusplus
}
#endif

#endif /* RTE_GPUDEV_H */

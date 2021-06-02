/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 NVIDIA Corporation & Affiliates
 */

#ifndef GPU_DRIVER_H
#define GPU_DRIVER_H

#include <stdint.h>

#include <rte_common.h>

#include "rte_gpudev.h"

struct rte_gpu_dev;

typedef int (*gpu_malloc_t)(struct rte_gpu_dev *dev, size_t size, void **ptr);
typedef int (*gpu_free_t)(struct rte_gpu_dev *dev, void *ptr);

struct rte_gpu_dev {
	/* Backing device. */
	struct rte_device *device;
	/* GPU info structure. */
	struct rte_gpu_info info;
	/* Counter of processes using the device. */
	uint16_t process_cnt;
	/* If device is currently used or not. */
	enum rte_gpu_state state;
	/* FUNCTION: Allocate memory on the GPU. */
	gpu_malloc_t gpu_malloc;
	/* FUNCTION: Allocate memory on the CPU visible from the GPU. */
	gpu_malloc_t gpu_malloc_visible;
	/* FUNCTION: Free allocated memory on the GPU. */
	gpu_free_t gpu_free;
	/* Device interrupt handle. */
	struct rte_intr_handle *intr_handle;
	/* Driver-specific private data. */
	void *dev_private;
} __rte_cache_aligned;

struct rte_gpu_dev *rte_gpu_dev_allocate(const char *name);
struct rte_gpu_dev *rte_gpu_dev_get_by_name(const char *name);
int rte_gpu_dev_release(struct rte_gpu_dev *gpudev);

#endif /* GPU_DRIVER_H */

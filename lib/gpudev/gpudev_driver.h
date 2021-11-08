/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA Corporation & Affiliates
 */

/*
 * This header file must be included only by drivers.
 * It is considered internal, i.e. hidden for the application.
 * The prefix rte_ is used to avoid namespace clash in drivers.
 */

#ifndef RTE_GPUDEV_DRIVER_H
#define RTE_GPUDEV_DRIVER_H

#include <stdint.h>
#include <sys/queue.h>

#include <rte_dev.h>

#include "rte_gpudev.h"

/* Flags indicate current state of device. */
enum rte_gpu_state {
	RTE_GPU_STATE_UNUSED,        /* not initialized */
	RTE_GPU_STATE_INITIALIZED,   /* initialized */
};

struct rte_gpu;
typedef int (rte_gpu_close_t)(struct rte_gpu *dev);
typedef int (rte_gpu_info_get_t)(struct rte_gpu *dev, struct rte_gpu_info *info);

struct rte_gpu_ops {
	/* Get device info. If NULL, info is just copied. */
	rte_gpu_info_get_t *dev_info_get;
	/* Close device or child context. */
	rte_gpu_close_t *dev_close;
};

struct rte_gpu_mpshared {
	/* Unique identifier name. */
	char name[RTE_DEV_NAME_MAX_LEN]; /* Updated by this library. */
	/* Driver-specific private data shared in multi-process. */
	void *dev_private;
	/* Device info structure. */
	struct rte_gpu_info info;
	/* Counter of processes using the device. */
	uint16_t process_refcnt; /* Updated by this library. */
};

struct rte_gpu {
	/* Backing device. */
	struct rte_device *device;
	/* Data shared between processes. */
	struct rte_gpu_mpshared *mpshared;
	/* Driver functions. */
	struct rte_gpu_ops ops;
	/* Event callback list. */
	TAILQ_HEAD(rte_gpu_callback_list, rte_gpu_callback) callbacks;
	/* Current state (used or not) in the running process. */
	enum rte_gpu_state process_state; /* Updated by this library. */
	/* Driver-specific private data for the running process. */
	void *process_private;
} __rte_cache_aligned;

__rte_internal
struct rte_gpu *rte_gpu_get_by_name(const char *name);

/* First step of initialization in primary process. */
__rte_internal
struct rte_gpu *rte_gpu_allocate(const char *name);

/* First step of initialization in secondary process. */
__rte_internal
struct rte_gpu *rte_gpu_attach(const char *name);

/* Last step of initialization. */
__rte_internal
void rte_gpu_complete_new(struct rte_gpu *dev);

/* Last step of removal (primary or secondary process). */
__rte_internal
int rte_gpu_release(struct rte_gpu *dev);

/* Call registered callbacks. No multi-process event. */
__rte_internal
void rte_gpu_notify(struct rte_gpu *dev, enum rte_gpu_event);

#endif /* RTE_GPUDEV_DRIVER_H */

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 HiSilicon Limited.
 * Copyright(c) 2021 Intel Corporation.
 */

#ifndef _RTE_DMADEV_CORE_H_
#define _RTE_DMADEV_CORE_H_

/**
 * @file
 *
 * RTE DMA Device internal header.
 *
 * This header contains internal data types, that are used by the DMA devices
 * in order to expose their ops to the class.
 *
 * Applications should not use these API directly.
 *
 */

struct rte_dmadev;

/** @internal Used to get device information of a device. */
typedef int (*dmadev_info_get_t)(const struct rte_dmadev *dev,
				 struct rte_dmadev_info *dev_info,
				 uint32_t info_sz);

/** @internal Used to configure a device. */
typedef int (*dmadev_configure_t)(struct rte_dmadev *dev,
				  const struct rte_dmadev_conf *dev_conf);

/** @internal Used to start a configured device. */
typedef int (*dmadev_start_t)(struct rte_dmadev *dev);

/** @internal Used to stop a configured device. */
typedef int (*dmadev_stop_t)(struct rte_dmadev *dev);

/** @internal Used to close a configured device. */
typedef int (*dmadev_close_t)(struct rte_dmadev *dev);

/** @internal Used to allocate and set up a virtual DMA channel. */
typedef int (*dmadev_vchan_setup_t)(struct rte_dmadev *dev,
				    const struct rte_dmadev_vchan_conf *conf);

/** @internal Used to release a virtual DMA channel. */
typedef int (*dmadev_vchan_release_t)(struct rte_dmadev *dev, uint16_t vchan);

/** @internal Used to retrieve basic statistics. */
typedef int (*dmadev_stats_get_t)(const struct rte_dmadev *dev, uint16_t vchan,
				  struct rte_dmadev_stats *stats,
				  uint32_t stats_sz);

/** @internal Used to reset basic statistics. */
typedef int (*dmadev_stats_reset_t)(struct rte_dmadev *dev, uint16_t vchan);

/** @internal Used to dump internal information. */
typedef int (*dmadev_dump_t)(const struct rte_dmadev *dev, FILE *f);

/** @internal Used to start dmadev selftest. */
typedef int (*dmadev_selftest_t)(uint16_t dev_id);

/** @internal Used to enqueue a copy operation. */
typedef int (*dmadev_copy_t)(struct rte_dmadev *dev, uint16_t vchan,
			     rte_iova_t src, rte_iova_t dst,
			     uint32_t length, uint64_t flags);

/** @internal Used to enqueue a scatter list copy operation. */
typedef int (*dmadev_copy_sg_t)(struct rte_dmadev *dev, uint16_t vchan,
				const struct rte_dma_sg *sg, uint64_t flags);

/** @internal Used to enqueue a fill operation. */
typedef int (*dmadev_fill_t)(struct rte_dmadev *dev, uint16_t vchan,
			     uint64_t pattern, rte_iova_t dst,
			     uint32_t length, uint64_t flags);

/** @internal Used to trigger hardware to begin working. */
typedef int (*dmadev_submit_t)(struct rte_dmadev *dev, uint16_t vchan);

/** @internal Used to return number of successful completed operations. */
typedef uint16_t (*dmadev_completed_t)(struct rte_dmadev *dev, uint16_t vchan,
				       const uint16_t nb_cpls,
				       uint16_t *last_idx, bool *has_error);

/** @internal Used to return number of failed completed operations. */
typedef uint16_t (*dmadev_completed_fails_t)(struct rte_dmadev *dev,
			uint16_t vchan, const uint16_t nb_status,
			uint32_t *status, uint16_t *last_idx);

/**
 * Possible states of a DMA device.
 */
enum rte_dmadev_state {
	/** Device is unused before being probed. */
	RTE_DMADEV_UNUSED = 0,
	/** Device is attached when allocated in probing. */
	RTE_DMADEV_ATTACHED,
};

/**
 * DMA device operations function pointer table
 */
struct rte_dmadev_ops {
	dmadev_info_get_t dev_info_get;
	dmadev_configure_t dev_configure;
	dmadev_start_t dev_start;
	dmadev_stop_t dev_stop;
	dmadev_close_t dev_close;
	dmadev_vchan_setup_t vchan_setup;
	dmadev_vchan_release_t vchan_release;
	dmadev_stats_get_t stats_get;
	dmadev_stats_reset_t stats_reset;
	dmadev_dump_t dev_dump;
	dmadev_selftest_t dev_selftest;
};

/**
 * @internal
 * The data part, with no function pointers, associated with each DMA device.
 *
 * This structure is safe to place in shared memory to be common among different
 * processes in a multi-process configuration.
 */
struct rte_dmadev_data {
	void *dev_private; /**< PMD-specific private data. */
	uint16_t dev_id; /**< Device [external] identifier. */
	char dev_name[RTE_DMADEV_NAME_MAX_LEN]; /**< Unique identifier name */
	struct rte_dmadev_conf dev_conf; /**< DMA device configuration. */
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
 */
struct rte_dmadev {
	dmadev_copy_t copy;
	dmadev_copy_sg_t copy_sg;
	dmadev_fill_t fill;
	dmadev_submit_t submit;
	dmadev_completed_t completed;
	dmadev_completed_fails_t completed_fails;
	void *reserved_ptr; /**< Reserved for future IO function */
	struct rte_dmadev_data *data; /**< Pointer to device data. */

	const struct rte_dmadev_ops *dev_ops; /**< Functions exported by PMD. */
	/** Device info which supplied during device initialization. */
	struct rte_device *device;
	enum rte_dmadev_state state; /**< Flag indicating the device state */
	uint64_t reserved[2]; /**< Reserved for future fields */
} __rte_cache_aligned;

extern struct rte_dmadev rte_dmadevices[];

#endif /* _RTE_DMADEV_CORE_H_ */

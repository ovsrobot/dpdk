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

struct rte_dma_dev;

/** @internal Used to get device information of a device. */
typedef int (*rte_dma_info_get_t)(const struct rte_dma_dev *dev,
				  struct rte_dma_info *dev_info,
				  uint32_t info_sz);

/** @internal Used to configure a device. */
typedef int (*rte_dma_configure_t)(struct rte_dma_dev *dev,
				   const struct rte_dma_conf *dev_conf,
				   uint32_t conf_sz);

/** @internal Used to start a configured device. */
typedef int (*rte_dma_start_t)(struct rte_dma_dev *dev);

/** @internal Used to stop a configured device. */
typedef int (*rte_dma_stop_t)(struct rte_dma_dev *dev);

/** @internal Used to close a configured device. */
typedef int (*rte_dma_close_t)(struct rte_dma_dev *dev);

/** @internal Used to allocate and set up a virtual DMA channel. */
typedef int (*rte_dma_vchan_setup_t)(struct rte_dma_dev *dev, uint16_t vchan,
				const struct rte_dma_vchan_conf *conf,
				uint32_t conf_sz);

/** @internal Used to retrieve basic statistics. */
typedef int (*rte_dma_stats_get_t)(const struct rte_dma_dev *dev,
			uint16_t vchan, struct rte_dma_stats *stats,
			uint32_t stats_sz);

/** @internal Used to reset basic statistics. */
typedef int (*rte_dma_stats_reset_t)(struct rte_dma_dev *dev, uint16_t vchan);

/** @internal Used to dump internal information. */
typedef int (*rte_dma_dump_t)(const struct rte_dma_dev *dev, FILE *f);

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
 * DMA device operations function pointer table.
 *
 * @see struct rte_dma_dev:dev_ops
 */
struct rte_dma_dev_ops {
	rte_dma_info_get_t       dev_info_get;
	rte_dma_configure_t      dev_configure;
	rte_dma_start_t          dev_start;
	rte_dma_stop_t           dev_stop;
	rte_dma_close_t          dev_close;

	rte_dma_vchan_setup_t    vchan_setup;

	rte_dma_stats_get_t      stats_get;
	rte_dma_stats_reset_t    stats_reset;

	rte_dma_dump_t           dev_dump;
};

/** @internal
 * The generic data structure associated with each DMA device.
 */
struct rte_dma_dev {
	char dev_name[RTE_DEV_NAME_MAX_LEN]; /**< Unique identifier name */
	int16_t dev_id; /**< Device [external] identifier. */
	int16_t numa_node; /**< Local NUMA memory ID. -1 if unknown. */
	void *dev_private; /**< PMD-specific private data. */
	/** Functions exported by PMD. */
	const struct rte_dma_dev_ops *dev_ops;
	struct rte_dma_conf dev_conf; /**< DMA device configuration. */
	/** Device info which supplied during device initialization. */
	struct rte_device *device;
	enum rte_dma_dev_state state; /**< Flag indicating the device state. */
	uint8_t dev_started : 1; /**< Device state: STARTED(1)/STOPPED(0). */
	uint64_t reserved[2]; /**< Reserved for future fields. */
} __rte_cache_aligned;

extern struct rte_dma_dev *rte_dma_devices;

#endif /* RTE_DMADEV_CORE_H */

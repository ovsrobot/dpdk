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
 * This header contains internal data types which are used by dataplane inline
 * function.
 *
 * Applications should not use these functions directly.
 */

/** @internal Used to enqueue a copy operation. */
typedef int (*rte_dma_copy_t)(void *dev_private, uint16_t vchan,
			      rte_iova_t src, rte_iova_t dst,
			      uint32_t length, uint64_t flags);

/** @internal Used to enqueue a scatter-gather list copy operation. */
typedef int (*rte_dma_copy_sg_t)(void *dev_private, uint16_t vchan,
				 const struct rte_dma_sge *src,
				 const struct rte_dma_sge *dst,
				 uint16_t nb_src, uint16_t nb_dst,
				 uint64_t flags);

/** @internal Used to enqueue a fill operation. */
typedef int (*rte_dma_fill_t)(void *dev_private, uint16_t vchan,
			      uint64_t pattern, rte_iova_t dst,
			      uint32_t length, uint64_t flags);

/** @internal Used to trigger hardware to begin working. */
typedef int (*rte_dma_submit_t)(void *dev_private, uint16_t vchan);

/** @internal Used to return number of successful completed operations. */
typedef uint16_t (*rte_dma_completed_t)(void *dev_private,
				uint16_t vchan, const uint16_t nb_cpls,
				uint16_t *last_idx, bool *has_error);

/** @internal Used to return number of completed operations. */
typedef uint16_t (*rte_dma_completed_status_t)(void *dev_private,
			uint16_t vchan, const uint16_t nb_cpls,
			uint16_t *last_idx, enum rte_dma_status_code *status);

/**
 * @internal
 * Fast-path dmadev functions and related data are hold in a flat array.
 * One entry per dmadev.
 *
 * On 64-bit systems contents of this structure occupy exactly two 64B lines.
 * On 32-bit systems contents of this structure fits into one 64B line.
 *
 * The 'dev_private' field was placed in the first cache line to optimize
 * performance because the PMD driver mainly depends on this field.
 */
struct rte_dma_fp_object {
	void *dev_private; /**< PMD-specific private data. */
	rte_dma_copy_t             copy;
	rte_dma_copy_sg_t          copy_sg;
	rte_dma_fill_t             fill;
	rte_dma_submit_t           submit;
	rte_dma_completed_t        completed;
	rte_dma_completed_status_t completed_status;
	void *reserved_cl0;
	/** Reserve space for future IO functions, while keeping data and
	 * dev_ops pointers on the second cacheline.
	 */
	void *reserved_cl1[6];
} __rte_cache_aligned;

extern struct rte_dma_fp_object *rte_dma_fp_objs;

#endif /* RTE_DMADEV_CORE_H */

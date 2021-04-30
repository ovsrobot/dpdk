/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Advanced Micro Devices, Inc. All rights reserved.
 */

#ifndef _RTE_PTMDA_RAWDEV_H_
#define _RTE_PTMDA_RAWDEV_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file rte_ptdma_rawdev.h
 *
 * Definitions for using the ptdma rawdev device driver
 *
 * @warning
 * @b EXPERIMENTAL: these structures and APIs may change without prior notice
 */

#include <rte_common.h>

/** Name of the device driver */
#define PTDMA_PMD_RAWDEV_NAME rawdev_ptdma
/** String reported as the device driver name by rte_rawdev_info_get() */
#define PTDMA_PMD_RAWDEV_NAME_STR "rawdev_ptdma"

/**
 * Configuration structure for an ptdma rawdev instance
 *
 * This structure is to be passed as the ".dev_private" parameter when
 * calling the rte_rawdev_get_info() and rte_rawdev_configure() APIs on
 * an ptdma rawdev instance.
 */
struct rte_ptdma_rawdev_config {
	unsigned short ring_size; /**< size of job submission descriptor ring */
	bool hdls_disable;    /**< if set, ignore user-supplied handle params */
};

/**
 * Enqueue a copy operation onto the ptdma device
 *
 * This queues up a copy operation to be performed by hardware, but does not
 * trigger hardware to begin that operation.
 *
 * @param dev_id
 *   The rawdev device id of the ptdma instance
 * @param src
 *   The physical address of the source buffer
 * @param dst
 *   The physical address of the destination buffer
 * @param length
 *   The length of the data to be copied
 * @param src_hdl
 *   An opaque handle for the source data, to be returned when this operation
 *   has been completed and the user polls for the completion details.
 *   NOTE: If hdls_disable configuration option for the device is set, this
 *   parameter is ignored.
 * @param dst_hdl
 *   An opaque handle for the destination data, to be returned when this
 *   operation has been completed and the user polls for the completion details.
 *   NOTE: If hdls_disable configuration option for the device is set, this
 *   parameter is ignored.
 * @return
 *   Number of operations enqueued, either 0 or 1
 */
static inline int
__rte_experimental
rte_ptdma_enqueue_copy(int dev_id, phys_addr_t src, phys_addr_t dst,
		unsigned int length, uintptr_t src_hdl, uintptr_t dst_hdl);


/**
 * Trigger hardware to begin performing enqueued operations
 *
 * This API is used to write to the hardware to trigger it
 * to begin the operations previously enqueued by rte_ptdma_enqueue_copy()
 *
 * @param dev_id
 *   The rawdev device id of the ptdma instance
 */
static inline void
__rte_experimental
rte_ptdma_perform_ops(int dev_id);

/**
 * Returns details of operations that have been completed
 *
 * This function returns number of newly-completed operations.
 *
 * @param dev_id
 *   The rawdev device id of the ptdma instance
 * @param max_copies
 *   The number of entries which can fit in the src_hdls and dst_hdls
 *   arrays, i.e. max number of completed operations to report.
 *   NOTE: If hdls_disable configuration option for the device is set, this
 *   parameter is ignored.
 * @param src_hdls
 *   Array to hold the source handle parameters of the completed ops.
 *   NOTE: If hdls_disable configuration option for the device is set, this
 *   parameter is ignored.
 * @param dst_hdls
 *   Array to hold the destination handle parameters of the completed ops.
 *   NOTE: If hdls_disable configuration option for the device is set, this
 *   parameter is ignored.
 * @return
 *   -1 on error, with rte_errno set appropriately.
 *   Otherwise number of completed operations i.e. number of entries written
 *   to the src_hdls and dst_hdls array parameters.
 */
static inline int
__rte_experimental
rte_ptdma_completed_ops(int dev_id, uint8_t max_copies,
		uintptr_t *src_hdls, uintptr_t *dst_hdls);


/* include the implementation details from a separate file */
#include "rte_ptdma_rawdev_fns.h"

#ifdef __cplusplus
}
#endif

#endif /* _RTE_PTMDA_RAWDEV_H_ */

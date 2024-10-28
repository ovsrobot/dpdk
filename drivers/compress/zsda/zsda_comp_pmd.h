/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#ifndef _ZSDA_COMP_PMD_H_
#define _ZSDA_COMP_PMD_H_

#include <rte_compressdev_pmd.h>

#include "zsda_common.h"
#include "zsda_qp.h"
#include "zsda_device.h"

/**< ZSDA Compression PMD driver name */
#define COMPRESSDEV_NAME_ZSDA_PMD compress_zsda

/** private data structure for a ZSDA compression device.
 * This ZSDA device is a device offering only a compression service,
 * there can be one of these on each zsda_pci_device (VF).
 */
struct zsda_comp_dev_private {
	struct zsda_pci_device *zsda_pci_dev;
	/**< The zsda pci device hosting the service */
	struct rte_compressdev *compressdev;
	/**< The pointer to this compression device structure */
	const struct rte_compressdev_capabilities *zsda_dev_capabilities;
	/* ZSDA device compression capabilities */
	struct rte_mempool *xformpool;
	/**< The device's pool for zsda_comp_xforms */
	const struct rte_memzone *capa_mz;
	/* Shared memzone for storing capabilities */
};

struct zsda_comp_xform {
	enum rte_comp_xform_type type;
	enum rte_comp_checksum_type checksum_type;
};

__rte_weak int
zsda_comp_match(const void *op_in);

__rte_weak int
zsda_decomp_match(const void *op_in);

__rte_weak int
zsda_build_comp_request(void *op_in, const struct zsda_queue *queue,
		       void **op_cookies, const uint16_t new_tail);

__rte_weak int
zsda_build_decomp_request(void *op_in, const struct zsda_queue *queue,
			 void **op_cookies, const uint16_t new_tail);

__rte_weak int
zsda_comp_callback(void *cookie_in, struct zsda_cqe *cqe);

int zsda_comp_dev_create(struct zsda_pci_device *zsda_pci_dev);

int zsda_comp_dev_destroy(struct zsda_pci_device *zsda_pci_dev);

#endif /* _ZSDA_COMP_PMD_H_ */

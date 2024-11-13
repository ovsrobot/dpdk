/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#ifndef _ZSDA_COMP_PMD_H_
#define _ZSDA_COMP_PMD_H_

#include <rte_compressdev_pmd.h>

#include "zsda_qp.h"
#include "zsda_device.h"

/**< ZSDA Compression PMD driver name */
#define COMPRESSDEV_NAME_ZSDA_PMD compress_zsda

int zsda_comp_dev_create(struct zsda_pci_device *zsda_pci_dev);

int zsda_comp_dev_destroy(struct zsda_pci_device *zsda_pci_dev);

#endif /* _ZSDA_COMP_PMD_H_ */

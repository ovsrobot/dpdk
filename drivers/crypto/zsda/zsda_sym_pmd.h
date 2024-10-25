/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#ifndef _ZSDA_SYM_PMD_H_
#define _ZSDA_SYM_PMD_H_

#include "zsda_device.h"

/** ZSDA Symmetric Crypto PMD driver name */
#define CRYPTODEV_NAME_ZSDA_SYM_PMD crypto_zsda

extern uint8_t zsda_sym_driver_id;

/** private data structure for a ZSDA device.
 * This ZSDA device is a device offering only symmetric crypto service,
 * there can be one of these on each zsda_pci_device (VF).
 */
struct zsda_sym_dev_private {
	struct zsda_pci_device *zsda_pci_dev;
	/**< The zsda pci device hosting the service */

	const struct rte_cryptodev_capabilities *zsda_dev_capabilities;
	/* ZSDA device symmetric crypto capabilities */
	const struct rte_memzone *capa_mz;
	/* Shared memzone for storing capabilities */
};

#endif /* _ZSDA_SYM_PMD_H_ */

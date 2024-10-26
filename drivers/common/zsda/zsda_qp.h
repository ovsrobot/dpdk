/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#ifndef _ZSDA_QP_H_
#define _ZSDA_QP_H_

int zsda_queue_start(const struct rte_pci_device *pci_dev);
int zsda_queue_stop(const struct rte_pci_device *pci_dev);

int zsda_queue_init(struct zsda_pci_device *zsda_pci_dev);

int zsda_get_queue_cfg(struct zsda_pci_device *zsda_pci_dev);

#endif /* _ZSDA_QP_H_ */

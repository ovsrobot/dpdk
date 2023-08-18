/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _NTNIC_VF_H_
#define _NTNIC_VF_H_

#include "rte_bus_pci.h"

int nt_vf_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
		    struct rte_pci_device *pci_dev);
int nt_vf_pci_remove(struct rte_pci_device *pci_dev __rte_unused);

int get_container_fd(int vf_num);
int close_vf_mem_mapping(int vf_num);

#endif /* _NTNIC_VF_H_ */

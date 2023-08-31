/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _NTNIC_VFIO_H_
#define _NTNIC_VFIO_H_

#include <rte_dev.h>
#include <rte_bus_pci.h>
#include <ethdev_pci.h>

int nt_vfio_setup(struct rte_pci_device *dev);
int nt_vfio_remove(int vf_num);

int nt_vfio_get_container_fd(int vf_num);
int nt_vfio_get_group_fd(int vf_num);
int nt_vfio_get_dev_fd(int vf_num);

int nt_vfio_dma_map(int vf_num, void *virt_addr, uint64_t *iova_addr,
		    uint64_t size);
int nt_vfio_dma_unmap(int vf_num, void *virt_addr, uint64_t iova_addr,
		      uint64_t size);

int nt_vfio_dma_map_vdpa(int vf_num, uint64_t virt_addr, uint64_t iova_addr,
			 uint64_t size);
int nt_vfio_dma_unmap_vdpa(int vf_num, uint64_t virt_addr, uint64_t iova_addr,
			   uint64_t size);

/* Find device (PF/VF) number from device address */
int nt_vfio_vf_num(const struct rte_pci_device *dev);
#endif /* _NTNIC_VFIO_H_ */

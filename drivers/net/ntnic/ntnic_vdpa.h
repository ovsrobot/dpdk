/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _NTNIC_VDPA_H_
#define _NTNIC_VDPA_H_

#include <stdint.h>

int nthw_vdpa_get_queue_id_info(struct rte_vdpa_device *vdpa_dev, int rx,
				int queue_id, uint32_t *hw_index,
				uint32_t *host_id, uint32_t *rep_port);

int nthw_vdpa_init(const struct rte_pci_device *vdev,
		   const char *backing_devname, const char *socket_path,
		   uint32_t index, int rxqs, int txqs, uint32_t rep_port,
		   int *vhid);

void nthw_vdpa_close(void);

#endif /* _NTNIC_VDPA_H_ */

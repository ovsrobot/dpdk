/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#ifndef _SPNIC_HWDEV_H_
#define _SPNIC_HWDEV_H_

#include <rte_ether.h>

#define SPNIC_CHIP_FAULT_SIZE		(110 * 1024)

struct spnic_hwdev {
	void *dev_handle; /* Pointer to spnic_nic_dev */
	void *pci_dev; /* Pointer to rte_pci_device */
	void *eth_dev; /* Pointer to rte_eth_dev */

	uint16_t port_id;

	struct spnic_hwif *hwif;
	struct spnic_mbox *func_to_func;
	u8 *chip_fault_stats;

	u16 max_vfs;
	u16 link_status;
};

int spnic_vf_handle_pf_comm_mbox(void *handle, __rte_unused void *pri_handle,
			   __rte_unused u16 cmd, __rte_unused void *buf_in,
			   __rte_unused u16 in_size, __rte_unused void *buf_out,
			   __rte_unused u16 *out_size);

int spnic_init_hwdev(struct spnic_hwdev *hwdev);

void spnic_free_hwdev(struct spnic_hwdev *hwdev);
#endif /* _SPNIC_HWDEV_H_ */

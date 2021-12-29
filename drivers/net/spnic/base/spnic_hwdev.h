/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#ifndef _SPNIC_HWDEV_H_
#define _SPNIC_HWDEV_H_

#include <rte_ether.h>

#define SPNIC_CHIP_FAULT_SIZE		(110 * 1024)
struct cfg_mgmt_info;
struct spnic_hwif;
struct spnic_aeqs;
struct spnic_mbox;
struct spnic_msg_pf_to_mgmt;

struct ffm_intr_info {
	u8 node_id;
	/* Error level of the interrupt source */
	u8 err_level;
	/* Classification by interrupt source properties */
	u16 err_type;
	u32 err_csr_addr;
	u32 err_csr_value;
};

struct spnic_hwdev {
	void *dev_handle; /* Pointer to spnic_nic_dev */
	void *pci_dev; /* Pointer to rte_pci_device */
	void *eth_dev; /* Pointer to rte_eth_dev */

	uint16_t port_id;

	struct spnic_hwif *hwif;
	struct spnic_mbox *func_to_func;
	struct cfg_mgmt_info *cfg_mgmt;
	struct spnic_aeqs *aeqs;
	struct spnic_msg_pf_to_mgmt *pf_to_mgmt;
	u8 *chip_fault_stats;

	u16 max_vfs;
	u16 link_status;
};

int spnic_vf_handle_pf_comm_mbox(void *handle, __rte_unused void *pri_handle,
			   __rte_unused u16 cmd, __rte_unused void *buf_in,
			   __rte_unused u16 in_size, __rte_unused void *buf_out,
			   __rte_unused u16 *out_size);

void spnic_pf_handle_mgmt_comm_event(void *handle, __rte_unused void *pri_handle,
			       u16 cmd, void *buf_in, u16 in_size,
			       void *buf_out, u16 *out_size);

int spnic_init_hwdev(struct spnic_hwdev *hwdev);

void spnic_free_hwdev(struct spnic_hwdev *hwdev);
#endif /* _SPNIC_HWDEV_H_ */

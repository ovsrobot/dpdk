/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#ifndef _SPNIC_HWDEV_H_
#define _SPNIC_HWDEV_H_

#include <rte_ether.h>

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

struct link_event_stats {
	u32 link_down_stats;
	u32 link_up_stats;
};

enum spnic_fault_err_level {
	FAULT_LEVEL_FATAL,
	FAULT_LEVEL_SERIOUS_RESET,
	FAULT_LEVEL_SERIOUS_FLR,
	FAULT_LEVEL_GENERAL,
	FAULT_LEVEL_SUGGESTION,
	FAULT_LEVEL_MAX
};

enum spnic_fault_type {
	FAULT_TYPE_CHIP,
	FAULT_TYPE_UCODE,
	FAULT_TYPE_MEM_RD_TIMEOUT,
	FAULT_TYPE_MEM_WR_TIMEOUT,
	FAULT_TYPE_REG_RD_TIMEOUT,
	FAULT_TYPE_REG_WR_TIMEOUT,
	FAULT_TYPE_PHY_FAULT,
	FAULT_TYPE_MAX
};

struct fault_event_stats {
	rte_atomic32_t chip_fault_stats[22][FAULT_LEVEL_MAX];
	rte_atomic32_t fault_type_stat[FAULT_TYPE_MAX];
	rte_atomic32_t pcie_fault_stats;
};

struct spnic_hw_stats {
	rte_atomic32_t heart_lost_stats;
	struct link_event_stats link_event_stats;
	struct fault_event_stats fault_event_stats;
};

#define SPNIC_CHIP_FAULT_SIZE		(110 * 1024)
#define MAX_DRV_BUF_SIZE		4096

struct nic_cmd_chip_fault_stats {
	u32 offset;
	u8 chip_fault_stats[MAX_DRV_BUF_SIZE];
};

struct spnic_board_info {
	u8 board_type;
	u8 port_num;
	u8 port_speed;
	u8 pcie_width;
	u8 host_num;
	u8 pf_num;
	u16 vf_total_num;
	u8 tile_num;
	u8 qcm_num;
	u8 core_num;
	u8 work_mode;
	u8 service_mode;
	u8 pcie_mode;
	u8 boot_sel;
	u8 board_id;
	u32 cfg_addr;
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
	struct spnic_hw_stats hw_stats;

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

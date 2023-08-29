/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#ifndef _SSSNIC_HW_H_
#define _SSSNIC_HW_H_

#define SSSNIC_PCI_VENDOR_ID 0x1F3F
#define SSSNIC_DEVICE_ID_STD 0x9020

#define SSSNIC_PCI_BAR_CFG 1
#define SSSNIC_PCI_BAR_MGMT 3
#define SSSNIC_PCI_BAR_DB 4

#define SSSNIC_FUNC_TYPE_PF 0
#define SSSNIC_FUNC_TYPE_VF 1
#define SSSNIC_FUNC_TYPE_AF 2
#define SSSNIC_FUNC_TYPE_INVALID 3

#define SSSNIC_DB_CTRL_ENABLE 0x0
#define SSSNIC_DB_CTRL_DISABLE 0x1

#define SSSNIC_MSIX_ENABLE 0
#define SSSNIC_MSIX_DISABLE 1

enum sssnic_pf_status {
	SSSNIC_PF_STATUS_INIT = 0x0,
	SSSNIC_PF_STATUS_ACTIVE = 0x11,
	SSSNIC_PF_STATUS_START = 0x12,
	SSSNIC_PF_STATUS_FINI = 0x13,
};

struct sssnic_hw_attr {
	uint16_t func_idx;
	uint8_t pf_idx;
	uint8_t pci_idx;
	uint8_t vf_off; /* vf offset in pf */
	uint8_t global_vf_off;
	uint8_t func_type;
	uint8_t af_idx;
	uint8_t mf_idx;
	uint8_t num_aeq;
	uint16_t num_ceq;
	uint16_t num_irq;
};

struct sssnic_hw {
	struct rte_pci_device *pci_dev;
	uint8_t *cfg_base_addr;
	uint8_t *mgmt_base_addr;
	uint8_t *db_base_addr;
	uint8_t *db_mem_len;
	struct sssnic_hw_attr attr;
	struct sssnic_eventq *eventqs;
	uint8_t num_eventqs;
	uint16_t eth_port_id;
};

#define SSSNIC_ETH_PORT_ID(hw) ((hw)->eth_port_id)

int sssnic_hw_init(struct sssnic_hw *hw);
void sssnic_hw_shutdown(struct sssnic_hw *hw);
void sssnic_msix_state_set(struct sssnic_hw *hw, uint16_t msix_id, int state);

#endif /* _SSSNIC_HW_H_ */

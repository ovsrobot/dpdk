/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 ZTE Corporation
 */

#include <stdint.h>
#include <ethdev_driver.h>

#include "zxdh_ethdev.h"
#include "zxdh_common.h"

uint32_t zxdh_read_bar_reg(struct rte_eth_dev *dev, uint32_t bar, uint32_t reg)
{
	struct zxdh_hw *hw = dev->data->dev_private;
	uint64_t baseaddr = (uint64_t)(hw->bar_addr[bar]);
	uint32_t val      = *((volatile uint32_t *)(baseaddr + reg));
	return val;
}

void zxdh_write_bar_reg(struct rte_eth_dev *dev, uint32_t bar, uint32_t reg, uint32_t val)
{
	struct zxdh_hw *hw = dev->data->dev_private;
	uint64_t baseaddr = (uint64_t)(hw->bar_addr[bar]);
	*((volatile uint32_t *)(baseaddr + reg)) = val;
}

int32_t zxdh_acquire_lock(struct zxdh_hw *hw)
{
	uint32_t var = zxdh_read_comm_reg((uint64_t)hw->common_cfg, ZXDH_VF_LOCK_REG);

	/* check whether lock is used */
	if (!(var & ZXDH_VF_LOCK_ENABLE_MASK))
		return -1;

	return 0;
}

int32_t zxdh_release_lock(struct zxdh_hw *hw)
{
	uint32_t var = zxdh_read_comm_reg((uint64_t)hw->common_cfg, ZXDH_VF_LOCK_REG);

	if (var & ZXDH_VF_LOCK_ENABLE_MASK) {
		var &= ~ZXDH_VF_LOCK_ENABLE_MASK;
		zxdh_write_comm_reg((uint64_t)hw->common_cfg, ZXDH_VF_LOCK_REG, var);
		return 0;
	}

	return -1;
}

uint32_t zxdh_read_comm_reg(uint64_t pci_comm_cfg_baseaddr, uint32_t reg)
{
	uint32_t val = *((volatile uint32_t *)(pci_comm_cfg_baseaddr + reg));
	return val;
}

void zxdh_write_comm_reg(uint64_t pci_comm_cfg_baseaddr, uint32_t reg, uint32_t val)
{
	*((volatile uint32_t *)(pci_comm_cfg_baseaddr + reg)) = val;
}

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 ZTE Corporation
 */

#ifndef _ZXDH_COMMON_H_
#define _ZXDH_COMMON_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <rte_ethdev.h>

#include "zxdh_ethdev.h"

#define ZXDH_VF_LOCK_ENABLE_MASK      0x1
#define ZXDH_ACQUIRE_CHANNEL_NUM_MAX   10
#define ZXDH_VF_LOCK_REG             0x90

uint32_t zxdh_read_bar_reg(struct rte_eth_dev *dev, uint32_t bar, uint32_t reg);
void zxdh_write_bar_reg(struct rte_eth_dev *dev, uint32_t bar, uint32_t reg, uint32_t val);
int32_t zxdh_release_lock(struct zxdh_hw *hw);
int32_t zxdh_acquire_lock(struct zxdh_hw *hw);
uint32_t zxdh_read_comm_reg(uint64_t pci_comm_cfg_baseaddr, uint32_t reg);
void zxdh_write_comm_reg(uint64_t pci_comm_cfg_baseaddr, uint32_t reg, uint32_t val);

#ifdef __cplusplus
}
#endif

#endif /* _ZXDH_COMMON_H_ */

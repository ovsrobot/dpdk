/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#ifndef __SXEVF_RX_H__
#define __SXEVF_RX_H__

#include "sxe_queue_common.h"

#define SXEVF_RX_DESC_RING_ALIGN	(SXE_ALIGN / sizeof(sxevf_rx_data_desc_t))

s32 sxevf_rx_configure(struct rte_eth_dev *eth_dev);

const u32 *sxevf_dev_supported_ptypes_get(struct rte_eth_dev *dev, size_t *no_of_elements);

void __rte_cold sxevf_rx_function_set(struct rte_eth_dev *dev);

#endif

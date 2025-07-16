/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#ifndef __SXEVF_TX_H__
#define __SXEVF_TX_H__

#include "sxe_queue_common.h"

#define SXEVF_TX_DESC_RING_ALIGN	(SXE_ALIGN / sizeof(sxevf_tx_data_desc_u))

void sxevf_tx_configure(struct rte_eth_dev *eth_dev);

#endif

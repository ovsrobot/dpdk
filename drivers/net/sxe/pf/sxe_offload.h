/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#ifndef __SXE_OFFLOAD_H__
#define __SXE_OFFLOAD_H__

#include "sxe_hw.h"

u64 sxe_rx_queue_offload_capa_get(struct rte_eth_dev *dev);

u64 sxe_rx_port_offload_capa_get(struct rte_eth_dev *dev);

u64 sxe_tx_queue_offload_capa_get(struct rte_eth_dev *dev);

u64 sxe_tx_port_offload_capa_get(struct rte_eth_dev *dev);

#endif

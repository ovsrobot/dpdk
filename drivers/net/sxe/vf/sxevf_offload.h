/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#ifndef __SXEVF_OFFLOAD_H__
#define __SXEVF_OFFLOAD_H__

u64 sxevf_rx_queue_offloads_get(struct rte_eth_dev *dev);

u64 sxevf_rx_port_offloads_get(struct rte_eth_dev *dev);

u64 sxevf_tx_queue_offloads_get(struct rte_eth_dev *dev);

u64 sxevf_tx_port_offloads_get(struct rte_eth_dev *dev);

#endif

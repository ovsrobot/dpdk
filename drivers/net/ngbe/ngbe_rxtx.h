/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2020 Beijing WangXun Technology Co., Ltd.
 * Copyright(c) 2010-2017 Intel Corporation
 */

#ifndef _NGBE_RXTX_H_
#define _NGBE_RXTX_H_

#define NGBE_TX_MAX_SEG                    40

uint64_t ngbe_get_tx_port_offloads(struct rte_eth_dev *dev);
uint64_t ngbe_get_rx_queue_offloads(struct rte_eth_dev *dev);
uint64_t ngbe_get_rx_port_offloads(struct rte_eth_dev *dev);

#endif /* _NGBE_RXTX_H_ */

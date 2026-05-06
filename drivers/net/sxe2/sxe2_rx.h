/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2025, Wuxi Stars Micro System Technologies Co., Ltd.
 */

#ifndef __SXE2_RX_H__
#define __SXE2_RX_H__

#include "sxe2_queue.h"

s32 __rte_cold sxe2_rx_queue_setup(struct rte_eth_dev *dev,
				u16 queue_idx, u16 nb_desc, u32 socket_id,
				const struct rte_eth_rxconf *rx_conf,
				struct rte_mempool *mp);

s32 __rte_cold sxe2_rx_queue_stop(struct rte_eth_dev *dev, u16 rx_queue_id);

void __rte_cold sxe2_rx_queue_mbufs_release(struct sxe2_rx_queue *rxq);

void __rte_cold sxe2_rx_queue_release(struct rte_eth_dev *dev, u16 queue_idx);

void __rte_cold sxe2_all_rxqs_release(struct rte_eth_dev *dev);

void __rte_cold sxe2_rx_queue_info_get(struct rte_eth_dev *dev, u16 queue_id,
		struct rte_eth_rxq_info *qinfo);

s32 __rte_cold sxe2_rx_queue_start(struct rte_eth_dev *dev, u16 rx_queue_id);

s32 __rte_cold sxe2_rxqs_all_start(struct rte_eth_dev *dev);

void __rte_cold sxe2_rxqs_all_stop(struct rte_eth_dev *dev);

struct rte_mbuf *sxe2_mbuf_raw_alloc(struct rte_mempool *mp);

#endif

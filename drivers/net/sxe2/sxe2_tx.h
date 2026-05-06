/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2025, Wuxi Stars Micro System Technologies Co., Ltd.
 */

#ifndef __SXE2_TX_H__
#define __SXE2_TX_H__
#include "sxe2_queue.h"

void __rte_cold sxe2_tx_queue_reset(struct sxe2_tx_queue *txq);

s32 __rte_cold sxe2_tx_queue_start(struct rte_eth_dev *dev, u16 queue_id);

void sxe2_tx_queue_mbufs_release(struct sxe2_tx_queue *txq);

s32 __rte_cold sxe2_tx_queue_stop(struct rte_eth_dev *dev, u16 queue_id);

s32 __rte_cold sxe2_tx_queue_setup(struct rte_eth_dev *dev,
		u16 queue_idx, u16 nb_desc, u32 socket_id,
		const struct rte_eth_txconf *tx_conf);

void __rte_cold sxe2_tx_queue_release(struct rte_eth_dev *dev, u16 queue_idx);

void __rte_cold sxe2_all_txqs_release(struct rte_eth_dev *dev);

void __rte_cold sxe2_tx_queue_info_get(struct rte_eth_dev *dev, u16 queue_id,
		struct rte_eth_txq_info *qinfo);

s32 __rte_cold sxe2_txqs_all_start(struct rte_eth_dev *dev);

void __rte_cold sxe2_txqs_all_stop(struct rte_eth_dev *dev);

#endif

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2025, Wuxi Stars Micro System Technologies Co., Ltd.
 */

#ifndef SXE2_TXRX_H
#define SXE2_TXRX_H
#include <ethdev_driver.h>
#include "sxe2_queue.h"
void sxe2_set_common_function(struct rte_eth_dev *dev);
s32 __rte_cold sxe2_tx_simple_batch_support_check(struct rte_eth_dev *dev,
	u32 *batch_flags);
u16 sxe2_tx_pkts_prepare(__rte_unused void *tx_queue,
		struct rte_mbuf **tx_pkts, u16 nb_pkts);
void sxe2_tx_mode_func_set(struct rte_eth_dev *dev);
void __rte_cold sxe2_rx_queue_reset(struct sxe2_rx_queue *rxq);
void sxe2_rx_mode_func_set(struct rte_eth_dev *dev);
s32 sxe2_tx_burst_mode_get(struct rte_eth_dev *dev,
			__rte_unused uint16_t queue_id, struct rte_eth_burst_mode *mode);
s32 sxe2_rx_burst_mode_get(struct rte_eth_dev *dev,
			__rte_unused u16 queue_id, struct rte_eth_burst_mode *mode);
#endif

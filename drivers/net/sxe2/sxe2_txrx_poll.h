/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2025, Wuxi Stars Micro System Technologies Co., Ltd.
 */

#ifndef SXE2_TXRX_POLL_H
#define SXE2_TXRX_POLL_H

#include "sxe2_queue.h"

u16 sxe2_tx_pkts(void *tx_queue, struct rte_mbuf **tx_pkts, u16 nb_pkts);
u16 sxe2_tx_pkts_simple(void *tx_queue,
			struct rte_mbuf **tx_pkts, u16 nb_pkts);
u16 sxe2_rx_pkts_scattered(void *rx_queue, struct rte_mbuf **rx_pkts, u16 nb_pkts);

u16 sxe2_rx_pkts_scattered_split(void *rx_queue, struct rte_mbuf **rx_pkts, u16 nb_pkts);

#endif

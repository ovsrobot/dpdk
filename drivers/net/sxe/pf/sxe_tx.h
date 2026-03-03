/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */
#ifndef __SXE_TX_H__
#define __SXE_TX_H__

#include <rte_mbuf_core.h>

#include "sxe_queue.h"

#define RTE_PMD_SXE_MAX_TX_BURST 32

#ifdef RTE_LIBRTE_IEEE1588
#define SXE_TX_IEEE1588_TMST RTE_MBUF_F_TX_IEEE1588_TMST
#else
#define SXE_TX_IEEE1588_TMST 0
#endif

#define SXE_TX_OFFLOAD_MASK (			 \
		RTE_MBUF_F_TX_OUTER_IPV6 |		 \
		RTE_MBUF_F_TX_OUTER_IPV4 |		 \
		RTE_MBUF_F_TX_IPV6 |			 \
		RTE_MBUF_F_TX_IPV4 |			 \
		RTE_MBUF_F_TX_VLAN |		 \
		RTE_MBUF_F_TX_IP_CKSUM |		 \
		RTE_MBUF_F_TX_L4_MASK |		 \
		RTE_MBUF_F_TX_TCP_SEG |		 \
		RTE_MBUF_F_TX_MACSEC  |	  \
		RTE_MBUF_F_TX_OUTER_IP_CKSUM |		 \
		SXE_TX_IEEE1588_TMST)

void __rte_cold sxe_tx_configure(struct rte_eth_dev *dev);

int __rte_cold sxe_tx_queue_setup(struct rte_eth_dev *dev,
				u16 tx_queue_id,
				u16 ring_depth,
				u32 socket_id,
				const struct rte_eth_txconf *tx_conf);
int sxe_tx_done_cleanup(void *tx_queue, u32 free_cnt);

void __rte_cold sxe_tx_function_set(struct rte_eth_dev *dev,
					sxe_tx_queue_s *txq);

int sxe_tx_done_cleanup_simple(sxe_tx_queue_s *txq, u32 free_cnt);

u32 sxe_tx_done_cleanup_full(sxe_tx_queue_s *txq, u32 free_cnt);

s32 sxe_tx_bufs_free(sxe_tx_queue_s *txq);

#endif

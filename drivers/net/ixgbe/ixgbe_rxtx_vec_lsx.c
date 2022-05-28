/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Loongson Technology Corporation Limited
 */

#include "base/ixgbe_common.h"
#include "ixgbe_ethdev.h"
#include "ixgbe_rxtx.h"

/* The vector support will come later */
#ifdef RTE_ARCH_NO_VECTOR
int
ixgbe_rx_vec_dev_conf_condition_check(__rte_unused struct rte_eth_dev *dev)
{
	return -1;
}

uint16_t
ixgbe_recv_pkts_vec(__rte_unused void *rx_queue,
	__rte_unused struct rte_mbuf **rx_pkts,
	__rte_unused uint16_t nb_pkts)
{
	return 0;
}

uint16_t
ixgbe_recv_scattered_pkts_vec(__rte_unused void *rx_queue,
	__rte_unused struct rte_mbuf **rx_pkts,
	__rte_unused uint16_t nb_pkts)
{
	return 0;
}

int
ixgbe_rxq_vec_setup(__rte_unused struct ixgbe_rx_queue *rxq)
{
	return -1;
}

uint16_t
ixgbe_xmit_fixed_burst_vec(__rte_unused void *tx_queue,
		__rte_unused struct rte_mbuf **tx_pkts,
		__rte_unused uint16_t nb_pkts)
{
	return 0;
}

int
ixgbe_txq_vec_setup(__rte_unused struct ixgbe_tx_queue *txq)
{
	return -1;
}

void
ixgbe_rx_queue_release_mbufs_vec(__rte_unused struct ixgbe_rx_queue *rxq)
{
}
#else
#error "The current version of LoongArch does not support vector!"
#endif

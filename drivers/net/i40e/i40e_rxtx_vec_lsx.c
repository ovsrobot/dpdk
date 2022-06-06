/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Loongson Technology Corporation Limited
 */

#include "i40e_ethdev.h"
#include "i40e_rxtx.h"

/* The vector support will come later */
#ifdef RTE_ARCH_NO_VECTOR
uint16_t
i40e_recv_scattered_pkts_vec(__rte_unused void *rx_queue,
		__rte_unused struct rte_mbuf **rx_pkts,
		__rte_unused uint16_t nb_pkts)
{
	return 0;
}

uint16_t
i40e_recv_pkts_vec(__rte_unused void *rx_queue,
		__rte_unused struct rte_mbuf **rx_pkts,
		__rte_unused uint16_t nb_pkts)
{
	return 0;
}
uint16_t
i40e_xmit_fixed_burst_vec(__rte_unused void *tx_queue,
		__rte_unused struct rte_mbuf **tx_pkts,
		__rte_unused uint16_t nb_pkts)
{
	return 0;
}
void __rte_cold
i40e_rx_queue_release_mbufs_vec(__rte_unused struct i40e_rx_queue *rxq)
{
}
int __rte_cold
i40e_rxq_vec_setup(__rte_unused struct i40e_rx_queue *rxq)
{
	return -1;
}
int __rte_cold
i40e_txq_vec_setup(__rte_unused struct i40e_tx_queue *txq)
{
	return -1;
}
int __rte_cold
i40e_rx_vec_dev_conf_condition_check(__rte_unused struct rte_eth_dev *dev)
{
	return -1;
}
#else
#error "The current version of LoongArch does not support vector!"
#endif

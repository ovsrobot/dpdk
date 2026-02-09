/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */
#include <ethdev_driver.h>
#include "sxe_types.h"
#include "sxe_offload_common.h"
#include "sxe_compat_version.h"

u64 __sxe_rx_queue_offload_capa_get(struct rte_eth_dev *dev)
{
	RTE_SET_USED(dev);

	u64 offloads = 0;

	offloads |= RTE_ETH_RX_OFFLOAD_VLAN_STRIP;

	return offloads;
}

u64 __sxe_rx_port_offload_capa_get(struct rte_eth_dev *dev)
{
	u64 rx_offload_capa;

	rx_offload_capa = RTE_ETH_RX_OFFLOAD_IPV4_CKSUM  |
			RTE_ETH_RX_OFFLOAD_UDP_CKSUM   |
			RTE_ETH_RX_OFFLOAD_TCP_CKSUM   |
			RTE_ETH_RX_OFFLOAD_KEEP_CRC	|
			RTE_ETH_RX_OFFLOAD_VLAN_FILTER |
			RTE_ETH_RX_OFFLOAD_VLAN_EXTEND |
			RTE_ETH_RX_OFFLOAD_SCATTER |
			RTE_ETH_RX_OFFLOAD_RSS_HASH;

	if (!RTE_ETH_DEV_SRIOV(dev).active)
		rx_offload_capa |= RTE_ETH_RX_OFFLOAD_TCP_LRO;

	return rx_offload_capa;
}

u64 __sxe_tx_port_offload_capa_get(struct rte_eth_dev *dev)
{
	u64 tx_offload_capa;
	RTE_SET_USED(dev);

	tx_offload_capa =
		RTE_ETH_TX_OFFLOAD_VLAN_INSERT |
		RTE_ETH_TX_OFFLOAD_IPV4_CKSUM  |
		RTE_ETH_TX_OFFLOAD_UDP_CKSUM   |
		RTE_ETH_TX_OFFLOAD_TCP_CKSUM   |
		RTE_ETH_TX_OFFLOAD_SCTP_CKSUM  |
		RTE_ETH_TX_OFFLOAD_TCP_TSO	 |
		RTE_ETH_TX_OFFLOAD_MULTI_SEGS;

	return tx_offload_capa;
}

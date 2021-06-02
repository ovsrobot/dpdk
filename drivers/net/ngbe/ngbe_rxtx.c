/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2020 Beijing WangXun Technology Co., Ltd.
 * Copyright(c) 2010-2017 Intel Corporation
 */

#include <stdint.h>
#include <rte_ethdev.h>

#include "base/ngbe.h"
#include "ngbe_ethdev.h"
#include "ngbe_rxtx.h"

uint64_t
ngbe_get_tx_port_offloads(struct rte_eth_dev *dev)
{
	uint64_t tx_offload_capa;
	struct ngbe_hw *hw = NGBE_DEV_HW(dev);

	tx_offload_capa =
		DEV_TX_OFFLOAD_VLAN_INSERT |
		DEV_TX_OFFLOAD_IPV4_CKSUM  |
		DEV_TX_OFFLOAD_UDP_CKSUM   |
		DEV_TX_OFFLOAD_TCP_CKSUM   |
		DEV_TX_OFFLOAD_SCTP_CKSUM  |
		DEV_TX_OFFLOAD_TCP_TSO     |
		DEV_TX_OFFLOAD_UDP_TSO	   |
		DEV_TX_OFFLOAD_UDP_TNL_TSO	|
		DEV_TX_OFFLOAD_IP_TNL_TSO	|
		DEV_TX_OFFLOAD_IPIP_TNL_TSO	|
		DEV_TX_OFFLOAD_MULTI_SEGS;

	if (hw->is_pf)
		tx_offload_capa |= DEV_TX_OFFLOAD_QINQ_INSERT;

	tx_offload_capa |= DEV_TX_OFFLOAD_OUTER_IPV4_CKSUM;

	return tx_offload_capa;
}

uint64_t
ngbe_get_rx_queue_offloads(struct rte_eth_dev *dev __rte_unused)
{
	return DEV_RX_OFFLOAD_VLAN_STRIP;
}

uint64_t
ngbe_get_rx_port_offloads(struct rte_eth_dev *dev)
{
	uint64_t offloads;
	struct ngbe_hw *hw = NGBE_DEV_HW(dev);

	offloads = DEV_RX_OFFLOAD_IPV4_CKSUM  |
		   DEV_RX_OFFLOAD_UDP_CKSUM   |
		   DEV_RX_OFFLOAD_TCP_CKSUM   |
		   DEV_RX_OFFLOAD_KEEP_CRC    |
		   DEV_RX_OFFLOAD_JUMBO_FRAME |
		   DEV_RX_OFFLOAD_VLAN_FILTER |
		   DEV_RX_OFFLOAD_SCATTER;

	if (hw->is_pf)
		offloads |= (DEV_RX_OFFLOAD_VLAN_FILTER |
			     DEV_RX_OFFLOAD_QINQ_STRIP |
			     DEV_RX_OFFLOAD_VLAN_EXTEND);

	return offloads;
}


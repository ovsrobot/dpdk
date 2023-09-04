/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#ifndef _SSSNIC_ETHDEV_H_
#define _SSSNIC_ETHDEV_H_

#define SSSNIC_ETHDEV_MIN_MTU 384
#define SSSNIC_ETHDEV_MAX_MTU 9600
#define SSSNIC_ETHDEV_OVERHEAD_LEN                                             \
	(RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN + RTE_VLAN_HLEN * 2)
#define SSSNIC_ETHDEV_MIN_FRAME_SZ                                             \
	(SSSNIC_ETHDEV_MIN_MTU + SSSNIC_ETHDEV_OVERHEAD_LEN)
#define SSSNIC_ETHDEV_MAX_FRAME_SZ                                             \
	(SSSNIC_ETHDEV_MAX_MTU + SSSNIC_ETHDEV_OVERHEAD_LEN)

#define SSSNIC_ETHDEV_MIN_RXBUF_SZ 1024
#define SSSNIC_ETHDEV_MAX_RXPKT_LEN SSSNIC_ETHDEV_MAX_FRAME_SZ
#define SSSNIC_ETHDEV_MAX_LRO_PKT_SZ 65536

#define SSSNIC_ETHDEV_RSS_KEY_SZ 40
#define SSSNIC_ETHDEV_RSS_RETA_SZ 256

#define SSSNIC_ETHDEV_MAX_NUM_Q_DESC 16384
#define SSSNIC_ETHDEV_MIN_NUM_Q_DESC 128
#define SSSNIC_ETHDEV_NUM_Q_DESC_ALGIN 1

#define SSSNIC_ETHDEV_RX_OFFLOAD_CAPA                                          \
	(RTE_ETH_RX_OFFLOAD_VLAN_STRIP | RTE_ETH_RX_OFFLOAD_VLAN_FILTER |      \
		RTE_ETH_RX_OFFLOAD_IPV4_CKSUM | RTE_ETH_RX_OFFLOAD_UDP_CKSUM | \
		RTE_ETH_RX_OFFLOAD_TCP_CKSUM | RTE_ETH_RX_OFFLOAD_SCTP_CKSUM | \
		RTE_ETH_RX_OFFLOAD_SCATTER | RTE_ETH_RX_OFFLOAD_TCP_LRO |      \
		RTE_ETH_RX_OFFLOAD_RSS_HASH)

#define SSSNIC_ETHDEV_TX_OFFLOAD_CAPA                                          \
	(RTE_ETH_TX_OFFLOAD_VLAN_INSERT | RTE_ETH_TX_OFFLOAD_IPV4_CKSUM |      \
		RTE_ETH_TX_OFFLOAD_OUTER_IPV4_CKSUM |                          \
		RTE_ETH_TX_OFFLOAD_UDP_CKSUM | RTE_ETH_TX_OFFLOAD_TCP_CKSUM |  \
		RTE_ETH_TX_OFFLOAD_SCTP_CKSUM | RTE_ETH_TX_OFFLOAD_TCP_TSO |   \
		RTE_ETH_TX_OFFLOAD_MULTI_SEGS)

#define SSSNIC_ETHDEV_RSS_OFFLOAD_FLOW_TYPES                                   \
	(RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_FRAG_IPV4 |                            \
		RTE_ETH_RSS_NONFRAG_IPV4_OTHER |                               \
		RTE_ETH_RSS_NONFRAG_IPV4_SCTP | RTE_ETH_RSS_NONFRAG_IPV4_TCP | \
		RTE_ETH_RSS_NONFRAG_IPV4_UDP | RTE_ETH_RSS_IPV6 |              \
		RTE_ETH_RSS_NONFRAG_IPV6_OTHER |                               \
		RTE_ETH_RSS_NONFRAG_IPV6_TCP | RTE_ETH_RSS_NONFRAG_IPV6_UDP |  \
		RTE_ETH_RSS_IPV6_EX | RTE_ETH_RSS_IPV6_TCP_EX |                \
		RTE_ETH_RSS_IPV6_UDP_EX)

#define SSSNIC_ETHDEV_DEF_BURST_SZ 32
#define SSSNIC_ETHDEV_DEF_NUM_QUEUES 1
#define SSSNIC_ETHDEV_DEF_RING_SZ 1024

#define SSSNIC_ETHDEV_MAX_NUM_UC_MAC 128
#define SSSNIC_ETHDEV_MAX_NUM_MC_MAC 2048

#define SSSNIC_ETHDEV_DEF_RX_FREE_THRESH 32
#define SSSNIC_ETHDEV_DEF_TX_FREE_THRESH 32

#define SSSNIC_ETHDEV_DEFAULT_FEATURES 0x3fff

enum sssnic_ethdev_rx_mode {
	SSSNIC_ETHDEV_RX_MODE_NONE = 0,
	SSSNIC_ETHDEV_RX_UCAST = RTE_BIT32(0),
	SSSNIC_ETHDEV_RX_MCAST = RTE_BIT32(1),
	SSSNIC_ETHDEV_RX_BCAST = RTE_BIT32(2),
	SSSNIC_ETHDEV_RX_ALL_MCAST = RTE_BIT32(3),
	SSSNIC_ETHDEV_RX_PROMISC = RTE_BIT32(4),
	SSSNIC_ETHDEV_RX_MODE_INVAL = RTE_BIT32(5),
};

#define SSSNIC_ETHDEV_DEF_RX_MODE                                              \
	(SSSNIC_ETHDEV_RX_UCAST | SSSNIC_ETHDEV_RX_MCAST |                     \
		SSSNIC_ETHDEV_RX_BCAST)

#define SSSNIC_ETHDEV_LRO_BUF_SIZE 1024
#define SSSNIC_ETHDEV_LRO_TIMER 16

struct sssnic_netdev {
	void *hw;
	struct rte_ether_addr *mcast_addrs;
	struct rte_ether_addr default_addr;
	uint16_t max_num_txq;
	uint16_t max_num_rxq;
	uint16_t num_started_rxqs;
	uint16_t num_started_txqs;
	uint16_t max_rx_size;
	uint32_t rx_mode;
};

#define SSSNIC_ETHDEV_PRIVATE(eth_dev)                                         \
	((struct sssnic_netdev *)(eth_dev)->data->dev_private)
#define SSSNIC_NETDEV_TO_HW(netdev) ((struct sssnic_hw *)(netdev)->hw)
#define SSSNIC_ETHDEV_TO_HW(eth_dev)                                           \
	SSSNIC_NETDEV_TO_HW(SSSNIC_ETHDEV_PRIVATE(eth_dev))

#endif /*_SSSNIC_ETHDEV_H_*/

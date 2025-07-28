/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#ifndef __SXE_OFFLOAD_H__
#define __SXE_OFFLOAD_H__

#include "sxe_hw.h"

#define SXE_RSS_OFFLOAD_ALL ( \
		RTE_ETH_RSS_IPV4 | \
		RTE_ETH_RSS_NONFRAG_IPV4_TCP | \
		RTE_ETH_RSS_NONFRAG_IPV4_UDP | \
		RTE_ETH_RSS_IPV6 | \
		RTE_ETH_RSS_NONFRAG_IPV6_TCP | \
		RTE_ETH_RSS_NONFRAG_IPV6_UDP)

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_FILTER_CTRL
u8 *sxe_rss_hash_key_get(void);
#endif

void sxe_rss_hash_set(struct sxe_hw *hw,
				struct rte_eth_rss_conf *rss_conf);

u64 sxe_rx_queue_offload_capa_get(struct rte_eth_dev *dev);

u64 sxe_rx_port_offload_capa_get(struct rte_eth_dev *dev);

u64 sxe_tx_queue_offload_capa_get(struct rte_eth_dev *dev);

u64 sxe_tx_port_offload_capa_get(struct rte_eth_dev *dev);

void sxe_rss_disable(struct rte_eth_dev *dev);

void sxe_rss_configure(struct rte_eth_dev *dev);

s32 sxe_rss_reta_update(struct rte_eth_dev *dev,
			struct rte_eth_rss_reta_entry64 *reta_conf,
			u16 reta_size);

s32 sxe_rss_reta_query(struct rte_eth_dev *dev,
			 struct rte_eth_rss_reta_entry64 *reta_conf,
			 u16 reta_size);

s32 sxe_rss_hash_update(struct rte_eth_dev *dev,
			struct rte_eth_rss_conf *rss_conf);

s32 sxe_rss_hash_conf_get(struct rte_eth_dev *dev,
				struct rte_eth_rss_conf *rss_conf);

#endif

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#ifndef __SXEVF_QUEUEU_H__
#define __SXEVF_QUEUEU_H__

#include "sxe_types.h"
#include "sxe_queue_common.h"

typedef union sxe_tx_data_desc sxevf_tx_data_desc_u;
typedef struct sxe_rx_buffer   sxevf_rx_buffer_s;
typedef union sxe_rx_data_desc sxevf_rx_data_desc_u;
typedef struct sxe_tx_queue	sxevf_tx_queue_s;
typedef struct sxe_rx_queue	sxevf_rx_queue_s;

s32 __rte_cold sxevf_rx_queue_mbufs_alloc(sxevf_rx_queue_s *rxq);

s32 __rte_cold sxevf_rx_queue_setup(struct rte_eth_dev *dev,
			 u16 queue_idx, u16 desc_num,
			 unsigned int socket_id,
			 const struct rte_eth_rxconf *rx_conf,
			 struct rte_mempool *mp);

s32 __rte_cold sxevf_tx_queue_setup(struct rte_eth_dev *dev,
				u16 tx_queue_id,
				u16 ring_depth,
				u32 socket_id,
				const struct rte_eth_txconf *tx_conf);
void __rte_cold sxevf_tx_queue_release(struct rte_eth_dev *dev, u16 queue_id);

void __rte_cold sxevf_rx_queue_release(struct rte_eth_dev *dev, u16 queue_id);

void sxevf_rx_queue_info_get(struct rte_eth_dev *dev, u16 queue_id,
	struct rte_eth_rxq_info *qinfo);

void sxevf_tx_queue_info_get(struct rte_eth_dev *dev, u16 queue_id,
		struct rte_eth_txq_info *q_info);

s32 sxevf_tx_done_cleanup(void *tx_queue, u32 free_cnt);

s32 sxevf_rss_reta_update(struct rte_eth_dev *dev,
			struct rte_eth_rss_reta_entry64 *reta_conf,
			u16 reta_size);

s32 sxevf_rss_reta_query(struct rte_eth_dev *dev,
			 struct rte_eth_rss_reta_entry64 *reta_conf,
			 u16 reta_size);

s32 sxevf_rss_hash_conf_get(struct rte_eth_dev *dev,
				struct rte_eth_rss_conf *rss_conf);

s32 sxevf_rss_hash_update(struct rte_eth_dev *dev,
			struct rte_eth_rss_conf *rss_conf);

void sxevf_secondary_proc_init(struct rte_eth_dev *eth_dev);

s32 sxevf_rx_descriptor_status(void *rx_queue, u16 offset);

u16 sxevf_pkts_recv(void *rx_queue, struct rte_mbuf **rx_pkts, u16 num_pkts);

u16 sxevf_pkts_xmit_with_offload(void *tx_queue, struct rte_mbuf **tx_pkts, u16 pkts_num);
s32 sxevf_tx_descriptor_status(void *tx_queue, u16 offset);

void __rte_cold sxevf_txrx_queues_clear(struct rte_eth_dev *dev, bool rx_batch_alloc_allowed);

void sxevf_queues_free(struct rte_eth_dev *dev);

#endif

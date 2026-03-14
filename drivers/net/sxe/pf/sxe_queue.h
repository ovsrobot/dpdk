/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */
#ifndef __SXE_QUEUE_H__
#define __SXE_QUEUE_H__

#include "sxe_queue_common.h"

#define SXE_TXRX_RING_NUM_MAX	 64

#define SXE_TX_MAX_SEG		  40

#define	SXE_MIN_RING_DESC	32
#define	SXE_MAX_RING_DESC	4096

#define SXE_MMW_SIZE_DEFAULT		0x4
#define SXE_MMW_SIZE_JUMBO_FRAME	0x14
#define SXE_MAX_JUMBO_FRAME_SIZE	0x2600

#define SXE_DEFAULT_RX_FREE_THRESH  32
#define SXE_DEFAULT_RX_PTHRESH	  8
#define SXE_DEFAULT_RX_HTHRESH	  8
#define SXE_DEFAULT_RX_WTHRESH	  0

#define SXE_DEFAULT_TX_FREE_THRESH  32
#define SXE_DEFAULT_TX_PTHRESH	  32
#define SXE_DEFAULT_TX_HTHRESH	  0
#define SXE_DEFAULT_TX_WTHRESH	  0
#define SXE_DEFAULT_TX_RSBIT_THRESH 32

#define SXE_ALIGN			   128
#define SXE_RX_DESC_RING_ALIGN	(SXE_ALIGN / sizeof(sxe_rx_data_desc_u))
#define SXE_TX_DESC_RING_ALIGN	(SXE_ALIGN / sizeof(sxe_tx_data_desc_u))

#define SXE_TX_MAX_SEG		  40
#define RTE_SXE_REGISTER_POLL_WAIT_10_MS  10

typedef union sxe_tx_data_desc sxe_tx_data_desc_u;
typedef struct sxe_rx_buffer   sxe_rx_buffer_s;
typedef union sxe_rx_data_desc sxe_rx_data_desc_u;
typedef struct sxe_tx_queue	sxe_tx_queue_s;
typedef struct sxe_rx_queue	sxe_rx_queue_s;

struct sxe_tx_context_desc {
	__le32 vlan_macip_lens;
	__le32 seqnum_seed;
	__le32 type_tucmd_mlhl;
	__le32 mss_l4len_idx;
};

s32 __rte_cold sxe_txq_arg_validate(struct rte_eth_dev *dev, u16 ring_depth,
				u16 *rs_thresh, u16 *free_thresh,
				const struct rte_eth_txconf *tx_conf);

sxe_tx_queue_s * __rte_cold sxe_tx_queue_alloc(struct rte_eth_dev *dev,
					u16 queue_idx,
					u16 ring_depth,
					u32 socket_id);

s32 __rte_cold sxe_tx_queue_start(struct rte_eth_dev *dev, u16 queue_id);

s32 __rte_cold sxe_tx_queue_stop(struct rte_eth_dev *dev, u16 queue_id);

void sxe_rx_queue_info_get(struct rte_eth_dev *dev, u16 queue_id,
	struct rte_eth_rxq_info *qinfo);

void __rte_cold sxe_rx_queue_release(struct rte_eth_dev *dev,
					u16 queue_idx);

s32 sxe_rx_queue_start(struct rte_eth_dev *dev, u16 queue_id);

s32 sxe_rx_queue_stop(struct rte_eth_dev *dev, u16 queue_id);

void sxe_rx_queue_init(bool rx_batch_alloc_allowed,
				sxe_rx_queue_s *rxq);

void sxe_rx_queue_free(sxe_rx_queue_s *rxq);

int sxe_rx_queue_count(void *rx_queue);

s32 sxe_mq_mode_check(struct rte_eth_dev *dev);

void sxe_txrx_queues_clear(struct rte_eth_dev *dev, bool rx_batch_alloc_allowed);

void sxe_queues_free(struct rte_eth_dev *dev);

void __rte_cold sxe_tx_queue_release(struct rte_eth_dev *dev,
					u16 queue_idx);

void sxe_multi_queue_tx_configure(struct rte_eth_dev *dev);

void sxe_tx_queue_info_get(struct rte_eth_dev *dev, uint16_t queue_id,
		struct rte_eth_txq_info *q_info);

void sxe_recycle_rxq_info_get(struct rte_eth_dev *dev, u16 queue_id,
		struct rte_eth_recycle_rxq_info *recycle_rxq_info);

u16 sxe_pkts_simple_xmit(void *tx_queue, struct rte_mbuf **tx_pkts, u16 pkts_num);

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SIMD
#if defined(RTE_ARCH_X86) || defined(RTE_ARCH_ARM)
u16 sxe_recycle_tx_mbufs_reuse_vec(void *tx_queue,
		struct rte_eth_recycle_rxq_info *recycle_rxq_info);
#endif

u16 sxe_pkts_vector_xmit(void *tx_queue, struct rte_mbuf **tx_pkts,
			   u16 pkts_num);
#endif

u16 sxe_pkts_xmit_with_offload(void *tx_queue, struct rte_mbuf **tx_pkts, u16 pkts_num);

u16 sxe_prep_pkts(void *tx_queue, struct rte_mbuf **tx_pkts, u16 pkts_num);

int sxe_tx_descriptor_status(void *tx_queue, u16 offset);

s32 sxe_queue_rate_limit_set(struct rte_eth_dev *dev,
					u16 queue_idx, u32 tx_rate);

const struct sxe_txq_ops *sxe_tx_default_ops_get(void);

s32 __rte_cold sxe_rx_queue_mbufs_alloc(sxe_rx_queue_s *rxq);

void __rte_cold sxe_tx_queue_free(sxe_tx_queue_s *txq);

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SRIOV
s32 sxe_sriov_mq_mode_check(struct rte_eth_dev *dev);

#endif

void __rte_cold sxe_rx_queue_mbufs_free(sxe_rx_queue_s *rxq);

#endif

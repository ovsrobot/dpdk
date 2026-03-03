/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#ifndef __SXE_QUEUE_COMMON_H__
#define __SXE_QUEUE_COMMON_H__

#include "sxe_types.h"
#include "sxe_compat_platform.h"
#include "sxe_compat_version.h"
#ifdef SXE_HOST_DRIVER
#include "sxe_drv_type.h"
#endif

#define RTE_PMD_SXE_MAX_RX_BURST 32

enum sxe_ctxt_num {
	SXE_CTXT_DESC_0	= 0,
	SXE_CTXT_DESC_1	= 1,
	SXE_CTXT_DESC_NUM  = 2,
};

struct rx_setup {
	struct rte_eth_dev *dev;
	u16 queue_idx;
	u16 desc_num;
	u32 socket_id;
	const struct rte_eth_rxconf *rx_conf;
	struct rte_mempool *mp;
	u8 __iomem *reg_base_addr;
	bool *rx_batch_alloc_allowed;
};

struct tx_setup {
	struct rte_eth_dev *dev;
	u16 queue_idx;
	u16 desc_num;
	u32 socket_id;
	const struct rte_eth_txconf *tx_conf;
	u8 __iomem *reg_base_addr;
};

union sxe_tx_data_desc {
	struct {
		__le64 buffer_addr;
		__le32 cmd_type_len;
		__le32 olinfo_status;
	} read;
	struct {
		__le64 rsvd;
		__le32 nxtseq_seed;
		__le32 status;
	} wb;
};

struct sxe_rx_buffer {
	struct rte_mbuf *mbuf;
};

struct sxe_rx_queue_stats {
	u64 csum_err;
};

union sxe_rx_data_desc {
	struct {
		__le64 pkt_addr;
		__le64 hdr_addr;
	} read;
	struct {
		struct {
			union {
				__le32 data;
				struct {
					__le16 pkt_info;
					__le16 hdr_info;
				} hs_rss;
			} lo_dword;
			union {
				__le32 rss;
				struct {
					__le16 ip_id;
					__le16 csum;
				} csum_ip;
			} hi_dword;
		} lower;
		struct {
			__le32 status_error;
			__le16 length;
			__le16 vlan;
		} upper;
	} wb;
};

struct sxe_tx_buffer {
	struct rte_mbuf *mbuf;
	u16 next_id;
	u16 last_id;
};

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SIMD
struct sxe_tx_buffer_vec {
	struct rte_mbuf *mbuf;
};
#endif

union sxe_tx_offload {
	u64 data[2];
	struct {
		u64 l2_len:7;
		u64 l3_len:9;
		u64 l4_len:8;
		u64 tso_segsz:16;
		u64 vlan_tci:16;

		u64 outer_l3_len:8;
		u64 outer_l2_len:8;
	};
};

struct sxe_ctxt_info {
	u64 flags;
	union sxe_tx_offload tx_offload;
	union sxe_tx_offload tx_offload_mask;
};

struct sxe_tx_queue {
	volatile union sxe_tx_data_desc *desc_ring;
	u64			 base_addr;
#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SIMD
	union {
		struct sxe_tx_buffer *buffer_ring;
		struct sxe_tx_buffer_vec *buffer_ring_vec;
	};
#else
	struct sxe_tx_buffer *buffer_ring;
#endif
	volatile u32   *tdt_reg_addr;
	u16			ring_depth;
	u16			next_to_use;
	u16			free_thresh;

	u16			rs_thresh;

	u16			desc_used_num;
	u16			next_to_clean;
	u16			desc_free_num;
	u16			next_dd;
	u16			next_rs;
	u16			queue_idx;
	u16			reg_idx;
	u16			port_id;
	u8			 pthresh;
	u8			 hthresh;

	u8			 wthresh;
	u64			offloads;
	u32			ctx_curr;
	struct sxe_ctxt_info ctx_cache[SXE_CTXT_DESC_NUM];
	const struct sxe_txq_ops *ops;
	u8	 tx_deferred_start;
	const struct rte_memzone *mz;
};

struct sxe_rx_queue {
	struct rte_mempool  *mb_pool;
	volatile union sxe_rx_data_desc *desc_ring;
	u64  base_addr;
	volatile u32   *rdt_reg_addr;
	struct sxe_rx_buffer *buffer_ring;
	struct sxe_rx_buffer *sc_buffer_ring;
#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SIMD
	struct rte_mbuf *pkt_first_seg;
	struct rte_mbuf *pkt_last_seg;
	u64	mbuf_init_value;
	u8	 is_using_sse;
#if defined(RTE_ARCH_X86) || defined(RTE_ARCH_ARM)
	u16	realloc_num;
	u16	realloc_start;
#endif
#endif
	u16	ring_depth;
	u16	processing_idx;
	u16	hold_num;
	u16	completed_pkts_num;
	u16	next_ret_pkg;
	u16	batch_alloc_trigger;

	u16	batch_alloc_size;
	u16	queue_id;
	u16	reg_idx;
	u16	pkt_type_mask;
	u16	port_id;
	u8	 crc_len;
	u8	 drop_en;
	u8	 deferred_start;
	u64	vlan_flags;
	u64	offloads;
	struct rte_mbuf fake_mbuf;
	struct rte_mbuf *completed_ring[RTE_PMD_SXE_MAX_RX_BURST * 2];
	const struct rte_memzone *mz;
	struct sxe_rx_queue_stats rx_stats;
};

struct sxe_txq_ops {
	void (*init)(struct sxe_tx_queue *txq);
	void (*mbufs_release)(struct sxe_tx_queue *txq);
	void (*buffer_ring_free)(struct sxe_tx_queue *txq);
};

s32 __rte_cold __sxe_rx_queue_setup(struct rx_setup *rx_setup, bool is_vf);

int __rte_cold __sxe_tx_queue_setup(struct tx_setup *tx_setup, bool is_vf);

void __sxe_rx_queue_info_get(struct rte_eth_dev *dev, u16 queue_id,
					struct rte_eth_rxq_info *qinfo);

void __sxe_recycle_rxq_info_get(struct rte_eth_dev *dev, u16 queue_id,
		struct rte_eth_recycle_rxq_info *q_info);

void __sxe_tx_queue_info_get(struct rte_eth_dev *dev, u16 queue_id,
		struct rte_eth_txq_info *q_info);

s32 __sxe_tx_done_cleanup(void *tx_queue, u32 free_cnt);

s32 __rte_cold __sxe_rx_queue_mbufs_alloc(struct sxe_rx_queue *rxq);

void __rte_cold __sxe_tx_queue_free(struct sxe_tx_queue *txq);

void sxe_rx_queue_free(struct sxe_rx_queue *rxq);

void __rte_cold __sxe_rx_queue_free(struct sxe_rx_queue *rxq);

void __rte_cold __sxe_txrx_queues_clear(struct rte_eth_dev *dev, bool rx_batch_alloc_allowed);

void __sxe_queues_free(struct rte_eth_dev *dev);

void __sxe_secondary_proc_init(struct rte_eth_dev *eth_dev,
	bool rx_batch_alloc_allowed, bool *rx_vec_allowed);

#endif

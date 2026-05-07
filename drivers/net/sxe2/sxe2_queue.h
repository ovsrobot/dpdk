/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2025, Wuxi Stars Micro System Technologies Co., Ltd.
 */

#ifndef __SXE2_QUEUE_H__
#define __SXE2_QUEUE_H__
#include <rte_ethdev.h>
#include <rte_io.h>
#include <rte_stdatomic.h>
#include <ethdev_driver.h>

#include "sxe2_drv_cmd.h"
#include "sxe2_txrx_common.h"

#define SXE2_PCI_REG_READ(reg)			\
		rte_read32(reg)
#define SXE2_PCI_REG_WRITE_WC(reg, value)			\
		rte_write32_wc((rte_cpu_to_le_32(value)), reg)
#define SXE2_PCI_REG_WRITE_WC_RELAXED(reg, value)		\
		rte_write32_wc_relaxed((rte_cpu_to_le_32(value)), reg)

struct sxe2_queue_context {
	u16 qp_cnt_assign;
	u16 base_idx_in_pf;

	u32 tx_mode_flags;
	u32 rx_mode_flags;
};

struct sxe2_tx_buffer {
	struct rte_mbuf *mbuf;

	u16 next_id;
	u16 last_id;
};

struct sxe2_tx_buffer_vec {
	struct rte_mbuf *mbuf;
};

struct sxe2_txq_stats {
	u64 tx_restart;
	u64 tx_busy;

	u64 tx_linearize;
	u64 tx_tso_linearize_chk;
	u64 tx_vlan_insert;
	u64 tx_tso_packets;
	u64 tx_tso_bytes;
	u64 tx_csum_none;
	u64 tx_csum_partial;
	u64 tx_csum_partial_inner;
	u64 tx_queue_dropped;
	u64 tx_xmit_more;
	u64 tx_pkts_num;
	u64 tx_desc_not_done;
};

struct sxe2_tx_queue;
struct sxe2_txq_ops {
	void (*queue_reset)(struct sxe2_tx_queue *txq);
	void (*mbufs_release)(struct sxe2_tx_queue *txq);
	void (*buffer_ring_free)(struct sxe2_tx_queue *txq);
};
struct sxe2_tx_queue {
	volatile union sxe2_tx_data_desc *desc_ring;
	struct sxe2_tx_buffer *buffer_ring;
	volatile u32 *tdt_reg_addr;

	u64 offloads;
	u16 ring_depth;
	u16 desc_free_num;

	u16 free_thresh;

	u16 rs_thresh;
	u16 next_use;
	u16 next_clean;

	u16 desc_used_num;
	u16 next_dd;
	u16 next_rs;
	u16 ipsec_pkt_md_offset;

	u16 port_id;
	u16 queue_id;
	u16 idx_in_func;
	bool tx_deferred_start;
	u8 pthresh;
	u8 hthresh;
	u8 wthresh;
	u16 reg_idx;
	u64 base_addr;
	struct sxe2_vsi *vsi;
	const struct rte_memzone *mz;
	struct sxe2_txq_ops ops;
#ifdef SXE2_DPDK_DEBUG
	struct sxe2_txq_stats tx_stats;
	struct sxe2_txq_stats tx_stats_cur;
	struct sxe2_txq_stats tx_stats_prev;
#endif
	u8  vlan_flag;
	u8  use_ctx:1,
		res:7;
};
struct sxe2_rx_queue;
struct sxe2_rxq_ops {
	void (*queue_reset)(struct sxe2_rx_queue *rxq);
	void (*mbufs_release)(struct sxe2_rx_queue *txq);
};
struct sxe2_rxq_stats {
	u64 rx_pkts_num;
	u64 rx_rss_pkt_num;
	u64 rx_fnav_pkt_num;
	u64 rx_ptp_pkt_num;
	u32 rx_vec_align_drop;

	u32 rxdid_1588_err;
	u32 ip_csum_err;
	u32 l4_csum_err;
	u32 outer_ip_csum_err;
	u32 outer_l4_csum_err;
	u32 macsec_err;
	u32 ipsec_err;

	u64 ptype_pkts[SXE2_MAX_PTYPE_NUM];
};

struct sxe2_rxq_sw_stats {
	RTE_ATOMIC(uint64_t)pkts;
	RTE_ATOMIC(uint64_t)bytes;
	RTE_ATOMIC(uint64_t)drop_pkts;
	RTE_ATOMIC(uint64_t)drop_bytes;
	RTE_ATOMIC(uint64_t)unicast_pkts;
	RTE_ATOMIC(uint64_t)multicast_pkts;
	RTE_ATOMIC(uint64_t)broadcast_pkts;
};

struct sxe2_rx_queue {
	volatile union sxe2_rx_desc *desc_ring;
	volatile u32 *rdt_reg_addr;
	struct rte_mempool *mb_pool;
	struct rte_mbuf **buffer_ring;
	struct sxe2_vsi *vsi;

	u64 offloads;
	u16 ring_depth;
	u16 rx_free_thresh;
	u16 processing_idx;
	u16 hold_num;
	u16 next_ret_pkt;
	u16 batch_alloc_trigger;
	u16 completed_pkts_num;
	u64 update_time;
	u32 desc_ts;
	u64 ts_high;
	u32 ts_low;
	u32 ts_need_update;
	u8  crc_len;
	bool fnav_enable;

	struct rte_eth_rxseg_split rx_seg[SXE2_RX_SEG_NUM];

	struct rte_mbuf *completed_buf[SXE2_RX_PKTS_BURST_BATCH_NUM * 2];
	struct rte_mbuf *pkt_first_seg;
	struct rte_mbuf *pkt_last_seg;
	u64 mbuf_init_value;
	u16 realloc_num;
	u16 realloc_start;
	struct rte_mbuf fake_mbuf;

	const struct rte_memzone *mz;
	struct sxe2_rxq_ops ops;
	rte_iova_t base_addr;
	u16 reg_idx;
	u32 low_desc_waterline : 16;
	u32 ldw_event_pending : 1;
#ifdef SXE2_DPDK_DEBUG
	struct sxe2_rxq_stats rx_stats;
	struct sxe2_rxq_stats rx_stats_cur;
	struct sxe2_rxq_stats rx_stats_prev;
#endif
	struct sxe2_rxq_sw_stats sw_stats;
	u16 port_id;
	u16 queue_id;
	u16 idx_in_func;
	u16 rx_buf_len;
	u16 rx_hdr_len;
	u16 max_pkt_len;
	bool rx_deferred_start;
	u8 drop_en;
};

#ifdef SXE2_DPDK_DEBUG
#define SXE2_RX_STATS_CNT(rxq, name, num) \
	((((struct sxe2_rx_queue *)(rxq))->rx_stats.name) += (num))

#define SXE2_TX_STATS_CNT(txq, name, num) \
	((((struct sxe2_tx_queue *)(txq))->tx_stats.name) += (num))
#else
#define SXE2_RX_STATS_CNT(rxq, name, num)
#define SXE2_TX_STATS_CNT(txq, name, num)
#endif

#ifdef SXE2_DPDK_DEBUG_RXTX_LOG
#define PMD_LOG_RX_DEBUG(fmt, ...)PMD_LOG_DEBUG(RX, fmt, ##__VA_ARGS__)

#define PMD_LOG_RX_INFO(fmt, ...) PMD_LOG_INFO(RX, fmt, ##__VA_ARGS__)

#define PMD_LOG_TX_DEBUG(fmt, ...) PMD_LOG_DEBUG(TX, fmt, ##__VA_ARGS__)

#define PMD_LOG_TX_INFO(fmt, ...) PMD_LOG_INFO(TX, fmt, ##__VA_ARGS__)
#else
#define PMD_LOG_RX_DEBUG(fmt, ...)
#define PMD_LOG_RX_INFO(fmt, ...)
#define PMD_LOG_TX_DEBUG(fmt, ...)
#define PMD_LOG_TX_INFO(fmt, ...)
#endif

struct sxe2_adapter;

void sxe2_sw_queue_ctx_hw_cap_set(struct sxe2_adapter *adapter,
		struct sxe2_drv_queue_caps *q_caps);

s32 sxe2_queues_init(struct rte_eth_dev *dev);

#endif

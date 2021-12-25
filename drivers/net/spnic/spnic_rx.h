/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#ifndef _SPNIC_RX_H_
#define _SPNIC_RX_H_

#define SPNIC_DEFAULT_RX_CSUM_OFFLOAD	0xFFF

#define SPNIC_RSS_OFFLOAD_ALL ( \
	ETH_RSS_IPV4 | \
	ETH_RSS_FRAG_IPV4 | \
	ETH_RSS_NONFRAG_IPV4_TCP | \
	ETH_RSS_NONFRAG_IPV4_UDP | \
	ETH_RSS_NONFRAG_IPV4_OTHER | \
	ETH_RSS_IPV6 | \
	ETH_RSS_FRAG_IPV6 | \
	ETH_RSS_NONFRAG_IPV6_TCP | \
	ETH_RSS_NONFRAG_IPV6_UDP | \
	ETH_RSS_NONFRAG_IPV6_OTHER | \
	ETH_RSS_IPV6_EX | \
	ETH_RSS_IPV6_TCP_EX | \
	ETH_RSS_IPV6_UDP_EX)

struct spnic_rxq_stats {
	u64 packets;
	u64 bytes;
	u64 errors;
	u64 csum_errors;
	u64 other_errors;
	u64 unlock_bp;
	u64 dropped;

	u64 rx_nombuf;
	u64 rx_discards;
	u64 burst_pkts;
};

struct spnic_rq_cqe {
	u32 status;
	u32 vlan_len;

	u32 offload_type;
	u32 hash_val;
	u32 xid;
	u32 decrypt_info;
	u32 rsvd6;
	u32 pkt_info;
};

/*
 * Attention: please do not add any member in spnic_rx_info because rxq bulk
 * rearm mode will write mbuf in rx_info
 */
struct spnic_rx_info {
	struct rte_mbuf *mbuf;
};

struct spnic_sge_sect {
	struct spnic_sge sge;
	u32 rsvd;
};

struct spnic_rq_extend_wqe {
	struct spnic_sge_sect buf_desc;
	struct spnic_sge_sect cqe_sect;
};

struct spnic_rq_normal_wqe {
	u32 buf_hi_addr;
	u32 buf_lo_addr;
	u32 cqe_hi_addr;
	u32 cqe_lo_addr;
};

struct spnic_rq_wqe {
	union {
		struct spnic_rq_normal_wqe normal_wqe;
		struct spnic_rq_extend_wqe extend_wqe;
	};
};

struct spnic_rxq {
	struct spnic_nic_dev *nic_dev;

	u16 q_id;
	u16 q_depth;
	u16 q_mask;
	u16 buf_len;

	u32 rx_buff_shift;

	u16 rx_free_thresh;
	u16 rxinfo_align_end;
	u16 wqebb_shift;
	u16 wqebb_size;

	u16 wqe_type;
	u16 cons_idx;
	u16 prod_idx;
	u16 delta;

	u16 next_to_update;
	u16 port_id;

	const struct rte_memzone *rq_mz;
	void *queue_buf_vaddr; /* Rq dma info */
	rte_iova_t queue_buf_paddr;

	const struct rte_memzone *pi_mz;
	u16 *pi_virt_addr;
	void *db_addr;
	rte_iova_t pi_dma_addr;

	struct spnic_rx_info *rx_info;
	struct spnic_rq_cqe *rx_cqe;
	struct rte_mempool *mb_pool;

	const struct rte_memzone *cqe_mz;
	rte_iova_t cqe_start_paddr;
	void *cqe_start_vaddr;
	u8 dp_intr_en;
	u16 msix_entry_idx;

	unsigned long status;

	struct spnic_rxq_stats	rxq_stats;
} __rte_cache_aligned;

int spnic_rx_fill_wqe(struct spnic_rxq *rxq);

u32 spnic_rx_fill_buffers(struct spnic_rxq *rxq);

void spnic_free_rxq_mbufs(struct spnic_rxq *rxq);

void spnic_free_all_rxq_mbufs(struct spnic_nic_dev *nic_dev);

int spnic_update_rss_config(struct rte_eth_dev *dev,
			    struct rte_eth_rss_conf *rss_conf);

int spnic_start_all_rqs(struct rte_eth_dev *eth_dev);

void spnic_add_rq_to_rx_queue_list(struct spnic_nic_dev *nic_dev,
				    u16 queue_id);

int spnic_refill_indir_rqid(struct spnic_rxq *rxq);

void spnic_init_rx_queue_list(struct spnic_nic_dev *nic_dev);

void spnic_remove_rq_from_rx_queue_list(struct spnic_nic_dev *nic_dev,
					 u16 queue_id);

/**
 * Get receive queue local ci
 *
 * @param[in] rxq
 *   Receive queue
 * @return
 *   Receive queue local ci
 */
static inline u16 spnic_get_rq_local_ci(struct spnic_rxq *rxq)
{
	return MASKED_QUEUE_IDX(rxq, rxq->cons_idx);
}

static inline u16 spnic_get_rq_free_wqebb(struct spnic_rxq *rxq)
{
	return rxq->delta - 1;
}

/**
 * Update receive queue local ci
 *
 * @param[in] rxq
 *   Receive queue
 * @param[in] wqe_cnt
 *   Wqebb counters
 */
static inline void spnic_update_rq_local_ci(struct spnic_rxq *rxq,
					     u16 wqe_cnt)
{
	rxq->cons_idx += wqe_cnt;
	rxq->delta += wqe_cnt;
}
#endif /* _SPNIC_RX_H_ */

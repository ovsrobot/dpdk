/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#ifndef _SPNIC_TX_H_
#define _SPNIC_TX_H_
#define MAX_SINGLE_SGE_SIZE		65536
#define SPNIC_NONTSO_PKT_MAX_SGE	38
#define SPNIC_NONTSO_SEG_NUM_VALID(num)	\
	((num) <= SPNIC_NONTSO_PKT_MAX_SGE)

#define SPNIC_TSO_PKT_MAX_SGE		127
#define SPNIC_TSO_SEG_NUM_INVALID(num)	((num) > SPNIC_TSO_PKT_MAX_SGE)
/* Tx offload info */
struct spnic_tx_offload_info {
	u8 outer_l2_len;
	u8 outer_l3_type;
	u16 outer_l3_len;

	u8 inner_l2_len;
	u8 inner_l3_type;
	u16 inner_l3_len;

	u8 tunnel_length;
	u8 tunnel_type;
	u8 inner_l4_type;
	u8 inner_l4_len;

	u16 payload_offset;
	u8 inner_l4_tcp_udp;
	u8 rsvd0;
};

/* tx wqe ctx */
struct spnic_wqe_info {
	u8 around;
	u8 cpy_mbuf_cnt;
	u16 sge_cnt;

	u8 offload;
	u8 rsvd0;
	u16 payload_offset;

	u8 wrapped;
	u8 owner;
	u16 pi;

	u16 wqebb_cnt;
	u16 rsvd1;

	u32 queue_info;
};
struct spnic_sq_wqe_desc {
	u32 ctrl_len;
	u32 queue_info;
	u32 hi_addr;
	u32 lo_addr;
};

/*
 * Engine only pass first 12B TS field directly to uCode through metadata,
 * vlan_offoad is used for hardware when vlan insert in tx
 */
struct spnic_sq_task {
	u32 pkt_info0;
	u32 ip_identify;
	u32 pkt_info2; /* Rsvd for ipsec spi */
	u32 vlan_offload;
};

struct spnic_sq_bufdesc {
	u32 len; /* 31-bits Length, L2NIC only use length[17:0] */
	u32 rsvd;
	u32 hi_addr;
	u32 lo_addr;
};

struct spnic_sq_compact_wqe {
	struct spnic_sq_wqe_desc wqe_desc;
};

struct spnic_sq_extend_wqe {
	struct spnic_sq_wqe_desc wqe_desc;
	struct spnic_sq_task task;
	struct spnic_sq_bufdesc buf_desc[0];
};

struct spnic_sq_wqe {
	union {
		struct spnic_sq_compact_wqe compact_wqe;
		struct spnic_sq_extend_wqe extend_wqe;
	};
};

/* Use section pointer to support non continuous wqe */
struct spnic_sq_wqe_combo {
	struct spnic_sq_wqe_desc *hdr;
	struct spnic_sq_task *task;
	struct spnic_sq_bufdesc *bds_head;
	u32 wqe_type;
	u32 task_type;
};

/* SQ ctrl info */
enum sq_wqe_data_format {
	SQ_NORMAL_WQE = 0,
};

enum sq_wqe_ec_type {
	SQ_WQE_COMPACT_TYPE = 0,
	SQ_WQE_EXTENDED_TYPE = 1,
};

#define COMPACT_WQE_MAX_CTRL_LEN 0x3FFF

enum sq_wqe_tasksect_len_type {
	SQ_WQE_TASKSECT_46BITS = 0,
	SQ_WQE_TASKSECT_16BYTES = 1,
};

#define SQ_CTRL_BD0_LEN_SHIFT			0
#define SQ_CTRL_RSVD_SHIFT			18
#define SQ_CTRL_BUFDESC_NUM_SHIFT		19
#define SQ_CTRL_TASKSECT_LEN_SHIFT		27
#define SQ_CTRL_DATA_FORMAT_SHIFT		28
#define SQ_CTRL_DIRECT_SHIFT			29
#define SQ_CTRL_EXTENDED_SHIFT			30
#define SQ_CTRL_OWNER_SHIFT			31

#define SQ_CTRL_BD0_LEN_MASK			0x3FFFFU
#define SQ_CTRL_RSVD_MASK			0x1U
#define SQ_CTRL_BUFDESC_NUM_MASK		0xFFU
#define SQ_CTRL_TASKSECT_LEN_MASK		0x1U
#define SQ_CTRL_DATA_FORMAT_MASK		0x1U
#define SQ_CTRL_DIRECT_MASK			0x1U
#define SQ_CTRL_EXTENDED_MASK			0x1U
#define SQ_CTRL_OWNER_MASK			0x1U

#define SQ_CTRL_SET(val, member)	(((u32)(val) & \
					 SQ_CTRL_##member##_MASK) << \
					 SQ_CTRL_##member##_SHIFT)

#define SQ_CTRL_GET(val, member)	(((val) >> SQ_CTRL_##member##_SHIFT) \
					& SQ_CTRL_##member##_MASK)

#define SQ_CTRL_CLEAR(val, member)	((val) & \
					(~(SQ_CTRL_##member##_MASK << \
					SQ_CTRL_##member##_SHIFT)))

#define SQ_CTRL_QUEUE_INFO_PKT_TYPE_SHIFT		0
#define SQ_CTRL_QUEUE_INFO_PLDOFF_SHIFT			2
#define SQ_CTRL_QUEUE_INFO_UFO_SHIFT			10
#define SQ_CTRL_QUEUE_INFO_TSO_SHIFT			11
#define SQ_CTRL_QUEUE_INFO_TCPUDP_CS_SHIFT		12
#define SQ_CTRL_QUEUE_INFO_MSS_SHIFT			13
#define SQ_CTRL_QUEUE_INFO_SCTP_SHIFT			27
#define SQ_CTRL_QUEUE_INFO_UC_SHIFT			28
#define SQ_CTRL_QUEUE_INFO_PRI_SHIFT			29

#define SQ_CTRL_QUEUE_INFO_PKT_TYPE_MASK		0x3U
#define SQ_CTRL_QUEUE_INFO_PLDOFF_MASK			0xFFU
#define SQ_CTRL_QUEUE_INFO_UFO_MASK			0x1U
#define SQ_CTRL_QUEUE_INFO_TSO_MASK			0x1U
#define SQ_CTRL_QUEUE_INFO_TCPUDP_CS_MASK		0x1U
#define SQ_CTRL_QUEUE_INFO_MSS_MASK			0x3FFFU
#define SQ_CTRL_QUEUE_INFO_SCTP_MASK			0x1U
#define SQ_CTRL_QUEUE_INFO_UC_MASK			0x1U
#define SQ_CTRL_QUEUE_INFO_PRI_MASK			0x7U

#define SQ_CTRL_QUEUE_INFO_SET(val, member)	\
	(((u32)(val) & SQ_CTRL_QUEUE_INFO_##member##_MASK) \
	<< SQ_CTRL_QUEUE_INFO_##member##_SHIFT)

#define SQ_CTRL_QUEUE_INFO_GET(val, member)	\
	(((val) >> SQ_CTRL_QUEUE_INFO_##member##_SHIFT) \
	& SQ_CTRL_QUEUE_INFO_##member##_MASK)

#define SQ_CTRL_QUEUE_INFO_CLEAR(val, member)	\
	((val) & (~(SQ_CTRL_QUEUE_INFO_##member##_MASK << \
	SQ_CTRL_QUEUE_INFO_##member##_SHIFT)))

#define	SQ_TASK_INFO0_TUNNEL_FLAG_SHIFT		19
#define	SQ_TASK_INFO0_ESP_NEXT_PROTO_SHIFT	22
#define	SQ_TASK_INFO0_INNER_L4_EN_SHIFT		24
#define	SQ_TASK_INFO0_INNER_L3_EN_SHIFT		25
#define	SQ_TASK_INFO0_INNER_L4_PSEUDO_SHIFT	26
#define	SQ_TASK_INFO0_OUT_L4_EN_SHIFT		27
#define	SQ_TASK_INFO0_OUT_L3_EN_SHIFT		28
#define	SQ_TASK_INFO0_OUT_L4_PSEUDO_SHIFT	29
#define	SQ_TASK_INFO0_ESP_OFFLOAD_SHIFT		30
#define	SQ_TASK_INFO0_IPSEC_PROTO_SHIFT		31

#define	SQ_TASK_INFO0_TUNNEL_FLAG_MASK		0x1U
#define	SQ_TASK_INFO0_ESP_NEXT_PROTO_MASK	0x3U
#define	SQ_TASK_INFO0_INNER_L4_EN_MASK		0x1U
#define	SQ_TASK_INFO0_INNER_L3_EN_MASK		0x1U
#define	SQ_TASK_INFO0_INNER_L4_PSEUDO_MASK	0x1U
#define	SQ_TASK_INFO0_OUT_L4_EN_MASK		0x1U
#define	SQ_TASK_INFO0_OUT_L3_EN_MASK		0x1U
#define	SQ_TASK_INFO0_OUT_L4_PSEUDO_MASK	0x1U
#define	SQ_TASK_INFO0_ESP_OFFLOAD_MASK		0x1U
#define	SQ_TASK_INFO0_IPSEC_PROTO_MASK		0x1U

#define SQ_TASK_INFO0_SET(val, member)			\
		(((u32)(val) & SQ_TASK_INFO0_##member##_MASK) <<	\
		SQ_TASK_INFO0_##member##_SHIFT)
#define SQ_TASK_INFO0_GET(val, member)			\
		(((val) >> SQ_TASK_INFO0_##member##_SHIFT) &	\
		SQ_TASK_INFO0_##member##_MASK)

#define SQ_TASK_INFO1_SET(val, member)			\
		(((val) & SQ_TASK_INFO1_##member##_MASK) <<	\
		SQ_TASK_INFO1_##member##_SHIFT)
#define SQ_TASK_INFO1_GET(val, member)			\
		(((val) >> SQ_TASK_INFO1_##member##_SHIFT) &	\
		SQ_TASK_INFO1_##member##_MASK)

#define	SQ_TASK_INFO3_VLAN_TAG_SHIFT		0
#define	SQ_TASK_INFO3_VLAN_TYPE_SHIFT		16
#define	SQ_TASK_INFO3_VLAN_TAG_VALID_SHIFT	19

#define	SQ_TASK_INFO3_VLAN_TAG_MASK		0xFFFFU
#define	SQ_TASK_INFO3_VLAN_TYPE_MASK		0x7U
#define	SQ_TASK_INFO3_VLAN_TAG_VALID_MASK	0x1U

#define SQ_TASK_INFO3_SET(val, member)			\
		(((val) & SQ_TASK_INFO3_##member##_MASK) <<	\
		SQ_TASK_INFO3_##member##_SHIFT)
#define SQ_TASK_INFO3_GET(val, member)			\
		(((val) >> SQ_TASK_INFO3_##member##_SHIFT) &	\
		SQ_TASK_INFO3_##member##_MASK)

/* Txq info */
struct spnic_txq_stats {
	u64 packets;
	u64 bytes;
	u64 tx_busy;
	u64 off_errs;
	u64 burst_pkts;
	u64 sge_len0;
	u64 mbuf_null;
	u64 cpy_pkts;
	u64 sge_len_too_large;
};

struct spnic_tx_info {
	struct rte_mbuf *mbuf;
	struct rte_mbuf *cpy_mbuf;
	int wqebb_cnt;
};

struct spnic_txq {
	struct spnic_nic_dev *nic_dev;

	u16 q_id;
	u16 q_depth;
	u16 q_mask;
	u16 wqebb_size;

	u16 wqebb_shift;
	u16 cons_idx;
	u16 prod_idx;

	u16 tx_free_thresh;
	u16 owner; /* Used for sq */

	void *db_addr;

	struct spnic_tx_info *tx_info;

	const struct rte_memzone *sq_mz;
	void *queue_buf_vaddr;
	rte_iova_t queue_buf_paddr; /* Sq dma info */

	const struct rte_memzone *ci_mz;
	void *ci_vaddr_base;
	rte_iova_t ci_dma_base;

	u64 sq_head_addr;
	u64 sq_bot_sge_addr;

	u32 cos;

	struct spnic_txq_stats txq_stats;
} __rte_cache_aligned;

void spnic_flush_txqs(struct spnic_nic_dev *nic_dev);

void spnic_free_txq_mbufs(struct spnic_txq *txq);

void spnic_free_all_txq_mbufs(struct spnic_nic_dev *nic_dev);

u16 spnic_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts, u16 nb_pkts);

int spnic_stop_sq(struct spnic_txq *txq);
int spnic_start_all_sqs(struct rte_eth_dev *eth_dev);
#endif /* _SPNIC_TX_H_ */

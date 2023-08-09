/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Intel Corporation
 */

#ifndef _IDPF_COMMON_RXTX_H_
#define _IDPF_COMMON_RXTX_H_

#include <rte_mbuf.h>
#include <rte_mbuf_ptype.h>
#include <rte_mbuf_core.h>

#include "idpf_common_device.h"

#define IDPF_RX_MAX_BURST		32

#define IDPF_RX_OFFLOAD_IPV4_CKSUM		RTE_BIT64(1)
#define IDPF_RX_OFFLOAD_UDP_CKSUM		RTE_BIT64(2)
#define IDPF_RX_OFFLOAD_TCP_CKSUM		RTE_BIT64(3)
#define IDPF_RX_OFFLOAD_OUTER_IPV4_CKSUM	RTE_BIT64(6)
#define IDPF_RX_OFFLOAD_TIMESTAMP		RTE_BIT64(14)

#define IDPF_TX_OFFLOAD_IPV4_CKSUM       RTE_BIT64(1)
#define IDPF_TX_OFFLOAD_UDP_CKSUM        RTE_BIT64(2)
#define IDPF_TX_OFFLOAD_TCP_CKSUM        RTE_BIT64(3)
#define IDPF_TX_OFFLOAD_SCTP_CKSUM       RTE_BIT64(4)
#define IDPF_TX_OFFLOAD_TCP_TSO          RTE_BIT64(5)
#define IDPF_TX_OFFLOAD_MULTI_SEGS       RTE_BIT64(15)
#define IDPF_TX_OFFLOAD_MBUF_FAST_FREE   RTE_BIT64(16)

#define IDPF_TX_MAX_MTU_SEG	10

#define IDPF_MIN_TSO_MSS	88
#define IDPF_MAX_TSO_MSS	9728
#define IDPF_MAX_TSO_FRAME_SIZE	262143
#define IDPF_TX_MAX_MTU_SEG     10

#define IDPF_RLAN_CTX_DBUF_S	7
#define IDPF_RX_MAX_DATA_BUF_SIZE	(16 * 1024 - 128)

#define IDPF_TX_CKSUM_OFFLOAD_MASK (		\
		RTE_MBUF_F_TX_IP_CKSUM |	\
		RTE_MBUF_F_TX_L4_MASK |		\
		RTE_MBUF_F_TX_TCP_SEG)

#define IDPF_TX_OFFLOAD_MASK (			\
		IDPF_TX_CKSUM_OFFLOAD_MASK |	\
		RTE_MBUF_F_TX_IPV4 |		\
		RTE_MBUF_F_TX_IPV6)

#define IDPF_TX_OFFLOAD_NOTSUP_MASK \
		(RTE_MBUF_F_TX_OFFLOAD_MASK ^ IDPF_TX_OFFLOAD_MASK)

/* used for Vector PMD */
#define IDPF_VPMD_RX_MAX_BURST		32
#define IDPF_VPMD_TX_MAX_BURST		32
#define IDPF_VPMD_DESCS_PER_LOOP	4
#define IDPF_RXQ_REARM_THRESH		64
#define IDPD_TXQ_SCAN_CQ_THRESH	64
#define IDPF_TX_CTYPE_NUM	8

/* MTS */
#define GLTSYN_CMD_SYNC_0_0	(PF_TIMESYNC_BASE + 0x0)
#define PF_GLTSYN_SHTIME_0_0	(PF_TIMESYNC_BASE + 0x4)
#define PF_GLTSYN_SHTIME_L_0	(PF_TIMESYNC_BASE + 0x8)
#define PF_GLTSYN_SHTIME_H_0	(PF_TIMESYNC_BASE + 0xC)
#define GLTSYN_ART_L_0		(PF_TIMESYNC_BASE + 0x10)
#define GLTSYN_ART_H_0		(PF_TIMESYNC_BASE + 0x14)
#define PF_GLTSYN_SHTIME_0_1	(PF_TIMESYNC_BASE + 0x24)
#define PF_GLTSYN_SHTIME_L_1	(PF_TIMESYNC_BASE + 0x28)
#define PF_GLTSYN_SHTIME_H_1	(PF_TIMESYNC_BASE + 0x2C)
#define PF_GLTSYN_SHTIME_0_2	(PF_TIMESYNC_BASE + 0x44)
#define PF_GLTSYN_SHTIME_L_2	(PF_TIMESYNC_BASE + 0x48)
#define PF_GLTSYN_SHTIME_H_2	(PF_TIMESYNC_BASE + 0x4C)
#define PF_GLTSYN_SHTIME_0_3	(PF_TIMESYNC_BASE + 0x64)
#define PF_GLTSYN_SHTIME_L_3	(PF_TIMESYNC_BASE + 0x68)
#define PF_GLTSYN_SHTIME_H_3	(PF_TIMESYNC_BASE + 0x6C)

#define PF_TIMESYNC_BAR4_BASE	0x0E400000
#define GLTSYN_ENA		(PF_TIMESYNC_BAR4_BASE + 0x90)
#define GLTSYN_CMD		(PF_TIMESYNC_BAR4_BASE + 0x94)
#define GLTSYC_TIME_L		(PF_TIMESYNC_BAR4_BASE + 0x104)
#define GLTSYC_TIME_H		(PF_TIMESYNC_BAR4_BASE + 0x108)

#define GLTSYN_CMD_SYNC_0_4	(PF_TIMESYNC_BAR4_BASE + 0x110)
#define PF_GLTSYN_SHTIME_L_4	(PF_TIMESYNC_BAR4_BASE + 0x118)
#define PF_GLTSYN_SHTIME_H_4	(PF_TIMESYNC_BAR4_BASE + 0x11C)
#define GLTSYN_INCVAL_L		(PF_TIMESYNC_BAR4_BASE + 0x150)
#define GLTSYN_INCVAL_H		(PF_TIMESYNC_BAR4_BASE + 0x154)
#define GLTSYN_SHADJ_L		(PF_TIMESYNC_BAR4_BASE + 0x158)
#define GLTSYN_SHADJ_H		(PF_TIMESYNC_BAR4_BASE + 0x15C)

#define GLTSYN_CMD_SYNC_0_5	(PF_TIMESYNC_BAR4_BASE + 0x130)
#define PF_GLTSYN_SHTIME_L_5	(PF_TIMESYNC_BAR4_BASE + 0x138)
#define PF_GLTSYN_SHTIME_H_5	(PF_TIMESYNC_BAR4_BASE + 0x13C)

#define IDPF_RX_SPLIT_BUFQ1_ID	1
#define IDPF_RX_SPLIT_BUFQ2_ID	2

struct idpf_rx_stats {
	uint64_t mbuf_alloc_failed;
};

struct idpf_rx_queue {
	struct idpf_adapter *adapter;   /* the adapter this queue belongs to */
	struct rte_mempool *mp;         /* mbuf pool to populate Rx ring */
	const struct rte_memzone *mz;   /* memzone for Rx ring */
	volatile void *rx_ring;
	struct rte_mbuf **sw_ring;      /* address of SW ring */
	uint64_t rx_ring_phys_addr;     /* Rx ring DMA address */

	uint16_t nb_rx_desc;            /* ring length */
	uint16_t rx_tail;               /* current value of tail */
	volatile uint8_t *qrx_tail;     /* register address of tail */
	uint16_t rx_free_thresh;        /* max free RX desc to hold */
	uint16_t nb_rx_hold;            /* number of held free RX desc */
	struct rte_mbuf *pkt_first_seg; /* first segment of current packet */
	struct rte_mbuf *pkt_last_seg;  /* last segment of current packet */
	struct rte_mbuf fake_mbuf;      /* dummy mbuf */

	/* used for VPMD */
	uint16_t rxrearm_nb;       /* number of remaining to be re-armed */
	uint16_t rxrearm_start;    /* the idx we start the re-arming from */
	uint64_t mbuf_initializer; /* value to init mbufs */

	uint16_t rx_nb_avail;
	uint16_t rx_next_avail;

	uint16_t port_id;       /* device port ID */
	uint16_t queue_id;      /* Rx queue index */
	uint16_t rx_buf_len;    /* The packet buffer size */
	uint16_t rx_hdr_len;    /* The header buffer size */
	uint16_t max_pkt_len;   /* Maximum packet length */
	uint8_t rxdid;

	bool q_set;             /* if rx queue has been configured */
	bool q_started;         /* if rx queue has been started */
	bool rx_deferred_start; /* don't start this queue in dev start */
	const struct idpf_rxq_ops *ops;

	struct idpf_rx_stats rx_stats;

	/* only valid for split queue mode */
	uint8_t expected_gen_id;
	struct idpf_rx_queue *bufq1;
	struct idpf_rx_queue *bufq2;

	uint64_t offloads;
	uint32_t hw_register_set;
};

struct idpf_tx_entry {
	struct rte_mbuf *mbuf;
	uint16_t next_id;
	uint16_t last_id;
};

/* Structure associated with each TX queue. */
struct idpf_tx_queue {
	const struct rte_memzone *mz;		/* memzone for Tx ring */
	volatile struct idpf_flex_tx_desc *tx_ring;	/* Tx ring virtual address */
	volatile union {
		struct idpf_flex_tx_sched_desc *desc_ring;
		struct idpf_splitq_tx_compl_desc *compl_ring;
	};
	uint64_t tx_ring_phys_addr;		/* Tx ring DMA address */
	struct idpf_tx_entry *sw_ring;		/* address array of SW ring */

	uint16_t nb_tx_desc;		/* ring length */
	uint16_t tx_tail;		/* current value of tail */
	volatile uint8_t *qtx_tail;	/* register address of tail */
	/* number of used desc since RS bit set */
	uint16_t nb_used;
	uint16_t nb_free;
	uint16_t last_desc_cleaned;	/* last desc have been cleaned*/
	uint16_t free_thresh;
	uint16_t rs_thresh;

	uint16_t port_id;
	uint16_t queue_id;
	uint64_t offloads;
	uint16_t next_dd;	/* next to set RS, for VPMD */
	uint16_t next_rs;	/* next to check DD,  for VPMD */

	bool q_set;		/* if tx queue has been configured */
	bool q_started;		/* if tx queue has been started */
	bool tx_deferred_start; /* don't start this queue in dev start */
	const struct idpf_txq_ops *ops;

	/* only valid for split queue mode */
	uint16_t sw_nb_desc;
	uint16_t sw_tail;
	void **txqs;
	uint32_t tx_start_qid;
	uint8_t expected_gen_id;
	struct idpf_tx_queue *complq;
	uint16_t ctype[IDPF_TX_CTYPE_NUM];
};

/* Offload features */
union idpf_tx_offload {
	uint64_t data;
	struct {
		uint64_t l2_len:7; /* L2 (MAC) Header Length. */
		uint64_t l3_len:9; /* L3 (IP) Header Length. */
		uint64_t l4_len:8; /* L4 Header Length. */
		uint64_t tso_segsz:16; /* TCP TSO segment size */
		/* uint64_t unused : 24; */
	};
};

struct idpf_tx_vec_entry {
	struct rte_mbuf *mbuf;
};

union idpf_tx_desc {
	struct idpf_base_tx_desc *tx_ring;
	struct idpf_flex_tx_sched_desc *desc_ring;
	struct idpf_splitq_tx_compl_desc *compl_ring;
};

struct idpf_rxq_ops {
	void (*release_mbufs)(struct idpf_rx_queue *rxq);
};

struct idpf_txq_ops {
	void (*release_mbufs)(struct idpf_tx_queue *txq);
};

extern int idpf_timestamp_dynfield_offset;
extern uint64_t idpf_timestamp_dynflag;

static inline void
idpf_split_tx_free(struct idpf_tx_queue *cq)
{
	volatile struct idpf_splitq_tx_compl_desc *compl_ring = cq->compl_ring;
	volatile struct idpf_splitq_tx_compl_desc *txd;
	uint16_t next = cq->tx_tail;
	struct idpf_tx_entry *txe;
	struct idpf_tx_queue *txq;
	uint16_t gen, qid, q_head;
	uint16_t nb_desc_clean;
	uint8_t ctype;

	txd = &compl_ring[next];
	gen = (rte_le_to_cpu_16(txd->qid_comptype_gen) &
	       IDPF_TXD_COMPLQ_GEN_M) >> IDPF_TXD_COMPLQ_GEN_S;
	if (gen != cq->expected_gen_id)
		return;

	ctype = (rte_le_to_cpu_16(txd->qid_comptype_gen) &
		 IDPF_TXD_COMPLQ_COMPL_TYPE_M) >> IDPF_TXD_COMPLQ_COMPL_TYPE_S;
	qid = (rte_le_to_cpu_16(txd->qid_comptype_gen) &
	       IDPF_TXD_COMPLQ_QID_M) >> IDPF_TXD_COMPLQ_QID_S;
	q_head = rte_le_to_cpu_16(txd->q_head_compl_tag.compl_tag);
	txq = cq->txqs[qid - cq->tx_start_qid];

	switch (ctype) {
	case IDPF_TXD_COMPLT_RE:
		/* clean to q_head which indicates be fetched txq desc id + 1.
		 * TODO: need to refine and remove the if condition.
		 */
		if (unlikely(q_head % 32)) {
			TX_LOG(ERR, "unexpected desc (head = %u) completion.",
			       q_head);
			return;
		}
		if (txq->last_desc_cleaned > q_head)
			nb_desc_clean = (txq->nb_tx_desc - txq->last_desc_cleaned) +
				q_head;
		else
			nb_desc_clean = q_head - txq->last_desc_cleaned;
		txq->nb_free += nb_desc_clean;
		txq->last_desc_cleaned = q_head;
		break;
	case IDPF_TXD_COMPLT_RS:
		/* q_head indicates sw_id when ctype is 2 */
		txe = &txq->sw_ring[q_head];
		if (txe->mbuf != NULL) {
			rte_pktmbuf_free_seg(txe->mbuf);
			txe->mbuf = NULL;
		}
		break;
	default:
		TX_LOG(ERR, "unknown completion type.");
		return;
	}

	if (++next == cq->nb_tx_desc) {
		next = 0;
		cq->expected_gen_id ^= 1;
	}

	cq->tx_tail = next;
}

#define IDPF_RX_FLEX_DESC_ADV_STATUS0_XSUM_S				\
	(RTE_BIT32(VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS0_XSUM_IPE_S) |     \
	 RTE_BIT32(VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS0_XSUM_L4E_S) |     \
	 RTE_BIT32(VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS0_XSUM_EIPE_S) |    \
	 RTE_BIT32(VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS0_XSUM_EUDPE_S))

static inline uint64_t
idpf_splitq_rx_csum_offload(uint8_t err)
{
	uint64_t flags = 0;

	if (unlikely((err & RTE_BIT32(VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS0_L3L4P_S)) == 0))
		return flags;

	if (likely((err & IDPF_RX_FLEX_DESC_ADV_STATUS0_XSUM_S) == 0)) {
		flags |= (RTE_MBUF_F_RX_IP_CKSUM_GOOD |
			  RTE_MBUF_F_RX_L4_CKSUM_GOOD);
		return flags;
	}

	if (unlikely((err & RTE_BIT32(VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS0_XSUM_IPE_S)) != 0))
		flags |= RTE_MBUF_F_RX_IP_CKSUM_BAD;
	else
		flags |= RTE_MBUF_F_RX_IP_CKSUM_GOOD;

	if (unlikely((err & RTE_BIT32(VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS0_XSUM_L4E_S)) != 0))
		flags |= RTE_MBUF_F_RX_L4_CKSUM_BAD;
	else
		flags |= RTE_MBUF_F_RX_L4_CKSUM_GOOD;

	if (unlikely((err & RTE_BIT32(VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS0_XSUM_EIPE_S)) != 0))
		flags |= RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD;

	if (unlikely((err & RTE_BIT32(VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS0_XSUM_EUDPE_S)) != 0))
		flags |= RTE_MBUF_F_RX_OUTER_L4_CKSUM_BAD;
	else
		flags |= RTE_MBUF_F_RX_OUTER_L4_CKSUM_GOOD;

	return flags;
}

#define IDPF_RX_FLEX_DESC_ADV_HASH1_S  0
#define IDPF_RX_FLEX_DESC_ADV_HASH2_S  16
#define IDPF_RX_FLEX_DESC_ADV_HASH3_S  24

static inline uint64_t
idpf_splitq_rx_rss_offload(struct rte_mbuf *mb,
			   volatile struct virtchnl2_rx_flex_desc_adv_nic_3 *rx_desc)
{
	uint8_t status_err0_qw0;
	uint64_t flags = 0;

	status_err0_qw0 = rx_desc->status_err0_qw0;

	if ((status_err0_qw0 & RTE_BIT32(VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS0_RSS_VALID_S)) != 0) {
		flags |= RTE_MBUF_F_RX_RSS_HASH;
		mb->hash.rss = (rte_le_to_cpu_16(rx_desc->hash1) <<
				IDPF_RX_FLEX_DESC_ADV_HASH1_S) |
			((uint32_t)(rx_desc->ff2_mirrid_hash2.hash2) <<
			 IDPF_RX_FLEX_DESC_ADV_HASH2_S) |
			((uint32_t)(rx_desc->hash3) <<
			 IDPF_RX_FLEX_DESC_ADV_HASH3_S);
	}

	return flags;
}

#define IDPF_TIMESYNC_REG_WRAP_GUARD_BAND  10000
/* Helper function to convert a 32b nanoseconds timestamp to 64b. */
static inline uint64_t
idpf_tstamp_convert_32b_64b(struct idpf_adapter *ad, uint32_t flag,
			    uint32_t in_timestamp)
{
#ifdef RTE_ARCH_X86_64
	struct idpf_hw *hw = &ad->hw;
	const uint64_t mask = 0xFFFFFFFF;
	uint32_t hi, lo, lo2, delta;
	uint64_t ns;

	if (flag != 0) {
		IDPF_WRITE_REG(hw, GLTSYN_CMD_SYNC_0_0, PF_GLTSYN_CMD_SYNC_SHTIME_EN_M);
		IDPF_WRITE_REG(hw, GLTSYN_CMD_SYNC_0_0, PF_GLTSYN_CMD_SYNC_EXEC_CMD_M |
			       PF_GLTSYN_CMD_SYNC_SHTIME_EN_M);
		lo = IDPF_READ_REG(hw, PF_GLTSYN_SHTIME_L_0);
		hi = IDPF_READ_REG(hw, PF_GLTSYN_SHTIME_H_0);
		/*
		 * On typical system, the delta between lo and lo2 is ~1000ns,
		 * so 10000 seems a large-enough but not overly-big guard band.
		 */
		if (lo > (UINT32_MAX - IDPF_TIMESYNC_REG_WRAP_GUARD_BAND))
			lo2 = IDPF_READ_REG(hw, PF_GLTSYN_SHTIME_L_0);
		else
			lo2 = lo;

		if (lo2 < lo) {
			lo = IDPF_READ_REG(hw, PF_GLTSYN_SHTIME_L_0);
			hi = IDPF_READ_REG(hw, PF_GLTSYN_SHTIME_H_0);
		}

		ad->time_hw = ((uint64_t)hi << 32) | lo;
	}

	delta = (in_timestamp - (uint32_t)(ad->time_hw & mask));
	if (delta > (mask / 2)) {
		delta = ((uint32_t)(ad->time_hw & mask) - in_timestamp);
		ns = ad->time_hw - delta;
	} else {
		ns = ad->time_hw + delta;
	}

	return ns;
#else /* !RTE_ARCH_X86_64 */
	RTE_SET_USED(ad);
	RTE_SET_USED(flag);
	RTE_SET_USED(in_timestamp);
	return 0;
#endif /* RTE_ARCH_X86_64 */
}

static inline void
idpf_split_rx_bufq_refill(struct idpf_rx_queue *rx_bufq)
{
	volatile struct virtchnl2_splitq_rx_buf_desc *rx_buf_ring;
	volatile struct virtchnl2_splitq_rx_buf_desc *rx_buf_desc;
	uint16_t nb_refill = rx_bufq->rx_free_thresh;
	uint16_t nb_desc = rx_bufq->nb_rx_desc;
	uint16_t next_avail = rx_bufq->rx_tail;
	struct rte_mbuf *nmb[rx_bufq->rx_free_thresh];
	uint64_t dma_addr;
	uint16_t delta;
	int i;

	if (rx_bufq->nb_rx_hold < rx_bufq->rx_free_thresh)
		return;

	rx_buf_ring = rx_bufq->rx_ring;
	delta = nb_desc - next_avail;
	if (unlikely(delta < nb_refill)) {
		if (likely(rte_pktmbuf_alloc_bulk(rx_bufq->mp, nmb, delta) == 0)) {
			for (i = 0; i < delta; i++) {
				rx_buf_desc = &rx_buf_ring[next_avail + i];
				rx_bufq->sw_ring[next_avail + i] = nmb[i];
				dma_addr = rte_cpu_to_le_64(rte_mbuf_data_iova_default(nmb[i]));
				rx_buf_desc->hdr_addr = 0;
				rx_buf_desc->pkt_addr = dma_addr;
			}
			nb_refill -= delta;
			next_avail = 0;
			rx_bufq->nb_rx_hold -= delta;
		} else {
			__atomic_fetch_add(&rx_bufq->rx_stats.mbuf_alloc_failed,
					   nb_desc - next_avail, __ATOMIC_RELAXED);
			RX_LOG(DEBUG, "RX mbuf alloc failed port_id=%u queue_id=%u",
			       rx_bufq->port_id, rx_bufq->queue_id);
			return;
		}
	}

	if (nb_desc - next_avail >= nb_refill) {
		if (likely(rte_pktmbuf_alloc_bulk(rx_bufq->mp, nmb, nb_refill) == 0)) {
			for (i = 0; i < nb_refill; i++) {
				rx_buf_desc = &rx_buf_ring[next_avail + i];
				rx_bufq->sw_ring[next_avail + i] = nmb[i];
				dma_addr = rte_cpu_to_le_64(rte_mbuf_data_iova_default(nmb[i]));
				rx_buf_desc->hdr_addr = 0;
				rx_buf_desc->pkt_addr = dma_addr;
			}
			next_avail += nb_refill;
			rx_bufq->nb_rx_hold -= nb_refill;
		} else {
			__atomic_fetch_add(&rx_bufq->rx_stats.mbuf_alloc_failed,
					   nb_desc - next_avail, __ATOMIC_RELAXED);
			RX_LOG(DEBUG, "RX mbuf alloc failed port_id=%u queue_id=%u",
			       rx_bufq->port_id, rx_bufq->queue_id);
		}
	}

	IDPF_PCI_REG_WRITE(rx_bufq->qrx_tail, next_avail);

	rx_bufq->rx_tail = next_avail;
}

__rte_internal
int idpf_qc_rx_thresh_check(uint16_t nb_desc, uint16_t thresh);
__rte_internal
int idpf_qc_tx_thresh_check(uint16_t nb_desc, uint16_t tx_rs_thresh,
			    uint16_t tx_free_thresh);
__rte_internal
void idpf_qc_rxq_mbufs_release(struct idpf_rx_queue *rxq);
__rte_internal
void idpf_qc_txq_mbufs_release(struct idpf_tx_queue *txq);
__rte_internal
void idpf_qc_split_rx_descq_reset(struct idpf_rx_queue *rxq);
__rte_internal
void idpf_qc_split_rx_bufq_reset(struct idpf_rx_queue *rxq);
__rte_internal
void idpf_qc_split_rx_queue_reset(struct idpf_rx_queue *rxq);
__rte_internal
void idpf_qc_single_rx_queue_reset(struct idpf_rx_queue *rxq);
__rte_internal
void idpf_qc_split_tx_descq_reset(struct idpf_tx_queue *txq);
__rte_internal
void idpf_qc_split_tx_complq_reset(struct idpf_tx_queue *cq);
__rte_internal
void idpf_qc_single_tx_queue_reset(struct idpf_tx_queue *txq);
__rte_internal
void idpf_qc_rx_queue_release(void *rxq);
__rte_internal
void idpf_qc_tx_queue_release(void *txq);
__rte_internal
int idpf_qc_ts_mbuf_register(struct idpf_rx_queue *rxq);
__rte_internal
int idpf_qc_single_rxq_mbufs_alloc(struct idpf_rx_queue *rxq);
__rte_internal
int idpf_qc_split_rxq_mbufs_alloc(struct idpf_rx_queue *rxq);
__rte_internal
uint16_t idpf_dp_splitq_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts,
				  uint16_t nb_pkts);
__rte_internal
uint16_t idpf_dp_splitq_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
				  uint16_t nb_pkts);
__rte_internal
uint16_t idpf_dp_singleq_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts,
				   uint16_t nb_pkts);
__rte_internal
uint16_t idpf_dp_singleq_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
				   uint16_t nb_pkts);
__rte_internal
uint16_t idpf_dp_prep_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
			   uint16_t nb_pkts);
__rte_internal
int idpf_qc_singleq_rx_vec_setup(struct idpf_rx_queue *rxq);
__rte_internal
int idpf_qc_splitq_rx_vec_setup(struct idpf_rx_queue *rxq);
__rte_internal
int idpf_qc_tx_vec_avx512_setup(struct idpf_tx_queue *txq);
__rte_internal
int idpf_qc_tx_vec_avx512_setup(struct idpf_tx_queue *txq);
__rte_internal
uint16_t idpf_dp_singleq_recv_pkts_avx512(void *rx_queue,
					  struct rte_mbuf **rx_pkts,
					  uint16_t nb_pkts);
__rte_internal
uint16_t idpf_dp_splitq_recv_pkts_avx512(void *tx_queue, struct rte_mbuf **tx_pkts,
					 uint16_t nb_pkts);
__rte_internal
uint16_t idpf_dp_singleq_xmit_pkts_avx512(void *tx_queue,
					  struct rte_mbuf **tx_pkts,
					  uint16_t nb_pkts);
__rte_internal
uint16_t idpf_dp_splitq_xmit_pkts_avx512(void *tx_queue, struct rte_mbuf **tx_pkts,
					 uint16_t nb_pkts);
__rte_internal
uint16_t idpf_dp_singleq_recv_scatter_pkts(void *rx_queue, struct rte_mbuf **rx_pkts,
			  uint16_t nb_pkts);

#endif /* _IDPF_COMMON_RXTX_H_ */

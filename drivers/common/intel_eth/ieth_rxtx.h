/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Intel Corporation
 */

#ifndef IETH_RXTX_H_
#define IETH_RXTX_H_

#include <stdint.h>
#include <rte_mbuf.h>

/**
 * Structure associated with each descriptor of the TX ring of a TX queue.
 */
struct ieth_tx_entry
{
	struct rte_mbuf *mbuf; /* mbuf associated with TX desc, if any. */
	uint16_t next_id; /* Index of next descriptor in ring. */
	uint16_t last_id; /* Index of last scattered descriptor. */
};

/**
 * Structure associated with each descriptor of the TX ring of a TX queue in vector Tx.
 */
struct ieth_vec_tx_entry
{
	struct rte_mbuf *mbuf; /* mbuf associated with TX desc, if any. */
};

struct ieth_tx_queue;

typedef void (*ice_tx_release_mbufs_t)(struct ieth_tx_queue *txq);

struct ieth_tx_queue {
	union { /* TX ring virtual address */
		volatile struct i40e_tx_desc *i40e_tx_ring;
		volatile struct iavf_tx_desc *iavf_tx_ring;
		volatile struct ice_tx_desc *ice_tx_ring;
		volatile union ixgbe_adv_tx_desc *ixgbe_tx_ring;
	};
	volatile uint8_t *qtx_tail;               /* register address of tail */
	union {
		struct ieth_tx_entry *sw_ring; /* virtual address of SW ring */
		struct ieth_vec_tx_entry *sw_ring_v;
	};
	uint16_t nb_tx_desc;           /* number of TX descriptors */
	uint16_t tx_tail; /* current value of tail register */
	uint16_t nb_tx_used; /* number of TX desc used since RS bit set */
	/* index to last TX descriptor to have been cleaned */
	uint16_t last_desc_cleaned;
	/* Total number of TX descriptors ready to be allocated. */
	uint16_t nb_tx_free;
	/* Start freeing TX buffers if there are less free descriptors than
	 * this value.
	 */
	uint16_t tx_free_thresh;
	/* Number of TX descriptors to use before RS bit is set. */
	uint16_t tx_rs_thresh;
	uint16_t port_id;  /* Device port identifier. */
	uint16_t queue_id; /* TX queue index. */
	uint16_t reg_idx;
	uint16_t tx_next_dd;
	uint16_t tx_next_rs;
	uint64_t offloads;
	uint64_t mbuf_errors;
	rte_iova_t tx_ring_dma;        /* TX ring DMA address */
	_Bool tx_deferred_start; /* don't start this queue in dev start */
	_Bool q_set;             /* indicate if tx queue has been configured */
	_Bool vector_tx;         /* port is using vector TX */
	_Bool vector_sw_ring;    /* port is using vectorized SW ring (ieth_vec_tx_entry) */
	union {                  /* the VSI this queue belongs to */
		struct i40e_vsi *i40e_vsi;
		struct iavf_vsi *iavf_vsi;
		struct ice_vsi *ice_vsi;
	};
	const struct rte_memzone *mz;

	union {
		struct { /* ICE driver specific values */
			uint32_t q_teid; /* TX schedule node id. */
		};
		struct { /* I40E driver specific values */
			uint8_t dcb_tc;
		};
		struct { /* iavf driver specific values */
			uint16_t ipsec_crypto_pkt_md_offset;
			uint8_t rel_mbufs_type;
#define IAVF_TX_FLAGS_VLAN_TAG_LOC_L2TAG1 BIT(0)
#define IAVF_TX_FLAGS_VLAN_TAG_LOC_L2TAG2 BIT(1)
			uint8_t vlan_flag;
			uint8_t tc;
			uint8_t use_ctx : 1; /* if use the ctx desc, a packet needs
					  two descriptors */
		};
		struct { /* ixgbe specific values */
			const struct ixgbe_txq_ops *ops;
			struct ixgbe_advctx_info *ctx_cache;
			uint32_t ctx_curr;
			uint8_t pthresh;   /**< Prefetch threshold register. */
			uint8_t hthresh;   /**< Host threshold register. */
			uint8_t wthresh;   /**< Write-back threshold reg. */
			uint8_t using_ipsec;  /**< indicates that IPsec TX feature is in use */
		};
	};
};

#define IETH_FREE_BUFS_LOOP(txq, swr, start) do { \
		uint16_t i = start; \
		if (txq->tx_tail < i) { \
			for (; i < txq->nb_tx_desc; i++) { \
				rte_pktmbuf_free_seg(swr[i].mbuf); \
				swr[i].mbuf = NULL; \
			} \
			i = 0; \
		} \
		for (; i < txq->tx_tail; i++) { \
			rte_pktmbuf_free_seg(swr[i].mbuf); \
			swr[i].mbuf = NULL; \
		} \
} while(0)

static inline void
ieth_txq_release_all_mbufs(struct ieth_tx_queue *txq)
{
	if (unlikely(!txq || !txq->sw_ring))
		return;

	if (!txq->vector_tx) {
		for (uint16_t i = 0; i < txq->nb_tx_desc; i++) {
			if (txq->sw_ring[i].mbuf != NULL) {
				rte_pktmbuf_free_seg(txq->sw_ring[i].mbuf);
				txq->sw_ring[i].mbuf = NULL;
			}
		}
		return;
	}

	/**
	 *  vPMD tx will not set sw_ring's mbuf to NULL after free,
	 *  so need to free remains more carefully.
	 */
	const uint16_t start = txq->tx_next_dd - txq->tx_rs_thresh + 1;

	if (txq->vector_sw_ring) {
		struct ieth_vec_tx_entry *swr = txq->sw_ring_v;
		IETH_FREE_BUFS_LOOP(txq, swr, start);
	} else {
		struct ieth_tx_entry *swr = txq->sw_ring;
		IETH_FREE_BUFS_LOOP(txq, swr, start);
	}
}

#endif /* IETH_RXTX_H_ */

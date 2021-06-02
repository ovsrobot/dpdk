/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2020 Beijing WangXun Technology Co., Ltd.
 * Copyright(c) 2010-2017 Intel Corporation
 */

#ifndef _NGBE_RXTX_H_
#define _NGBE_RXTX_H_

/*****************************************************************************
 * Receive Descriptor
 *****************************************************************************/
struct ngbe_rx_desc {
	struct {
		union {
			__le32 dw0;
			struct {
				__le16 pkt;
				__le16 hdr;
			} lo;
		};
		union {
			__le32 dw1;
			struct {
				__le16 ipid;
				__le16 csum;
			} hi;
		};
	} qw0; /* also as r.pkt_addr */
	struct {
		union {
			__le32 dw2;
			struct {
				__le32 status;
			} lo;
		};
		union {
			__le32 dw3;
			struct {
				__le16 len;
				__le16 tag;
			} hi;
		};
	} qw1; /* also as r.hdr_addr */
};

/*****************************************************************************
 * Transmit Descriptor
 *****************************************************************************/
/**
 * Transmit Context Descriptor (NGBE_TXD_TYP=CTXT)
 **/
struct ngbe_tx_ctx_desc {
	__le32 dw0; /* w.vlan_macip_lens  */
	__le32 dw1; /* w.seqnum_seed      */
	__le32 dw2; /* w.type_tucmd_mlhl  */
	__le32 dw3; /* w.mss_l4len_idx    */
};

/* @ngbe_tx_ctx_desc.dw3 */
#define NGBE_TXD_DD               MS(0, 0x1) /* descriptor done */

/**
 * Transmit Data Descriptor (NGBE_TXD_TYP=DATA)
 **/
struct ngbe_tx_desc {
	__le64 qw0; /* r.buffer_addr ,  w.reserved    */
	__le32 dw2; /* r.cmd_type_len,  w.nxtseq_seed */
	__le32 dw3; /* r.olinfo_status, w.status      */
};

#define RTE_PMD_NGBE_RX_MAX_BURST 32

#define RX_RING_SZ ((NGBE_RING_DESC_MAX + RTE_PMD_NGBE_RX_MAX_BURST) * \
		    sizeof(struct ngbe_rx_desc))

#define NGBE_TX_MAX_SEG                    40
#define NGBE_PTID_MASK                     0xFF

/**
 * Structure associated with each descriptor of the RX ring of a RX queue.
 */
struct ngbe_rx_entry {
	struct rte_mbuf *mbuf; /**< mbuf associated with RX descriptor. */
};

struct ngbe_scattered_rx_entry {
	struct rte_mbuf *fbuf; /**< First segment of the fragmented packet. */
};

/**
 * Structure associated with each descriptor of the TX ring of a TX queue.
 */
struct ngbe_tx_entry {
	struct rte_mbuf *mbuf; /**< mbuf associated with TX desc, if any. */
	uint16_t next_id; /**< Index of next descriptor in ring. */
	uint16_t last_id; /**< Index of last scattered descriptor. */
};

/**
 * Structure associated with each RX queue.
 */
struct ngbe_rx_queue {
	struct rte_mempool  *mb_pool; /**< mbuf pool to populate RX ring. */
	volatile struct ngbe_rx_desc *rx_ring; /**< RX ring virtual address. */
	uint64_t            rx_ring_phys_addr; /**< RX ring DMA address. */
	volatile uint32_t   *rdt_reg_addr; /**< RDT register address. */
	volatile uint32_t   *rdh_reg_addr; /**< RDH register address. */
	struct ngbe_rx_entry *sw_ring; /**< address of RX software ring. */
	/**< address of scattered Rx software ring. */
	struct ngbe_scattered_rx_entry *sw_sc_ring;
	struct rte_mbuf *pkt_first_seg; /**< First segment of current packet. */
	struct rte_mbuf *pkt_last_seg; /**< Last segment of current packet. */
	uint16_t            nb_rx_desc; /**< number of RX descriptors. */
	uint16_t            rx_tail;  /**< current value of RDT register. */
	uint16_t            nb_rx_hold; /**< number of held free RX desc. */
	uint16_t rx_nb_avail; /**< nr of staged pkts ready to ret to app */
	uint16_t rx_next_avail; /**< idx of next staged pkt to ret to app */
	uint16_t rx_free_trigger; /**< triggers rx buffer allocation */
	uint16_t            rx_free_thresh; /**< max free RX desc to hold. */
	uint16_t            queue_id; /**< RX queue index. */
	uint16_t            reg_idx;  /**< RX queue register index. */
	/**< Packet type mask for different NICs. */
	uint16_t            pkt_type_mask;
	uint16_t            port_id;  /**< Device port identifier. */
	uint8_t             crc_len;  /**< 0 if CRC stripped, 4 otherwise. */
	uint8_t             drop_en;  /**< If not 0, set SRRCTL.Drop_En. */
	uint8_t             rx_deferred_start; /**< not in global dev start. */
	uint64_t	    offloads; /**< Rx offloads with DEV_RX_OFFLOAD_* */
	/** need to alloc dummy mbuf, for wraparound when scanning hw ring */
	struct rte_mbuf fake_mbuf;
	/** hold packets to return to application */
	struct rte_mbuf *rx_stage[RTE_PMD_NGBE_RX_MAX_BURST * 2];
};

/**
 * NGBE CTX Constants
 */
enum ngbe_ctx_num {
	NGBE_CTX_0    = 0, /**< CTX0 */
	NGBE_CTX_1    = 1, /**< CTX1  */
	NGBE_CTX_NUM  = 2, /**< CTX NUMBER  */
};

/**
 * Structure to check if new context need be built
 */
struct ngbe_ctx_info {
	uint64_t flags;           /**< ol_flags for context build. */
};

/**
 * Structure associated with each TX queue.
 */
struct ngbe_tx_queue {
	/** TX ring virtual address. */
	volatile struct ngbe_tx_desc *tx_ring;
	uint64_t            tx_ring_phys_addr; /**< TX ring DMA address. */
	struct ngbe_tx_entry *sw_ring; /**< address of SW ring for scalar PMD.*/
	volatile uint32_t   *tdt_reg_addr; /**< Address of TDT register. */
	volatile uint32_t   *tdc_reg_addr; /**< Address of TDC register. */
	uint16_t            nb_tx_desc;    /**< number of TX descriptors. */
	uint16_t            tx_tail;       /**< current value of TDT reg. */
	/**< Start freeing TX buffers if there are less free descriptors than
	 *   this value.
	 */
	uint16_t            tx_free_thresh;
	/** Index to last TX descriptor to have been cleaned. */
	uint16_t            last_desc_cleaned;
	/** Total number of TX descriptors ready to be allocated. */
	uint16_t            nb_tx_free;
	uint16_t            tx_next_dd;    /**< next desc to scan for DD bit */
	uint16_t            queue_id;      /**< TX queue index. */
	uint16_t            reg_idx;       /**< TX queue register index. */
	uint16_t            port_id;       /**< Device port identifier. */
	uint8_t             pthresh;       /**< Prefetch threshold register. */
	uint8_t             hthresh;       /**< Host threshold register. */
	uint8_t             wthresh;       /**< Write-back threshold reg. */
	uint64_t            offloads; /* Tx offload flags of DEV_TX_OFFLOAD_* */
	uint32_t            ctx_curr;      /**< Hardware context states. */
	/** Hardware context0 history. */
	struct ngbe_ctx_info ctx_cache[NGBE_CTX_NUM];
	const struct ngbe_txq_ops *ops;       /**< txq ops */
	uint8_t             tx_deferred_start; /**< not in global dev start. */
};

struct ngbe_txq_ops {
	void (*release_mbufs)(struct ngbe_tx_queue *txq);
	void (*free_swring)(struct ngbe_tx_queue *txq);
	void (*reset)(struct ngbe_tx_queue *txq);
};

uint64_t ngbe_get_tx_port_offloads(struct rte_eth_dev *dev);
uint64_t ngbe_get_rx_queue_offloads(struct rte_eth_dev *dev);
uint64_t ngbe_get_rx_port_offloads(struct rte_eth_dev *dev);

#endif /* _NGBE_RXTX_H_ */

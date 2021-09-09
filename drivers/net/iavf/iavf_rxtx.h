/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Intel Corporation
 */

#ifndef _IAVF_RXTX_H_
#define _IAVF_RXTX_H_

/* In QLEN must be whole number of 32 descriptors. */
#define IAVF_ALIGN_RING_DESC      32
#define IAVF_MIN_RING_DESC        64
#define IAVF_MAX_RING_DESC        4096
#define IAVF_DMA_MEM_ALIGN        4096
/* Base address of the HW descriptor ring should be 128B aligned. */
#define IAVF_RING_BASE_ALIGN      128

/* used for Rx Bulk Allocate */
#define IAVF_RX_MAX_BURST         32

/* used for Vector PMD */
#define IAVF_VPMD_RX_MAX_BURST    32
#define IAVF_VPMD_TX_MAX_BURST    32
#define IAVF_RXQ_REARM_THRESH     32
#define IAVF_VPMD_DESCS_PER_LOOP  4
#define IAVF_VPMD_TX_MAX_FREE_BUF 64

#define IAVF_TX_NO_VECTOR_FLAGS (				 \
		DEV_TX_OFFLOAD_MULTI_SEGS |		 \
		DEV_TX_OFFLOAD_TCP_TSO |		 \
		DEV_TX_OFFLOAD_SECURITY)

#define IAVF_TX_VECTOR_OFFLOAD (				 \
		DEV_TX_OFFLOAD_VLAN_INSERT |		 \
		DEV_TX_OFFLOAD_QINQ_INSERT |		 \
		DEV_TX_OFFLOAD_IPV4_CKSUM |		 \
		DEV_TX_OFFLOAD_SCTP_CKSUM |		 \
		DEV_TX_OFFLOAD_UDP_CKSUM |		 \
		DEV_TX_OFFLOAD_TCP_CKSUM)

#define IAVF_RX_VECTOR_OFFLOAD (				 \
		DEV_RX_OFFLOAD_CHECKSUM |		 \
		DEV_RX_OFFLOAD_SCTP_CKSUM |		 \
		DEV_RX_OFFLOAD_VLAN |		 \
		DEV_RX_OFFLOAD_RSS_HASH)

#define IAVF_VECTOR_PATH 0
#define IAVF_VECTOR_OFFLOAD_PATH 1

#define DEFAULT_TX_RS_THRESH     32
#define DEFAULT_TX_FREE_THRESH   32

#define IAVF_MIN_TSO_MSS          256
#define IAVF_MAX_TSO_MSS          9668
#define IAVF_TSO_MAX_SEG          UINT8_MAX
#define IAVF_TX_MAX_MTU_SEG       8

#define IAVF_TX_CKSUM_OFFLOAD_MASK (		 \
		PKT_TX_IP_CKSUM |		 \
		PKT_TX_L4_MASK |		 \
		PKT_TX_TCP_SEG)

#define IAVF_TX_OFFLOAD_MASK (  \
		PKT_TX_OUTER_IPV6 |		 \
		PKT_TX_OUTER_IPV4 |		 \
		PKT_TX_IPV6 |			 \
		PKT_TX_IPV4 |			 \
		PKT_TX_VLAN_PKT |		 \
		PKT_TX_IP_CKSUM |		 \
		PKT_TX_L4_MASK |		 \
		PKT_TX_TCP_SEG |		 \
		DEV_TX_OFFLOAD_SECURITY)

#define IAVF_TX_OFFLOAD_NOTSUP_MASK \
		(PKT_TX_OFFLOAD_MASK ^ IAVF_TX_OFFLOAD_MASK)

/**
 * Rx Flex Descriptors
 * These descriptors are used instead of the legacy version descriptors
 */
union iavf_16b_rx_flex_desc {
	struct {
		__le64 pkt_addr; /* Packet buffer address */
		__le64 hdr_addr; /* Header buffer address */
				 /* bit 0 of hdr_addr is DD bit */
	} read;
	struct {
		/* Qword 0 */
		u8 rxdid; /* descriptor builder profile ID */
		u8 mir_id_umb_cast; /* mirror=[5:0], umb=[7:6] */
		__le16 ptype_flex_flags0; /* ptype=[9:0], ff0=[15:10] */
		__le16 pkt_len; /* [15:14] are reserved */
		__le16 hdr_len_sph_flex_flags1; /* header=[10:0] */
						/* sph=[11:11] */
						/* ff1/ext=[15:12] */

		/* Qword 1 */
		__le16 status_error0;
		__le16 l2tag1;
		__le16 flex_meta0;
		__le16 flex_meta1;
	} wb; /* writeback */
};

union iavf_32b_rx_flex_desc {
	struct {
		__le64 pkt_addr; /* Packet buffer address */
		__le64 hdr_addr; /* Header buffer address */
				 /* bit 0 of hdr_addr is DD bit */
		__le64 rsvd1;
		__le64 rsvd2;
	} read;
	struct {
		/* Qword 0 */
		u8 rxdid; /* descriptor builder profile ID */
		u8 mir_id_umb_cast; /* mirror=[5:0], umb=[7:6] */
		__le16 ptype_flex_flags0; /* ptype=[9:0], ff0=[15:10] */
		__le16 pkt_len; /* [15:14] are reserved */
		__le16 hdr_len_sph_flex_flags1; /* header=[10:0] */
						/* sph=[11:11] */
						/* ff1/ext=[15:12] */

		/* Qword 1 */
		__le16 status_error0;
		__le16 l2tag1;
		__le16 flex_meta0;
		__le16 flex_meta1;

		/* Qword 2 */
		__le16 status_error1;
		u8 flex_flags2;
		u8 time_stamp_low;
		__le16 l2tag2_1st;
		__le16 l2tag2_2nd;

		/* Qword 3 */
		__le16 flex_meta2;
		__le16 flex_meta3;
		union {
			struct {
				__le16 flex_meta4;
				__le16 flex_meta5;
			} flex;
			__le32 ts_high;
		} flex_ts;
	} wb; /* writeback */
};

/* HW desc structure, both 16-byte and 32-byte types are supported */
#ifdef RTE_LIBRTE_IAVF_16BYTE_RX_DESC
#define iavf_rx_desc iavf_16byte_rx_desc
#define iavf_rx_flex_desc iavf_16b_rx_flex_desc
#else
#define iavf_rx_desc iavf_32byte_rx_desc
#define iavf_rx_flex_desc iavf_32b_rx_flex_desc
#endif

typedef void (*iavf_rxd_to_pkt_fields_t)(struct iavf_rx_queue *rxq,
				struct rte_mbuf *mb,
				volatile union iavf_rx_flex_desc *rxdp);

struct iavf_rxq_ops {
	void (*release_mbufs)(struct iavf_rx_queue *rxq);
};

struct iavf_txq_ops {
	void (*release_mbufs)(struct iavf_tx_queue *txq);
};

struct iavf_ipsec_crypto_stats {
	uint64_t icount;
	uint64_t ibytes;
	struct {
		uint64_t count;
		uint64_t sad_miss;
		uint64_t not_processed;
		uint64_t icv_check;
		uint64_t ipsec_length;
		uint64_t misc;
	} ierrors;
};

struct iavf_rx_queue_stats {
	uint64_t reserved;
	struct iavf_ipsec_crypto_stats ipsec_crypto;
};

/* Structure associated with each Rx queue. */
struct iavf_rx_queue {
	struct rte_mempool *mp;       /* mbuf pool to populate Rx ring */
	const struct rte_memzone *mz; /* memzone for Rx ring */
	volatile union iavf_rx_desc *rx_ring; /* Rx ring virtual address */
	uint64_t rx_ring_phys_addr;   /* Rx ring DMA address */
	struct rte_mbuf **sw_ring;     /* address of SW ring */
	uint16_t nb_rx_desc;          /* ring length */
	uint16_t rx_tail;             /* current value of tail */
	volatile uint8_t *qrx_tail;   /* register address of tail */
	uint16_t rx_free_thresh;      /* max free RX desc to hold */
	uint16_t nb_rx_hold;          /* number of held free RX desc */
	struct rte_mbuf *pkt_first_seg; /* first segment of current packet */
	struct rte_mbuf *pkt_last_seg;  /* last segment of current packet */
	struct rte_mbuf fake_mbuf;      /* dummy mbuf */
	uint8_t rxdid;

	/* used for VPMD */
	uint16_t rxrearm_nb;       /* number of remaining to be re-armed */
	uint16_t rxrearm_start;    /* the idx we start the re-arming from */
	uint64_t mbuf_initializer; /* value to init mbufs */

	/* for rx bulk */
	uint16_t rx_nb_avail;      /* number of staged packets ready */
	uint16_t rx_next_avail;    /* index of next staged packets */
	uint16_t rx_free_trigger;  /* triggers rx buffer allocation */
	struct rte_mbuf *rx_stage[IAVF_RX_MAX_BURST * 2]; /* store mbuf */

	uint16_t port_id;        /* device port ID */
	uint8_t crc_len;        /* 0 if CRC stripped, 4 otherwise */
	uint8_t fdir_enabled;   /* 0 if FDIR disabled, 1 when enabled */
	uint16_t queue_id;      /* Rx queue index */
	uint16_t rx_buf_len;    /* The packet buffer size */
	uint16_t rx_hdr_len;    /* The header buffer size */
	uint16_t max_pkt_len;   /* Maximum packet length */
	struct iavf_vsi *vsi; /**< the VSI this queue belongs to */

	bool q_set;             /* if rx queue has been configured */
	bool rx_deferred_start; /* don't start this queue in dev start */
	const struct iavf_rxq_ops *ops;
	uint8_t rx_flags;
#define IAVF_RX_FLAGS_VLAN_TAG_LOC_L2TAG1     BIT(0)
#define IAVF_RX_FLAGS_VLAN_TAG_LOC_L2TAG2_2   BIT(1)
	uint8_t proto_xtr; /* protocol extraction type */
	uint64_t xtr_ol_flag;
		/* flexible descriptor metadata extraction offload flag */
	iavf_rxd_to_pkt_fields_t rxd_to_pkt_fields;
				/* handle flexible descriptor by RXDID */
	struct iavf_rx_queue_stats stats;
	uint64_t offloads;
};

struct iavf_tx_entry {
	struct rte_mbuf *mbuf;
	uint16_t next_id;
	uint16_t last_id;
};

struct iavf_tx_vec_entry {
	struct rte_mbuf *mbuf;
};

/* Structure associated with each TX queue. */
struct iavf_tx_queue {
	const struct rte_memzone *mz;  /* memzone for Tx ring */
	volatile struct iavf_tx_desc *tx_ring; /* Tx ring virtual address */
	uint64_t tx_ring_phys_addr;    /* Tx ring DMA address */
	struct iavf_tx_entry *sw_ring;  /* address array of SW ring */
	uint16_t nb_tx_desc;           /* ring length */
	uint16_t tx_tail;              /* current value of tail */
	volatile uint8_t *qtx_tail;    /* register address of tail */
	/* number of used desc since RS bit set */
	uint16_t nb_used;
	uint16_t nb_free;
	uint16_t last_desc_cleaned;    /* last desc have been cleaned*/
	uint16_t free_thresh;
	uint16_t rs_thresh;

	uint16_t port_id;
	uint16_t queue_id;
	uint64_t offloads;
	uint16_t next_dd;              /* next to set RS, for VPMD */
	uint16_t next_rs;              /* next to check DD,  for VPMD */
	uint16_t ipsec_crypto_pkt_md_offset;

	bool q_set;                    /* if rx queue has been configured */
	bool tx_deferred_start;        /* don't start this queue in dev start */
	const struct iavf_txq_ops *ops;
#define IAVF_TX_FLAGS_VLAN_TAG_LOC_L2TAG1	BIT(0)
#define IAVF_TX_FLAGS_VLAN_TAG_LOC_L2TAG2	BIT(1)
	uint8_t vlan_flag;
	uint8_t tc;
};

#ifdef RTE_LIBRTE_IAVF_DEBUG_TX_DESC_RING

static void iavf_dump_tx_entry(uint16_t txe_id, const struct iavf_tx_entry *txe)
{
	printf("txe %3d : next %3d, last %3d, mbuf 0x%p\n",
		txe_id, txe->next_id, txe->last_id, txe->mbuf);
}

static void iavf_dump_tx_entry_ring(const struct iavf_tx_queue *txq)
{
	uint16_t i;

	printf("port %d, queue %d :\n\n", txq->port_id, txq->queue_id);

	printf("nb descriptors %d\n", txq->nb_tx_desc);
	printf("tail %d\n", txq->tx_tail);
	printf("nb used %d, nb free %d\n", txq->nb_used, txq->nb_free);
	printf("last cleaned %d\n", txq->last_desc_cleaned);
	printf("free threshold %d\n", txq->free_thresh);
	printf("rs threshold %d\n\n", txq->rs_thresh);


	for (i = 0; i < txq->nb_tx_desc; i++)
		iavf_dump_tx_entry(i, &txq->sw_ring[i]);
}

static void iavf_dump_tx_desc_ring(const struct iavf_tx_queue *txq)
{
	uint16_t i;

	printf("port %3d, queue %d :\n\n", txq->port_id, txq->queue_id);
	printf("nb descriptors %d\n", txq->nb_tx_desc);

	for (i = 0; i < txq->nb_tx_desc; i++) {
		volatile struct iavf_tx_data_desc *txd = &txq->tx_ring[i];

		printf("txid %3d - "
		"QW0: 0x%04"PRIx16" %04"PRIx16" %04"PRIx16" %04"PRIx16", "
		"QW1: 0x%04"PRIx16" %04"PRIx16" %04"PRIx16" %04"PRIx16"\n",
	       i, 0, 0, 0, 0, 0, 0, 0,
	       (const volatile uint16_t)(txd->qw1 & 0xF));
	}
}

#endif

/* Offload features */
union iavf_tx_offload {
	uint64_t data;
	struct {
		uint64_t l2_len:7; /* L2 (MAC) Header Length. */
		uint64_t l3_len:9; /* L3 (IP) Header Length. */
		uint64_t l4_len:8; /* L4 Header Length. */
		uint64_t tso_segsz:16; /* TCP TSO segment size */
		/* uint64_t unused : 24; */
	};
};

/* Rx Flex Descriptor
 * RxDID Profile ID 16-21
 * Flex-field 0: RSS hash lower 16-bits
 * Flex-field 1: RSS hash upper 16-bits
 * Flex-field 2: Flow ID lower 16-bits
 * Flex-field 3: Flow ID upper 16-bits
 * Flex-field 4: AUX0
 * Flex-field 5: AUX1
 */
struct iavf_32b_rx_flex_desc_comms {
	union {
		struct {
	/* Qword 0 */
	u8 rxdid;
	u8 mir_id_umb_cast;
	__le16 ptype_flexi_flags0;
	__le16 pkt_len;
	__le16 hdr_len_sph_flex_flags1;

	/* Qword 1 */
	__le16 status_error0;
	__le16 l2tag1;
	__le32 rss_hash;

	/* Qword 2 */
	__le16 status_error1;
	u8 flexi_flags2;
	u8 ts_low;
	__le16 l2tag2_1st;
	__le16 l2tag2_2nd;

	/* Qword 3 */
	__le32 flow_id;
	union {
		struct {
			__le16 aux0;
			__le16 aux1;
		} flex;
		__le32 ts_high;
	} flex_ts;
		};
		struct {
			/* Quad Word 0 */

			u8 rxdid;	/**< Descriptor builder profile ID */

			u8 mirror_id:6;
			u8 umbcast:2;

			__le16 ptype:10;
			__le16 flexi_flags_0:6;

			__le16 packet_length:14;
			__le16 rsv_0:2;

			__le16 hlen:11;
			__le16 sph:1;
			__le16 flexi_flags_1:4;

			/* Quad Word 1 */
			union {
				__le16 status_error0;
				struct {
					__le16 status_error0_dd:1;
					/* descriptor done */
					__le16 status_error0_eop:1;
					/* end of packet */
					__le16 status_error0_hbo:1;
					/* header buffer overflow */
					__le16 status_error0_l3l4p:1;
					/* l3/l4 integrity check */
					__le16 status_error0_xsum:4;
					/* checksum report */
					__le16 status_error0_lpbk:1;
					/* loopback */
					__le16 status_error0_ipv6exadd:1;
					/* ipv6 w/ dst options or routing hdr */
					__le16 status_error0_rxe:1;
					/* rcv mac errors */
					__le16 status_error0_crcp:1;
					/* ethernet crc present */
					__le16 status_error0_rsshash:1;
					/* rss hash valid */
					__le16 status_error0_l2tag1p:1;
					/* l2 tag 1 present */
					__le16 status_error0_flexi_md0:1;
					/* flexi md field 0 valid */
					__le16 status_error0_flexi_md1:1;
					/* flexi md field 1 valid */
				};
			};
			__le16 l2tag1;
			__le16 flex_meta0;	/**< flexi metadata field 0 */
			__le16 flex_meta1;	/**< flexi metadata field 1 */

			/* Quad Word 2 */
			union {
				__le16 status_error1;
				struct {
					__le16 status_error1_cpm:4;
					/* Inline IPsec Crypto Status */
					__le16 status_error1_udp_tunnel:1;
					/* UDP tunnelled packet NAT-T/UDP-NAT */
					__le16 status_error1_crypto:1;
					/* Inline IPsec Crypto Offload */
					__le16 status_error1_rsv:5;
					/* Reserved */
					__le16 status_error1_l2tag2p:1;
					/* l2 tag 2 present */
					__le16 status_error1_flexi_md2:1;
					/* flexi md field 2 valid */
					__le16 status_error1_flexi_md3:1;
					/* flexi md field 3 valid */
					__le16 status_error1_flexi_md4:1;
					/* flexi md field 4 valid */
					__le16 status_error1_flexi_md5:1;
					/* flexi md field 5 valid */
				};
			};

			u8 flex_flags2;
			u8 time_stamp_low;

			__le16 l2tag2_1st;			/**< L2TAG */
			__le16 l2tag2_2nd;			/**< L2TAG */

			/* Quad Word 3 */

			__le16 flex_meta2;	/**< flexi metadata field 2 */
			__le16 flex_meta3;	/**< flexi metadata field 3 */
			__le16 flex_meta4;	/**< flexi metadata field 4 */
			__le16 flex_meta5;	/**< flexi metadata field 5 */

		} debug;
	};
};

/* Rx Flex Descriptor
 * RxDID Profile ID 22-23 (swap Hash and FlowID)
 * Flex-field 0: Flow ID lower 16-bits
 * Flex-field 1: Flow ID upper 16-bits
 * Flex-field 2: RSS hash lower 16-bits
 * Flex-field 3: RSS hash upper 16-bits
 * Flex-field 4: AUX0
 * Flex-field 5: AUX1
 */
struct iavf_32b_rx_flex_desc_comms_ovs {
	/* Qword 0 */
	u8 rxdid;
	u8 mir_id_umb_cast;
	__le16 ptype_flexi_flags0;
	__le16 pkt_len;
	__le16 hdr_len_sph_flex_flags1;

	/* Qword 1 */
	__le16 status_error0;
	__le16 l2tag1;
	__le32 flow_id;

	/* Qword 2 */
	__le16 status_error1;
	u8 flexi_flags2;
	u8 ts_low;
	__le16 l2tag2_1st;
	__le16 l2tag2_2nd;

	/* Qword 3 */
	__le32 rss_hash;
	union {
		struct {
			__le16 aux0;
			__le16 aux1;
		} flex;
		__le32 ts_high;
	} flex_ts;
};

/* Rx Flex Descriptor
 * RxDID Profile ID 24 Inline IPsec
 * Flex-field 0: RSS hash lower 16-bits
 * Flex-field 1: RSS hash upper 16-bits
 * Flex-field 2: Flow ID lower 16-bits
 * Flex-field 3: Flow ID upper 16-bits
 * Flex-field 4: Inline IPsec SAID lower 16-bits
 * Flex-field 5: Inline IPsec SAID upper 16-bits
 */
struct iavf_32b_rx_flex_desc_comms_ipsec {
	/* Qword 0 */
	u8 rxdid;
	u8 mir_id_umb_cast;
	__le16 ptype_flexi_flags0;
	__le16 pkt_len;
	__le16 hdr_len_sph_flex_flags1;

	/* Qword 1 */
	__le16 status_error0;
	__le16 l2tag1;
	__le32 rss_hash;

	/* Qword 2 */
	__le16 status_error1;
	u8 flexi_flags2;
	u8 ts_low;
	__le16 l2tag2_1st;
	__le16 l2tag2_2nd;

	/* Qword 3 */
	__le32 flow_id;
	__le32 ipsec_said;
};

/* Receive Flex Descriptor profile IDs: There are a total
 * of 64 profiles where profile IDs 0/1 are for legacy; and
 * profiles 2-63 are flex profiles that can be programmed
 * with a specific metadata (profile 7 reserved for HW)
 */
enum iavf_rxdid {
	IAVF_RXDID_LEGACY_0		= 0,
	IAVF_RXDID_LEGACY_1		= 1,
	IAVF_RXDID_FLEX_NIC		= 2,
	IAVF_RXDID_FLEX_NIC_2		= 6,
	IAVF_RXDID_HW			= 7,
	IAVF_RXDID_COMMS_GENERIC	= 16,
	IAVF_RXDID_COMMS_AUX_VLAN	= 17,
	IAVF_RXDID_COMMS_AUX_IPV4	= 18,
	IAVF_RXDID_COMMS_AUX_IPV6	= 19,
	IAVF_RXDID_COMMS_AUX_IPV6_FLOW	= 20,
	IAVF_RXDID_COMMS_AUX_TCP	= 21,
	IAVF_RXDID_COMMS_OVS_1		= 22,
	IAVF_RXDID_COMMS_OVS_2		= 23,
	IAVF_RXDID_COMMS_IPSEC_CRYPTO	= 24,
	IAVF_RXDID_COMMS_AUX_IP_OFFSET	= 25,
	IAVF_RXDID_LAST			= 63,
};

enum iavf_rx_flex_desc_status_error_0_bits {
	/* Note: These are predefined bit offsets */
	IAVF_RX_FLEX_DESC_STATUS0_DD_S = 0,
	IAVF_RX_FLEX_DESC_STATUS0_EOF_S,
	IAVF_RX_FLEX_DESC_STATUS0_HBO_S,
	IAVF_RX_FLEX_DESC_STATUS0_L3L4P_S,
	IAVF_RX_FLEX_DESC_STATUS0_XSUM_IPE_S,
	IAVF_RX_FLEX_DESC_STATUS0_XSUM_L4E_S,
	IAVF_RX_FLEX_DESC_STATUS0_XSUM_EIPE_S,
	IAVF_RX_FLEX_DESC_STATUS0_XSUM_EUDPE_S,
	IAVF_RX_FLEX_DESC_STATUS0_LPBK_S,
	IAVF_RX_FLEX_DESC_STATUS0_IPV6EXADD_S,
	IAVF_RX_FLEX_DESC_STATUS0_RXE_S,
	IAVF_RX_FLEX_DESC_STATUS0_CRCP_S,
	IAVF_RX_FLEX_DESC_STATUS0_RSS_VALID_S,
	IAVF_RX_FLEX_DESC_STATUS0_L2TAG1P_S,
	IAVF_RX_FLEX_DESC_STATUS0_XTRMD0_VALID_S,
	IAVF_RX_FLEX_DESC_STATUS0_XTRMD1_VALID_S,
	IAVF_RX_FLEX_DESC_STATUS0_LAST /* this entry must be last!!! */
};

enum iavf_rx_flex_desc_status_error_1_bits {
	/* Note: These are predefined bit offsets */
	/* Bits 3:0 are reserved for inline ipsec status */
	IAVF_RX_FLEX_DESC_STATUS1_IPSEC_CRYPTO_STATUS_0 = 0,
	IAVF_RX_FLEX_DESC_STATUS1_IPSEC_CRYPTO_STATUS_1,
	IAVF_RX_FLEX_DESC_STATUS1_IPSEC_CRYPTO_STATUS_2,
	IAVF_RX_FLEX_DESC_STATUS1_IPSEC_CRYPTO_STATUS_3,
	IAVF_RX_FLEX_DESC_STATUS1_NAT_S,
	IAVF_RX_FLEX_DESC_STATUS1_IPSEC_CRYPTO_PROCESSED,
	/* [10:6] reserved */
	IAVF_RX_FLEX_DESC_STATUS1_L2TAG2P_S = 11,
	IAVF_RX_FLEX_DESC_STATUS1_XTRMD2_VALID_S = 12,
	IAVF_RX_FLEX_DESC_STATUS1_XTRMD3_VALID_S = 13,
	IAVF_RX_FLEX_DESC_STATUS1_XTRMD4_VALID_S = 14,
	IAVF_RX_FLEX_DESC_STATUS1_XTRMD5_VALID_S = 15,
	IAVF_RX_FLEX_DESC_STATUS1_LAST /* this entry must be last!!! */
};

#define IAVF_RX_FLEX_DESC_IPSEC_CRYPTO_STATUS_MASK  (		\
	BIT(IAVF_RX_FLEX_DESC_STATUS1_IPSEC_CRYPTO_STATUS_0) |	\
	BIT(IAVF_RX_FLEX_DESC_STATUS1_IPSEC_CRYPTO_STATUS_1) |	\
	BIT(IAVF_RX_FLEX_DESC_STATUS1_IPSEC_CRYPTO_STATUS_2) |	\
	BIT(IAVF_RX_FLEX_DESC_STATUS1_IPSEC_CRYPTO_STATUS_3))

enum iavf_rx_flex_desc_ipsec_crypto_status {
	IAVF_IPSEC_CRYPTO_STATUS_SUCCESS = 0,
	IAVF_IPSEC_CRYPTO_STATUS_SAD_MISS,
	IAVF_IPSEC_CRYPTO_STATUS_NOT_PROCESSED,
	IAVF_IPSEC_CRYPTO_STATUS_ICV_CHECK_FAIL,
	IAVF_IPSEC_CRYPTO_STATUS_LENGTH_ERR,
	/* Reserved */
	IAVF_IPSEC_CRYPTO_STATUS_MISC_ERR = 0xF
};

#define IAVF_RX_FLEX_DESC_IPSEC_CRYPTO_SAID_MASK	(0xFFFFF)

/* for iavf_32b_rx_flex_desc.ptype_flex_flags0 member */
#define IAVF_RX_FLEX_DESC_PTYPE_M	(0x3FF) /* 10-bits */

/* for iavf_32b_rx_flex_desc.pkt_len member */
#define IAVF_RX_FLX_DESC_PKT_LEN_M	(0x3FFF) /* 14-bits */

int iavf_dev_rx_queue_setup(struct rte_eth_dev *dev,
			   uint16_t queue_idx,
			   uint16_t nb_desc,
			   unsigned int socket_id,
			   const struct rte_eth_rxconf *rx_conf,
			   struct rte_mempool *mp);

int iavf_dev_rx_queue_start(struct rte_eth_dev *dev, uint16_t rx_queue_id);
int iavf_dev_rx_queue_stop(struct rte_eth_dev *dev, uint16_t rx_queue_id);
void iavf_dev_rx_queue_release(void *rxq);

int iavf_dev_tx_queue_setup(struct rte_eth_dev *dev,
			   uint16_t queue_idx,
			   uint16_t nb_desc,
			   unsigned int socket_id,
			   const struct rte_eth_txconf *tx_conf);
int iavf_dev_tx_queue_start(struct rte_eth_dev *dev, uint16_t tx_queue_id);
int iavf_dev_tx_queue_stop(struct rte_eth_dev *dev, uint16_t tx_queue_id);
int iavf_dev_tx_done_cleanup(void *txq, uint32_t free_cnt);
void iavf_dev_tx_queue_release(void *txq);
void iavf_stop_queues(struct rte_eth_dev *dev);
uint16_t iavf_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts,
		       uint16_t nb_pkts);
uint16_t iavf_recv_pkts_flex_rxd(void *rx_queue,
				 struct rte_mbuf **rx_pkts,
				 uint16_t nb_pkts);
uint16_t iavf_recv_scattered_pkts(void *rx_queue,
				 struct rte_mbuf **rx_pkts,
				 uint16_t nb_pkts);
uint16_t iavf_recv_scattered_pkts_flex_rxd(void *rx_queue,
					   struct rte_mbuf **rx_pkts,
					   uint16_t nb_pkts);
uint16_t iavf_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
		       uint16_t nb_pkts);
uint16_t iavf_prep_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
		       uint16_t nb_pkts);
void iavf_set_rx_function(struct rte_eth_dev *dev);
void iavf_set_tx_function(struct rte_eth_dev *dev);
void iavf_dev_rxq_info_get(struct rte_eth_dev *dev, uint16_t queue_id,
			  struct rte_eth_rxq_info *qinfo);
void iavf_dev_txq_info_get(struct rte_eth_dev *dev, uint16_t queue_id,
			  struct rte_eth_txq_info *qinfo);
uint32_t iavf_dev_rxq_count(struct rte_eth_dev *dev, uint16_t queue_id);
int iavf_dev_rx_desc_status(void *rx_queue, uint16_t offset);
int iavf_dev_tx_desc_status(void *tx_queue, uint16_t offset);

uint16_t iavf_recv_pkts_vec(void *rx_queue, struct rte_mbuf **rx_pkts,
			   uint16_t nb_pkts);
uint16_t iavf_recv_pkts_vec_flex_rxd(void *rx_queue, struct rte_mbuf **rx_pkts,
				     uint16_t nb_pkts);
uint16_t iavf_recv_scattered_pkts_vec(void *rx_queue,
				     struct rte_mbuf **rx_pkts,
				     uint16_t nb_pkts);
uint16_t iavf_recv_scattered_pkts_vec_flex_rxd(void *rx_queue,
					       struct rte_mbuf **rx_pkts,
					       uint16_t nb_pkts);
uint16_t iavf_xmit_fixed_burst_vec(void *tx_queue, struct rte_mbuf **tx_pkts,
				  uint16_t nb_pkts);
uint16_t iavf_recv_pkts_vec_avx2(void *rx_queue, struct rte_mbuf **rx_pkts,
				 uint16_t nb_pkts);
uint16_t iavf_recv_pkts_vec_avx2_flex_rxd(void *rx_queue,
					  struct rte_mbuf **rx_pkts,
					  uint16_t nb_pkts);
uint16_t iavf_recv_scattered_pkts_vec_avx2(void *rx_queue,
					   struct rte_mbuf **rx_pkts,
					   uint16_t nb_pkts);
uint16_t iavf_recv_scattered_pkts_vec_avx2_flex_rxd(void *rx_queue,
						    struct rte_mbuf **rx_pkts,
						    uint16_t nb_pkts);
uint16_t iavf_xmit_pkts_vec(void *tx_queue, struct rte_mbuf **tx_pkts,
			    uint16_t nb_pkts);
uint16_t iavf_xmit_pkts_vec_avx2(void *tx_queue, struct rte_mbuf **tx_pkts,
				 uint16_t nb_pkts);
int iavf_get_monitor_addr(void *rx_queue, struct rte_power_monitor_cond *pmc);
int iavf_rx_vec_dev_check(struct rte_eth_dev *dev);
int iavf_tx_vec_dev_check(struct rte_eth_dev *dev);
int iavf_rxq_vec_setup(struct iavf_rx_queue *rxq);
int iavf_txq_vec_setup(struct iavf_tx_queue *txq);
uint16_t iavf_recv_pkts_vec_avx512(void *rx_queue, struct rte_mbuf **rx_pkts,
				   uint16_t nb_pkts);
uint16_t iavf_recv_pkts_vec_avx512_offload(void *rx_queue,
					   struct rte_mbuf **rx_pkts,
					   uint16_t nb_pkts);
uint16_t iavf_recv_pkts_vec_avx512_flex_rxd(void *rx_queue,
					    struct rte_mbuf **rx_pkts,
					    uint16_t nb_pkts);
uint16_t iavf_recv_pkts_vec_avx512_flex_rxd_offload(void *rx_queue,
						    struct rte_mbuf **rx_pkts,
						    uint16_t nb_pkts);
uint16_t iavf_recv_scattered_pkts_vec_avx512(void *rx_queue,
					     struct rte_mbuf **rx_pkts,
					     uint16_t nb_pkts);
uint16_t iavf_recv_scattered_pkts_vec_avx512_offload(void *rx_queue,
						     struct rte_mbuf **rx_pkts,
						     uint16_t nb_pkts);
uint16_t iavf_recv_scattered_pkts_vec_avx512_flex_rxd(void *rx_queue,
						      struct rte_mbuf **rx_pkts,
						      uint16_t nb_pkts);
uint16_t iavf_recv_scattered_pkts_vec_avx512_flex_rxd_offload(void *rx_queue,
						struct rte_mbuf **rx_pkts,
						uint16_t nb_pkts);
uint16_t iavf_xmit_pkts_vec_avx512(void *tx_queue, struct rte_mbuf **tx_pkts,
				   uint16_t nb_pkts);
uint16_t iavf_xmit_pkts_vec_avx512_offload(void *tx_queue,
					   struct rte_mbuf **tx_pkts,
					   uint16_t nb_pkts);
int iavf_txq_vec_setup_avx512(struct iavf_tx_queue *txq);

uint8_t iavf_proto_xtr_type_to_rxdid(uint8_t xtr_type);

const uint32_t *iavf_get_default_ptype_table(void);

static void iavf_dump_rx_flex_desc(const volatile
		struct iavf_32b_rx_flex_desc_comms *desc)
{
	printf("QW0: rxdid          : (0x%x) %d\n", desc->debug.rxdid,
			desc->debug.rxdid);
	printf("QW0: mirror id      : %d\n", desc->debug.mirror_id);
	printf("QW0: umbcast id     : %d\n", desc->debug.umbcast);
	printf("QW0: mirror id      : (0x%x) %d\n", desc->debug.ptype,
			desc->debug.ptype);
	printf("QW0: flexi flags 0  : %x\n", desc->debug.flexi_flags_0);
	printf("QW0: packet len     : %d\n", desc->debug.packet_length);
	printf("QW0: header len     : %d\n", desc->debug.hlen);
	printf("QW0: sph len        : %d\n", desc->debug.sph);
	printf("QW0: flexi flags 1  : %x\n", desc->debug.flexi_flags_1);


	printf("QW1: status/error 0 : 0x%x\n", desc->debug.status_error0);

	printf("QW1: status/error 0 - dd         : 0x%x\n",
			desc->debug.status_error0_dd);
	printf("QW1: status/error 0 - eop        : 0x%x\n",
			desc->debug.status_error0_eop);
	printf("QW1: status/error 0 - hbo        : 0x%x\n",
			desc->debug.status_error0_hbo);
	printf("QW1: status/error 0 - l3l4p      : 0x%x\n",
			desc->debug.status_error0_l3l4p);
	printf("QW1: status/error 0 - xsum       : 0x%x\n",
			desc->debug.status_error0_xsum);
	printf("QW1: status/error 0 - lpbk       : 0x%x\n",
			desc->debug.status_error0_lpbk);
	printf("QW1: status/error 0 - ipv6extadd : 0x%x\n",
			desc->debug.status_error0_ipv6exadd);
	printf("QW1: status/error 0 - rxe        : 0x%x\n",
			desc->debug.status_error0_rxe);
	printf("QW1: status/error 0 - crcp       : 0x%x\n",
			desc->debug.status_error0_crcp);
	printf("QW1: status/error 0 - rsshash    : 0x%x\n",
			desc->debug.status_error0_rsshash);
	printf("QW1: status/error 0 - l2tag 1 p  : 0x%x\n",
			desc->debug.status_error0_l2tag1p);
	printf("QW1: status/error 0 - flexi md 0 : 0x%x\n",
			desc->debug.status_error0_flexi_md0);
	printf("QW1: status/error 0 - flexi md 1 : 0x%x\n",
			desc->debug.status_error0_flexi_md1);

	printf("QW1: l2tag1     : %d\n",
		desc->debug.status_error0_l2tag1p ? desc->debug.l2tag1 : 0);
	printf("QW1: flexi md 0 : 0x%x\n",
		desc->debug.status_error0_flexi_md0 ?
				desc->debug.flex_meta0 : 0);
	printf("QW1: flexi md 1 : 0x%x\n",
			desc->debug.status_error0_flexi_md1 ?
					desc->debug.flex_meta1 : 0);


	printf("QW2: status/error 1 : 0x%x\n", desc->debug.status_error1);

	printf("QW2: status/error 1 - cpm status : 0x%x\n",
			desc->debug.status_error1_cpm);
	printf("QW2: status/error 1 - udp tunnel : 0x%x\n",
			desc->debug.status_error1_udp_tunnel);
	printf("QW2: status/error 1 - crypto     : 0x%x\n",
			desc->debug.status_error1_crypto);
	printf("QW2: status/error 1 - l2tag 2 p  : 0x%x\n",
			desc->debug.status_error1_l2tag2p);
	printf("QW2: status/error 1 - flexi md 2 : 0x%x\n",
			desc->debug.status_error1_flexi_md2);
	printf("QW2: status/error 1 - flexi md 3 : 0x%x\n",
			desc->debug.status_error1_flexi_md3);
	printf("QW2: status/error 1 - flexi md 4 : 0x%x\n",
			desc->debug.status_error1_flexi_md4);
	printf("QW2: status/error 1 - flexi md 5 : 0x%x\n",
			desc->debug.status_error1_flexi_md5);


	printf("QW2: flexi flags 2  : 0x%x\n", desc->debug.flex_flags2);
	printf("QW2: timestamp low  : 0x%x\n", desc->debug.time_stamp_low);
	printf("QW2: l2tag2_1       : 0x%x\n", desc->debug.l2tag2_1st);
	printf("QW2: l2tag2_2       : 0x%x\n", desc->debug.l2tag2_2nd);

	printf("QW3: flexi md 2     : 0x%x\n",
			desc->debug.status_error1_flexi_md2 ?
					desc->debug.flex_meta2 : 0);
	printf("QW3: flexi md 3     : 0x%x\n",
			desc->debug.status_error1_flexi_md3 ?
					desc->debug.flex_meta3 : 0);
	printf("QW3: flexi md 4     : 0x%x\n",
			desc->debug.status_error1_flexi_md4 ?
					desc->debug.flex_meta4 : 0);
	printf("QW3: flexi md 5     : 0x%x\n",
			desc->debug.status_error1_flexi_md5 ?
					desc->debug.flex_meta5 : 0);
}

static inline
void iavf_dump_rx_descriptor(struct iavf_rx_queue *rxq,
			    const volatile void *desc,
			    uint16_t rx_id)
{
#ifdef RTE_LIBRTE_IAVF_16BYTE_RX_DESC
	const volatile union iavf_16byte_rx_desc *rx_desc = desc;

	printf("Queue %d Rx_desc %d: QW0: 0x%016"PRIx64" QW1: 0x%016"PRIx64"\n",
	       rxq->queue_id, rx_id, rx_desc->read.pkt_addr,
	       rx_desc->read.hdr_addr);
#else
	const volatile union iavf_32byte_rx_desc *rx_desc = desc;

	printf("Queue %d Rx_desc %d: QW0: 0x%016"PRIx64" QW1: 0x%016"PRIx64
	       " QW2: 0x%016"PRIx64" QW3: 0x%016"PRIx64"\n", rxq->queue_id,
	       rx_id, rx_desc->read.pkt_addr, rx_desc->read.hdr_addr,
	       rx_desc->read.rsvd1, rx_desc->read.rsvd2);

	iavf_dump_rx_flex_desc(desc);
#endif
}

static uint8_t cipherblock_sz(uint8_t blksz)
{
	switch (blksz) {
	case 2:
		return 8;
	case 3:
		return 16;
	}

	return 0;
}

static void iavf_dump_tx_ctx_desc(const volatile
		struct iavf_tx_context_desc *desc)
{
	struct iavf_tx_context_desc ctx;

	ctx.qw0 = rte_le_to_cpu_64(desc->qw0);
	ctx.qw1 = rte_le_to_cpu_64(desc->qw1);

	const char *eipt, *l4tunt;

	const char *eipt_no_exip = "no_exip";
	const char *eipt_ip6 = "ip6";
	const char *eipt_ip4_no_checksum = "ip4_no_checksum";
	const char *eipt_ip4_w_checksum = "ip4_w_checksum";

	const char *l4tunt_no_udp_gre = "no_udp_gre";
	const char *l4tunt_udp = "udp";
	const char *l4tunt_gre = "gre";

	switch (ctx.debug.tunneling & 0x3) {
	case 1:
		eipt = eipt_ip6;
		break;
	case 2:
		eipt = eipt_ip4_no_checksum;
		break;
	case 3:
		eipt = eipt_ip4_w_checksum;
		break;
	default:
		eipt = eipt_no_exip;
	}

	switch ((ctx.debug.tunneling & 0x600) >> 9) {
	case 0:
		l4tunt = l4tunt_no_udp_gre;
		break;
	case 1:
		l4tunt = l4tunt_udp;
		break;
	case 2:
		l4tunt = l4tunt_gre;
		break;
	default:
		l4tunt = "invalid value set for l4 tunnel type ";
	}

	printf("QW0: Tunnel EIPT : (%d) %s\n", ctx.debug.tunneling & 0x3, eipt);
	printf("QW0: Tunnel EIPLEN : %d\n",
			(uint32_t)(((ctx.debug.tunneling >>
				IAVF_TXD_CTX_QW0_TUN_PARAMS_EIPLEN_SHIFT) &
				IAVF_TXD_CTX_QW0_TUN_PARAMS_EIPLEN_MASK) << 2));
	printf("QW0: Tunnel EIP_NOINC : %d\n",
			(ctx.debug.tunneling >> 11) & 0x1);

	printf("QW0: Tunnel L4TUNT : (%d) %s\n",
			(ctx.debug.tunneling & 0x600) >> 9, l4tunt);
	printf("QW0: Tunnel L4TUNLEN : (%d)\n",
			(ctx.debug.tunneling >> 12) & 0x7F);

	printf("QW0: Tunnel DEC Inner TTL : %d\n", 0);
	printf("QW0: Tunnel UDP Checksum : %d\n", 0);

	printf("QW0: L2TAG1 : %d\n", ctx.l2tag2);

	printf("QW1: DTYP: %d\n", ctx.debug.type);

	printf("QW1: Cmd TSO          : %x\n", (ctx.debug.cmd >> 0) & 0x1);
	printf("QW1: Cmd TSYN         : %x\n", (ctx.debug.cmd >> 1) & 0x1);
	printf("QW1: Cmd IL2TAG2      : %x\n", (ctx.debug.cmd >> 2) & 0x1);
	printf("QW1: Cmd IL2TAG2_IL2H : %x\n", (ctx.debug.cmd >> 3) & 0x1);
	printf("QW1: Cmd SWITCH       : %x\n", (ctx.debug.cmd >> 4) & 0x3);

	printf("QW1: IPsec Cipher Block Sz: %d\n",
			cipherblock_sz(ctx.debug.ipsec & 0x7));
	printf("QW1: IPsec ICV Sz         : %d\n", (ctx.debug.ipsec >> 3) << 2);

	printf("QW1: TLength: %d\n", ctx.debug.tlen_tsyn);
	printf("QW1: MSS: %d\n", ctx.debug.mss_target_vsi);
}

#include <netinet/in.h>

static const char *ipproto_to_str(uint8_t ipproto)
{
	switch (ipproto) {
	case IPPROTO_IP:
		return "Dummy";
	case IPPROTO_IPIP:
		return "IPIP";
	case IPPROTO_TCP:
		return "TCP";
	case IPPROTO_UDP:
		return "UDP";
	case IPPROTO_ESP:
		return "ESP";
	case IPPROTO_AH:
		return "AH";
	case IPPROTO_IPV6:
		return "IPV6";
	case IPPROTO_SCTP:
		return "SCTP";
	case IPPROTO_RAW:
		return "RAW";
	}

	return "Unknown";
}

static void iavf_dump_tx_ipsec_desc(const volatile
		struct iavf_tx_ipsec_desc *desc)
{
	struct iavf_tx_ipsec_desc ipsec;
	uint16_t ivlen = 0;

	ipsec.qw0 = rte_le_to_cpu_64(desc->qw0);
	ipsec.qw1 = rte_le_to_cpu_64(desc->qw1);

	switch (ipsec.ivlen) {
	case 1:
		ivlen = 4;
		break;
	case 2:
		ivlen = 8;
		break;
	case 3:
		ivlen = 16;
		break;
	}

	printf("QW0: L4 Payload Length: %d\n", ipsec.l4payload_length);
	printf("QW0: ESN : %d\n", ipsec.esn);
	printf("QW0: ESP Trailer Length: %d\n", ipsec.trailer_length);

	printf("QW1: DTYP: %d\n", ipsec.type);
	printf("QW1: UDP: %s\n", ipsec.udp ? "yes" : "no");
	printf("QW1: IV Length: %d\n", ivlen);
	printf("QW1: Next Proto: (%d) %s\n", ipsec.next_header,
			ipproto_to_str(ipsec.next_header));
	printf("QW1: IPv6 Extension Headers Length: %d\n",
			ipsec.ipv6_ext_hdr_length);
	printf("QW1: SAID: %d\n", ipsec.said);
}

static const char *iipt_to_str(uint8_t iipt)
{
	switch (iipt) {
	case 0:
		return "Non IP packet / not defined";
	case 1:
		return "IPv6";
	case 2:
		return "IPv4 w/ no IP Checksum";
	case 3:
		return "IPv4 w/ IP Checksum";
	}

	return "";
}

static const char *l4t_to_str(uint8_t l4t)
{
	switch (l4t) {
	case 0:
		return "unknown / fragment";
	case 1:
		return "TCP";
	case 2:
		return "SCTP";
	case 3:
		return "UDP";
	}

	return "";
}

static void iavf_dump_tx_data_desc(const volatile struct iavf_tx_desc *desc)
{
	struct iavf_tx_desc data;


	data.qw0 = rte_le_to_cpu_64(desc->qw0);
	data.qw1 = rte_le_to_cpu_64(desc->qw1);

	printf("QW0: Buffer Address : 0x%016"PRIx64"\n",
			data.debug.buffer_addr);

	printf("QW1: Dtype : %d\n", data.debug.type);

	printf("QW1: Cmd : %x\n", data.debug.cmd);
	printf("QW1: Cmd EOP     : %x\n", (data.debug.cmd >> 0) & 0x1);
	printf("QW1: Cmd RS      : %x\n", (data.debug.cmd >> 1) & 0x1);
	printf("QW1: Cmd RSV     : %x\n", (data.debug.cmd >> 2) & 0x1);
	printf("QW1: Cmd IL2TAG1 : %x\n", (data.debug.cmd >> 3) & 0x1);
	printf("QW1: Cmd DUMMY   : %x\n", (data.debug.cmd >> 4) & 0x1);
	printf("QW1: Cmd IIPT    : (%x) %s\n", (data.debug.cmd >> 5) & 0x3,
			iipt_to_str((data.debug.cmd >> 5) & 0x3));
	printf("QW1: Cmd RSV     : %x\n", (data.debug.cmd >> 7) & 0x1);
	printf("QW1: Cmd L4T     : (%x) %s\n", (data.debug.cmd >> 8) & 0x3,
			l4t_to_str((data.debug.cmd >> 8) & 0x3));
	printf("QW1: Cmd RE      : %x\n", (data.debug.cmd >> 10) & 0x1);
	printf("QW1: Cmd RSV     : %x\n", (data.debug.cmd >> 11) & 0x1);

	printf("QW1: Offset L2  : %d\n", data.debug.offset_l2len << 1);
	printf("QW1: Offset L3  : %d\n", data.debug.offset_l3len << 2);
	printf("QW1: Offset L4  : %d\n", data.debug.offset_l4len << 2);

	printf("QW1: Tx Buf Sz  : %d\n", data.debug.buffer_sz);

	printf("QW1: l2tag1 : %d\n", data.debug.l2tag1);
}

/* All the descriptors are 16 bytes, so just use one of them
 * to print the qwords
 */
static inline
void iavf_dump_tx_descriptor(const struct iavf_tx_queue *txq,
			    const volatile void *desc, uint16_t tx_id)
{
	const char *name;
	const volatile struct iavf_tx_desc *tx_desc = desc;
	enum iavf_tx_desc_dtype_value type;


	type = (enum iavf_tx_desc_dtype_value)rte_le_to_cpu_64(tx_desc->qw1 &
			rte_cpu_to_le_64(IAVF_TXD_DATA_QW1_DTYPE_MASK));
	switch (type) {
	case IAVF_TX_DESC_DTYPE_DATA:
		name = "Data Tx Desc: ";
		iavf_dump_tx_data_desc(desc);
		break;
	case IAVF_TX_DESC_DTYPE_CONTEXT:
		name = "Context Tx Desc: ";
		iavf_dump_tx_ctx_desc(desc);
		break;
	case IAVF_TX_DESC_DTYPE_IPSEC:
		name = "IPsec Tx Desc: ";
		iavf_dump_tx_ipsec_desc(desc);
		break;
	default:
		name = "Unknown Tx Desc: ";
		break;
	}

	printf("Queue %d %s %d: QW0: 0x%016"PRIx64" QW1: 0x%016"PRIx64"\n",
		txq->queue_id, name, tx_id, tx_desc->qw0, tx_desc->qw1);
}

#define FDIR_PROC_ENABLE_PER_QUEUE(ad, on) do { \
	int i; \
	for (i = 0; i < (ad)->eth_dev->data->nb_rx_queues; i++) { \
		struct iavf_rx_queue *rxq = (ad)->eth_dev->data->rx_queues[i]; \
		if (!rxq) \
			continue; \
		rxq->fdir_enabled = on; \
	} \
	PMD_DRV_LOG(DEBUG, "FDIR processing on RX set to %d", on); \
} while (0)

/* Enable/disable flow director Rx processing in data path. */
static inline
void iavf_fdir_rx_proc_enable(struct iavf_adapter *ad, bool on)
{
	if (on) {
		/* enable flow director processing */
		FDIR_PROC_ENABLE_PER_QUEUE(ad, on);
		ad->fdir_ref_cnt++;
	} else {
		if (ad->fdir_ref_cnt >= 1) {
			ad->fdir_ref_cnt--;

			if (ad->fdir_ref_cnt == 0)
				FDIR_PROC_ENABLE_PER_QUEUE(ad, on);
		}
	}
}

#ifdef RTE_LIBRTE_IAVF_DEBUG_DUMP_DESC
#define IAVF_DUMP_RX_DESC(rxq, desc, rx_id) \
	iavf_dump_rx_descriptor(rxq, desc, rx_id)
#define IAVF_DUMP_TX_DESC(txq, desc, tx_id) \
	iavf_dump_tx_descriptor(txq, desc, tx_id)
#else
#define IAVF_DUMP_RX_DESC(rxq, desc, rx_id) do { } while (0)
#define IAVF_DUMP_TX_DESC(txq, desc, tx_id) do { } while (0)
#endif

#endif /* _IAVF_RXTX_H_ */

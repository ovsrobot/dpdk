/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2022 Microsoft Corporation
 */

#ifndef __MANA_H__
#define __MANA_H__

enum {
	PCI_VENDOR_ID_MICROSOFT = 0x1414,
};

enum {
	PCI_DEVICE_ID_MICROSOFT_MANA = 0x00ba,
};

/* Shared data between primary/secondary processes */
struct mana_shared_data {
	rte_spinlock_t lock;
	int init_done;
	unsigned int primary_cnt;
	unsigned int secondary_cnt;
};

#define MIN_RX_BUF_SIZE	1024
#define MAX_FRAME_SIZE	RTE_ETHER_MAX_LEN
#define BNIC_MAX_MAC_ADDR 1

#define BNIC_DEV_RX_OFFLOAD_SUPPORT ( \
		DEV_RX_OFFLOAD_CHECKSUM | \
		DEV_RX_OFFLOAD_RSS_HASH)

#define BNIC_DEV_TX_OFFLOAD_SUPPORT ( \
		RTE_ETH_TX_OFFLOAD_MULTI_SEGS | \
		RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | \
		RTE_ETH_TX_OFFLOAD_TCP_CKSUM | \
		RTE_ETH_TX_OFFLOAD_UDP_CKSUM | \
		RTE_ETH_TX_OFFLOAD_TCP_TSO)

#define INDIRECTION_TABLE_NUM_ELEMENTS 64
#define TOEPLITZ_HASH_KEY_SIZE_IN_BYTES 40
#define BNIC_ETH_RSS_SUPPORT ( \
	ETH_RSS_IPV4 |	     \
	ETH_RSS_NONFRAG_IPV4_TCP | \
	ETH_RSS_NONFRAG_IPV4_UDP | \
	ETH_RSS_IPV6 |	     \
	ETH_RSS_NONFRAG_IPV6_TCP | \
	ETH_RSS_NONFRAG_IPV6_UDP)

#define MIN_BUFFERS_PER_QUEUE		64
#define MAX_RECEIVE_BUFFERS_PER_QUEUE	256
#define MAX_SEND_BUFFERS_PER_QUEUE	256

#define GDMA_WQE_ALIGNMENT_UNIT_SIZE 32

#define COMP_ENTRY_SIZE 64
#define MAX_TX_WQE_SIZE 512
#define MAX_RX_WQE_SIZE 256

/* Values from the GDMA specification document, WQE format description */
#define INLINE_OOB_SMALL_SIZE_IN_BYTES 8
#define INLINE_OOB_LARGE_SIZE_IN_BYTES 24

#define NOT_USING_CLIENT_DATA_UNIT 0

enum gdma_queue_types {
	gdma_queue_type_invalid = 0,
	gdma_queue_send,
	gdma_queue_receive,
	gdma_queue_completion,
	gdma_queue_event,
	gdma_queue_type_max = 16,
	/*Room for expansion */

	/* This enum can be expanded to add more queue types but
	 * it's expected to be done in a contiguous manner.
	 * Failing that will result in unexpected behavior.
	 */
};

#define WORK_QUEUE_NUMBER_BASE_BITS 10

struct gdma_header {
	/* size of the entire gdma structure, including the entire length of
	 * the struct that is formed by extending other gdma struct. i.e.
	 * GDMA_BASE_SPEC extends gdma_header, GDMA_EVENT_QUEUE_SPEC extends
	 * GDMA_BASE_SPEC, StructSize for GDMA_EVENT_QUEUE_SPEC will be size of
	 * GDMA_EVENT_QUEUE_SPEC which includes size of GDMA_BASE_SPEC and size
	 * of gdma_header.
	 * Above example is for illustration purpose and is not in code
	 */
	size_t struct_size;
};

/* The following macros are from GDMA SPEC 3.6, "Table 2: CQE data structure"
 * and "Table 4: Event Queue Entry (EQE) data format"
 */
#define GDMA_COMP_DATA_SIZE 0x3C /* Must be a multiple of 4 */
#define GDMA_COMP_DATA_SIZE_IN_UINT32 (GDMA_COMP_DATA_SIZE / 4)

#define COMPLETION_QUEUE_ENTRY_WORK_QUEUE_INDEX 0
#define COMPLETION_QUEUE_ENTRY_WORK_QUEUE_SIZE 24
#define COMPLETION_QUEUE_ENTRY_SEND_WORK_QUEUE_INDEX 24
#define COMPLETION_QUEUE_ENTRY_SEND_WORK_QUEUE_SIZE 1
#define COMPLETION_QUEUE_ENTRY_OWNER_BITS_INDEX 29
#define COMPLETION_QUEUE_ENTRY_OWNER_BITS_SIZE 3

#define COMPLETION_QUEUE_OWNER_MASK \
	((1 << (COMPLETION_QUEUE_ENTRY_OWNER_BITS_SIZE)) - 1)

struct gdma_comp {
	struct gdma_header gdma_header;

	/* Filled by GDMA core */
	uint32_t completion_data[GDMA_COMP_DATA_SIZE_IN_UINT32];

	/* Filled by GDMA core */
	uint32_t work_queue_number;

	/* Filled by GDMA core */
	bool send_work_queue;
};

struct gdma_hardware_completion_entry {
	char dma_client_data[GDMA_COMP_DATA_SIZE];
	union {
		uint32_t work_queue_owner_bits;
		struct {
			uint32_t wq_num		: 24;
			uint32_t is_sq		: 1;
			uint32_t reserved	: 4;
			uint32_t owner_bits	: 3;
		};
	};
}; /* HW DATA */

struct gdma_posted_wqe_info {
	struct gdma_header gdma_header;

	/* size of the written wqe in basic units (32B), filled by GDMA core.
	 * Use this value to progress the work queue after the wqe is processed
	 * by hardware.
	 */
	uint32_t wqe_size_in_bu;

	/* At the time of writing the wqe to the work queue, the offset in the
	 * work queue buffer where by the wqe will be written. Each unit
	 * represents 32B of buffer space.
	 */
	uint32_t wqe_index;

	/* Unmasked offset in the queue to which the WQE was written.
	 * In 32 byte units.
	 */
	uint32_t unmasked_queue_offset;
};

struct gdma_sgl_element {
	uint64_t address;
	uint32_t memory_key;
	uint32_t size;
};

#define MAX_SGL_ENTRIES_FOR_TRANSMIT 30

struct one_sgl {
	struct gdma_sgl_element gdma_sgl[MAX_SGL_ENTRIES_FOR_TRANSMIT];
};

struct gdma_work_request {
	struct gdma_header gdma_header;
	struct gdma_sgl_element *sgl;
	uint32_t num_sgl_elements;
	uint32_t inline_oob_size_in_bytes;
	void *inline_oob_data;
	uint32_t flags; /* From _gdma_work_request_FLAGS */
	uint32_t client_data_unit; /* For LSO, this is the MTU of the data */
};

enum mana_cqe_type {
	CQE_INVALID                     = 0,
};

struct mana_cqe_header {
	uint32_t cqe_type    : 6;
	uint32_t client_type : 2;
	uint32_t vendor_err  : 24;
}; /* HW DATA */

/* NDIS HASH Types */
#define BIT(nr)		(1 << (nr))
#define NDIS_HASH_IPV4          BIT(0)
#define NDIS_HASH_TCP_IPV4      BIT(1)
#define NDIS_HASH_UDP_IPV4      BIT(2)
#define NDIS_HASH_IPV6          BIT(3)
#define NDIS_HASH_TCP_IPV6      BIT(4)
#define NDIS_HASH_UDP_IPV6      BIT(5)
#define NDIS_HASH_IPV6_EX       BIT(6)
#define NDIS_HASH_TCP_IPV6_EX   BIT(7)
#define NDIS_HASH_UDP_IPV6_EX   BIT(8)

#define MANA_HASH_L3 (NDIS_HASH_IPV4 | NDIS_HASH_IPV6 | NDIS_HASH_IPV6_EX)
#define MANA_HASH_L4                                                         \
	(NDIS_HASH_TCP_IPV4 | NDIS_HASH_UDP_IPV4 | NDIS_HASH_TCP_IPV6 |      \
	 NDIS_HASH_UDP_IPV6 | NDIS_HASH_TCP_IPV6_EX | NDIS_HASH_UDP_IPV6_EX)

struct gdma_wqe_dma_oob {
	uint32_t reserved:24;
	uint32_t last_v_bytes:8;
	union {
		uint32_t flags;
		struct {
			uint32_t num_sgl_entries:8;
			uint32_t inline_client_oob_size_in_dwords:3;
			uint32_t client_oob_in_sgl:1;
			uint32_t consume_credit:1;
			uint32_t fence:1;
			uint32_t reserved1:2;
			uint32_t client_data_unit:14;
			uint32_t check_sn:1;
			uint32_t sgl_direct:1;
		};
	};
};

struct mana_mr_cache {
	uint32_t	lkey;
	uintptr_t	addr;
	size_t		len;
	void		*verb_obj;
};

#define MANA_MR_BTREE_CACHE_N	512
struct mana_mr_btree {
	uint16_t	len;	/* Used entries */
	uint16_t	size;	/* Total entries */
	int		overflow;
	int		socket;
	struct mana_mr_cache *table;
};

struct mana_process_priv {
	void *db_page;
};

struct mana_priv {
	struct rte_eth_dev_data *dev_data;
	struct mana_process_priv *process_priv;
	int num_queues;

	/* DPDK port */
	uint16_t port_id;

	/* IB device port */
	uint8_t dev_port;

	struct ibv_context *ib_ctx;
	struct ibv_pd *ib_pd;
	struct ibv_pd *ib_parent_pd;
	struct ibv_rwq_ind_table *ind_table;
	uint8_t ind_table_key[40];
	struct ibv_qp *rwq_qp;
	void *db_page;
	struct rte_eth_rss_conf rss_conf;
	struct rte_intr_handle *intr_handle;
	int max_rx_queues;
	int max_tx_queues;
	int max_rx_desc;
	int max_tx_desc;
	int max_send_sge;
	int max_recv_sge;
	int max_mr;
	uint64_t max_mr_size;
	struct mana_mr_btree mr_btree;
	rte_spinlock_t	mr_btree_lock;
};

struct mana_txq_desc {
	struct rte_mbuf *pkt;
	uint32_t wqe_size_in_bu;
};

struct mana_rxq_desc {
	struct rte_mbuf *pkt;
	uint32_t wqe_size_in_bu;
};

struct mana_gdma_queue {
	void *buffer;
	uint32_t count;	/* in entries */
	uint32_t size;	/* in bytes */
	uint32_t id;
	uint32_t head;
	uint32_t tail;
};

struct mana_stats {
	uint64_t packets;
	uint64_t bytes;
	uint64_t errors;
	uint64_t nombuf;
};

#define MANA_MR_BTREE_PER_QUEUE_N	64
struct mana_txq {
	struct mana_priv *priv;
	uint32_t num_desc;
	struct ibv_cq *cq;
	struct ibv_qp *qp;

	struct mana_gdma_queue gdma_sq;
	struct mana_gdma_queue gdma_cq;

	uint32_t tx_vp_offset;

	/* For storing pending requests */
	struct mana_txq_desc *desc_ring;

	/* desc_ring_head is where we put pending requests to ring,
	 * completion pull off desc_ring_tail
	 */
	uint32_t desc_ring_head, desc_ring_tail;

	struct mana_stats stats;
	struct mana_mr_btree mr_btree;
	unsigned int socket;
};

struct mana_rxq {
	struct mana_priv *priv;
	uint32_t num_desc;
	struct rte_mempool *mp;
	struct ibv_cq *cq;
	struct ibv_wq *wq;

	/* For storing pending requests */
	struct mana_rxq_desc *desc_ring;

	/* desc_ring_head is where we put pending requests to ring,
	 * completion pull off desc_ring_tail
	 */
	uint32_t desc_ring_head, desc_ring_tail;

	struct mana_gdma_queue gdma_rq;
	struct mana_gdma_queue gdma_cq;

	struct mana_stats stats;
	struct mana_mr_btree mr_btree;

	unsigned int socket;
};

extern int mana_logtype_driver;
extern int mana_logtype_init;

#define DRV_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, mana_logtype_driver, "%s(): " fmt "\n", \
		__func__, ## args)

#define PMD_INIT_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, mana_logtype_init, "%s(): " fmt "\n",\
		__func__, ## args)

#define PMD_INIT_FUNC_TRACE() PMD_INIT_LOG(DEBUG, " >>")

int mana_ring_doorbell(void *db_page, enum gdma_queue_types queue_type,
		       uint32_t queue_id, uint32_t tail);

int gdma_post_work_request(struct mana_gdma_queue *queue,
			   struct gdma_work_request *work_req,
			   struct gdma_posted_wqe_info *wqe_info);
uint8_t *gdma_get_wqe_pointer(struct mana_gdma_queue *queue);

uint16_t mana_rx_burst_removed(void *dpdk_rxq, struct rte_mbuf **pkts,
			       uint16_t pkts_n);

uint16_t mana_tx_burst_removed(void *dpdk_rxq, struct rte_mbuf **pkts,
			       uint16_t pkts_n);

int gdma_poll_completion_queue(struct mana_gdma_queue *cq,
			       struct gdma_comp *comp);

int mana_start_tx_queues(struct rte_eth_dev *dev);

int mana_stop_tx_queues(struct rte_eth_dev *dev);

struct mana_mr_cache *mana_find_pmd_mr(struct mana_mr_btree *local_tree,
				       struct mana_priv *priv,
				       struct rte_mbuf *mbuf);
int mana_new_pmd_mr(struct mana_mr_btree *local_tree, struct mana_priv *priv,
		    struct rte_mempool *pool);
void mana_remove_all_mr(struct mana_priv *priv);
void mana_del_pmd_mr(struct mana_mr_cache *mr);

void mana_mempool_chunk_cb(struct rte_mempool *mp, void *opaque,
			   struct rte_mempool_memhdr *memhdr, unsigned int idx);

struct mana_mr_cache *mana_mr_btree_lookup(struct mana_mr_btree *bt,
					   uint16_t *idx,
					   uintptr_t addr, size_t len);
int mana_mr_btree_insert(struct mana_mr_btree *bt, struct mana_mr_cache *entry);
int mana_mr_btree_init(struct mana_mr_btree *bt, int n, int socket);
void mana_mr_btree_free(struct mana_mr_btree *bt);

/** Request timeout for IPC. */
#define MANA_MP_REQ_TIMEOUT_SEC 5

/* Request types for IPC. */
enum mana_mp_req_type {
	MANA_MP_REQ_VERBS_CMD_FD = 1,
	MANA_MP_REQ_CREATE_MR,
	MANA_MP_REQ_START_RXTX,
	MANA_MP_REQ_STOP_RXTX,
};

/* Pameters for IPC. */
struct mana_mp_param {
	enum mana_mp_req_type type;
	int port_id;
	int result;

	/* MANA_MP_REQ_CREATE_MR */
	uintptr_t addr;
	uint32_t len;
};

#define MANA_MP_NAME	"net_mana_mp"
int mana_mp_init_primary(void);
int mana_mp_init_secondary(void);
void mana_mp_uninit_primary(void);
void mana_mp_uninit_secondary(void);
int mana_mp_req_verbs_cmd_fd(struct rte_eth_dev *dev);
int mana_mp_req_mr_create(struct mana_priv *priv, uintptr_t addr, uint32_t len);

void mana_mp_req_on_rxtx(struct rte_eth_dev *dev, enum mana_mp_req_type type);

void *mana_alloc_verbs_buf(size_t size, void *data);
void mana_free_verbs_buf(void *ptr, void *data __rte_unused);

#endif

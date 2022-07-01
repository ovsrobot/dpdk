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
	int port_id;

	/* IB device port */
	int dev_port;

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
	rte_rwlock_t	mr_list_lock;
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

uint16_t mana_rx_burst_removed(void *dpdk_rxq, struct rte_mbuf **pkts,
			       uint16_t pkts_n);

uint16_t mana_tx_burst_removed(void *dpdk_rxq, struct rte_mbuf **pkts,
			       uint16_t pkts_n);

struct mana_mr_cache *find_pmd_mr(struct mana_mr_btree *local_tree,
				  struct mana_priv *priv,
				  struct rte_mbuf *mbuf);
int new_pmd_mr(struct mana_mr_btree *local_tree, struct mana_priv *priv,
	       struct rte_mempool *pool);
void remove_all_mr(struct mana_priv *priv);
void del_pmd_mr(struct mana_mr_cache *mr);

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

#endif

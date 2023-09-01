/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#include <rte_common.h>
#include <rte_io.h>
#include <ethdev_pci.h>

#include "sssnic_log.h"
#include "sssnic_ethdev.h"
#include "sssnic_ethdev_tx.h"
#include "base/sssnic_hw.h"
#include "base/sssnic_workq.h"
#include "base/sssnic_api.h"
#include "base/sssnic_misc.h"

/* Hardware format of tx desc */
struct sssnic_ethdev_tx_desc {
	union {
		uint32_t dw0;
		struct {
			/* length of the first tx seg data */
			uint32_t data_len : 18;
			uint32_t dw0_resvd0 : 1;
			/* number of tx segments in tx entry */
			uint32_t num_segs : 8;
			/* offload desc enable */
			uint32_t offload_en : 1;
			/* data format, use SGL if 0 else inline */
			uint32_t data_fmt : 1;
			/* DN, always set 0  */
			uint32_t dw0_resvd1 : 1;
			/* refer sssnic_ethdev_txq_entry_type */
			uint32_t entry_type : 1;
			uint32_t owner : 1;
		};
	};
	union {
		uint32_t dw1;
		struct {
			uint32_t pkt_type : 2;
			uint32_t payload_off : 8;
			/* UFO, not used, always set 0 */
			uint32_t dw1_resvd0 : 1;
			uint32_t tso_en : 1;
			/* TCP/UDP checksum offload enable flag */
			uint32_t csum_en : 1;
			uint32_t mss : 14;
			uint32_t sctp_crc_en : 1;
			/* set 1 if entry type is not compact else set 0 */
			uint32_t uc : 1;
			/* PRI, not used, always set 0  */
			uint32_t dw1_resvd1 : 3;
		};
	};
	union {
		uint32_t dw2;
		/* high 32bit of  DMA address of the first tx seg data */
		uint32_t data_addr_hi;
	};
	union {
		uint32_t dw3;
		/* low 32bit of DMA address of the first tx seg data */
		uint32_t data_addr_lo;
	};
};

/* Hardware format of tx offload */
struct sssnic_ethdev_tx_offload {
	union {
		uint32_t dw0;
		struct {
			uint32_t dw0_resvd0 : 19;
			/* indicate a tunnel packet or normal packet */
			uint32_t tunnel_flag : 1;
			uint32_t dw0_resvd1 : 2;
			/* not used, always set 0 */
			uint32_t esp_next_proto : 2;
			/* indicate inner L4 csum offload enable */
			uint32_t inner_l4_csum_en : 1;
			/* indicate inner L3 csum offload enable */
			uint32_t inner_l3_csum_en : 1;
			/* indicate inner L4 header with pseudo csum */
			uint32_t inner_l4_pseudo_csum : 1;
			/* indicate outer L4 csum offload enable*/
			uint32_t l4_csum_en : 1;
			/* indicate outer L3 csum offload enable*/
			uint32_t l3_csum_en : 1;
			/* indicate outer L4 header with pseudo csum */
			uint32_t l4_pseudo_csum : 1;
			/* indicate ESP offload */
			uint32_t esp_en : 1;
			/* indicate IPSEC offload */
			uint32_t ipsec_en : 1;
		};
	};
	uint32_t dw1;
	uint32_t dw2;
	union {
		uint32_t dw3;
		struct {
			uint32_t vlan_tag : 16;
			/* Always set 0 */
			uint32_t vlan_type : 3;
			/* indicate VLAN offload enable */
			uint32_t vlan_en : 1;
			uint32_t dw3_resvd0 : 12;
		};
	};
};

/* Hardware format of tx seg */
struct sssnic_ethdev_tx_seg {
	uint32_t len;
	uint32_t resvd;
	uint32_t buf_hi_addr;
	uint32_t buf_lo_addr;
};

/* hardware format of txq doobell register*/
struct sssnic_ethdev_txq_doorbell {
	union {
		uint64_t u64;
		struct {
			union {
				uint32_t dword0;
				struct {
					uint32_t qid : 13;
					uint32_t resvd0 : 9;
					uint32_t nf : 1;
					uint32_t cf : 1;
					uint32_t cos : 3;
					uint32_t service : 5;
				};
			};
			union {
				uint32_t dword1;
				struct {
					uint32_t pi_hi : 8;
					uint32_t resvd1 : 24;
				};
			};
		};
	};
};

struct sssnic_ethdev_tx_entry {
	struct rte_mbuf *pktmbuf;
	uint16_t num_workq_entries;
};

struct sssnic_ethdev_txq {
	struct rte_eth_dev *ethdev;
	struct sssnic_workq *workq;
	const struct rte_memzone *ci_mz;
	volatile uint16_t *hw_ci_addr;
	uint8_t *doorbell;
	struct sssnic_ethdev_tx_entry *txe;
	struct sssnic_ethdev_txq_stats stats;
	uint16_t port;
	uint16_t qid;
	uint16_t depth;
	uint16_t idx_mask;
	uint16_t tx_free_thresh;
	uint8_t owner;
	uint8_t cos;
} __rte_cache_aligned;

enum sssnic_ethdev_txq_entry_type {
	SSSNIC_ETHDEV_TXQ_ENTRY_COMPACT = 0,
	SSSNIC_ETHDEV_TXQ_ENTRY_EXTEND = 1,
};

struct sssnic_ethdev_tx_info {
	/* offload enable flag */
	uint16_t offload_en;
	/*l4 payload offset*/
	uint16_t payload_off;
	/* number of txq entries */
	uint16_t nb_entries;
	/* number of tx segs */
	uint16_t nb_segs;
};

#define SSSNIC_ETHDEV_TXQ_ENTRY_SZ_BITS 4
#define SSSNIC_ETHDEV_TXQ_ENTRY_SZ (RTE_BIT32(SSSNIC_ETHDEV_TXQ_ENTRY_SZ_BITS))

#define SSSNIC_ETHDEV_TX_HW_CI_SIZE 64

/* Doorbell offset 4096 */
#define SSSNIC_ETHDEV_TXQ_DB_OFFSET 0x1000

#define SSSNIC_ETHDEV_TX_CI_DEF_COALESCING_TIME 16
#define SSSNIC_ETHDEV_TX_CI_DEF_PENDING_TIME 4

#define SSSNIC_ETHDEV_TX_CSUM_OFFLOAD_MASK                                     \
	(RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_TCP_CKSUM |                    \
		RTE_MBUF_F_TX_UDP_CKSUM | RTE_MBUF_F_TX_SCTP_CKSUM |           \
		RTE_MBUF_F_TX_OUTER_IP_CKSUM | RTE_MBUF_F_TX_TCP_SEG)

#define SSSNIC_ETHDEV_TX_OFFLOAD_MASK                                          \
	(RTE_MBUF_F_TX_VLAN | SSSNIC_ETHDEV_TX_CSUM_OFFLOAD_MASK)

#define SSSNIC_ETHDEV_TX_MAX_NUM_SEGS 38
#define SSSNIC_ETHDEV_TX_MAX_SEG_SIZE 65535
#define SSSNIC_ETHDEV_TX_MAX_PAYLOAD_OFF 221
#define SSSNIC_ETHDEV_TX_DEF_MSS 0x3e00
#define SSSNIC_ETHDEV_TX_MIN_MSS 0x50
#define SSSNIC_ETHDEV_TX_COMPACT_SEG_MAX_SIZE 0x3fff

#define SSSNIC_ETHDEV_TXQ_DESC_ENTRY(txq, idx)                                 \
	(SSSNIC_WORKQ_ENTRY_CAST((txq)->workq, idx,                            \
		struct sssnic_ethdev_tx_desc))

#define SSSNIC_ETHDEV_TXQ_OFFLOAD_ENTRY(txq, idx)                              \
	SSSNIC_WORKQ_ENTRY_CAST((txq)->workq, idx,                             \
		struct sssnic_ethdev_tx_offload)

#define SSSNIC_ETHDEV_TXQ_SEG_ENTRY(txq, idx)                                  \
	SSSNIC_WORKQ_ENTRY_CAST((txq)->workq, idx, struct sssnic_ethdev_tx_seg)

static inline uint16_t
sssnic_ethdev_txq_num_used_entries(struct sssnic_ethdev_txq *txq)
{
	return sssnic_workq_num_used_entries(txq->workq);
}

static inline uint16_t
sssnic_ethdev_txq_num_idle_entries(struct sssnic_ethdev_txq *txq)
{
	return sssnic_workq_num_idle_entries(txq->workq);
}

static inline uint16_t
sssnic_ethdev_txq_ci_get(struct sssnic_ethdev_txq *txq)
{
	return sssnic_workq_ci_get(txq->workq);
}

static inline int
sssnic_ethdev_txq_pi_get(struct sssnic_ethdev_txq *txq)
{
	return sssnic_workq_pi_get(txq->workq);
}

static inline uint16_t
sssnic_ethdev_txq_hw_ci_get(struct sssnic_ethdev_txq *txq)
{
	return *txq->hw_ci_addr & txq->idx_mask;
}

static inline void
sssnic_ethdev_txq_consume(struct sssnic_ethdev_txq *txq, uint16_t num_entries)
{
	sssnic_workq_consume_fast(txq->workq, num_entries);
}

static inline void
sssnic_ethdev_txq_produce(struct sssnic_ethdev_txq *txq, uint16_t num_entries)
{
	sssnic_workq_produce_fast(txq->workq, num_entries);
}

int
sssnic_ethdev_tx_queue_setup(struct rte_eth_dev *ethdev, uint16_t tx_queue_id,
	uint16_t nb_tx_desc, unsigned int socket_id,
	const struct rte_eth_txconf *tx_conf)
{
	int ret;
	struct sssnic_hw *hw;
	struct sssnic_ethdev_txq *txq;
	uint16_t q_depth;
	uint16_t tx_free_thresh;
	char m_name[RTE_MEMZONE_NAMESIZE];

	hw = SSSNIC_ETHDEV_TO_HW(ethdev);

	q_depth = nb_tx_desc;
	/* Adjust q_depth to power of 2 */
	if (!rte_is_power_of_2(nb_tx_desc)) {
		q_depth = 1 << rte_log2_u32(nb_tx_desc);
		PMD_DRV_LOG(NOTICE,
			"nb_tx_desc(%u) is not power of 2, adjust to %u",
			nb_tx_desc, q_depth);
	}

	if (q_depth > SSSNIC_ETHDEV_MAX_NUM_Q_DESC) {
		PMD_DRV_LOG(ERR, "nb_tx_desc(%u) is out of range(max. %u)",
			q_depth, SSSNIC_ETHDEV_MAX_NUM_Q_DESC);
		return -EINVAL;
	}

	if (tx_conf->tx_free_thresh > 0)
		tx_free_thresh = tx_conf->tx_free_thresh;
	else
		tx_free_thresh = SSSNIC_ETHDEV_DEF_TX_FREE_THRESH;
	if (tx_free_thresh >= q_depth - 1) {
		PMD_DRV_LOG(ERR,
			"tx_free_thresh(%u) must be less than nb_tx_desc(%u)-1",
			tx_free_thresh, q_depth);
		return -EINVAL;
	}

	snprintf(m_name, sizeof(m_name), "sssnic_p%u_sq%u",
		ethdev->data->port_id, tx_queue_id);

	txq = rte_zmalloc_socket(m_name, sizeof(struct sssnic_ethdev_txq),
		RTE_CACHE_LINE_SIZE, (int)socket_id);

	if (txq == NULL) {
		PMD_DRV_LOG(ERR,
			"Failed to allocate memory for sssnic port %u, txq %u",
			ethdev->data->port_id, tx_queue_id);
		return -ENOMEM;
	}

	txq->ethdev = ethdev;
	txq->depth = q_depth;
	txq->port = ethdev->data->port_id;
	txq->qid = tx_queue_id;
	txq->tx_free_thresh = tx_free_thresh;
	txq->idx_mask = q_depth - 1;
	txq->owner = 1;
	txq->doorbell = hw->db_base_addr + SSSNIC_ETHDEV_TXQ_DB_OFFSET;

	snprintf(m_name, sizeof(m_name), "sssnic_p%u_sq%u_wq",
		ethdev->data->port_id, tx_queue_id);

	txq->workq = sssnic_workq_new(m_name, (int)socket_id,
		SSSNIC_ETHDEV_TXQ_ENTRY_SZ, q_depth);
	if (txq->workq == NULL) {
		PMD_DRV_LOG(ERR,
			"Failed to create workq for sssnic port %u, txq %u",
			ethdev->data->port_id, tx_queue_id);
		ret = -ENOMEM;
		goto new_workq_fail;
	}

	txq->ci_mz = rte_eth_dma_zone_reserve(ethdev, "sssnic_txci_mz",
		txq->qid, SSSNIC_ETHDEV_TX_HW_CI_SIZE,
		SSSNIC_ETHDEV_TX_HW_CI_SIZE, (int)socket_id);
	if (txq->ci_mz == NULL) {
		PMD_DRV_LOG(ERR,
			"Failed to alloc DMA memory for tx ci of sssnic port %u rxq %u",
			ethdev->data->port_id, tx_queue_id);
		ret = -ENOMEM;
		goto alloc_ci_mz_fail;
	}
	txq->hw_ci_addr = (volatile uint16_t *)txq->ci_mz->addr;

	snprintf(m_name, sizeof(m_name), "sssnic_p%u_sq%u_txe",
		ethdev->data->port_id, tx_queue_id);
	txq->txe = rte_zmalloc_socket(m_name,
		sizeof(struct sssnic_ethdev_tx_entry) * q_depth,
		RTE_CACHE_LINE_SIZE, (int)socket_id);
	if (txq->txe == NULL) {
		PMD_DRV_LOG(ERR, "Failed to allocate memory for %s", m_name);
		ret = -ENOMEM;
		goto alloc_txe_fail;
	}

	ethdev->data->tx_queues[tx_queue_id] = txq;

	return 0;

alloc_txe_fail:
	rte_memzone_free(txq->ci_mz);
alloc_ci_mz_fail:
	sssnic_workq_destroy(txq->workq);
new_workq_fail:
	rte_free(txq);

	return ret;
}

static void
sssnic_ethdev_txq_pktmbufs_release(struct sssnic_ethdev_txq *txq)
{
	struct sssnic_ethdev_tx_entry *txe;
	uint16_t num_entries;
	uint16_t ci;
	uint16_t i;

	num_entries = sssnic_ethdev_txq_num_used_entries(txq);
	for (i = 0; i < num_entries; i++) {
		ci = sssnic_ethdev_txq_ci_get(txq);
		txe = &txq->txe[ci];
		rte_pktmbuf_free(txe->pktmbuf);
		txe->pktmbuf = NULL;
		sssnic_ethdev_txq_consume(txq, txe->num_workq_entries);
		txe->num_workq_entries = 0;
	}
}

void
sssnic_ethdev_tx_queue_release(struct rte_eth_dev *ethdev, uint16_t queue_id)
{
	struct sssnic_ethdev_txq *txq = ethdev->data->tx_queues[queue_id];

	if (txq == NULL)
		return;

	sssnic_ethdev_txq_pktmbufs_release(txq);
	rte_free(txq->txe);
	rte_memzone_free(txq->ci_mz);
	sssnic_workq_destroy(txq->workq);
	rte_free(txq);
	ethdev->data->tx_queues[queue_id] = NULL;
}

void
sssnic_ethdev_tx_queue_all_release(struct rte_eth_dev *ethdev)
{
	uint16_t qid;

	for (qid = 0; qid < ethdev->data->nb_tx_queues; qid++)
		sssnic_ethdev_tx_queue_release(ethdev, qid);
}

#define SSSNIC_ETHDEV_TX_FREE_BULK 64
static inline int
sssnic_ethdev_txq_pktmbufs_cleanup(struct sssnic_ethdev_txq *txq)
{
	struct sssnic_ethdev_tx_entry *txe;
	struct rte_mbuf *free_pkts[SSSNIC_ETHDEV_TX_FREE_BULK];
	uint16_t num_free_pkts = 0;
	uint16_t hw_ci, ci, id_mask;
	uint16_t count = 0;
	int num_entries;

	ci = sssnic_ethdev_txq_ci_get(txq);
	hw_ci = sssnic_ethdev_txq_hw_ci_get(txq);
	id_mask = txq->idx_mask;
	num_entries = sssnic_ethdev_txq_num_used_entries(txq);

	while (num_entries > 0) {
		txe = &txq->txe[ci];

		/* HW has not consumed enough entries of current packet */
		if (((hw_ci - ci) & id_mask) < txe->num_workq_entries)
			break;

		num_entries -= txe->num_workq_entries;
		count += txe->num_workq_entries;
		ci = (ci + txe->num_workq_entries) & id_mask;

		if (likely(txe->pktmbuf->nb_segs == 1)) {
			struct rte_mbuf *pkt =
				rte_pktmbuf_prefree_seg(txe->pktmbuf);
			txe->pktmbuf = NULL;

			if (unlikely(pkt == NULL))
				continue;

			free_pkts[num_free_pkts++] = pkt;
			if (unlikely(pkt->pool != free_pkts[0]->pool ||
				     num_free_pkts >=
					     SSSNIC_ETHDEV_TX_FREE_BULK)) {
				rte_mempool_put_bulk(free_pkts[0]->pool,
					(void **)free_pkts, num_free_pkts - 1);
				num_free_pkts = 0;
				free_pkts[num_free_pkts++] = pkt;
			}
		} else {
			rte_pktmbuf_free(txe->pktmbuf);
			txe->pktmbuf = NULL;
		}
	}

	if (num_free_pkts > 0)
		rte_mempool_put_bulk(free_pkts[0]->pool, (void **)free_pkts,
			num_free_pkts);

	sssnic_ethdev_txq_consume(txq, count);

	return count;
}

#define SSSNIC_ETHDEV_TXQ_FUSH_TIMEOUT 3000 /* 3 seconds */
static int
sssnic_ethdev_txq_flush(struct sssnic_ethdev_txq *txq)
{
	uint64_t timeout;
	uint16_t used_entries;

	timeout = rte_get_timer_cycles() +
		  rte_get_timer_hz() * SSSNIC_ETHDEV_TXQ_FUSH_TIMEOUT / 1000;

	do {
		sssnic_ethdev_txq_pktmbufs_cleanup(txq);
		used_entries = sssnic_ethdev_txq_num_used_entries(txq);
		if (used_entries == 0)
			return 0;

		rte_delay_us_sleep(1000);
	} while (((long)(rte_get_timer_cycles() - timeout)) < 0);

	PMD_DRV_LOG(ERR, "Flush port:%u txq:%u timeout, used_txq_entries:%u",
		txq->port, txq->qid, sssnic_ethdev_txq_num_used_entries(txq));

	return -ETIMEDOUT;
}

int
sssnic_ethdev_tx_queue_start(struct rte_eth_dev *ethdev, uint16_t queue_id)
{
	struct sssnic_netdev *netdev = SSSNIC_ETHDEV_PRIVATE(ethdev);

	ethdev->data->tx_queue_state[queue_id] = RTE_ETH_QUEUE_STATE_STARTED;
	netdev->num_started_txqs++;

	PMD_DRV_LOG(DEBUG, "port %u txq %u started", ethdev->data->port_id,
		queue_id);

	return 0;
}

int
sssnic_ethdev_tx_queue_stop(struct rte_eth_dev *ethdev, uint16_t queue_id)
{
	int ret;
	struct sssnic_netdev *netdev = SSSNIC_ETHDEV_PRIVATE(ethdev);
	struct sssnic_ethdev_txq *txq = ethdev->data->tx_queues[queue_id];

	ret = sssnic_ethdev_txq_flush(txq);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to flush port %u txq %u",
			ethdev->data->port_id, queue_id);
		return ret;
	}

	ethdev->data->tx_queue_state[queue_id] = RTE_ETH_QUEUE_STATE_STOPPED;
	netdev->num_started_txqs--;

	PMD_DRV_LOG(DEBUG, "port %u txq %u stopped", ethdev->data->port_id,
		queue_id);

	return 0;
}

int
sssnic_ethdev_tx_queue_all_start(struct rte_eth_dev *ethdev)
{
	uint16_t qid;
	uint16_t numq = ethdev->data->nb_tx_queues;

	for (qid = 0; qid < numq; qid++)
		sssnic_ethdev_tx_queue_start(ethdev, qid);

	return 0;
}

void
sssnic_ethdev_tx_queue_all_stop(struct rte_eth_dev *ethdev)
{
	uint16_t qid;
	uint16_t numq = ethdev->data->nb_tx_queues;

	for (qid = 0; qid < numq; qid++)
		sssnic_ethdev_tx_queue_stop(ethdev, qid);
}

static void
sssnic_ethdev_txq_ctx_build(struct sssnic_ethdev_txq *txq,
	struct sssnic_txq_ctx *qctx)
{
	uint64_t pfn;

	/* dw0 */
	qctx->pi = sssnic_ethdev_txq_pi_get(txq);
	qctx->ci = sssnic_ethdev_txq_ci_get(txq);

	/* dw1 */
	qctx->sp = 0;
	qctx->drop = 0;

	/* workq buf phyaddress PFN */
	pfn = SSSNIC_WORKQ_BUF_PHYADDR(txq->workq) >> 12;

	/* dw2 */
	qctx->wq_pfn_hi = SSSNIC_UPPER_32_BITS(pfn);
	qctx->wq_owner = 1;

	/* dw3 */
	qctx->wq_pfn_lo = SSSNIC_LOWER_32_BITS(pfn);

	/* dw4 reserved */

	/* dw5 */
	qctx->drop_on_thd = 0xffff;
	qctx->drop_off_thd = 0;

	/* dw6 */
	qctx->qid = txq->qid;

	/* dw7 */
	qctx->insert_mode = 1;

	/* dw8 */
	qctx->pre_cache_thd = 256;
	qctx->pre_cache_max = 6;
	qctx->pre_cache_min = 1;

	/* dw9 */
	qctx->pre_ci_hi = sssnic_ethdev_txq_ci_get(txq) >> 12;
	qctx->pre_owner = 1;

	/* dw10 */
	qctx->pre_wq_pfn_hi = SSSNIC_UPPER_32_BITS(pfn);
	qctx->pre_ci_lo = sssnic_ethdev_txq_ci_get(txq);

	/* dw11 */
	qctx->pre_wq_pfn_lo = SSSNIC_LOWER_32_BITS(pfn);

	/* dw12,dw13 are reserved */

	/* workq buf block PFN */
	pfn = SSSNIC_WORKQ_BUF_PHYADDR(txq->workq) >> 9;

	/* dw14 */
	qctx->wq_blk_pfn_hi = SSSNIC_UPPER_32_BITS(pfn);

	/* dw15 */
	qctx->wq_blk_pfn_lo = SSSNIC_LOWER_32_BITS(pfn);
}

int
sssnic_ethdev_tx_queues_ctx_init(struct rte_eth_dev *ethdev)
{
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);
	struct sssnic_ethdev_txq *txq;
	struct sssnic_txq_ctx *qctx;
	uint16_t qid, numq;
	int ret;

	numq = ethdev->data->nb_tx_queues;

	qctx = rte_zmalloc(NULL, numq * sizeof(struct sssnic_txq_ctx), 0);
	if (qctx == NULL) {
		PMD_DRV_LOG(ERR, "Failed to alloc memory for txq ctx");
		return -EINVAL;
	}

	for (qid = 0; qid < numq; qid++) {
		txq = ethdev->data->tx_queues[qid];

		/* reset ci and pi */
		sssnic_workq_reset(txq->workq);

		*txq->hw_ci_addr = 0;
		txq->owner = 1;

		sssnic_ethdev_txq_ctx_build(txq, &qctx[qid]);
	}

	ret = sssnic_txq_ctx_set(hw, qctx, 0, numq);
	rte_free(qctx);

	return ret;
}

int
sssnic_ethdev_tx_offload_ctx_reset(struct rte_eth_dev *ethdev)
{
	return sssnic_tx_offload_ctx_reset(SSSNIC_ETHDEV_TO_HW(ethdev));
}

uint16_t
sssnic_ethdev_tx_queue_depth_get(struct rte_eth_dev *ethdev, uint16_t qid)
{
	struct sssnic_ethdev_txq *txq;

	if (qid >= ethdev->data->nb_tx_queues)
		return 0;

	txq = ethdev->data->tx_queues[qid];

	return txq->depth;
}

int
sssnic_ethdev_tx_ci_attr_init(struct rte_eth_dev *ethdev)
{
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);
	struct sssnic_ethdev_txq *txq;
	uint16_t i;
	int ret;

	for (i = 0; i < ethdev->data->nb_tx_queues; i++) {
		txq = ethdev->data->tx_queues[i];

		ret = sssnic_port_tx_ci_attr_set(hw, i,
			SSSNIC_ETHDEV_TX_CI_DEF_PENDING_TIME,
			SSSNIC_ETHDEV_TX_CI_DEF_COALESCING_TIME,
			txq->ci_mz->iova);

		if (ret != 0) {
			PMD_DRV_LOG(ERR,
				"Failed to initialize tx ci attributes of queue %u",
				i);
			return ret;
		}
	}

	return 0;
}

int
sssnic_ethdev_tx_max_size_set(struct rte_eth_dev *ethdev, uint16_t size)
{
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);
	int ret;

	ret = sssnic_tx_max_size_set(hw, size);
	if (ret != 0)
		return ret;

	PMD_DRV_LOG(INFO, "Set tx_max_size to %u", size);

	return 0;
};

int
sssnic_ethdev_tx_queue_stats_get(struct rte_eth_dev *ethdev, uint16_t qid,
	struct sssnic_ethdev_txq_stats *stats)
{
	struct sssnic_ethdev_txq *txq;

	if (qid >= ethdev->data->nb_tx_queues) {
		PMD_DRV_LOG(ERR,
			"Invalid qid, qid must less than nb_tx_queues(%u)",
			ethdev->data->nb_tx_queues);
		return -EINVAL;
	}

	txq = ethdev->data->tx_queues[qid];
	memcpy(stats, &txq->stats, sizeof(txq->stats));

	return 0;
}

void
sssnic_ethdev_tx_queue_stats_clear(struct rte_eth_dev *ethdev, uint16_t qid)
{
	struct sssnic_ethdev_txq *txq;
	uint64_t *stat;
	int i, len;

	len = sizeof(struct sssnic_ethdev_txq_stats) / sizeof(uint64_t);

	if (qid < ethdev->data->nb_tx_queues) {
		txq = ethdev->data->tx_queues[qid];
		stat = (uint64_t *)&txq->stats;
		for (i = 0; i < len; i++)
			*(stat++) = 0;
	}
}

static inline uint16_t
sssnic_ethdev_tx_payload_calc(struct rte_mbuf *tx_mbuf)
{
	if ((tx_mbuf->ol_flags & RTE_MBUF_F_TX_TUNNEL_MASK) != 0) {
		uint64_t mask = RTE_MBUF_F_TX_OUTER_IPV6 |
				RTE_MBUF_F_TX_OUTER_IP_CKSUM |
				RTE_MBUF_F_TX_TCP_SEG;

		if ((tx_mbuf->ol_flags & mask) != 0)
			return tx_mbuf->outer_l2_len + tx_mbuf->outer_l3_len +
			       tx_mbuf->l2_len + tx_mbuf->l3_len +
			       tx_mbuf->l4_len;
	}

	return tx_mbuf->l2_len + tx_mbuf->l3_len + tx_mbuf->l4_len;
}

static inline int
sssnic_ethdev_tx_offload_check(struct rte_mbuf *tx_mbuf,
	struct sssnic_ethdev_tx_info *tx_info)
{
	uint64_t ol_flags = tx_mbuf->ol_flags;

	if ((ol_flags & SSSNIC_ETHDEV_TX_OFFLOAD_MASK) == 0) {
		tx_info->offload_en = 0;
		return 0;
	}

#ifdef RTE_LIBRTE_ETHDEV_DEBUG
	if (rte_validate_tx_offload(tx_mbuf) != 0) {
		SSSNIC_TX_LOG(ERR, "Bad tx mbuf offload flags: %" PRIx64, ol_flags);
		return -EINVAL;
	}
#endif

	tx_info->offload_en = 1;

	if (unlikely(((ol_flags & RTE_MBUF_F_TX_TUNNEL_MASK) != 0) &&
		     ((ol_flags & RTE_MBUF_F_TX_TUNNEL_VXLAN) == 0))) {
		SSSNIC_TX_LOG(ERR, "Only support VXLAN offload");
		return -EINVAL;
	}

	if (unlikely((ol_flags & RTE_MBUF_F_TX_TCP_SEG) != 0)) {
		uint16_t off = sssnic_ethdev_tx_payload_calc(tx_mbuf);
		if (unlikely((off >> 1) > SSSNIC_ETHDEV_TX_MAX_PAYLOAD_OFF)) {
			SSSNIC_TX_LOG(ERR, "Bad tx payload offset: %u", off);
			return -EINVAL;
		}
		tx_info->payload_off = off;
	}

	return 0;
}

static inline int
sssnic_ethdev_tx_num_segs_calc(struct rte_mbuf *tx_mbuf,
	struct sssnic_ethdev_tx_info *tx_info)
{
	uint16_t nb_segs = tx_mbuf->nb_segs;

	if (tx_info->offload_en == 0) {
		/* offload not enabled, need no offload entry,
		 * then txq entries equals tx_segs
		 */
		tx_info->nb_entries = nb_segs;
	} else {
		if (unlikely(nb_segs > SSSNIC_ETHDEV_TX_MAX_NUM_SEGS)) {
			SSSNIC_TX_LOG(ERR, "Too many segment for tso");
			return -EINVAL;
		}

		/*offload enabled, need offload entry,
		 * then txq entries equals tx_segs + 1
		 */
		tx_info->nb_entries = nb_segs + 1;
	}

	tx_info->nb_segs = nb_segs;
	;

	return 0;
}

static inline int
sssnic_ethdev_tx_info_init(struct sssnic_ethdev_txq *txq,
	struct rte_mbuf *tx_mbuf, struct sssnic_ethdev_tx_info *tx_info)
{
	int ret;

	/* check tx offload valid and enabled */
	ret = sssnic_ethdev_tx_offload_check(tx_mbuf, tx_info);
	if (unlikely(ret != 0)) {
		txq->stats.offload_errors++;
		return ret;
	}

	/* Calculate how many num tx segs and num of txq entries are required*/
	ret = sssnic_ethdev_tx_num_segs_calc(tx_mbuf, tx_info);
	if (unlikely(ret != 0)) {
		txq->stats.too_many_segs++;
		return ret;
	}

	return 0;
}

static inline void
sssnic_ethdev_tx_offload_setup(struct sssnic_ethdev_txq *txq,
	struct sssnic_ethdev_tx_desc *tx_desc, uint16_t pi,
	struct rte_mbuf *tx_mbuf, struct sssnic_ethdev_tx_info *tx_info)
{
	struct sssnic_ethdev_tx_offload *offload;

	/* reset offload settings */
	offload = SSSNIC_ETHDEV_TXQ_OFFLOAD_ENTRY(txq, pi);
	offload->dw0 = 0;
	offload->dw1 = 0;
	offload->dw2 = 0;
	offload->dw3 = 0;

	if (unlikely((tx_mbuf->ol_flags & RTE_MBUF_F_TX_VLAN) != 0)) {
		offload->vlan_en = 1;
		offload->vlan_tag = tx_mbuf->vlan_tci;
	}

	if ((tx_mbuf->ol_flags & SSSNIC_ETHDEV_TX_CSUM_OFFLOAD_MASK) == 0)
		return;

	if ((tx_mbuf->ol_flags & RTE_MBUF_F_TX_TCP_SEG) != 0) {
		offload->inner_l3_csum_en = 1;
		offload->inner_l4_csum_en = 1;

		tx_desc->tso_en = 1;
		tx_desc->payload_off = tx_info->payload_off >> 1;
		tx_desc->mss = tx_mbuf->tso_segsz;
	} else {
		if ((tx_mbuf->ol_flags & RTE_MBUF_F_TX_IP_CKSUM) != 0)
			offload->inner_l3_csum_en = 1;

		if ((tx_mbuf->ol_flags & RTE_MBUF_F_TX_L4_MASK) != 0)
			offload->inner_l4_csum_en = 1;
	}

	if (tx_mbuf->ol_flags & RTE_MBUF_F_TX_TUNNEL_VXLAN)
		offload->tunnel_flag = 1;

	if (tx_mbuf->ol_flags & RTE_MBUF_F_TX_OUTER_IP_CKSUM)
		offload->l3_csum_en = 1;
}

static inline int
sssnic_ethdev_tx_segs_setup(struct sssnic_ethdev_txq *txq,
	struct sssnic_ethdev_tx_desc *tx_desc, uint16_t pi,
	struct rte_mbuf *tx_mbuf, struct sssnic_ethdev_tx_info *tx_info)
{
	struct sssnic_ethdev_tx_seg *tx_seg;
	uint16_t idx_mask = txq->idx_mask;
	uint16_t nb_segs, i;
	rte_iova_t seg_iova;

	nb_segs = tx_info->nb_segs;

	/* first segment info fill into tx desc entry*/
	seg_iova = rte_mbuf_data_iova(tx_mbuf);
	tx_desc->data_addr_hi = SSSNIC_UPPER_32_BITS(seg_iova);
	tx_desc->data_addr_lo = SSSNIC_LOWER_32_BITS(seg_iova);
	tx_desc->data_len = tx_mbuf->data_len;

	/* next tx segment */
	tx_mbuf = tx_mbuf->next;

	for (i = 1; i < nb_segs; i++) {
		if (unlikely(tx_mbuf == NULL)) {
			txq->stats.null_segs++;
			SSSNIC_TX_LOG(DEBUG, "Tx mbuf segment is NULL");
			return -EINVAL;
		}

		if (unlikely(tx_mbuf->data_len == 0)) {
			txq->stats.zero_len_segs++;
			SSSNIC_TX_LOG(DEBUG,
				"Length of tx mbuf segment is zero");
			return -EINVAL;
		}

		seg_iova = rte_mbuf_data_iova(tx_mbuf);
		tx_seg = SSSNIC_ETHDEV_TXQ_SEG_ENTRY(txq, pi);
		tx_seg->buf_hi_addr = SSSNIC_UPPER_32_BITS(seg_iova);
		tx_seg->buf_lo_addr = SSSNIC_LOWER_32_BITS(seg_iova);
		tx_seg->len = tx_mbuf->data_len;
		tx_seg->resvd = 0;

		pi = (pi + 1) & idx_mask;
		tx_mbuf = tx_mbuf->next;
	}

	return 0;
}

static inline int
sssnic_ethdev_txq_entries_setup(struct sssnic_ethdev_txq *txq, uint16_t pi,
	struct rte_mbuf *tx_mbuf, struct sssnic_ethdev_tx_info *tx_info)
{
	struct sssnic_ethdev_tx_desc *tx_desc;
	uint16_t idx_mask = txq->idx_mask;

	/* reset tx desc entry*/
	tx_desc = SSSNIC_ETHDEV_TXQ_DESC_ENTRY(txq, pi);
	tx_desc->dw0 = 0;
	tx_desc->dw1 = 0;
	tx_desc->dw2 = 0;
	tx_desc->dw3 = 0;
	tx_desc->owner = txq->owner;
	tx_desc->uc = 1;

	if (tx_info->offload_en != 0) {
		/* next_pi points to tx offload entry */
		pi = (pi + 1) & idx_mask;
		sssnic_ethdev_tx_offload_setup(txq, tx_desc, pi, tx_mbuf,
			tx_info);

		tx_desc->entry_type = SSSNIC_ETHDEV_TXQ_ENTRY_EXTEND;
		tx_desc->offload_en = 1;
		tx_desc->num_segs = tx_info->nb_segs;

		if (tx_desc->mss == 0)
			tx_desc->mss = SSSNIC_ETHDEV_TX_DEF_MSS;
		else if (tx_desc->mss < SSSNIC_ETHDEV_TX_MIN_MSS)
			tx_desc->mss = SSSNIC_ETHDEV_TX_MIN_MSS;

	} else {
		/*
		 * if offload disabled and nb_tx_seg > 0 use extend tx entry
		 * else use default compact entry
		 */
		if (tx_info->nb_segs > 1) {
			tx_desc->num_segs = tx_info->nb_segs;
			tx_desc->entry_type = SSSNIC_ETHDEV_TXQ_ENTRY_EXTEND;
		} else {
			if (unlikely(tx_mbuf->data_len >
				     SSSNIC_ETHDEV_TX_COMPACT_SEG_MAX_SIZE)) {
				txq->stats.too_large_pkts++;
				SSSNIC_TX_LOG(ERR,
					"Too large pakcet (size=%u) for compact tx entry",
					tx_mbuf->data_len);
				return -EINVAL;
			}
		}
	}

	/* get next_pi that points to tx seg entry */
	pi = (pi + 1) & idx_mask;

	return sssnic_ethdev_tx_segs_setup(txq, tx_desc, pi, tx_mbuf, tx_info);
}

static inline void
sssnic_ethdev_txq_doorbell_ring(struct sssnic_ethdev_txq *txq, uint16_t pi)
{
	uint64_t *db_addr;
	struct sssnic_ethdev_txq_doorbell db;
	static const struct sssnic_ethdev_txq_doorbell default_db = {
		.cf = 0,
		.service = 1,
	};

	db.u64 = default_db.u64;
	db.qid = txq->qid;
	db.cos = txq->cos;
	db.pi_hi = (pi >> 8) & 0xff;

	db_addr = ((uint64_t *)txq->doorbell) + (pi & 0xff);

	rte_write64(db.u64, db_addr);
}

uint16_t
sssnic_ethdev_tx_pkt_burst(void *tx_queue, struct rte_mbuf **tx_pkts,
	uint16_t nb_pkts)
{
	struct sssnic_ethdev_txq *txq = (struct sssnic_ethdev_txq *)tx_queue;
	struct sssnic_ethdev_tx_entry *txe;
	struct rte_mbuf *txm;
	struct sssnic_ethdev_tx_info tx_info;
	uint64_t tx_bytes = 0;
	uint16_t nb_tx = 0;
	uint16_t idle_entries;
	uint16_t pi;
	int ret;

	/* cleanup previous xmit if idle entries is less than tx_free_thresh*/
	idle_entries = sssnic_ethdev_txq_num_idle_entries(txq) - 1;
	if (unlikely(idle_entries < txq->tx_free_thresh))
		sssnic_ethdev_txq_pktmbufs_cleanup(txq);

	pi = sssnic_ethdev_txq_pi_get(txq);

	while (nb_tx < nb_pkts) {
		txm = tx_pkts[nb_tx];

		ret = sssnic_ethdev_tx_info_init(txq, txm, &tx_info);
		if (unlikely(ret != 0))
			break;

		idle_entries = sssnic_ethdev_txq_num_idle_entries(txq) - 1;

		/* check if there are enough txq entries to xmit one packet */
		if (unlikely(idle_entries < tx_info.nb_entries)) {
			sssnic_ethdev_txq_pktmbufs_cleanup(txq);
			idle_entries =
				sssnic_ethdev_txq_num_idle_entries(txq) - 1;
			if (idle_entries < tx_info.nb_entries) {
				SSSNIC_TX_LOG(ERR,
					"No tx entries, idle_entries: %u, expect %u",
					idle_entries, tx_info.nb_entries);
				txq->stats.nobuf++;
				break;
			}
		}

		/* setup txq entries, include tx_desc, offload, seg */
		ret = sssnic_ethdev_txq_entries_setup(txq, pi, txm, &tx_info);
		if (unlikely(ret != 0))
			break;

		txe = &txq->txe[pi];
		txe->pktmbuf = txm;
		txe->num_workq_entries = tx_info.nb_entries;

		if (unlikely((pi + tx_info.nb_entries) >= txq->depth))
			txq->owner = !txq->owner;

		sssnic_ethdev_txq_produce(txq, tx_info.nb_entries);

		pi = sssnic_ethdev_txq_pi_get(txq);
		nb_tx++;
		tx_bytes += txm->pkt_len;

		SSSNIC_TX_LOG(DEBUG,
			"Transmitted one packet on port %u, len=%u, nb_seg=%u, tso_segsz=%u, ol_flags=%"
			PRIx64, txq->port, txm->pkt_len, txm->nb_segs, txm->tso_segsz,
			txm->ol_flags);
	}

	if (likely(nb_tx > 0)) {
		sssnic_ethdev_txq_doorbell_ring(txq, pi);
		txq->stats.packets += nb_tx;
		txq->stats.bytes += tx_bytes;
		txq->stats.burst = nb_tx;
	}

	return nb_tx;
}

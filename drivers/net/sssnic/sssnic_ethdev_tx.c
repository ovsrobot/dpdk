/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#include <error.h>
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

/* Hardware format of tx tx seg */
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

#define SSSNIC_ETHDEV_TXQ_ENTRY_SZ_BITS 4
#define SSSNIC_ETHDEV_TXQ_ENTRY_SZ (RTE_BIT32(SSSNIC_ETHDEV_TXQ_ENTRY_SZ_BITS))

#define SSSNIC_ETHDEV_TX_HW_CI_SIZE 64

/* Doorbell offset 4096 */
#define SSSNIC_ETHDEV_TXQ_DB_OFFSET 0x1000

#define SSSNIC_ETHDEV_TX_CI_DEF_COALESCING_TIME 16
#define SSSNIC_ETHDEV_TX_CI_DEF_PENDING_TIME 4

static inline uint16_t
sssnic_ethdev_txq_num_used_entries(struct sssnic_ethdev_txq *txq)
{
	return sssnic_workq_num_used_entries(txq->workq);
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

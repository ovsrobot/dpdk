/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#include <rte_io.h>
#include <rte_common.h>
#include <rte_memzone.h>
#include <ethdev_pci.h>

#include "sssnic_log.h"
#include "sssnic_ethdev.h"
#include "sssnic_ethdev_rx.h"
#include "sssnic_ethdev_rss.h"
#include "base/sssnic_hw.h"
#include "base/sssnic_workq.h"
#include "base/sssnic_api.h"
#include "base/sssnic_misc.h"

/* hardware format of rx descriptor*/
struct sssnic_ethdev_rx_desc {
	/* status field */
	union {
		uint32_t dword0;
		struct {
			uint32_t ip_csum_err : 1;
			uint32_t tcp_csum_err : 1;
			uint32_t udp_csum_err : 1;
			uint32_t igmp_csum_err : 1;
			uint32_t icmpv4_csum_err : 1;
			uint32_t icmpv6_csum_err : 1;
			uint32_t sctp_crc_err : 1;
			uint32_t hw_crc_err : 1;
			uint32_t other_err : 1;
			uint32_t err_resvd0 : 7;
			uint32_t lro_num : 8;
			uint32_t resvd1 : 1;
			uint32_t lro_push : 1;
			uint32_t lro_enter : 1;
			uint32_t lro_intr : 1;
			uint32_t flush : 1;
			uint32_t decry : 1;
			uint32_t bp_en : 1;
			uint32_t done : 1;
		};
		struct {
			uint32_t status_err : 16;
			uint32_t status_rest : 16;
		};
	};

	/* VLAN and length field */
	union {
		uint32_t dword1;
		struct {
			uint32_t vlan : 16;
			uint32_t len : 16;
		};
	};

	/* offload field */
	union {
		uint32_t dword2;
		struct {
			uint32_t pkt_type : 12;
			uint32_t dword2_resvd0 : 9;
			uint32_t vlan_en : 1;
			uint32_t dword2_resvd1 : 2;
			uint32_t rss_type : 8;
		};
	};

	/* rss hash field */
	union {
		uint32_t dword3;
		uint32_t rss_hash;
	};

	uint32_t dword4;
	uint32_t dword5;
	uint32_t dword6;
	uint32_t dword7;
} __rte_cache_aligned;

struct sssnic_ethdev_rx_entry {
	struct rte_mbuf *pktmbuf;
};

struct sssnic_ethdev_rxq {
	struct rte_eth_dev *ethdev;
	struct sssnic_workq *workq;
	volatile struct sssnic_ethdev_rx_desc *desc;
	const struct rte_memzone *pi_mz;
	const struct rte_memzone *desc_mz;
	struct rte_mempool *mp;
	struct sssnic_ethdev_rx_entry *rxe;
	volatile uint16_t *hw_pi_addr;
	uint8_t *doorbell;
	struct sssnic_ethdev_rxq_stats stats;
	uint16_t port;
	uint16_t qid;
	uint16_t depth;
	uint16_t rx_buf_size;
	uint16_t rx_free_thresh;
	struct {
		uint16_t enable : 1;
		uint16_t msix_id : 15;
	} intr;
	uint32_t resvd0;
} __rte_cache_aligned;

/* Hardware format of rxq entry */
struct sssnic_ethdev_rxq_entry {
	uint32_t buf_hi_addr;
	uint32_t buf_lo_addr;
	uint32_t desc_hi_addr;
	uint32_t desc_lo_addr;
};

#define SSSNIC_ETHDEV_RX_ENTRY_SZ_BITS 4
#define SSSNIC_ETHDEV_RXQ_ENTRY_SZ (RTE_BIT32(SSSNIC_ETHDEV_RX_ENTRY_SZ_BITS))

#define SSSNIC_ETHDEV_RXQ_ENTRY(rxq, idx)                                      \
	SSSNIC_WORKQ_ENTRY_CAST((rxq)->workq, idx,                             \
		struct sssnic_ethdev_rxq_entry)

static const uint16_t sssnic_ethdev_rx_buf_size_tbl[] = { 32, 64, 96, 128, 192,
	256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096, 8192, 16384 };

#define SSSNIC_ETHDEV_RX_BUF_SIZE_COUNT (RTE_DIM(sssnic_ethdev_rx_buf_size_tbl))

#define SSSNIC_ETHDEV_MIN_RX_BUF_SIZE (sssnic_ethdev_rx_buf_size_tbl[0])
#define SSSNIC_ETHDEV_MAX_RX_BUF_SIZE                                          \
	(sssnic_ethdev_rx_buf_size_tbl[SSSNIC_ETHDEV_RX_BUF_SIZE_COUNT - 1])

#define SSSNIC_ETHDEV_DEF_RX_BUF_SIZE_IDX 11 /* 2048 Bytes */

/* Doorbell offset 8192 */
#define SSSNIC_ETHDEV_RXQ_DB_OFFSET 0x2000

#define SSSNIC_ETHDEV_RX_MSIX_ID_START 1
#define SSSNIC_ETHDEV_RX_MSIX_ID_INVAL 0
#define SSSNIC_ETHDEV_RX_MSIX_PENDING_LIMIT 2
#define SSSNIC_ETHDEV_RX_MSIX_COALESCING_TIMER 2
#define SSSNIC_ETHDEV_RX_MSIX_RESNEDING_TIMER 7

struct sssnic_ethdev_rxq_doorbell {
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

static inline void
sssnic_ethdev_rxq_doorbell_ring(struct sssnic_ethdev_rxq *rxq, uint16_t pi)
{
	uint64_t *db_addr;
	struct sssnic_ethdev_rxq_doorbell db;
	uint16_t hw_pi;
	static const struct sssnic_ethdev_rxq_doorbell default_db = {
		.cf = 1,
		.service = 1,
	};

	hw_pi = pi << 1;

	db.u64 = default_db.u64;
	db.qid = rxq->qid;
	db.pi_hi = (hw_pi >> 8) & 0xff;

	db_addr = ((uint64_t *)rxq->doorbell) + (hw_pi & 0xff);

	rte_write64(db.u64, db_addr);
}

static inline uint16_t
sssnic_ethdev_rxq_num_used_entries(struct sssnic_ethdev_rxq *rxq)
{
	return sssnic_workq_num_used_entries(rxq->workq);
}

static inline uint16_t
sssnic_ethdev_rxq_num_idle_entries(struct sssnic_ethdev_rxq *rxq)
{
	return rxq->workq->idle_entries;
}

static inline uint16_t
sssnic_ethdev_rxq_ci_get(struct sssnic_ethdev_rxq *rxq)
{
	return sssnic_workq_ci_get(rxq->workq);
}

static inline uint16_t
sssnic_ethdev_rxq_pi_get(struct sssnic_ethdev_rxq *rxq)
{
	return sssnic_workq_pi_get(rxq->workq);
}

static inline void
sssnic_ethdev_rxq_consume(struct sssnic_ethdev_rxq *rxq, uint16_t num_entries)
{
	sssnic_workq_consume_fast(rxq->workq, num_entries);
}

static inline void
sssnic_ethdev_rxq_produce(struct sssnic_ethdev_rxq *rxq, uint16_t num_entries)
{
	sssnic_workq_produce_fast(rxq->workq, num_entries);
}

static void
sssnic_ethdev_rx_buf_size_optimize(uint32_t orig_size, uint16_t *new_size)
{
	uint32_t i;
	uint16_t size;

	if (orig_size >= SSSNIC_ETHDEV_MAX_RX_BUF_SIZE) {
		*new_size = SSSNIC_ETHDEV_MAX_RX_BUF_SIZE;
		return;
	}

	size = SSSNIC_ETHDEV_MIN_RX_BUF_SIZE;
	for (i = 0; i < SSSNIC_ETHDEV_RX_BUF_SIZE_COUNT; i++) {
		if (orig_size == sssnic_ethdev_rx_buf_size_tbl[i]) {
			*new_size = sssnic_ethdev_rx_buf_size_tbl[i];
			return;
		}

		if (orig_size < sssnic_ethdev_rx_buf_size_tbl[i]) {
			*new_size = size;
			return;
		}
		size = sssnic_ethdev_rx_buf_size_tbl[i];
	}
	*new_size = size;
}

static void
sssnic_ethdev_rxq_entries_init(struct sssnic_ethdev_rxq *rxq)
{
	struct sssnic_ethdev_rxq_entry *rqe;
	rte_iova_t rxd_iova;
	int i;

	rxd_iova = rxq->desc_mz->iova;

	for (i = 0; i < rxq->depth; i++) {
		rqe = SSSNIC_ETHDEV_RXQ_ENTRY(rxq, i);
		rqe->desc_hi_addr = SSSNIC_UPPER_32_BITS(rxd_iova);
		rqe->desc_lo_addr = SSSNIC_LOWER_32_BITS(rxd_iova);
		rxd_iova += sizeof(struct sssnic_ethdev_rx_desc);
	}
}

int
sssnic_ethdev_rx_queue_setup(struct rte_eth_dev *ethdev, uint16_t rx_queue_id,
	uint16_t nb_rx_desc, unsigned int socket_id,
	const struct rte_eth_rxconf *rx_conf, struct rte_mempool *mb_pool)
{
	int ret;
	struct sssnic_hw *hw;
	struct sssnic_ethdev_rxq *rxq;
	uint16_t q_depth;
	uint16_t rx_buf_size;
	uint16_t rx_free_thresh;
	char m_name[RTE_MEMZONE_NAMESIZE];

	hw = SSSNIC_ETHDEV_TO_HW(ethdev);

	q_depth = nb_rx_desc;
	/* Adjust q_depth to power of 2 */
	if (!rte_is_power_of_2(nb_rx_desc)) {
		q_depth = 1 << rte_log2_u32(nb_rx_desc);
		PMD_DRV_LOG(NOTICE,
			"nb_rx_desc(%u) is not power of 2, adjust to %u",
			nb_rx_desc, q_depth);
	}

	if (q_depth > SSSNIC_ETHDEV_MAX_NUM_Q_DESC) {
		PMD_DRV_LOG(ERR, "nb_rx_desc(%u) is out of range(max. %u)",
			q_depth, SSSNIC_ETHDEV_MAX_NUM_Q_DESC);
		return -EINVAL;
	}

	rx_buf_size =
		rte_pktmbuf_data_room_size(mb_pool) - RTE_PKTMBUF_HEADROOM;
	if (rx_buf_size < SSSNIC_ETHDEV_MIN_RX_BUF_SIZE) {
		PMD_DRV_LOG(ERR,
			"Bad data_room_size(%u), must be great than %u",
			rte_pktmbuf_data_room_size(mb_pool),
			RTE_PKTMBUF_HEADROOM + SSSNIC_ETHDEV_MIN_RX_BUF_SIZE);
		return -EINVAL;
	}
	sssnic_ethdev_rx_buf_size_optimize(rx_buf_size, &rx_buf_size);

	if (rx_conf->rx_free_thresh > 0)
		rx_free_thresh = rx_conf->rx_free_thresh;
	else
		rx_free_thresh = SSSNIC_ETHDEV_DEF_RX_FREE_THRESH;
	if (rx_free_thresh >= q_depth - 1) {
		PMD_DRV_LOG(ERR,
			"rx_free_thresh(%u) must be less than nb_rx_desc(%u)-1",
			rx_free_thresh, q_depth);
		return -EINVAL;
	}

	snprintf(m_name, sizeof(m_name), "sssnic_p%u_rq%u",
		ethdev->data->port_id, rx_queue_id);

	rxq = rte_zmalloc_socket(m_name, sizeof(struct sssnic_ethdev_rxq),
		RTE_CACHE_LINE_SIZE, (int)socket_id);
	if (rxq == NULL) {
		PMD_DRV_LOG(ERR,
			"Failed to allocate memory for sssnic port %u, rxq %u",
			ethdev->data->port_id, rx_queue_id);
		return -ENOMEM;
	}

	rxq->ethdev = ethdev;
	rxq->mp = mb_pool;
	rxq->doorbell = hw->db_base_addr + SSSNIC_ETHDEV_RXQ_DB_OFFSET;
	rxq->port = ethdev->data->port_id;
	rxq->qid = rx_queue_id;
	rxq->depth = q_depth;
	rxq->rx_buf_size = rx_buf_size;
	rxq->rx_free_thresh = rx_free_thresh;

	snprintf(m_name, sizeof(m_name), "sssnic_p%u_rq%u_wq",
		ethdev->data->port_id, rx_queue_id);
	rxq->workq = sssnic_workq_new(m_name, (int)socket_id,
		SSSNIC_ETHDEV_RXQ_ENTRY_SZ, q_depth);
	if (rxq->workq == NULL) {
		PMD_DRV_LOG(ERR,
			"Failed to create workq for sssnic port %u, rxq %u",
			ethdev->data->port_id, rx_queue_id);
		ret = -ENOMEM;
		goto new_workq_fail;
	}

	rxq->pi_mz = rte_eth_dma_zone_reserve(ethdev, "sssnic_rxpi_mz",
		rxq->qid, RTE_PGSIZE_4K, RTE_CACHE_LINE_SIZE, (int)socket_id);
	if (rxq->pi_mz == NULL) {
		PMD_DRV_LOG(ERR,
			"Failed to alloc DMA memory for rx pi of sssnic port %u rxq %u",
			ethdev->data->port_id, rx_queue_id);
		ret = -ENOMEM;
		goto alloc_pi_mz_fail;
	}
	rxq->hw_pi_addr = (uint16_t *)rxq->pi_mz->addr;

	rxq->desc_mz = rte_eth_dma_zone_reserve(ethdev, "sssnic_rxd_mz",
		rxq->qid, sizeof(struct sssnic_ethdev_rx_desc) * rxq->depth,
		RTE_CACHE_LINE_SIZE, (int)socket_id);
	if (rxq->pi_mz == NULL) {
		PMD_DRV_LOG(ERR,
			"Failed to alloc DMA memory for rx desc of sssnic port %u rxq %u",
			ethdev->data->port_id, rx_queue_id);
		ret = -ENOMEM;
		goto alloc_rxd_mz_fail;
	}
	rxq->desc = (struct sssnic_ethdev_rx_desc *)rxq->desc_mz->addr;

	snprintf(m_name, sizeof(m_name), "sssnic_p%u_rq%u_rxe",
		ethdev->data->port_id, rx_queue_id);

	rxq->rxe = rte_zmalloc_socket(m_name,
		sizeof(struct sssnic_ethdev_rx_entry) * rxq->depth,
		RTE_CACHE_LINE_SIZE, (int)socket_id);
	if (rxq->rxe == NULL) {
		PMD_DRV_LOG(ERR,
			"Failed to alloc memory for rx entries of sssnic port %u rxq %u",
			ethdev->data->port_id, rx_queue_id);
		ret = -ENOMEM;
		goto alloc_pktmbuf_fail;
	}

	sssnic_ethdev_rxq_entries_init(rxq);

	ethdev->data->rx_queues[rx_queue_id] = rxq;

	return 0;

alloc_pktmbuf_fail:
	rte_memzone_free(rxq->desc_mz);
alloc_rxd_mz_fail:
	rte_memzone_free(rxq->pi_mz);
alloc_pi_mz_fail:
	sssnic_workq_destroy(rxq->workq);
new_workq_fail:
	rte_free(rxq);

	return ret;
}

static void
sssnic_ethdev_rxq_pktmbufs_release(struct sssnic_ethdev_rxq *rxq)
{
	struct sssnic_ethdev_rx_entry *rxe;
	volatile struct sssnic_ethdev_rx_desc *rxd;
	uint16_t num_entries;
	uint16_t ci;
	uint16_t i;

	num_entries = sssnic_ethdev_rxq_num_used_entries(rxq);
	for (i = 0; i < num_entries; i++) {
		ci = sssnic_ethdev_rxq_ci_get(rxq);
		rxd = &rxq->desc[ci];
		rxd->dword0 = 0;
		rxe = &rxq->rxe[ci];
		rte_pktmbuf_free(rxe->pktmbuf);
		rxe->pktmbuf = NULL;
		sssnic_ethdev_rxq_consume(rxq, 1);
	}
}

static void
sssnic_ethdev_rxq_free(struct sssnic_ethdev_rxq *rxq)
{
	if (rxq == NULL)
		return;

	sssnic_ethdev_rxq_pktmbufs_release(rxq);
	rte_free(rxq->rxe);
	rte_memzone_free(rxq->desc_mz);
	rte_memzone_free(rxq->pi_mz);
	sssnic_workq_destroy(rxq->workq);
	rte_free(rxq);
}

void
sssnic_ethdev_rx_queue_release(struct rte_eth_dev *ethdev, uint16_t queue_id)
{
	struct sssnic_ethdev_rxq *rxq = ethdev->data->rx_queues[queue_id];

	if (rxq == NULL)
		return;
	sssnic_ethdev_rxq_free(rxq);
	ethdev->data->rx_queues[queue_id] = NULL;
}

void
sssnic_ethdev_rx_queue_all_release(struct rte_eth_dev *ethdev)
{
	uint16_t qid;

	for (qid = 0; qid < ethdev->data->nb_rx_queues; qid++)
		sssnic_ethdev_rx_queue_release(ethdev, qid);
}

static void
sssnic_ethdev_rxq_pktmbufs_fill(struct sssnic_ethdev_rxq *rxq)
{
	struct rte_mbuf **pktmbuf;
	rte_iova_t buf_iova;
	struct sssnic_ethdev_rxq_entry *rqe;
	uint16_t idle_entries;
	uint16_t bulk_entries;
	uint16_t pi;
	uint16_t i;
	int ret;

	idle_entries = sssnic_ethdev_rxq_num_idle_entries(rxq) - 1;
	pi = sssnic_ethdev_rxq_pi_get(rxq);

	while (idle_entries > 0) {
		/* calculate number of continuous entries */
		bulk_entries = rxq->depth - pi;
		if (idle_entries < bulk_entries)
			bulk_entries = idle_entries;

		pktmbuf = (struct rte_mbuf **)(&rxq->rxe[pi]);

		ret = rte_pktmbuf_alloc_bulk(rxq->mp, pktmbuf, bulk_entries);
		if (ret != 0) {
			rxq->stats.nombuf += idle_entries;
			return;
		}

		for (i = 0; i < bulk_entries; i++) {
			rqe = SSSNIC_ETHDEV_RXQ_ENTRY(rxq, pi);
			buf_iova = rte_mbuf_data_iova(pktmbuf[i]);
			rqe->buf_hi_addr = SSSNIC_UPPER_32_BITS(buf_iova);
			rqe->buf_lo_addr = SSSNIC_LOWER_32_BITS(buf_iova);
			sssnic_ethdev_rxq_produce(rxq, 1);
			pi = sssnic_ethdev_rxq_pi_get(rxq);
		}

		idle_entries -= bulk_entries;
		sssnic_ethdev_rxq_doorbell_ring(rxq, pi);
	}
}

static uint16_t
sssnic_ethdev_rxq_pktmbufs_cleanup(struct sssnic_ethdev_rxq *rxq)
{
	struct sssnic_ethdev_rx_entry *rxe;
	volatile struct sssnic_ethdev_rx_desc *rxd;
	uint16_t ci, count = 0;
	uint32_t pktlen = 0;
	uint32_t buflen = rxq->rx_buf_size;
	uint16_t num_entries;

	num_entries = sssnic_ethdev_rxq_num_used_entries(rxq);

	ci = sssnic_ethdev_rxq_ci_get(rxq);
	rxe = &rxq->rxe[ci];
	rxd = &rxq->desc[ci];

	while (num_entries > 0) {
		if (pktlen > 0)
			pktlen = pktlen > buflen ? (pktlen - buflen) : 0;
		else if (rxd->flush != 0)
			pktlen = 0;
		else if (rxd->done != 0)
			pktlen = rxd->len > buflen ? (rxd->len - buflen) : 0;
		else
			break;

		rte_pktmbuf_free(rxe->pktmbuf);
		rxe->pktmbuf = NULL;

		count++;
		num_entries--;

		sssnic_ethdev_rxq_consume(rxq, 1);
		ci = sssnic_ethdev_rxq_ci_get(rxq);
		rxe = &rxq->rxe[ci];
		rxd = &rxq->desc[ci];
	}

	PMD_DRV_LOG(DEBUG,
		"%u rx packets cleanned up (Port:%u rxq:%u), ci=%u, pi=%u",
		count, rxq->port, rxq->qid, ci, sssnic_ethdev_rxq_pi_get(rxq));

	return count;
}

#define SSSNIC_ETHDEV_RXQ_FUSH_TIMEOUT 3000 /* 3000 ms */
static int
sssnic_ethdev_rxq_flush(struct sssnic_ethdev_rxq *rxq)
{
	struct sssnic_hw *hw;
	uint64_t timeout;
	uint16_t used_entries;
	int ret;

	hw = SSSNIC_ETHDEV_TO_HW(rxq->ethdev);

	ret = sssnic_rxq_flush(hw, rxq->qid);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to flush rxq:%u, port:%u", rxq->qid,
			rxq->port);
		return ret;
	}

	timeout = rte_get_timer_cycles() +
		  rte_get_timer_hz() * SSSNIC_ETHDEV_RXQ_FUSH_TIMEOUT / 1000;

	do {
		sssnic_ethdev_rxq_pktmbufs_cleanup(rxq);
		used_entries = sssnic_ethdev_rxq_num_used_entries(rxq);
		if (used_entries == 0)
			return 0;
		rte_delay_us_sleep(1000);
	} while (((long)(rte_get_timer_cycles() - timeout)) < 0);

	PMD_DRV_LOG(ERR, "Flush port:%u rxq:%u timeout, used_rxq_entries:%u",
		rxq->port, rxq->qid, sssnic_ethdev_rxq_num_used_entries(rxq));

	return -ETIMEDOUT;
}

static int
sssnic_ethdev_rxq_enable(struct rte_eth_dev *ethdev, uint16_t queue_id)
{
	struct sssnic_ethdev_rxq *rxq = ethdev->data->rx_queues[queue_id];

	sssnic_ethdev_rxq_pktmbufs_fill(rxq);

	return 0;
}

static int
sssnic_ethdev_rxq_disable(struct rte_eth_dev *ethdev, uint16_t queue_id)
{
	struct sssnic_ethdev_rxq *rxq = ethdev->data->rx_queues[queue_id];
	int ret;

	ret = sssnic_ethdev_rxq_flush(rxq);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to flush rxq:%u, port:%u", queue_id,
			ethdev->data->port_id);
		return ret;
	}

	return 0;
}
int
sssnic_ethdev_rx_queue_start(struct rte_eth_dev *ethdev, uint16_t queue_id)
{
	struct sssnic_netdev *netdev = SSSNIC_ETHDEV_PRIVATE(ethdev);
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);
	int ret;

	ret = sssnic_ethdev_rxq_enable(ethdev, queue_id);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to start rxq:%u, port:%u", queue_id,
			ethdev->data->port_id);
		return ret;
	}

	if (netdev->num_started_rxqs == 0) {
		ret = sssnic_port_enable_set(hw, true);
		if (ret != 0) {
			PMD_DRV_LOG(ERR, "Failed to enable sssnic port:%u",
				ethdev->data->port_id);
			sssnic_ethdev_rxq_disable(ethdev, queue_id);
			return ret;
		}
	}

	netdev->num_started_rxqs++;
	ethdev->data->rx_queue_state[queue_id] = RTE_ETH_QUEUE_STATE_STARTED;

	ret = sssnic_ethdev_rss_reta_reset(ethdev);
	if (ret)
		PMD_DRV_LOG(WARNING, "Failed to reset RSS reta");

	PMD_DRV_LOG(DEBUG, "port %u rxq %u started", ethdev->data->port_id,
		queue_id);

	return 0;
}

int
sssnic_ethdev_rx_queue_stop(struct rte_eth_dev *ethdev, uint16_t queue_id)
{
	struct sssnic_netdev *netdev = SSSNIC_ETHDEV_PRIVATE(ethdev);
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);
	int ret;

	if (netdev->num_started_rxqs == 1) {
		ret = sssnic_port_enable_set(hw, false);
		if (ret != 0) {
			PMD_DRV_LOG(ERR, "Failed to disable sssnic port:%u",
				ethdev->data->port_id);
			return ret;
		}
	}

	ret = sssnic_ethdev_rxq_disable(ethdev, queue_id);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to disable rxq:%u, port:%u", queue_id,
			ethdev->data->port_id);
		sssnic_port_enable_set(hw, true);
		return ret;
	}

	netdev->num_started_rxqs--;
	ethdev->data->rx_queue_state[queue_id] = RTE_ETH_QUEUE_STATE_STOPPED;

	ret = sssnic_ethdev_rss_reta_reset(ethdev);
	if (ret)
		PMD_DRV_LOG(WARNING, "Failed to reset RSS reta");

	PMD_DRV_LOG(DEBUG, "port %u rxq %u stopped", ethdev->data->port_id,
		queue_id);

	return 0;
}

int
sssnic_ethdev_rx_queue_all_start(struct rte_eth_dev *ethdev)
{
	struct sssnic_netdev *netdev = SSSNIC_ETHDEV_PRIVATE(ethdev);
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);
	uint16_t numq = ethdev->data->nb_rx_queues;
	uint16_t qid;

	int ret;

	for (qid = 0; qid < numq; qid++) {
		ret = sssnic_ethdev_rxq_enable(ethdev, qid);
		if (ret != 0) {
			PMD_DRV_LOG(ERR, "Failed to enable rxq:%u, port:%u",
				qid, ethdev->data->port_id);
			goto fail_out;
		}

		ethdev->data->rx_queue_state[qid] = RTE_ETH_QUEUE_STATE_STARTED;
		netdev->num_started_rxqs++;

		PMD_DRV_LOG(DEBUG, "port %u rxq %u started",
			ethdev->data->port_id, qid);
	}

	ret = sssnic_ethdev_rss_reta_reset(ethdev);
	if (ret)
		PMD_DRV_LOG(WARNING, "Failed to reset RSS reta");

	ret = sssnic_port_enable_set(hw, true);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failed to enable port:%u",
			ethdev->data->port_id);
		goto fail_out;
	}

	return 0;

fail_out:
	while (qid--) {
		sssnic_ethdev_rxq_disable(ethdev, qid);
		ethdev->data->rx_queue_state[qid] = RTE_ETH_QUEUE_STATE_STOPPED;
		netdev->num_started_rxqs--;
	}

	return ret;
}

int
sssnic_ethdev_rx_queue_all_stop(struct rte_eth_dev *ethdev)
{
	struct sssnic_netdev *netdev = SSSNIC_ETHDEV_PRIVATE(ethdev);
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);
	uint16_t numq = ethdev->data->nb_rx_queues;
	uint16_t qid;
	int ret;

	ret = sssnic_port_enable_set(hw, false);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failed to disable port:%u",
			ethdev->data->port_id);
		return ret;
	}

	for (qid = 0; qid < numq; qid++) {
		ret = sssnic_ethdev_rxq_disable(ethdev, qid);
		if (ret != 0) {
			PMD_DRV_LOG(WARNING, "Failed to enable rxq:%u, port:%u",
				qid, ethdev->data->port_id);
			continue;
		}

		ethdev->data->rx_queue_state[qid] = RTE_ETH_QUEUE_STATE_STOPPED;
		netdev->num_started_rxqs--;

		PMD_DRV_LOG(DEBUG, "port %u rxq %u stopped",
			ethdev->data->port_id, qid);
	}

	return 0;
}

static int
sssinc_ethdev_rxq_intr_attr_init(struct sssnic_ethdev_rxq *rxq)
{
	int ret;
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(rxq->ethdev);
	struct sssnic_msix_attr attr;

	attr.lli_set = 0;
	attr.coalescing_set = 1;
	attr.pending_limit = SSSNIC_ETHDEV_RX_MSIX_PENDING_LIMIT;
	attr.coalescing_timer = SSSNIC_ETHDEV_RX_MSIX_COALESCING_TIMER;
	attr.resend_timer = SSSNIC_ETHDEV_RX_MSIX_RESNEDING_TIMER;

	ret = sssnic_msix_attr_set(hw, rxq->intr.msix_id, &attr);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to set msxi attributes");
		return ret;
	}

	return 0;
}

int
sssnic_ethdev_rx_queue_intr_enable(struct rte_eth_dev *ethdev, uint16_t qid)
{
	struct sssnic_ethdev_rxq *rxq = ethdev->data->rx_queues[qid];
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);

	if (rxq->intr.enable)
		return 0;

	sssnic_msix_auto_mask_set(hw, rxq->intr.msix_id, SSSNIC_MSIX_ENABLE);
	sssnic_msix_state_set(hw, rxq->intr.msix_id, SSSNIC_MSIX_ENABLE);
	rxq->intr.enable = 1;

	return 0;
}

int
sssnic_ethdev_rx_queue_intr_disable(struct rte_eth_dev *ethdev, uint16_t qid)
{
	struct sssnic_ethdev_rxq *rxq = ethdev->data->rx_queues[qid];
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);

	if (!rxq->intr.enable)
		return 0;

	sssnic_msix_auto_mask_set(hw, rxq->intr.msix_id, SSSNIC_MSIX_DISABLE);
	sssnic_msix_state_set(hw, rxq->intr.msix_id, SSSNIC_MSIX_DISABLE);
	sssnic_msix_resend_disable(hw, rxq->intr.msix_id);
	rxq->intr.enable = 0;

	return 0;
}

int
sssnic_ethdev_rx_intr_init(struct rte_eth_dev *ethdev)
{
	struct rte_intr_handle *intr_handle;
	struct sssnic_ethdev_rxq *rxq;
	uint32_t nb_rxq, i;
	int vec;
	int ret;

	if (!ethdev->data->dev_conf.intr_conf.rxq)
		return 0;

	intr_handle = ethdev->intr_handle;

	if (!rte_intr_cap_multiple(intr_handle)) {
		PMD_DRV_LOG(ERR,
			"Rx interrupts require MSI-X interrupts (vfio-pci driver)\n");
		return -ENOTSUP;
	}

	rte_intr_efd_disable(intr_handle);

	nb_rxq = ethdev->data->nb_rx_queues;

	ret = rte_intr_efd_enable(intr_handle, nb_rxq);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to enable intr efd");
		return ret;
	}

	ret = rte_intr_vec_list_alloc(intr_handle, NULL, nb_rxq);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to allocate rx intr vec list");
		rte_intr_efd_disable(intr_handle);
		return ret;
	}

	for (i = 0; i < nb_rxq; i++) {
		vec = (int)(i + SSSNIC_ETHDEV_RX_MSIX_ID_START);
		rte_intr_vec_list_index_set(intr_handle, i, vec);
		rxq = ethdev->data->rx_queues[i];
		rxq->intr.msix_id = vec;

		ret = sssinc_ethdev_rxq_intr_attr_init(rxq);
		if (ret != 0) {
			PMD_DRV_LOG(ERR,
				"Failed to initialize rxq %u (port %u) msix attribute.",
				rxq->qid, rxq->port);
			goto intr_attr_init_fail;
		}
	}

	return 0;

intr_attr_init_fail:
	rte_intr_vec_list_free(intr_handle);
	rte_intr_efd_disable(intr_handle);

	return ret;
}

void
sssnic_ethdev_rx_intr_shutdown(struct rte_eth_dev *ethdev)
{
	struct rte_intr_handle *intr_handle = ethdev->intr_handle;
	uint16_t i;

	for (i = 0; i < ethdev->data->nb_rx_queues; i++)
		sssnic_ethdev_rx_queue_intr_disable(ethdev, i);

	rte_intr_efd_disable(intr_handle);
	rte_intr_vec_list_free(intr_handle);
}

uint16_t
sssnic_ethdev_rx_max_size_determine(struct rte_eth_dev *ethdev)
{
	struct sssnic_ethdev_rxq *rxq;
	uint16_t max_size = 0;
	uint16_t i;

	for (i = 0; i < ethdev->data->nb_rx_queues; i++) {
		rxq = ethdev->data->rx_queues[i];
		if (rxq->rx_buf_size > max_size)
			max_size = rxq->rx_buf_size;
	}

	return max_size;
}

static void
sssnic_ethdev_rxq_ctx_build(struct sssnic_ethdev_rxq *rxq,
	struct sssnic_rxq_ctx *rxq_ctx)
{
	uint16_t hw_ci, hw_pi;
	uint64_t pfn;

	hw_ci = sssnic_ethdev_rxq_ci_get(rxq) << 1;
	hw_pi = sssnic_ethdev_rxq_pi_get(rxq) << 1;

	/* dw0 */
	rxq_ctx->pi = hw_pi;
	rxq_ctx->ci = hw_ci;

	/* dw1 */
	rxq_ctx->msix_id = rxq->intr.msix_id;
	rxq_ctx->intr_dis = !rxq->intr.enable;

	/* workq buf phyaddress PFN, size = 4K */
	pfn = SSSNIC_WORKQ_BUF_PHYADDR(rxq->workq) >> 12;

	/* dw2 */
	rxq_ctx->wq_pfn_hi = SSSNIC_UPPER_32_BITS(pfn);
	rxq_ctx->wqe_type = 2;
	rxq_ctx->wq_owner = 1;

	/* dw3 */
	rxq_ctx->wq_pfn_lo = SSSNIC_LOWER_32_BITS(pfn);

	/* dw4, dw5, dw6 are reserved */

	/* dw7 */
	rxq_ctx->rxd_len = 1;

	/* dw8 */
	rxq_ctx->pre_cache_thd = 256;
	rxq_ctx->pre_cache_max = 6;
	rxq_ctx->pre_cache_min = 1;

	/* dw9 */
	rxq_ctx->pre_ci_hi = (hw_ci >> 12) & 0xf;
	rxq_ctx->pre_owner = 1;

	/* dw10 */
	rxq_ctx->pre_wq_pfn_hi = SSSNIC_UPPER_32_BITS(pfn);
	rxq_ctx->pre_ci_lo = hw_ci & 0xfff;

	/* dw11 */
	rxq_ctx->pre_wq_pfn_lo = SSSNIC_LOWER_32_BITS(pfn);

	/* dw12 */
	rxq_ctx->pi_addr_hi = SSSNIC_UPPER_32_BITS(rxq->pi_mz->iova);

	/* dw13 */
	rxq_ctx->pi_addr_lo = SSSNIC_LOWER_32_BITS(rxq->pi_mz->iova);

	/* workq buf block PFN, size = 512B */
	pfn = SSSNIC_WORKQ_BUF_PHYADDR(rxq->workq) >> 9;

	/* dw14 */
	rxq_ctx->wq_blk_pfn_hi = SSSNIC_UPPER_32_BITS(pfn);

	/* dw15 */
	rxq_ctx->wq_blk_pfn_lo = SSSNIC_LOWER_32_BITS(pfn);
}

int
sssnic_ethdev_rx_queues_ctx_init(struct rte_eth_dev *ethdev)
{
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);
	struct sssnic_ethdev_rxq *rxq;
	struct sssnic_rxq_ctx *qctx;
	uint16_t qid, numq;
	int ret;

	numq = ethdev->data->nb_rx_queues;

	qctx = rte_zmalloc(NULL, numq * sizeof(struct sssnic_rxq_ctx), 0);
	if (qctx == NULL) {
		PMD_DRV_LOG(ERR, "Failed to alloc memory for rxq ctx");
		return -EINVAL;
	}

	for (qid = 0; qid < numq; qid++) {
		rxq = ethdev->data->rx_queues[qid];

		/* reset ci and pi */
		sssnic_workq_reset(rxq->workq);

		sssnic_ethdev_rxq_ctx_build(rxq, &qctx[qid]);
	}

	ret = sssnic_rxq_ctx_set(hw, qctx, 0, numq);
	rte_free(qctx);

	return ret;
}

int
sssnic_ethdev_rx_offload_ctx_reset(struct rte_eth_dev *ethdev)
{
	return sssnic_rx_offload_ctx_reset(SSSNIC_ETHDEV_TO_HW(ethdev));
}

uint16_t
sssnic_ethdev_rx_queue_depth_get(struct rte_eth_dev *ethdev, uint16_t qid)
{
	struct sssnic_ethdev_rxq *rxq;

	if (qid >= ethdev->data->nb_rx_queues)
		return 0;

	rxq = ethdev->data->rx_queues[qid];

	return rxq->depth;
};

uint32_t
sssnic_ethdev_rx_buf_size_index_get(uint16_t rx_buf_size)
{
	uint32_t i;

	for (i = 0; i < SSSNIC_ETHDEV_RX_BUF_SIZE_COUNT; i++) {
		if (rx_buf_size == sssnic_ethdev_rx_buf_size_tbl[i])
			return i;
	}

	return SSSNIC_ETHDEV_DEF_RX_BUF_SIZE_IDX;
}

int
sssnic_ethdev_rx_mode_set(struct rte_eth_dev *ethdev, uint32_t mode)
{
	struct sssnic_netdev *netdev = SSSNIC_ETHDEV_PRIVATE(ethdev);
	int ret;

	ret = sssnic_port_rx_mode_set(SSSNIC_ETHDEV_TO_HW(ethdev), mode);
	if (ret != 0)
		return ret;

	netdev->rx_mode = mode;

	PMD_DRV_LOG(DEBUG, "Set rx_mode to %x", mode);

	return 0;
}

static int
sssnic_ethdev_lro_setup(struct rte_eth_dev *ethdev)
{
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);
	struct rte_eth_conf *dev_conf = &ethdev->data->dev_conf;
	bool enable;
	uint8_t num_lro_bufs;
	uint32_t max_lro_pkt_size;
	uint32_t timer = SSSNIC_ETHDEV_LRO_TIMER;
	int ret;

	if (dev_conf->rxmode.offloads & RTE_ETH_RX_OFFLOAD_TCP_LRO)
		enable = true;
	else
		enable = false;

	max_lro_pkt_size = dev_conf->rxmode.max_lro_pkt_size;
	num_lro_bufs = max_lro_pkt_size / SSSNIC_ETHDEV_LRO_BUF_SIZE;

	if (num_lro_bufs == 0)
		num_lro_bufs = 1;

	ret = sssnic_lro_enable_set(hw, enable, enable, num_lro_bufs);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to %s LRO",
			enable ? "enable" : "disable");
		return ret;
	}

	ret = sssnic_lro_timer_set(hw, timer);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to set lro timer to %u", timer);
		return ret;
	}

	PMD_DRV_LOG(INFO,
		"%s LRO, max_lro_pkt_size: %u, num_lro_bufs: %u, lro_timer: %u",
		enable ? "Enabled" : "Disabled", max_lro_pkt_size, num_lro_bufs,
		timer);

	return 0;
}

static int
sssnic_ethdev_rx_vlan_offload_setup(struct rte_eth_dev *ethdev)
{
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);
	struct rte_eth_conf *dev_conf = &ethdev->data->dev_conf;
	bool vlan_strip_en;
	uint32_t vlan_filter_en;
	int ret;

	if (dev_conf->rxmode.offloads & RTE_ETH_RX_OFFLOAD_VLAN_STRIP)
		vlan_strip_en = true;
	else
		vlan_strip_en = false;

	ret = sssnic_vlan_strip_enable_set(hw, vlan_strip_en);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to %s VLAN strip",
			vlan_strip_en ? "enable" : "disable");
		return ret;
	}

	PMD_DRV_LOG(INFO, "%s VLAN strip",
		vlan_strip_en ? "Enabled" : "Disabled");

	if (dev_conf->rxmode.offloads & RTE_ETH_RX_OFFLOAD_VLAN_FILTER)
		vlan_filter_en = true;
	else
		vlan_filter_en = false;

	ret = sssnic_vlan_filter_enable_set(hw, vlan_filter_en);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to %s VLAN filter",
			vlan_filter_en ? "enable" : "disable");
		return ret;
	}

	PMD_DRV_LOG(ERR, "%s VLAN filter",
		vlan_filter_en ? "Enabled" : "Disabled");

	return 0;
}

int
sssnic_ethdev_rx_offload_setup(struct rte_eth_dev *ethdev)
{
	int ret;

	ret = sssnic_ethdev_lro_setup(ethdev);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to setup LRO");
		return ret;
	}

	ret = sssnic_ethdev_rx_vlan_offload_setup(ethdev);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to setup rx vlan offload");
		return ret;
	}

	return 0;
}

int
sssnic_ethdev_rx_queue_stats_get(struct rte_eth_dev *ethdev, uint16_t qid,
	struct sssnic_ethdev_rxq_stats *stats)
{
	struct sssnic_ethdev_rxq *rxq;

	if (qid >= ethdev->data->nb_rx_queues) {
		PMD_DRV_LOG(ERR,
			"Invalid qid, qid must less than nb_rx_queues(%u)",
			ethdev->data->nb_rx_queues);
		return -EINVAL;
	}

	rxq = ethdev->data->rx_queues[qid];
	memcpy(stats, &rxq->stats, sizeof(rxq->stats));

	return 0;
}

void
sssnic_ethdev_rx_queue_stats_clear(struct rte_eth_dev *ethdev, uint16_t qid)
{
	struct sssnic_ethdev_rxq *rxq;

	if (qid < ethdev->data->nb_rx_queues) {
		rxq = ethdev->data->rx_queues[qid];
		memset(&rxq->stats, 0, sizeof(rxq->stats));
	}
};

static inline void
sssnic_ethdev_rx_csum_offload(struct sssnic_ethdev_rxq *rxq,
	struct rte_mbuf *rxm, volatile struct sssnic_ethdev_rx_desc *rxd)
{
	/* no errors */
	if (likely(rxd->status_err == 0)) {
		rxm->ol_flags |= RTE_MBUF_F_RX_IP_CKSUM_GOOD |
				 RTE_MBUF_F_RX_L4_CKSUM_GOOD;
		return;
	}

	/* bypass hw crc error*/
	if (unlikely(rxd->hw_crc_err)) {
		rxm->ol_flags |= RTE_MBUF_F_RX_IP_CKSUM_UNKNOWN;
		return;
	}

	if (rxd->ip_csum_err) {
		rxm->ol_flags |= RTE_MBUF_F_RX_IP_CKSUM_BAD;
		rxq->stats.csum_errors++;
	}

	if (rxd->tcp_csum_err || rxd->udp_csum_err || rxd->sctp_crc_err) {
		rxm->ol_flags |= RTE_MBUF_F_RX_L4_CKSUM_BAD;
		rxq->stats.csum_errors++;
	}

	if (unlikely(rxd->other_err))
		rxq->stats.other_errors++;
}

static inline void
sssnic_ethdev_rx_vlan_offload(struct rte_mbuf *rxm,
	volatile struct sssnic_ethdev_rx_desc *rxd)
{
	if (rxd->vlan_en == 0 || rxd->vlan == 0) {
		rxm->vlan_tci = 0;
		return;
	}

	rxm->vlan_tci = rxd->vlan;
	rxm->ol_flags |= RTE_MBUF_F_RX_VLAN | RTE_MBUF_F_RX_VLAN_STRIPPED;
}

static inline void
sssnic_ethdev_rx_segments(struct sssnic_ethdev_rxq *rxq, struct rte_mbuf *head,
	uint32_t remain_size)
{
	struct sssnic_ethdev_rx_entry *rxe;
	struct rte_mbuf *curr, *prev = head;
	uint16_t rx_buf_size = rxq->rx_buf_size;
	uint16_t ci;
	uint32_t rx_size;

	while (remain_size > 0) {
		ci = sssnic_ethdev_rxq_ci_get(rxq);
		rxe = &rxq->rxe[ci];
		curr = rxe->pktmbuf;

		sssnic_ethdev_rxq_consume(rxq, 1);

		rx_size = RTE_MIN(remain_size, rx_buf_size);
		remain_size -= rx_size;

		curr->data_len = rx_size;
		curr->next = NULL;
		prev->next = curr;
		prev = curr;
		head->nb_segs++;
	}
}

uint16_t
sssnic_ethdev_rx_pkt_burst(void *rx_queue, struct rte_mbuf **rx_pkts,
	uint16_t nb_pkts)
{
	struct sssnic_ethdev_rxq *rxq = (struct sssnic_ethdev_rxq *)rx_queue;
	struct sssnic_ethdev_rx_entry *rxe;
	struct rte_mbuf *rxm;
	struct sssnic_ethdev_rx_desc *rxd, rx_desc;
	uint16_t ci, idle_entries;
	uint16_t rx_buf_size;
	uint32_t rx_size;
	uint64_t nb_rx = 0;
	uint64_t rx_bytes = 0;

	ci = sssnic_ethdev_rxq_ci_get(rxq);
	rx_buf_size = rxq->rx_buf_size;
	rxd = &rx_desc;

	while (nb_rx < nb_pkts) {
		rxd->dword0 = __atomic_load_n(&rxq->desc[ci].dword0,
			__ATOMIC_ACQUIRE);
		/* check rx done */
		if (!rxd->done)
			break;

		rxd->dword1 = rxq->desc[ci].dword1;
		rxd->dword2 = rxq->desc[ci].dword2;
		rxd->dword3 = rxq->desc[ci].dword3;

		/* reset rx desc status */
		rxq->desc[ci].dword0 = 0;

		/* get current pktmbuf */
		rxe = &rxq->rxe[ci];
		rxm = rxe->pktmbuf;

		/* prefetch next packet */
		sssnic_ethdev_rxq_consume(rxq, 1);
		ci = sssnic_ethdev_rxq_ci_get(rxq);
		rte_prefetch0(rxq->rxe[ci].pktmbuf);

		/* set pktmbuf len */
		rx_size = rxd->len;
		rxm->pkt_len = rx_size;
		if (likely(rx_size <= rx_buf_size)) {
			rxm->data_len = rx_size;
		} else {
			rxm->data_len = rx_buf_size;
			sssnic_ethdev_rx_segments(rxq, rxm,
				rx_size - rx_buf_size);
		}
		rxm->data_off = RTE_PKTMBUF_HEADROOM;
		rxm->port = rxq->port;

		/* process checksum offload*/
		sssnic_ethdev_rx_csum_offload(rxq, rxm, rxd);

		/* process vlan offload */
		sssnic_ethdev_rx_vlan_offload(rxm, rxd);

		/* process lro */
		if (unlikely(rxd->lro_num != 0)) {
			rxm->ol_flags |= RTE_MBUF_F_RX_LRO;
			rxm->tso_segsz = rx_size / rxd->lro_num;
		}

		/* process RSS offload */
		if (likely(rxd->rss_type != 0)) {
			rxm->hash.rss = rxd->rss_hash;
			rxm->ol_flags |= RTE_MBUF_F_RX_RSS_HASH;
		}

		rx_pkts[nb_rx++] = rxm;
		rx_bytes += rx_size;

		SSSNIC_RX_LOG(DEBUG,
			"Received one packet on port %u, len=%u, nb_seg=%u, tso_segsz=%u, ol_flags=%"
			PRIx64, rxq->port, rxm->pkt_len, rxm->nb_segs, rxm->tso_segsz,
			rxm->ol_flags);
	}

	if (nb_rx > 0) {
		rxq->stats.packets += nb_rx;
		rxq->stats.bytes += rx_bytes;
		rxq->stats.burst = nb_rx;

		/* refill packet mbuf */
		idle_entries = sssnic_ethdev_rxq_num_idle_entries(rxq) - 1;
		if (idle_entries >= rxq->rx_free_thresh)
			sssnic_ethdev_rxq_pktmbufs_fill(rxq);
	}

	return nb_rx;
}

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

	db_addr = (uint64_t *)(rxq->doorbell + (hw_pi & 0xff));

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

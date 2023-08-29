/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#include <error.h>
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

static inline uint16_t
sssnic_ethdev_rxq_num_used_entries(struct sssnic_ethdev_rxq *rxq)
{
	return sssnic_workq_num_used_entries(rxq->workq);
}

static inline uint16_t
sssnic_ethdev_rxq_ci_get(struct sssnic_ethdev_rxq *rxq)
{
	return sssnic_workq_ci_get(rxq->workq);
}

static inline void
sssnic_ethdev_rxq_consume(struct sssnic_ethdev_rxq *rxq, uint16_t num_entries)
{
	sssnic_workq_consume_fast(rxq->workq, num_entries);
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

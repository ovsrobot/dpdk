/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#include <rte_pci.h>
#include <rte_bus_pci.h>
#include <ethdev_pci.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_mempool.h>
#include <rte_errno.h>
#include <rte_ether.h>

#include "base/spnic_compat.h"
#include "base/spnic_cmd.h"
#include "base/spnic_csr.h"
#include "base/spnic_wq.h"
#include "base/spnic_eqs.h"
#include "base/spnic_mgmt.h"
#include "base/spnic_cmdq.h"
#include "base/spnic_hwdev.h"
#include "base/spnic_hwif.h"
#include "base/spnic_hw_cfg.h"
#include "base/spnic_hw_comm.h"
#include "base/spnic_nic_cfg.h"
#include "base/spnic_nic_event.h"
#include "spnic_io.h"
#include "spnic_tx.h"
#include "spnic_rx.h"
#include "spnic_ethdev.h"

#define SPNIC_MIN_RX_BUF_SIZE		1024

#define SPNIC_DEFAULT_BURST_SIZE	32
#define SPNIC_DEFAULT_NB_QUEUES		1
#define SPNIC_DEFAULT_RING_SIZE		1024
#define SPNIC_MAX_LRO_SIZE		65536

#define SPNIC_DEFAULT_RX_FREE_THRESH	32
#define SPNIC_DEFAULT_TX_FREE_THRESH	32

/*
 * Vlan_id is a 12 bit number. The VFTA array is actually a 4096 bit array,
 * 128 of 32bit elements. 2^5 = 32. The val of lower 5 bits specifies the bit
 * in the 32bit element. The higher 7 bit val specifies VFTA array index.
 */
#define SPNIC_VFTA_BIT(vlan_id)    (1 << ((vlan_id) & 0x1F))
#define SPNIC_VFTA_IDX(vlan_id)    ((vlan_id) >> 5)

#define SPNIC_LRO_DEFAULT_COAL_PKT_SIZE		32
#define SPNIC_LRO_DEFAULT_TIME_LIMIT		16
#define SPNIC_LRO_UNIT_WQE_SIZE			1024 /* Bytes */

/* Driver-specific log messages type */
int spnic_logtype;

enum spnic_rx_mod {
	SPNIC_RX_MODE_UC = 1 << 0,
	SPNIC_RX_MODE_MC = 1 << 1,
	SPNIC_RX_MODE_BC = 1 << 2,
	SPNIC_RX_MODE_MC_ALL = 1 << 3,
	SPNIC_RX_MODE_PROMISC = 1 << 4,
};

#define SPNIC_DEFAULT_RX_MODE	(SPNIC_RX_MODE_UC | SPNIC_RX_MODE_MC | \
				SPNIC_RX_MODE_BC)

#define SPNIC_MAX_QUEUE_DEPTH		16384
#define SPNIC_MIN_QUEUE_DEPTH		128
#define SPNIC_TXD_ALIGN			1
#define SPNIC_RXD_ALIGN			1

static const struct rte_eth_desc_lim spnic_rx_desc_lim = {
	.nb_max = SPNIC_MAX_QUEUE_DEPTH,
	.nb_min = SPNIC_MIN_QUEUE_DEPTH,
	.nb_align = SPNIC_RXD_ALIGN,
};

static const struct rte_eth_desc_lim spnic_tx_desc_lim = {
	.nb_max = SPNIC_MAX_QUEUE_DEPTH,
	.nb_min = SPNIC_MIN_QUEUE_DEPTH,
	.nb_align = SPNIC_TXD_ALIGN,
};

/**
 * Ethernet device configuration.
 *
 * Prepare the driver for a given number of TX and RX queues, mtu size
 * and configure RSS.
 *
 * @param[in] dev
 *   Pointer to ethernet device structure.
 *
 * @retval zero : Success
 * @retval non-zero : Failure.
 */
static int spnic_dev_configure(struct rte_eth_dev *dev)
{
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);

	nic_dev->num_sqs =  dev->data->nb_tx_queues;
	nic_dev->num_rqs = dev->data->nb_rx_queues;

	nic_dev->mtu_size =
		SPNIC_PKTLEN_TO_MTU(dev->data->dev_conf.rxmode.mtu);

	if (dev->data->dev_conf.rxmode.mq_mode & ETH_MQ_RX_RSS_FLAG)
		dev->data->dev_conf.rxmode.offloads |= DEV_RX_OFFLOAD_RSS_HASH;

	return 0;
}

/**
 * Get information about the device.
 *
 * @param[in] dev
 *   Pointer to ethernet device structure.
 * @param[out] info
 *   Info structure for ethernet device.
 *
 * @retval zero : Success
 * @retval non-zero : Failure.
 */
static int spnic_dev_infos_get(struct rte_eth_dev *dev,
			       struct rte_eth_dev_info *info)
{
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);

	info->max_rx_queues  = nic_dev->max_rqs;
	info->max_tx_queues  = nic_dev->max_sqs;
	info->min_rx_bufsize = SPNIC_MIN_RX_BUF_SIZE;
	info->max_rx_pktlen  = SPNIC_MAX_JUMBO_FRAME_SIZE;
	info->max_mac_addrs  = SPNIC_MAX_UC_MAC_ADDRS;
	info->min_mtu = SPNIC_MIN_MTU_SIZE;
	info->max_mtu = SPNIC_MAX_MTU_SIZE;
	info->max_lro_pkt_size = SPNIC_MAX_LRO_SIZE;

	info->rx_queue_offload_capa = 0;
	info->rx_offload_capa = DEV_RX_OFFLOAD_VLAN_STRIP |
				DEV_RX_OFFLOAD_IPV4_CKSUM |
				DEV_RX_OFFLOAD_UDP_CKSUM |
				DEV_RX_OFFLOAD_TCP_CKSUM |
				DEV_RX_OFFLOAD_SCTP_CKSUM |
				DEV_RX_OFFLOAD_VLAN_FILTER |
				DEV_RX_OFFLOAD_SCATTER |
				DEV_RX_OFFLOAD_TCP_LRO |
				DEV_RX_OFFLOAD_RSS_HASH;

	info->tx_queue_offload_capa = 0;
	info->tx_offload_capa = DEV_TX_OFFLOAD_VLAN_INSERT |
				DEV_TX_OFFLOAD_IPV4_CKSUM |
				DEV_TX_OFFLOAD_UDP_CKSUM |
				DEV_TX_OFFLOAD_TCP_CKSUM |
				DEV_TX_OFFLOAD_SCTP_CKSUM |
				DEV_TX_OFFLOAD_OUTER_IPV4_CKSUM |
				DEV_TX_OFFLOAD_TCP_TSO |
				DEV_TX_OFFLOAD_MULTI_SEGS;

	info->hash_key_size = SPNIC_RSS_KEY_SIZE;
	info->reta_size = SPNIC_RSS_INDIR_SIZE;
	info->flow_type_rss_offloads = SPNIC_RSS_OFFLOAD_ALL;

	info->rx_desc_lim = spnic_rx_desc_lim;
	info->tx_desc_lim = spnic_tx_desc_lim;

	/* Driver-preferred rx/tx parameters */
	info->default_rxportconf.burst_size = SPNIC_DEFAULT_BURST_SIZE;
	info->default_txportconf.burst_size = SPNIC_DEFAULT_BURST_SIZE;
	info->default_rxportconf.nb_queues = SPNIC_DEFAULT_NB_QUEUES;
	info->default_txportconf.nb_queues = SPNIC_DEFAULT_NB_QUEUES;
	info->default_rxportconf.ring_size = SPNIC_DEFAULT_RING_SIZE;
	info->default_txportconf.ring_size = SPNIC_DEFAULT_RING_SIZE;

	return 0;
}

static int spnic_fw_version_get(struct rte_eth_dev *dev, char *fw_version,
				size_t fw_size)
{
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	char mgmt_ver[MGMT_VERSION_MAX_LEN] = { 0 };
	int err;

	err = spnic_get_mgmt_version(nic_dev->hwdev, mgmt_ver,
				     SPNIC_MGMT_VERSION_MAX_LEN);
	if (err) {
		PMD_DRV_LOG(ERR, "Get fw version failed");
		return -EIO;
	}

	if (fw_size < strlen(mgmt_ver) + 1)
		return (strlen(mgmt_ver) + 1);

	snprintf(fw_version, fw_size, "%s", mgmt_ver);

	return 0;
}

/**
 * Set ethernet device link state up.
 *
 * @param[in] dev
 *   Pointer to ethernet device structure.
 *
 * @retval zero : Success
 * @retval non-zero : Failure.
 */
static int spnic_dev_set_link_up(struct rte_eth_dev *dev)
{
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	int err;

	/* Link status follow phy port status, mpu will open pma */
	err = spnic_set_port_enable(nic_dev->hwdev, true);
	if (err)
		PMD_DRV_LOG(ERR, "Set MAC link up failed, dev_name: %s, port_id: %d",
			    nic_dev->dev_name, dev->data->port_id);

	return err;
}

/**
 * Set ethernet device link state down.
 *
 * @param[in] dev
 *   Pointer to ethernet device structure.
 *
 * @retval zero : Success
 * @retval non-zero : Failure.
 */
static int spnic_dev_set_link_down(struct rte_eth_dev *dev)
{
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	int err;

	/* Link status follow phy port status, mpu will close pma */
	err = spnic_set_port_enable(nic_dev->hwdev, false);
	if (err)
		PMD_DRV_LOG(ERR, "Set MAC link down failed, dev_name: %s, port_id: %d",
			    nic_dev->dev_name, dev->data->port_id);

	return err;
}

/**
 * Get device physical link information.
 *
 * @param[in] dev
 *   Pointer to ethernet device structure.
 * @param[in] wait_to_complete
 *   Wait for request completion.
 *
 * @retval 0 : Link status changed
 * @retval -1 : Link status not changed.
 */
static int spnic_link_update(struct rte_eth_dev *dev, int wait_to_complete)
{
#define CHECK_INTERVAL 10  /* 10ms */
#define MAX_REPEAT_TIME 100  /* 1s (100 * 10ms) in total */
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	struct rte_eth_link link;
	u8 link_state;
	unsigned int rep_cnt = MAX_REPEAT_TIME;
	int ret;

	memset(&link, 0, sizeof(link));
	do {
		/* Get link status information from hardware */
		ret = spnic_get_link_state(nic_dev->hwdev, &link_state);
		if (ret) {
			link.link_status = ETH_LINK_DOWN;
			link.link_speed = ETH_SPEED_NUM_NONE;
			link.link_duplex = ETH_LINK_HALF_DUPLEX;
			link.link_autoneg = ETH_LINK_FIXED;
			goto out;
		}

		spnic_get_port_link_info(nic_dev->hwdev, link_state, &link);

		if (!wait_to_complete || link.link_status)
			break;

		rte_delay_ms(CHECK_INTERVAL);
	} while (rep_cnt--);

out:
	return rte_eth_linkstatus_set(dev, &link);
}

static void spnic_reset_rx_queue(struct rte_eth_dev *dev)
{
	struct spnic_rxq *rxq = NULL;
	struct spnic_nic_dev *nic_dev;
	int q_id = 0;

	nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);

	for (q_id = 0; q_id < nic_dev->num_rqs; q_id++) {
		rxq = nic_dev->rxqs[q_id];

		rxq->cons_idx = 0;
		rxq->prod_idx = 0;
		rxq->delta = rxq->q_depth;
		rxq->next_to_update = 0;
	}
}

static void spnic_reset_tx_queue(struct rte_eth_dev *dev)
{
	struct spnic_nic_dev *nic_dev;
	struct spnic_txq *txq = NULL;
	int q_id = 0;

	nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);

	for (q_id = 0; q_id < nic_dev->num_sqs; q_id++) {
		txq = nic_dev->txqs[q_id];

		txq->cons_idx = 0;
		txq->prod_idx = 0;
		txq->owner = 1;

		/* Clear hardware ci */
		*(u16 *)txq->ci_vaddr_base = 0;
	}
}

/**
 * Create the receive queue.
 *
 * @param[in] dev
 *   Pointer to ethernet device structure.
 * @param[in] qid
 *   Receive queue index.
 * @param[in] nb_desc
 *   Number of descriptors for receive queue.
 * @param[in] socket_id
 *   Socket index on which memory must be allocated.
 * @param rx_conf
 *   Thresholds parameters (unused_).
 * @param mp
 *   Memory pool for buffer allocations.
 *
 * @retval zero : Success
 * @retval non-zero : Failure
 */
static int spnic_rx_queue_setup(struct rte_eth_dev *dev, uint16_t qid,
			uint16_t nb_desc, unsigned int socket_id,
			__rte_unused const struct rte_eth_rxconf *rx_conf,
			struct rte_mempool *mp)
{
	struct spnic_nic_dev *nic_dev;
	struct spnic_rxq *rxq = NULL;
	const struct rte_memzone *rq_mz = NULL;
	const struct rte_memzone *cqe_mz = NULL;
	const struct rte_memzone *pi_mz = NULL;
	u16 rq_depth, rx_free_thresh;
	u32 queue_buf_size, mb_buf_size;
	void *db_addr = NULL;
	int wqe_count;
	u32 buf_size;
	int err;

	nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);

	/* Queue depth must be power of 2, otherwise will be aligned up */
	rq_depth = (nb_desc & (nb_desc - 1)) ?
		   ((u16)(1U << (ilog2(nb_desc) + 1))) : nb_desc;

	/*
	 * Validate number of receive descriptors.
	 * It must not exceed hardware maximum and minimum.
	 */
	if (rq_depth > SPNIC_MAX_QUEUE_DEPTH ||
	    rq_depth < SPNIC_MIN_QUEUE_DEPTH) {
		PMD_DRV_LOG(ERR, "RX queue depth is out of range from %d to %d,"
			    "(nb_desc: %d, q_depth: %d, port: %d queue: %d)",
			    SPNIC_MIN_QUEUE_DEPTH, SPNIC_MAX_QUEUE_DEPTH,
			    (int)nb_desc, (int)rq_depth,
			    (int)dev->data->port_id, (int)qid);
		return -EINVAL;
	}

	/*
	 * The RX descriptor ring will be cleaned after rxq->rx_free_thresh
	 * descriptors are used or if the number of descriptors required
	 * to transmit a packet is greater than the number of free RX
	 * descriptors.
	 * The following constraints must be satisfied:
	 *  -rx_free_thresh must be greater than 0.
	 *  -rx_free_thresh must be less than the size of the ring minus 1.
	 * When set to zero use default values.
	 */
	rx_free_thresh = (u16)((rx_conf->rx_free_thresh) ?
			rx_conf->rx_free_thresh : SPNIC_DEFAULT_RX_FREE_THRESH);
	if (rx_free_thresh >= (rq_depth - 1)) {
		PMD_DRV_LOG(ERR, "rx_free_thresh must be less than the number "
			    "of RX descriptors minus 1, rx_free_thresh: %u port: %d queue: %d)",
			    (unsigned int)rx_free_thresh,
			    (int)dev->data->port_id, (int)qid);
		return -EINVAL;
	}

	rxq = rte_zmalloc_socket("spnic_rq", sizeof(struct spnic_rxq),
				 RTE_CACHE_LINE_SIZE, socket_id);
	if (!rxq) {
		PMD_DRV_LOG(ERR, "Allocate rxq[%d] failed, dev_name: %s",
			    qid, dev->data->name);
		return -ENOMEM;
	}

	/* Init rq parameters */
	rxq->nic_dev = nic_dev;
	nic_dev->rxqs[qid] = rxq;
	rxq->mb_pool = mp;
	rxq->q_id = qid;
	rxq->next_to_update = 0;
	rxq->q_depth = rq_depth;
	rxq->q_mask = rq_depth - 1;
	rxq->delta = rq_depth;
	rxq->cons_idx = 0;
	rxq->prod_idx = 0;
	rxq->wqe_type = SPNIC_NORMAL_RQ_WQE;
	rxq->wqebb_shift = SPNIC_RQ_WQEBB_SHIFT + rxq->wqe_type;
	rxq->wqebb_size = (u16)BIT(rxq->wqebb_shift);
	rxq->rx_free_thresh = rx_free_thresh;
	rxq->rxinfo_align_end = rxq->q_depth - rxq->rx_free_thresh;
	rxq->port_id = dev->data->port_id;

	/* If buf_len used for function table, need to translated */
	mb_buf_size = rte_pktmbuf_data_room_size(rxq->mb_pool) -
		      RTE_PKTMBUF_HEADROOM;
	err = spnic_convert_rx_buf_size(mb_buf_size, &buf_size);
	if (err) {
		PMD_DRV_LOG(ERR, "Adjust buf size failed, dev_name: %s",
			    dev->data->name);
		goto adjust_bufsize_fail;
	}

	rxq->buf_len = buf_size;
	rxq->rx_buff_shift = ilog2(rxq->buf_len);

	pi_mz = rte_eth_dma_zone_reserve(dev, "spnic_rq_pi", qid,
					 RTE_PGSIZE_4K, RTE_CACHE_LINE_SIZE,
					 socket_id);
	if (!pi_mz) {
		PMD_DRV_LOG(ERR, "Allocate rxq[%d] pi_mz failed, dev_name: %s",
			    qid, dev->data->name);
		err = -ENOMEM;
		goto alloc_pi_mz_fail;
	}
	rxq->pi_mz = pi_mz;
	rxq->pi_dma_addr = pi_mz->iova;
	rxq->pi_virt_addr = pi_mz->addr;

	/* Rxq doesn't use direct wqe */
	err = spnic_alloc_db_addr(nic_dev->hwdev, &db_addr, NULL);
	if (err) {
		PMD_DRV_LOG(ERR, "Alloc rq doorbell addr failed");
		goto alloc_db_err_fail;
	}
	rxq->db_addr = db_addr;

	queue_buf_size = BIT(rxq->wqebb_shift) * rq_depth;
	rq_mz = rte_eth_dma_zone_reserve(dev, "spnic_rq_mz", qid,
					 queue_buf_size, RTE_PGSIZE_256K,
					 socket_id);
	if (!rq_mz) {
		PMD_DRV_LOG(ERR, "Allocate rxq[%d] rq_mz failed, dev_name: %s",
			    qid, dev->data->name);
		err = -ENOMEM;
		goto alloc_rq_mz_fail;
	}

	memset(rq_mz->addr, 0, queue_buf_size);
	rxq->rq_mz = rq_mz;
	rxq->queue_buf_paddr = rq_mz->iova;
	rxq->queue_buf_vaddr = rq_mz->addr;

	rxq->rx_info = rte_zmalloc_socket("rx_info",
					  rq_depth * sizeof(*rxq->rx_info),
					  RTE_CACHE_LINE_SIZE, socket_id);
	if (!rxq->rx_info) {
		PMD_DRV_LOG(ERR, "Allocate rx_info failed, dev_name: %s",
			dev->data->name);
		err = -ENOMEM;
		goto alloc_rx_info_fail;
	}

	cqe_mz = rte_eth_dma_zone_reserve(dev, "spnic_cqe_mz", qid,
					  rq_depth * sizeof(*rxq->rx_cqe),
					  RTE_CACHE_LINE_SIZE, socket_id);
	if (!cqe_mz) {
		PMD_DRV_LOG(ERR, "Allocate cqe mem zone failed, dev_name: %s",
			    dev->data->name);
		err = -ENOMEM;
		goto alloc_cqe_mz_fail;
	}
	memset(cqe_mz->addr, 0, rq_depth * sizeof(*rxq->rx_cqe));
	rxq->cqe_mz = cqe_mz;
	rxq->cqe_start_paddr = cqe_mz->iova;
	rxq->cqe_start_vaddr = cqe_mz->addr;
	rxq->rx_cqe = (struct spnic_rq_cqe *)rxq->cqe_start_vaddr;

	wqe_count = spnic_rx_fill_wqe(rxq);
	if (wqe_count != rq_depth) {
		PMD_DRV_LOG(ERR, "Fill rx wqe failed, wqe_count: %d, dev_name: %s",
			    wqe_count, dev->data->name);
		err = -ENOMEM;
		goto fill_rx_wqe_fail;
	}

	/* Record rxq pointer in rte_eth rx_queues */
	dev->data->rx_queues[qid] = rxq;

	return 0;

fill_rx_wqe_fail:
	rte_memzone_free(rxq->cqe_mz);
alloc_cqe_mz_fail:
	rte_free(rxq->rx_info);

alloc_rx_info_fail:
	rte_memzone_free(rxq->rq_mz);

alloc_rq_mz_fail:
	spnic_free_db_addr(nic_dev->hwdev, rxq->db_addr, NULL);

alloc_db_err_fail:
	rte_memzone_free(rxq->pi_mz);

alloc_pi_mz_fail:
adjust_bufsize_fail:

	rte_free(rxq);
	nic_dev->rxqs[qid] = NULL;

	return err;
}

/**
 * Create the transmit queue.
 *
 * @param[in] dev
 *   Pointer to ethernet device structure.
 * @param[in] queue_idx
 *   Transmit queue index.
 * @param[in] nb_desc
 *   Number of descriptors for transmit queue.
 * @param[in] socket_id
 *   Socket index on which memory must be allocated.
 * @param[in] tx_conf
 *   Tx queue configuration parameters (unused_).
 *
 * @retval zero : Success
 * @retval non-zero : Failure
 */
static int spnic_tx_queue_setup(struct rte_eth_dev *dev, uint16_t qid,
			 uint16_t nb_desc, unsigned int socket_id,
			 __rte_unused const struct rte_eth_txconf *tx_conf)
{
	struct spnic_nic_dev *nic_dev;
	struct spnic_hwdev *hwdev;
	struct spnic_txq *txq = NULL;
	const struct rte_memzone *sq_mz = NULL;
	const struct rte_memzone *ci_mz = NULL;
	void *db_addr = NULL;
	u16 sq_depth, tx_free_thresh;
	u32 queue_buf_size;
	int err;

	nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	hwdev = nic_dev->hwdev;

	/* Queue depth must be power of 2, otherwise will be aligned up */
	sq_depth = (nb_desc & (nb_desc - 1)) ?
		   ((u16)(1U << (ilog2(nb_desc) + 1))) : nb_desc;

	/*
	 * Validate number of transmit descriptors.
	 * It must not exceed hardware maximum and minimum.
	 */
	if (sq_depth > SPNIC_MAX_QUEUE_DEPTH ||
		sq_depth < SPNIC_MIN_QUEUE_DEPTH) {
		PMD_DRV_LOG(ERR, "TX queue depth is out of range from %d to %d,"
			    "(nb_desc: %d, q_depth: %d, port: %d queue: %d)",
			    SPNIC_MIN_QUEUE_DEPTH, SPNIC_MAX_QUEUE_DEPTH,
			    (int)nb_desc, (int)sq_depth,
			    (int)dev->data->port_id, (int)qid);
		return -EINVAL;
	}

	/*
	 * The TX descriptor ring will be cleaned after txq->tx_free_thresh
	 * descriptors are used or if the number of descriptors required
	 * to transmit a packet is greater than the number of free TX
	 * descriptors.
	 * The following constraints must be satisfied:
	 *  -tx_free_thresh must be greater than 0.
	 *  -tx_free_thresh must be less than the size of the ring minus 1.
	 * When set to zero use default values.
	 */
	tx_free_thresh = (u16)((tx_conf->tx_free_thresh) ?
		tx_conf->tx_free_thresh : SPNIC_DEFAULT_TX_FREE_THRESH);
	if (tx_free_thresh >= (sq_depth - 1)) {
		PMD_DRV_LOG(ERR, "tx_free_thresh must be less than the number of tx "
			    "descriptors minus 1, tx_free_thresh: %u port: %d queue: %d",
			    (unsigned int)tx_free_thresh,
			    (int)dev->data->port_id, (int)qid);
		return -EINVAL;
	}

	txq = rte_zmalloc_socket("spnic_tx_queue", sizeof(struct spnic_txq),
				 RTE_CACHE_LINE_SIZE, socket_id);
	if (!txq) {
		PMD_DRV_LOG(ERR, "Allocate txq[%d] failed, dev_name: %s",
			    qid, dev->data->name);
		return -ENOMEM;
	}
	nic_dev->txqs[qid] = txq;
	txq->nic_dev = nic_dev;
	txq->q_id = qid;
	txq->q_depth = sq_depth;
	txq->q_mask = sq_depth - 1;
	txq->cons_idx = 0;
	txq->prod_idx = 0;
	txq->wqebb_shift = SPNIC_SQ_WQEBB_SHIFT;
	txq->wqebb_size = (u16)BIT(txq->wqebb_shift);
	txq->tx_free_thresh = tx_free_thresh;
	txq->owner = 1;
	txq->cos = nic_dev->default_cos;

	ci_mz = rte_eth_dma_zone_reserve(dev, "spnic_sq_ci", qid,
					 SPNIC_CI_Q_ADDR_SIZE,
					 SPNIC_CI_Q_ADDR_SIZE, socket_id);
	if (!ci_mz) {
		PMD_DRV_LOG(ERR, "Allocate txq[%d] ci_mz failed, dev_name: %s",
			    qid, dev->data->name);
		err = -ENOMEM;
		goto alloc_ci_mz_fail;
	}
	txq->ci_mz = ci_mz;
	txq->ci_dma_base = ci_mz->iova;
	txq->ci_vaddr_base = ci_mz->addr;

	queue_buf_size = BIT(txq->wqebb_shift) * sq_depth;
	sq_mz = rte_eth_dma_zone_reserve(dev, "spnic_sq_mz", qid,
					 queue_buf_size, RTE_PGSIZE_256K,
					 socket_id);
	if (!sq_mz) {
		PMD_DRV_LOG(ERR, "Allocate txq[%d] sq_mz failed, dev_name: %s",
			    qid, dev->data->name);
		err = -ENOMEM;
		goto alloc_sq_mz_fail;
	}
	memset(sq_mz->addr, 0, queue_buf_size);
	txq->sq_mz = sq_mz;
	txq->queue_buf_paddr = sq_mz->iova;
	txq->queue_buf_vaddr = sq_mz->addr;
	txq->sq_head_addr = (u64)txq->queue_buf_vaddr;
	txq->sq_bot_sge_addr = txq->sq_head_addr + queue_buf_size;

	/* Sq doesn't use direct wqe */
	err = spnic_alloc_db_addr(hwdev, &db_addr, NULL);
	if (err) {
		PMD_DRV_LOG(ERR, "Alloc sq doorbell addr failed");
		goto alloc_db_err_fail;
	}
	txq->db_addr = db_addr;

	txq->tx_info = rte_zmalloc_socket("tx_info",
					  sq_depth * sizeof(*txq->tx_info),
					  RTE_CACHE_LINE_SIZE, socket_id);
	if (!txq->tx_info) {
		PMD_DRV_LOG(ERR, "Allocate tx_info failed, dev_name: %s",
			    dev->data->name);
		err = -ENOMEM;
		goto alloc_tx_info_fail;
	}

	/* Record txq pointer in rte_eth tx_queues */
	dev->data->tx_queues[qid] = txq;

	return 0;

alloc_tx_info_fail:
	spnic_free_db_addr(hwdev, txq->db_addr, NULL);

alloc_db_err_fail:
	rte_memzone_free(txq->sq_mz);

alloc_sq_mz_fail:
	rte_memzone_free(txq->ci_mz);

alloc_ci_mz_fail:
	rte_free(txq);

	return err;
}

static void spnic_rx_queue_release(struct rte_eth_dev *dev, uint16_t qid)
{
	struct spnic_rxq *rxq = dev->data->rx_queues[qid];
	struct spnic_nic_dev *nic_dev;

	if (!rxq) {
		PMD_DRV_LOG(WARNING, "Rxq is null when release");
		return;
	}
	nic_dev = rxq->nic_dev;

	spnic_free_rxq_mbufs(rxq);

	rte_memzone_free(rxq->cqe_mz);

	rte_free(rxq->rx_info);

	rte_memzone_free(rxq->rq_mz);

	rte_memzone_free(rxq->pi_mz);

	nic_dev->rxqs[rxq->q_id] = NULL;
	rte_free(rxq);
}

static void spnic_tx_queue_release(struct rte_eth_dev *dev, uint16_t qid)
{
	struct spnic_txq *txq = dev->data->tx_queues[qid];
	struct spnic_nic_dev *nic_dev;

	if (!txq) {
		PMD_DRV_LOG(WARNING, "Txq is null when release");
		return;
	}
	nic_dev = txq->nic_dev;

	spnic_free_txq_mbufs(txq);

	rte_free(txq->tx_info);
	txq->tx_info = NULL;

	spnic_free_db_addr(nic_dev->hwdev, txq->db_addr, NULL);

	rte_memzone_free(txq->sq_mz);

	rte_memzone_free(txq->ci_mz);

	nic_dev->txqs[txq->q_id] = NULL;
	rte_free(txq);
}

static void spnic_delete_mc_addr_list(struct spnic_nic_dev *nic_dev);

/**
 * Deinit mac_vlan table in hardware.
 *
 * @param[in] eth_dev
 *   Pointer to ethernet device structure.
 */
static void spnic_deinit_mac_addr(struct rte_eth_dev *eth_dev)
{
	struct spnic_nic_dev *nic_dev =
				SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(eth_dev);
	u16 func_id = 0;
	int err;
	int i;

	func_id = spnic_global_func_id(nic_dev->hwdev);

	for (i = 0; i < SPNIC_MAX_UC_MAC_ADDRS; i++) {
		if (rte_is_zero_ether_addr(&eth_dev->data->mac_addrs[i]))
			continue;

		err = spnic_del_mac(nic_dev->hwdev,
				    eth_dev->data->mac_addrs[i].addr_bytes,
				    0, func_id);
		if (err && err != SPNIC_PF_SET_VF_ALREADY)
			PMD_DRV_LOG(ERR, "Delete mac table failed, dev_name: %s",
				    eth_dev->data->name);

		memset(&eth_dev->data->mac_addrs[i], 0,
		       sizeof(struct rte_ether_addr));
	}

	/* Delete multicast mac addrs */
	spnic_delete_mc_addr_list(nic_dev);
}

static int spnic_set_rxtx_configure(struct rte_eth_dev *dev)
{
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	struct rte_eth_conf *dev_conf = &dev->data->dev_conf;
	struct rte_eth_rss_conf *rss_conf = NULL;
	bool lro_en, vlan_filter, vlan_strip;
	int max_lro_size, lro_max_pkt_len;
	int err;

	/* Config rx mode */
	err = spnic_set_rx_mode(nic_dev->hwdev, SPNIC_DEFAULT_RX_MODE);
	if (err) {
		PMD_DRV_LOG(ERR, "Set rx_mode: 0x%x failed",
			    SPNIC_DEFAULT_RX_MODE);
		return err;
	}
	nic_dev->rx_mode = SPNIC_DEFAULT_RX_MODE;

	/* Config rx checksum offload */
	if (dev_conf->rxmode.offloads & DEV_RX_OFFLOAD_CHECKSUM)
		nic_dev->rx_csum_en = SPNIC_DEFAULT_RX_CSUM_OFFLOAD;

	/* Config lro */
	lro_en = dev_conf->rxmode.offloads & DEV_RX_OFFLOAD_TCP_LRO ?
		 true : false;
	max_lro_size = dev->data->dev_conf.rxmode.max_lro_pkt_size;
	lro_max_pkt_len = max_lro_size / SPNIC_LRO_UNIT_WQE_SIZE ?
			  max_lro_size / SPNIC_LRO_UNIT_WQE_SIZE : 1;

	PMD_DRV_LOG(INFO, "max_lro_size: %d, rx_buff_len: %d, lro_max_pkt_len: %d mtu: %d",
		    max_lro_size, nic_dev->rx_buff_len, lro_max_pkt_len,
		    dev->data->dev_conf.rxmode.mtu);

	err = spnic_set_rx_lro_state(nic_dev->hwdev, lro_en,
				     SPNIC_LRO_DEFAULT_TIME_LIMIT,
				     lro_max_pkt_len);
	if (err) {
		PMD_DRV_LOG(ERR, "Set lro state failed, err: %d", err);
		return err;
	}

	/* Config RSS */
	if ((dev_conf->rxmode.mq_mode & ETH_MQ_RX_RSS_FLAG) &&
	    nic_dev->num_rqs > 1) {
		rss_conf = &dev_conf->rx_adv_conf.rss_conf;
		err = spnic_update_rss_config(dev, rss_conf);
		if (err) {
			PMD_DRV_LOG(ERR, "Set rss config failed, err: %d", err);
			return err;
		}
	}

	/* Config vlan filter */
	vlan_filter = dev_conf->rxmode.offloads & DEV_RX_OFFLOAD_VLAN_FILTER ?
		      true : false;

	err = spnic_set_vlan_fliter(nic_dev->hwdev, vlan_filter);
	if (err) {
		PMD_DRV_LOG(ERR, "Config vlan filter failed, device: %s, port_id: %d, err: %d",
			    nic_dev->dev_name, dev->data->port_id, err);
		return err;
	}

	/* Config vlan stripping */
	vlan_strip = dev_conf->rxmode.offloads & DEV_RX_OFFLOAD_VLAN_STRIP ?
		     true : false;

	err = spnic_set_rx_vlan_offload(nic_dev->hwdev, vlan_strip);
	if (err) {
		PMD_DRV_LOG(ERR, "Config vlan strip failed, device: %s, port_id: %d, err: %d",
			    nic_dev->dev_name, dev->data->port_id, err);
		return err;
	}

	spnic_init_rx_queue_list(nic_dev);

	return 0;
}

static void spnic_remove_rxtx_configure(struct rte_eth_dev *dev)
{
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	u8 prio_tc[SPNIC_DCB_UP_MAX] = {0};

	spnic_set_rx_mode(nic_dev->hwdev, 0);

	if (nic_dev->rss_state == SPNIC_RSS_ENABLE) {
		spnic_rss_cfg(nic_dev->hwdev, SPNIC_RSS_DISABLE, 0, prio_tc);
		spnic_rss_template_free(nic_dev->hwdev);
	}
}

static bool spnic_find_vlan_filter(struct spnic_nic_dev *nic_dev,
				   uint16_t vlan_id)
{
	u32 vid_idx, vid_bit;

	vid_idx = SPNIC_VFTA_IDX(vlan_id);
	vid_bit = SPNIC_VFTA_BIT(vlan_id);

	return (nic_dev->vfta[vid_idx] & vid_bit) ? true : false;
}

static void spnic_store_vlan_filter(struct spnic_nic_dev *nic_dev,
				    u16 vlan_id, bool on)
{
	u32 vid_idx, vid_bit;

	vid_idx = SPNIC_VFTA_IDX(vlan_id);
	vid_bit = SPNIC_VFTA_BIT(vlan_id);

	if (on)
		nic_dev->vfta[vid_idx] |= vid_bit;
	else
		nic_dev->vfta[vid_idx] &= ~vid_bit;
}

static void spnic_remove_all_vlanid(struct rte_eth_dev *dev)
{
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	int vlan_id;
	u16 func_id;

	func_id = spnic_global_func_id(nic_dev->hwdev);

	for (vlan_id = 1; vlan_id < RTE_ETHER_MAX_VLAN_ID; vlan_id++) {
		if (spnic_find_vlan_filter(nic_dev, vlan_id)) {
			spnic_del_vlan(nic_dev->hwdev, vlan_id, func_id);
			spnic_store_vlan_filter(nic_dev, vlan_id, false);
		}
	}
}

static int spnic_init_sw_rxtxqs(struct spnic_nic_dev *nic_dev)
{
	u32 txq_size;
	u32 rxq_size;

	/* Allocate software txq array */
	txq_size = nic_dev->max_sqs * sizeof(*nic_dev->txqs);
	nic_dev->txqs = rte_zmalloc("spnic_txqs", txq_size,
				    RTE_CACHE_LINE_SIZE);
	if (!nic_dev->txqs) {
		PMD_DRV_LOG(ERR, "Allocate txqs failed");
		return -ENOMEM;
	}

	/* Allocate software rxq array */
	rxq_size = nic_dev->max_rqs * sizeof(*nic_dev->rxqs);
	nic_dev->rxqs = rte_zmalloc("spnic_rxqs", rxq_size,
				    RTE_CACHE_LINE_SIZE);
	if (!nic_dev->rxqs) {
		/* Free txqs */
		rte_free(nic_dev->txqs);
		nic_dev->txqs = NULL;

		PMD_DRV_LOG(ERR, "Allocate rxqs failed");
		return -ENOMEM;
	}

	return 0;
}

static void spnic_deinit_sw_rxtxqs(struct spnic_nic_dev *nic_dev)
{
	rte_free(nic_dev->txqs);
	nic_dev->txqs = NULL;

	rte_free(nic_dev->rxqs);
	nic_dev->rxqs = NULL;
}

/**
 * Start the device.
 *
 * Initialize function table, rxq and txq context, config rx offload, and enable
 * vport and port to prepare receiving packets.
 *
 * @param[in] eth_dev
 *   Pointer to ethernet device structure.
 *
 * @retval zero : Success
 * @retval non-zero : Failure
 */
static int spnic_dev_start(struct rte_eth_dev *eth_dev)
{
	struct spnic_nic_dev *nic_dev;
	struct spnic_rxq *rxq = NULL;
	u64 nic_features;
	int err;
	u16 i;

	nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(eth_dev);

	spnic_get_func_rx_buf_size(nic_dev);
	err = spnic_init_function_table(nic_dev->hwdev, nic_dev->rx_buff_len);
	if (err) {
		PMD_DRV_LOG(ERR, "Init function table failed, dev_name: %s",
			    eth_dev->data->name);
		goto init_func_tbl_fail;
	}

	nic_features = spnic_get_driver_feature(nic_dev->hwdev);
	nic_features &= DEFAULT_DRV_FEATURE;
	spnic_update_driver_feature(nic_dev->hwdev, nic_features);

	err = spnic_set_feature_to_hw(nic_dev->hwdev, &nic_dev->feature_cap, 1);
	if (err) {
		PMD_DRV_LOG(ERR, "Failed to set nic features to hardware, err %d\n",
			    err);
		goto get_feature_err;
	}

	/* reset rx and tx queue */
	spnic_reset_rx_queue(eth_dev);
	spnic_reset_tx_queue(eth_dev);

	/* Init txq and rxq context */
	err = spnic_init_qp_ctxts(nic_dev);
	if (err) {
		PMD_DRV_LOG(ERR, "Init qp context failed, dev_name: %s",
			    eth_dev->data->name);
		goto init_qp_fail;
	}

	/* Set default mtu */
	err = spnic_set_port_mtu(nic_dev->hwdev, nic_dev->mtu_size);
	if (err) {
		PMD_DRV_LOG(ERR, "Set mtu_size[%d] failed, dev_name: %s",
			    nic_dev->mtu_size, eth_dev->data->name);
		goto set_mtu_fail;
	}

	/* Set rx configuration: rss/checksum/rxmode/lro */
	err = spnic_set_rxtx_configure(eth_dev);
	if (err) {
		PMD_DRV_LOG(ERR, "Set rx config failed, dev_name: %s",
			    eth_dev->data->name);
		goto set_rxtx_config_fail;
	}

	err = spnic_start_all_rqs(eth_dev);
	if (err) {
		PMD_DRV_LOG(ERR, "Set rx config failed, dev_name: %s",
			    eth_dev->data->name);
		goto start_rqs_fail;
	}

	spnic_start_all_sqs(eth_dev);

	/* Open virtual port and ready to start packet receiving */
	err = spnic_set_vport_enable(nic_dev->hwdev, true);
	if (err) {
		PMD_DRV_LOG(ERR, "Enable vport failed, dev_name: %s",
			    eth_dev->data->name);
		goto en_vport_fail;
	}

	/* Open physical port and start packet receiving */
	err = spnic_set_port_enable(nic_dev->hwdev, true);
	if (err) {
		PMD_DRV_LOG(ERR, "Enable physical port failed, dev_name: %s",
			    eth_dev->data->name);
		goto en_port_fail;
	}

	/* Update eth_dev link status */
	if (eth_dev->data->dev_conf.intr_conf.lsc != 0)
		(void)spnic_link_update(eth_dev, 0);

	rte_bit_relaxed_set32(SPNIC_DEV_START, &nic_dev->dev_status);

	return 0;

en_port_fail:
	(void)spnic_set_vport_enable(nic_dev->hwdev, false);

en_vport_fail:
	/* Flush tx && rx chip resources in case of setting vport fake fail */
	(void)spnic_flush_qps_res(nic_dev->hwdev);
	rte_delay_ms(100);
	for (i = 0; i < nic_dev->num_rqs; i++) {
		rxq = nic_dev->rxqs[i];
		spnic_remove_rq_from_rx_queue_list(nic_dev, rxq->q_id);
		spnic_free_rxq_mbufs(rxq);
		eth_dev->data->rx_queue_state[i] = RTE_ETH_QUEUE_STATE_STOPPED;
		eth_dev->data->tx_queue_state[i] = RTE_ETH_QUEUE_STATE_STOPPED;
	}
start_rqs_fail:
	spnic_remove_rxtx_configure(eth_dev);

set_rxtx_config_fail:
set_mtu_fail:
	spnic_free_qp_ctxts(nic_dev->hwdev);

init_qp_fail:
get_feature_err:
init_func_tbl_fail:

	return err;
}

static int spnic_copy_mempool_init(struct spnic_nic_dev *nic_dev)
{
	nic_dev->cpy_mpool = rte_mempool_lookup(nic_dev->dev_name);
	if (nic_dev->cpy_mpool == NULL) {
		nic_dev->cpy_mpool =
		rte_pktmbuf_pool_create(nic_dev->dev_name,
					SPNIC_COPY_MEMPOOL_DEPTH, 0, 0,
					SPNIC_COPY_MBUF_SIZE, rte_socket_id());
		if (nic_dev->cpy_mpool == NULL) {
			PMD_DRV_LOG(ERR, "Create copy mempool failed, errno: %d, dev_name: %s",
				    rte_errno, nic_dev->dev_name);
			return -ENOMEM;
		}
	}

	return 0;
}

static void spnic_copy_mempool_uninit(struct spnic_nic_dev *nic_dev)
{
	if (nic_dev->cpy_mpool != NULL) {
		rte_mempool_free(nic_dev->cpy_mpool);
		nic_dev->cpy_mpool = NULL;
	}
}

/**
 * Stop the device.
 *
 * Stop phy port and vport, flush pending io request, clean context configure
 * and free io resourece.
 *
 * @param[in] dev
 *   Pointer to ethernet device structure.
 */
static int spnic_dev_stop(struct rte_eth_dev *dev)
{
	struct spnic_nic_dev *nic_dev;
	struct rte_eth_link link;
	int err;

	nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	if (!nic_dev || !spnic_support_nic(nic_dev->hwdev))
		return 0;

	if (!rte_bit_relaxed_test_and_clear32(SPNIC_DEV_START, &nic_dev->dev_status)) {
		PMD_DRV_LOG(INFO, "Device %s already stopped",
			    nic_dev->dev_name);
		return 0;
	}

	/* Stop phy port and vport */
	err = spnic_set_port_enable(nic_dev->hwdev, false);
	if (err)
		PMD_DRV_LOG(WARNING, "Disable phy port failed, error: %d, "
			    "dev_name: %s, port_id: %d", err, dev->data->name,
			    dev->data->port_id);

	err = spnic_set_vport_enable(nic_dev->hwdev, false);
	if (err)
		PMD_DRV_LOG(WARNING, "Disable vport failed, error: %d, "
			    "dev_name: %s, port_id: %d", err, dev->data->name,
			    dev->data->port_id);

	/* Clear recorded link status */
	memset(&link, 0, sizeof(link));
	(void)rte_eth_linkstatus_set(dev, &link);

	/* Flush pending io request */
	spnic_flush_txqs(nic_dev);

	spnic_flush_qps_res(nic_dev->hwdev);

	/*
	 * After set vport disable 100ms, no packets will be send to host
	 */
	rte_delay_ms(100);

	/* Clean RSS table and rx_mode */
	spnic_remove_rxtx_configure(dev);

	/* Clean root context */
	spnic_free_qp_ctxts(nic_dev->hwdev);

	/* Free all tx and rx mbufs */
	spnic_free_all_txq_mbufs(nic_dev);
	spnic_free_all_rxq_mbufs(nic_dev);

	return 0;
}

/**
 * Close the device.
 *
 * @param[in] dev
 *   Pointer to ethernet device structure.
 */
static int spnic_dev_close(struct rte_eth_dev *eth_dev)
{
	struct spnic_nic_dev *nic_dev =
	SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(eth_dev);
	int qid;

	if (rte_bit_relaxed_test_and_set32(SPNIC_DEV_CLOSE, &nic_dev->dev_status)) {
		PMD_DRV_LOG(WARNING, "Device %s already closed",
			    nic_dev->dev_name);
		return 0;
	}

	spnic_dev_stop(eth_dev);

	/* Release io resource */
	for (qid = 0; qid < nic_dev->num_sqs; qid++)
		spnic_tx_queue_release(eth_dev, qid);

	for (qid = 0; qid < nic_dev->num_rqs; qid++)
		spnic_rx_queue_release(eth_dev, qid);

	spnic_copy_mempool_uninit(nic_dev);
	spnic_deinit_sw_rxtxqs(nic_dev);
	spnic_deinit_mac_addr(eth_dev);
	rte_free(nic_dev->mc_list);
	spnic_remove_all_vlanid(eth_dev);

	rte_bit_relaxed_clear32(SPNIC_DEV_INTR_EN, &nic_dev->dev_status);

	/* Destroy rx mode mutex */
	spnic_mutex_destroy(&nic_dev->rx_mode_mutex);

	spnic_free_nic_hwdev(nic_dev->hwdev);
	spnic_free_hwdev(nic_dev->hwdev);

	eth_dev->rx_pkt_burst = NULL;
	eth_dev->tx_pkt_burst = NULL;
	eth_dev->dev_ops = NULL;

	rte_free(nic_dev->hwdev);
	nic_dev->hwdev = NULL;

	return 0;
}

static int spnic_dev_set_mtu(struct rte_eth_dev *dev, uint16_t mtu)
{
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	int err = 0;

	PMD_DRV_LOG(INFO, "Set port mtu, port_id: %d, mtu: %d, max_pkt_len: %d",
		    dev->data->port_id, mtu, SPNIC_MTU_TO_PKTLEN(mtu));

	if (mtu < SPNIC_MIN_MTU_SIZE || mtu > SPNIC_MAX_MTU_SIZE) {
		PMD_DRV_LOG(ERR, "Invalid mtu: %d, must between %d and %d",
			    mtu, SPNIC_MIN_MTU_SIZE, SPNIC_MAX_MTU_SIZE);
		return -EINVAL;
	}

	err = spnic_set_port_mtu(nic_dev->hwdev, mtu);
	if (err) {
		PMD_DRV_LOG(ERR, "Set port mtu failed, err: %d", err);
		return err;
	}

	/* Update max frame size */
	dev->data->dev_conf.rxmode.mtu = SPNIC_MTU_TO_PKTLEN(mtu);
	nic_dev->mtu_size = mtu;

	return err;
}

/**
 * Add or delete vlan id.
 *
 * @param[in] dev
 *   Pointer to ethernet device structure.
 * @param[in] vlan_id
 *   Vlan id is used to filter vlan packets
 * @param[in] enable
 *   Disable or enable vlan filter function
 *
 * @retval zero: Success
 * @retval non-zero: Failure
 */
static int spnic_vlan_filter_set(struct rte_eth_dev *dev, uint16_t vlan_id,
				 int enable)
{
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	int err = 0;
	u16 func_id;

	if (vlan_id >= RTE_ETHER_MAX_VLAN_ID)
		return -EINVAL;

	if (vlan_id == 0)
		return 0;

	func_id = spnic_global_func_id(nic_dev->hwdev);

	if (enable) {
		/* If vlanid is already set, just return */
		if (spnic_find_vlan_filter(nic_dev, vlan_id)) {
			PMD_DRV_LOG(INFO, "Vlan %u has been added, device: %s",
				    vlan_id, nic_dev->dev_name);
			return 0;
		}

		err = spnic_add_vlan(nic_dev->hwdev, vlan_id, func_id);
	} else {
		/* If vlanid can't be found, just return */
		if (!spnic_find_vlan_filter(nic_dev, vlan_id)) {
			PMD_DRV_LOG(INFO, "Vlan %u is not in the vlan filter list, device: %s",
				    vlan_id, nic_dev->dev_name);
			return 0;
		}

		err = spnic_del_vlan(nic_dev->hwdev, vlan_id, func_id);
	}

	if (err) {
		PMD_DRV_LOG(ERR, "%s vlan failed, func_id: %d, vlan_id: %d, err: %d",
			    enable ? "Add" : "Remove", func_id, vlan_id, err);
		return err;
	}

	spnic_store_vlan_filter(nic_dev, vlan_id, enable);

	PMD_DRV_LOG(INFO, "%s vlan %u succeed, device: %s",
		    enable ? "Add" : "Remove", vlan_id, nic_dev->dev_name);

	return 0;
}

/**
 * Enable or disable vlan offload.
 *
 * @param[in] dev
 *   Pointer to ethernet device structure.
 * @param[in] mask
 *   Definitions used for VLAN setting, vlan filter of vlan strip
 *
 * @retval zero: Success
 * @retval non-zero: Failure
 */
static int spnic_vlan_offload_set(struct rte_eth_dev *dev, int mask)
{
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	struct rte_eth_rxmode *rxmode = &dev->data->dev_conf.rxmode;
	bool on;
	int err;

	/* Enable or disable VLAN filter */
	if (mask & ETH_VLAN_FILTER_MASK) {
		on = (rxmode->offloads & DEV_RX_OFFLOAD_VLAN_FILTER) ?
		     true : false;
		err = spnic_set_vlan_fliter(nic_dev->hwdev, on);
		if (err) {
			PMD_DRV_LOG(ERR, "%s vlan filter failed, device: %s, port_id: %d, err: %d",
				    on ? "Enable" : "Disable",
				    nic_dev->dev_name, dev->data->port_id, err);
			return err;
		}

		PMD_DRV_LOG(INFO, "%s vlan filter succeed, device: %s, port_id: %d",
			    on ? "Enable" : "Disable",
			    nic_dev->dev_name, dev->data->port_id);
	}

	/* Enable or disable VLAN stripping */
	if (mask & ETH_VLAN_STRIP_MASK) {
		on = (rxmode->offloads & DEV_RX_OFFLOAD_VLAN_STRIP) ?
		     true : false;
		err = spnic_set_rx_vlan_offload(nic_dev->hwdev, on);
		if (err) {
			PMD_DRV_LOG(ERR, "%s vlan strip failed, device: %s, port_id: %d, err: %d",
				    on ? "Enable" : "Disable",
				    nic_dev->dev_name, dev->data->port_id, err);
			return err;
		}

		PMD_DRV_LOG(INFO, "%s vlan strip succeed, device: %s, port_id: %d",
			    on ? "Enable" : "Disable",
			    nic_dev->dev_name, dev->data->port_id);
	}

	return 0;
}

/**
 * Enable allmulticast mode.
 *
 * @param[in] dev
 *   Pointer to ethernet device structure.
 *
 * @retval zero: Success
 * @retval non-zero: Failure
 */
static int spnic_dev_allmulticast_enable(struct rte_eth_dev *dev)
{
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	u32 rx_mode;
	int err;

	err = spnic_mutex_lock(&nic_dev->rx_mode_mutex);
	if (err)
		return err;

	rx_mode = nic_dev->rx_mode | SPNIC_RX_MODE_MC_ALL;

	err = spnic_set_rx_mode(nic_dev->hwdev, rx_mode);
	if (err) {
		(void)spnic_mutex_unlock(&nic_dev->rx_mode_mutex);
		PMD_DRV_LOG(ERR, "Enable allmulticast failed, error: %d", err);
		return err;
	}

	nic_dev->rx_mode = rx_mode;

	(void)spnic_mutex_unlock(&nic_dev->rx_mode_mutex);

	PMD_DRV_LOG(INFO, "Enable allmulticast succeed, nic_dev: %s, port_id: %d",
		    nic_dev->dev_name, dev->data->port_id);
	return 0;
}

/**
 * Disable allmulticast mode.
 *
 * @param[in] dev
 *   Pointer to ethernet device structure.
 *
 * @retval zero: Success
 * @retval non-zero: Failure
 */
static int spnic_dev_allmulticast_disable(struct rte_eth_dev *dev)
{
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	u32 rx_mode;
	int err;

	err = spnic_mutex_lock(&nic_dev->rx_mode_mutex);
	if (err)
		return err;

	rx_mode = nic_dev->rx_mode & (~SPNIC_RX_MODE_MC_ALL);

	err = spnic_set_rx_mode(nic_dev->hwdev, rx_mode);
	if (err) {
		(void)spnic_mutex_unlock(&nic_dev->rx_mode_mutex);
		PMD_DRV_LOG(ERR, "Disable allmulticast failed, error: %d", err);
		return err;
	}

	nic_dev->rx_mode = rx_mode;

	(void)spnic_mutex_unlock(&nic_dev->rx_mode_mutex);

	PMD_DRV_LOG(INFO, "Disable allmulticast succeed, nic_dev: %s, port_id: %d",
		    nic_dev->dev_name, dev->data->port_id);
	return 0;
}

/**
 * Enable promiscuous mode.
 *
 * @param[in] dev
 *   Pointer to ethernet device structure.
 *
 * @retval zero: Success
 * @retval non-zero: Failure
 */
static int spnic_dev_promiscuous_enable(struct rte_eth_dev *dev)
{
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	u32 rx_mode;
	int err;

	err = spnic_mutex_lock(&nic_dev->rx_mode_mutex);
	if (err)
		return err;

	rx_mode = nic_dev->rx_mode | SPNIC_RX_MODE_PROMISC;

	err = spnic_set_rx_mode(nic_dev->hwdev, rx_mode);
	if (err) {
		(void)spnic_mutex_unlock(&nic_dev->rx_mode_mutex);
		PMD_DRV_LOG(ERR, "Enable promiscuous failed");
		return err;
	}

	nic_dev->rx_mode = rx_mode;

	(void)spnic_mutex_unlock(&nic_dev->rx_mode_mutex);

	PMD_DRV_LOG(INFO, "Enable promiscuous, nic_dev: %s, port_id: %d, promisc: %d",
		    nic_dev->dev_name, dev->data->port_id,
		    dev->data->promiscuous);
	return 0;
}

/**
 * Disable promiscuous mode.
 *
 * @param[in] dev
 *   Pointer to ethernet device structure.
 *
 * @retval zero: Success
 * @retval non-zero: Failure
 */
static int spnic_dev_promiscuous_disable(struct rte_eth_dev *dev)
{
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	u32 rx_mode;
	int err;

	err = spnic_mutex_lock(&nic_dev->rx_mode_mutex);
	if (err)
		return err;

	rx_mode = nic_dev->rx_mode & (~SPNIC_RX_MODE_PROMISC);

	err = spnic_set_rx_mode(nic_dev->hwdev, rx_mode);
	if (err) {
		(void)spnic_mutex_unlock(&nic_dev->rx_mode_mutex);
		PMD_DRV_LOG(ERR, "Disable promiscuous failed");
		return err;
	}

	nic_dev->rx_mode = rx_mode;

	(void)spnic_mutex_unlock(&nic_dev->rx_mode_mutex);

	PMD_DRV_LOG(INFO, "Disable promiscuous, nic_dev: %s, port_id: %d, promisc: %d",
		    nic_dev->dev_name, dev->data->port_id,
		    dev->data->promiscuous);
	return 0;
}

static int spnic_dev_flow_ctrl_get(struct rte_eth_dev *dev,
				   struct rte_eth_fc_conf *fc_conf)
{
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	struct nic_pause_config nic_pause;
	int err;

	err = spnic_mutex_lock(&nic_dev->pause_mutuex);
	if (err)
		return err;

	memset(&nic_pause, 0, sizeof(nic_pause));
	err = spnic_get_pause_info(nic_dev->hwdev, &nic_pause);
	if (err) {
		(void)spnic_mutex_unlock(&nic_dev->pause_mutuex);
		return err;
	}

	if (nic_dev->pause_set || !nic_pause.auto_neg) {
		nic_pause.rx_pause = nic_dev->nic_pause.rx_pause;
		nic_pause.tx_pause = nic_dev->nic_pause.tx_pause;
	}

	fc_conf->autoneg = nic_pause.auto_neg;

	if (nic_pause.tx_pause && nic_pause.rx_pause)
		fc_conf->mode = RTE_FC_FULL;
	else if (nic_pause.tx_pause)
		fc_conf->mode = RTE_FC_TX_PAUSE;
	else if (nic_pause.rx_pause)
		fc_conf->mode = RTE_FC_RX_PAUSE;
	else
		fc_conf->mode = RTE_FC_NONE;

	(void)spnic_mutex_unlock(&nic_dev->pause_mutuex);
	return 0;
}

static int spnic_dev_flow_ctrl_set(struct rte_eth_dev *dev,
				   struct rte_eth_fc_conf *fc_conf)
{
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	struct nic_pause_config nic_pause;
	int err;

	err = spnic_mutex_lock(&nic_dev->pause_mutuex);
	if (err)
		return err;

	memset(&nic_pause, 0, sizeof(nic_pause));
	if (((fc_conf->mode & RTE_FC_FULL) == RTE_FC_FULL) ||
	    (fc_conf->mode & RTE_FC_TX_PAUSE))
		nic_pause.tx_pause = true;

	if (((fc_conf->mode & RTE_FC_FULL) == RTE_FC_FULL) ||
	    (fc_conf->mode & RTE_FC_RX_PAUSE))
		nic_pause.rx_pause = true;

	err = spnic_set_pause_info(nic_dev->hwdev, nic_pause);
	if (err) {
		(void)spnic_mutex_unlock(&nic_dev->pause_mutuex);
		return err;
	}

	nic_dev->pause_set = true;
	nic_dev->nic_pause.rx_pause = nic_pause.rx_pause;
	nic_dev->nic_pause.tx_pause = nic_pause.tx_pause;

	PMD_DRV_LOG(INFO, "Just support set tx or rx pause info, tx: %s, rx: %s\n",
		    nic_pause.tx_pause ? "on" : "off",
		    nic_pause.rx_pause ? "on" : "off");

	(void)spnic_mutex_unlock(&nic_dev->pause_mutuex);
	return 0;
}

/**
 * Update the RSS hash key and RSS hash type.
 *
 * @param[in] dev
 *   Pointer to ethernet device structure.
 * @param[in] rss_conf
 *   RSS configuration data.
 *
 * @retval zero: Success
 * @retval non-zero: Failure
 */
static int spnic_rss_hash_update(struct rte_eth_dev *dev,
				 struct rte_eth_rss_conf *rss_conf)
{
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	struct spnic_rss_type rss_type = {0};
	u64 rss_hf = rss_conf->rss_hf;
	int err = 0;

	if (nic_dev->rss_state == SPNIC_RSS_DISABLE) {
		if (rss_hf != 0)
			return -EINVAL;

		PMD_DRV_LOG(INFO, "RSS is not enabled");
		return 0;
	}

	if (rss_conf->rss_key_len > SPNIC_RSS_KEY_SIZE) {
		PMD_DRV_LOG(ERR, "Invalid RSS key, rss_key_len: %d",
			    rss_conf->rss_key_len);
		return -EINVAL;
	}

	if (rss_conf->rss_key) {
		err = spnic_rss_set_hash_key(nic_dev->hwdev, nic_dev->rss_key);
		if (err) {
			PMD_DRV_LOG(ERR, "Set RSS hash key failed");
			return err;
		}
		memcpy(nic_dev->rss_key, rss_conf->rss_key,
		       rss_conf->rss_key_len);
	}

	rss_type.ipv4 = (rss_hf & (ETH_RSS_IPV4 | ETH_RSS_FRAG_IPV4 |
		ETH_RSS_NONFRAG_IPV4_OTHER)) ? 1 : 0;
	rss_type.tcp_ipv4 = (rss_hf & ETH_RSS_NONFRAG_IPV4_TCP) ? 1 : 0;
	rss_type.ipv6 = (rss_hf & (ETH_RSS_IPV6 | ETH_RSS_FRAG_IPV6 |
		ETH_RSS_NONFRAG_IPV6_OTHER)) ? 1 : 0;
	rss_type.ipv6_ext = (rss_hf & ETH_RSS_IPV6_EX) ? 1 : 0;
	rss_type.tcp_ipv6 = (rss_hf & ETH_RSS_NONFRAG_IPV6_TCP) ? 1 : 0;
	rss_type.tcp_ipv6_ext = (rss_hf & ETH_RSS_IPV6_TCP_EX) ? 1 : 0;
	rss_type.udp_ipv4 = (rss_hf & ETH_RSS_NONFRAG_IPV4_UDP) ? 1 : 0;
	rss_type.udp_ipv6 = (rss_hf & ETH_RSS_NONFRAG_IPV6_UDP) ? 1 : 0;

	err = spnic_set_rss_type(nic_dev->hwdev, rss_type);
	if (err)
		PMD_DRV_LOG(ERR, "Set RSS type failed");

	return err;
}

/**
 * Get the RSS hash configuration.
 *
 * @param[in] dev
 *   Pointer to ethernet device structure.
 * @param[out] rss_conf
 *   RSS configuration data.
 *
 * @retval zero: Success
 * @retval non-zero: Failure
 */
static int spnic_rss_conf_get(struct rte_eth_dev *dev,
			      struct rte_eth_rss_conf *rss_conf)
{
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	struct spnic_rss_type rss_type = {0};
	int err;

	if (!rss_conf)
		return -EINVAL;

	if (nic_dev->rss_state == SPNIC_RSS_DISABLE) {
		rss_conf->rss_hf = 0;
		PMD_DRV_LOG(INFO, "RSS is not enabled");
		return 0;
	}

	if (rss_conf->rss_key &&
	    rss_conf->rss_key_len >= SPNIC_RSS_KEY_SIZE) {
		/*
		 * Get RSS key from driver to reduce the frequency of the MPU
		 * accessing the RSS memory.
		 */
		rss_conf->rss_key_len = sizeof(nic_dev->rss_key);
		memcpy(rss_conf->rss_key, nic_dev->rss_key,
		       rss_conf->rss_key_len);
	}

	err = spnic_get_rss_type(nic_dev->hwdev, &rss_type);
	if (err)
		return err;

	rss_conf->rss_hf = 0;
	rss_conf->rss_hf |=  rss_type.ipv4 ? (ETH_RSS_IPV4 |
		ETH_RSS_FRAG_IPV4 | ETH_RSS_NONFRAG_IPV4_OTHER) : 0;
	rss_conf->rss_hf |=  rss_type.tcp_ipv4 ? ETH_RSS_NONFRAG_IPV4_TCP : 0;
	rss_conf->rss_hf |=  rss_type.ipv6 ? (ETH_RSS_IPV6 |
		ETH_RSS_FRAG_IPV6 | ETH_RSS_NONFRAG_IPV6_OTHER) : 0;
	rss_conf->rss_hf |=  rss_type.ipv6_ext ? ETH_RSS_IPV6_EX : 0;
	rss_conf->rss_hf |=  rss_type.tcp_ipv6 ? ETH_RSS_NONFRAG_IPV6_TCP : 0;
	rss_conf->rss_hf |=  rss_type.tcp_ipv6_ext ? ETH_RSS_IPV6_TCP_EX : 0;
	rss_conf->rss_hf |=  rss_type.udp_ipv4 ? ETH_RSS_NONFRAG_IPV4_UDP : 0;
	rss_conf->rss_hf |=  rss_type.udp_ipv6 ? ETH_RSS_NONFRAG_IPV6_UDP : 0;

	return 0;
}

/**
 * Get the RETA indirection table.
 *
 * @param[in] dev
 *   Pointer to ethernet device structure.
 * @param[out] reta_conf
 *   Pointer to RETA configuration structure array.
 * @param[in] reta_size
 *   Size of the RETA table.
 *
 * @retval zero: Success
 * @retval non-zero: Failure
 */
static int spnic_rss_reta_query(struct rte_eth_dev *dev,
				struct rte_eth_rss_reta_entry64 *reta_conf,
				uint16_t reta_size)
{
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	u32 indirtbl[SPNIC_RSS_INDIR_SIZE] = {0};
	u16 idx, shift;
	u16 i;
	int err;

	if (nic_dev->rss_state == SPNIC_RSS_DISABLE) {
		PMD_DRV_LOG(INFO, "RSS is not enabled");
		return 0;
	}

	if (reta_size != SPNIC_RSS_INDIR_SIZE) {
		PMD_DRV_LOG(ERR, "Invalid reta size, reta_size: %d", reta_size);
		return -EINVAL;
	}

	err = spnic_rss_get_indir_tbl(nic_dev->hwdev, indirtbl);
	if (err) {
		PMD_DRV_LOG(ERR, "Get RSS retas table failed, error: %d",
			    err);
		return err;
	}

	for (i = 0; i < reta_size; i++) {
		idx = i / RTE_RETA_GROUP_SIZE;
		shift = i % RTE_RETA_GROUP_SIZE;
		if (reta_conf[idx].mask & (1ULL << shift))
			reta_conf[idx].reta[shift] = (uint16_t)indirtbl[i];
	}

	return 0;
}

/**
 * Update the RETA indirection table.
 *
 * @param[in] dev
 *   Pointer to ethernet device structure.
 * @param[in] reta_conf
 *   Pointer to RETA configuration structure array.
 * @param[in] reta_size
 *   Size of the RETA table.
 *
 * @retval zero: Success
 * @retval non-zero: Failure
 */
static int spnic_rss_reta_update(struct rte_eth_dev *dev,
				 struct rte_eth_rss_reta_entry64 *reta_conf,
				 uint16_t reta_size)
{
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	u32 indirtbl[SPNIC_RSS_INDIR_SIZE] = {0};
	u16 idx, shift;
	u16 i;
	int err;

	if (nic_dev->rss_state == SPNIC_RSS_DISABLE)
		return 0;

	if (reta_size != SPNIC_RSS_INDIR_SIZE) {
		PMD_DRV_LOG(ERR, "Invalid reta size, reta_size: %d", reta_size);
		return -EINVAL;
	}

	err = spnic_rss_get_indir_tbl(nic_dev->hwdev, indirtbl);
	if (err)
		return err;

	/* Update RSS reta table */
	for (i = 0; i < reta_size; i++) {
		idx = i / RTE_RETA_GROUP_SIZE;
		shift = i % RTE_RETA_GROUP_SIZE;
		if (reta_conf[idx].mask & (1ULL << shift))
			indirtbl[i] = reta_conf[idx].reta[shift];
	}

	for (i = 0 ; i < reta_size; i++) {
		if (indirtbl[i] >= nic_dev->num_rqs) {
			PMD_DRV_LOG(ERR, "Invalid reta entry, index: %d, num_rqs: %d",
				    indirtbl[i], nic_dev->num_rqs);
			return -EFAULT;
		}
	}

	err = spnic_rss_set_indir_tbl(nic_dev->hwdev, indirtbl);
	if (err)
		PMD_DRV_LOG(ERR, "Set RSS reta table failed");

	return err;
}

static void spnic_rxq_info_get(struct rte_eth_dev *dev, uint16_t queue_id,
			       struct rte_eth_rxq_info *rxq_info)
{
	struct spnic_rxq *rxq = dev->data->rx_queues[queue_id];

	rxq_info->mp = rxq->mb_pool;
	rxq_info->nb_desc = rxq->q_depth;
}

static void spnic_txq_info_get(struct rte_eth_dev *dev, uint16_t queue_id,
			       struct rte_eth_txq_info *txq_qinfo)
{
	struct spnic_txq *txq = dev->data->tx_queues[queue_id];

	txq_qinfo->nb_desc = txq->q_depth;
}

/**
 * Update MAC address
 *
 * @param[in] dev
 *   Pointer to ethernet device structure.
 * @param[in] addr
 *   Pointer to MAC address
 *
 * @retval zero: Success
 * @retval non-zero: Failure
 */
static int spnic_set_mac_addr(struct rte_eth_dev *dev,
			      struct rte_ether_addr *addr)
{
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	char mac_addr[RTE_ETHER_ADDR_FMT_SIZE];
	u16 func_id;
	int err;

	if (!rte_is_valid_assigned_ether_addr(addr)) {
		rte_ether_format_addr(mac_addr, RTE_ETHER_ADDR_FMT_SIZE, addr);
		PMD_DRV_LOG(ERR, "Set invalid MAC address %s", mac_addr);
		return -EINVAL;
	}

	func_id = spnic_global_func_id(nic_dev->hwdev);
	err = spnic_update_mac(nic_dev->hwdev,
				nic_dev->default_addr.addr_bytes,
				addr->addr_bytes, 0, func_id);
	if (err)
		return err;

	rte_ether_addr_copy(addr, &nic_dev->default_addr);
	rte_ether_format_addr(mac_addr, RTE_ETHER_ADDR_FMT_SIZE,
			      &nic_dev->default_addr);

	PMD_DRV_LOG(INFO, "Set new MAC address %s", mac_addr);

	return 0;
}

/**
 * Remove a MAC address.
 *
 * @param[in] dev
 *   Pointer to ethernet device structure.
 * @param[in] index
 *   MAC address index.
 */
static void spnic_mac_addr_remove(struct rte_eth_dev *dev, uint32_t index)
{
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	u16 func_id;
	int err;

	if (index >= SPNIC_MAX_UC_MAC_ADDRS) {
		PMD_DRV_LOG(INFO, "Remove MAC index(%u) is out of range",
			    index);
		return;
	}

	func_id = spnic_global_func_id(nic_dev->hwdev);
	err = spnic_del_mac(nic_dev->hwdev,
			     dev->data->mac_addrs[index].addr_bytes,
			     0, func_id);
	if (err)
		PMD_DRV_LOG(ERR, "Remove MAC index(%u) failed", index);
}

/**
 * Add a MAC address.
 *
 * @param[in] dev
 *   Pointer to ethernet device structure.
 * @param[in] mac_addr
 *   MAC address to register.
 * @param[in] index
 *   MAC address index.
 * @param[in] vmdq
 *   VMDq pool index to associate address with (unused_).
 *
 * @retval zero: Success
 * @retval non-zero: Failure
 */
static int spnic_mac_addr_add(struct rte_eth_dev *dev,
			      struct rte_ether_addr *mac_addr, uint32_t index,
			      __rte_unused uint32_t vmdq)
{
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	unsigned int i;
	u16 func_id;
	int err;

	if (!rte_is_valid_assigned_ether_addr(mac_addr)) {
		PMD_DRV_LOG(ERR, "Add invalid MAC address");
		return -EINVAL;
	}

	if (index >= SPNIC_MAX_UC_MAC_ADDRS) {
		PMD_DRV_LOG(ERR, "Add MAC index(%u) is out of range", index);
		return -EINVAL;
	}

	/* Make sure this address doesn't already be configured */
	for (i = 0; i < SPNIC_MAX_UC_MAC_ADDRS; i++) {
		if (rte_is_same_ether_addr(mac_addr,
			&dev->data->mac_addrs[i])) {
			PMD_DRV_LOG(ERR, "MAC address is already configured");
			return -EADDRINUSE;
		}
	}

	func_id = spnic_global_func_id(nic_dev->hwdev);
	err = spnic_set_mac(nic_dev->hwdev, mac_addr->addr_bytes, 0, func_id);
	if (err)
		return err;

	return 0;
}

static void spnic_delete_mc_addr_list(struct spnic_nic_dev *nic_dev)
{
	u16 func_id;
	u32 i;

	func_id = spnic_global_func_id(nic_dev->hwdev);

	for (i = 0; i < SPNIC_MAX_MC_MAC_ADDRS; i++) {
		if (rte_is_zero_ether_addr(&nic_dev->mc_list[i]))
			break;

		spnic_del_mac(nic_dev->hwdev, nic_dev->mc_list[i].addr_bytes,
			      0, func_id);
		memset(&nic_dev->mc_list[i], 0, sizeof(struct rte_ether_addr));
	}
}

/**
 * Set multicast MAC address
 *
 * @param[in] dev
 *   Pointer to ethernet device structure.
 * @param[in] mc_addr_set
 *   Pointer to multicast MAC address
 * @param[in] nb_mc_addr
 *   The number of multicast MAC address to set
 *
 * @retval zero: Success
 * @retval non-zero: Failure
 */
static int spnic_set_mc_addr_list(struct rte_eth_dev *dev,
				  struct rte_ether_addr *mc_addr_set,
				  uint32_t nb_mc_addr)
{
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	char mac_addr[RTE_ETHER_ADDR_FMT_SIZE];
	u16 func_id;
	int err;
	u32 i;

	func_id = spnic_global_func_id(nic_dev->hwdev);

	/* Delete old multi_cast addrs firstly */
	spnic_delete_mc_addr_list(nic_dev);

	if (nb_mc_addr > SPNIC_MAX_MC_MAC_ADDRS)
		return -EINVAL;

	for (i = 0; i < nb_mc_addr; i++) {
		if (!rte_is_multicast_ether_addr(&mc_addr_set[i])) {
			rte_ether_format_addr(mac_addr, RTE_ETHER_ADDR_FMT_SIZE,
					      &mc_addr_set[i]);
			PMD_DRV_LOG(ERR, "Set mc MAC addr failed, addr(%s) invalid",
				    mac_addr);
			return -EINVAL;
		}
	}

	for (i = 0; i < nb_mc_addr; i++) {
		err = spnic_set_mac(nic_dev->hwdev, mc_addr_set[i].addr_bytes,
				    0, func_id);
		if (err) {
			spnic_delete_mc_addr_list(nic_dev);
			return err;
		}

		rte_ether_addr_copy(&mc_addr_set[i], &nic_dev->mc_list[i]);
	}

	return 0;
}

static const struct eth_dev_ops spnic_pmd_ops = {
	.dev_configure                 = spnic_dev_configure,
	.dev_infos_get                 = spnic_dev_infos_get,
	.fw_version_get                = spnic_fw_version_get,
	.dev_set_link_up               = spnic_dev_set_link_up,
	.dev_set_link_down             = spnic_dev_set_link_down,
	.link_update                   = spnic_link_update,
	.rx_queue_setup                = spnic_rx_queue_setup,
	.tx_queue_setup                = spnic_tx_queue_setup,
	.rx_queue_release              = spnic_rx_queue_release,
	.tx_queue_release              = spnic_tx_queue_release,
	.dev_start                     = spnic_dev_start,
	.dev_stop                      = spnic_dev_stop,
	.dev_close                     = spnic_dev_close,
	.mtu_set                       = spnic_dev_set_mtu,
	.vlan_filter_set               = spnic_vlan_filter_set,
	.vlan_offload_set              = spnic_vlan_offload_set,
	.allmulticast_enable           = spnic_dev_allmulticast_enable,
	.allmulticast_disable          = spnic_dev_allmulticast_disable,
	.promiscuous_enable            = spnic_dev_promiscuous_enable,
	.promiscuous_disable           = spnic_dev_promiscuous_disable,
	.flow_ctrl_get                 = spnic_dev_flow_ctrl_get,
	.flow_ctrl_set                 = spnic_dev_flow_ctrl_set,
	.rss_hash_update               = spnic_rss_hash_update,
	.rss_hash_conf_get             = spnic_rss_conf_get,
	.reta_update                   = spnic_rss_reta_update,
	.reta_query                    = spnic_rss_reta_query,
	.rxq_info_get                  = spnic_rxq_info_get,
	.txq_info_get                  = spnic_txq_info_get,
	.mac_addr_set                  = spnic_set_mac_addr,
	.mac_addr_remove               = spnic_mac_addr_remove,
	.mac_addr_add                  = spnic_mac_addr_add,
	.set_mc_addr_list              = spnic_set_mc_addr_list,
};

static const struct eth_dev_ops spnic_pmd_vf_ops = {
	.dev_configure                 = spnic_dev_configure,
	.dev_infos_get                 = spnic_dev_infos_get,
	.fw_version_get                = spnic_fw_version_get,
	.rx_queue_setup                = spnic_rx_queue_setup,
	.tx_queue_setup                = spnic_tx_queue_setup,
	.dev_start                     = spnic_dev_start,
	.link_update                   = spnic_link_update,
	.rx_queue_release              = spnic_rx_queue_release,
	.tx_queue_release              = spnic_tx_queue_release,
	.dev_stop                      = spnic_dev_stop,
	.dev_close                     = spnic_dev_close,
	.mtu_set                       = spnic_dev_set_mtu,
	.vlan_filter_set               = spnic_vlan_filter_set,
	.vlan_offload_set              = spnic_vlan_offload_set,
	.allmulticast_enable           = spnic_dev_allmulticast_enable,
	.allmulticast_disable          = spnic_dev_allmulticast_disable,
	.rss_hash_update               = spnic_rss_hash_update,
	.rss_hash_conf_get             = spnic_rss_conf_get,
	.reta_update                   = spnic_rss_reta_update,
	.reta_query                    = spnic_rss_reta_query,
	.rxq_info_get                  = spnic_rxq_info_get,
	.txq_info_get                  = spnic_txq_info_get,
	.mac_addr_set                  = spnic_set_mac_addr,
	.mac_addr_remove               = spnic_mac_addr_remove,
	.mac_addr_add                  = spnic_mac_addr_add,
	.set_mc_addr_list              = spnic_set_mc_addr_list,
};

/**
 * Init mac_vlan table in hardwares.
 *
 * @param[in] eth_dev
 *   Pointer to ethernet device structure.
 *
 * @retval zero: Success
 * @retval non-zero: Failure
 */
static int spnic_init_mac_table(struct rte_eth_dev *eth_dev)
{
	struct spnic_nic_dev *nic_dev =
		SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(eth_dev);
	u8 addr_bytes[RTE_ETHER_ADDR_LEN];
	u16 func_id = 0;
	int err = 0;

	err = spnic_get_default_mac(nic_dev->hwdev, addr_bytes,
				     RTE_ETHER_ADDR_LEN);
	if (err)
		return err;

	rte_ether_addr_copy((struct rte_ether_addr *)addr_bytes,
			    &eth_dev->data->mac_addrs[0]);
	if (rte_is_zero_ether_addr(&eth_dev->data->mac_addrs[0]))
		rte_eth_random_addr(eth_dev->data->mac_addrs[0].addr_bytes);

	func_id = spnic_global_func_id(nic_dev->hwdev);
	err = spnic_set_mac(nic_dev->hwdev,
			    eth_dev->data->mac_addrs[0].addr_bytes,
			    0, func_id);
	if (err && err != SPNIC_PF_SET_VF_ALREADY)
		return err;

	rte_ether_addr_copy(&eth_dev->data->mac_addrs[0],
			    &nic_dev->default_addr);

	return 0;
}

static int spnic_pf_get_default_cos(struct spnic_hwdev *hwdev, u8 *cos_id)
{
	u8 default_cos = 0;
	u8 valid_cos_bitmap;
	u8 i;

	valid_cos_bitmap = hwdev->cfg_mgmt->svc_cap.cos_valid_bitmap;
	if (!valid_cos_bitmap) {
		PMD_DRV_LOG(ERR, "PF has none cos to support\n");
		return -EFAULT;
	}

	for (i = 0; i < SPNIC_COS_NUM_MAX; i++) {
		if (valid_cos_bitmap & BIT(i))
			/* Find max cos id as default cos */
			default_cos = i;
	}

	*cos_id = default_cos;

	return 0;
}

static int spnic_init_default_cos(struct spnic_nic_dev *nic_dev)
{
	u8 cos_id = 0;
	int err;

	if (!SPNIC_IS_VF(nic_dev->hwdev)) {
		err = spnic_pf_get_default_cos(nic_dev->hwdev, &cos_id);
		if (err) {
			PMD_DRV_LOG(ERR, "Get PF default cos failed, err: %d",
				    err);
			return err;
		}
	} else {
		err = spnic_vf_get_default_cos(nic_dev->hwdev, &cos_id);
		if (err) {
			PMD_DRV_LOG(ERR, "Get VF default cos failed, err: %d",
				    err);
			return err;
		}
	}

	nic_dev->default_cos = cos_id;
	PMD_DRV_LOG(INFO, "Default cos %d", nic_dev->default_cos);
	return 0;
}

static int spnic_set_default_hw_feature(struct spnic_nic_dev *nic_dev)
{
	int err;

	err = spnic_init_default_cos(nic_dev);
	if (err)
		return err;

	return 0;
}

static int spnic_func_init(struct rte_eth_dev *eth_dev)
{
	struct spnic_nic_dev *nic_dev = NULL;
	struct rte_pci_device *pci_dev = NULL;
	int err;

	pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);

	/* EAL is secondary and eth_dev is already created */
	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		PMD_DRV_LOG(INFO, "Initialize %s in secondary process",
			    eth_dev->data->name);

		return 0;
	}

	nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(eth_dev);
	memset(nic_dev, 0, sizeof(*nic_dev));
	snprintf(nic_dev->dev_name, sizeof(nic_dev->dev_name),
		 "spnic-%.4x:%.2x:%.2x.%x",
		 pci_dev->addr.domain, pci_dev->addr.bus,
		 pci_dev->addr.devid, pci_dev->addr.function);

	/* Alloc mac_addrs */
	eth_dev->data->mac_addrs = rte_zmalloc("spnic_mac",
		SPNIC_MAX_UC_MAC_ADDRS * sizeof(struct rte_ether_addr), 0);
	if (!eth_dev->data->mac_addrs) {
		PMD_DRV_LOG(ERR, "Allocate %zx bytes to store MAC addresses "
			    "failed, dev_name: %s",
			    SPNIC_MAX_UC_MAC_ADDRS *
			    sizeof(struct rte_ether_addr),
			    eth_dev->data->name);
		err = -ENOMEM;
		goto alloc_eth_addr_fail;
	}

	nic_dev->mc_list = rte_zmalloc("spnic_mc",
		SPNIC_MAX_MC_MAC_ADDRS * sizeof(struct rte_ether_addr), 0);
	if (!nic_dev->mc_list) {
		PMD_DRV_LOG(ERR, "Allocate %zx bytes to store multicast "
			    "addresses failed, dev_name: %s",
			    SPNIC_MAX_MC_MAC_ADDRS *
			    sizeof(struct rte_ether_addr),
			    eth_dev->data->name);
		err = -ENOMEM;
		goto alloc_mc_list_fail;
	}

	eth_dev->data->dev_flags |= RTE_ETH_DEV_AUTOFILL_QUEUE_XSTATS;
	/* Create hardware device */
	nic_dev->hwdev = rte_zmalloc("spnic_hwdev", sizeof(*nic_dev->hwdev),
				     RTE_CACHE_LINE_SIZE);
	if (!nic_dev->hwdev) {
		PMD_DRV_LOG(ERR, "Allocate hwdev memory failed, dev_name: %s",
			    eth_dev->data->name);
		err = -ENOMEM;
		goto alloc_hwdev_mem_fail;
	}
	nic_dev->hwdev->pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	nic_dev->hwdev->dev_handle = nic_dev;
	nic_dev->hwdev->eth_dev = eth_dev;
	nic_dev->hwdev->port_id = eth_dev->data->port_id;

	err = spnic_init_hwdev(nic_dev->hwdev);
	if (err) {
		PMD_DRV_LOG(ERR, "Init chip hwdev failed, dev_name: %s",
			    eth_dev->data->name);
		goto init_hwdev_fail;
	}

	if (!spnic_support_nic(nic_dev->hwdev)) {
		PMD_DRV_LOG(ERR, "Hw of %s don't support nic\n",
			    eth_dev->data->name);
		goto init_hwdev_fail;
	}

	nic_dev->max_sqs = spnic_func_max_sqs(nic_dev->hwdev);
	nic_dev->max_rqs = spnic_func_max_rqs(nic_dev->hwdev);

	if (SPNIC_FUNC_TYPE(nic_dev->hwdev) == TYPE_VF)
		eth_dev->dev_ops = &spnic_pmd_vf_ops;
	else
		eth_dev->dev_ops = &spnic_pmd_ops;

	err = spnic_init_nic_hwdev(nic_dev->hwdev);
	if (err) {
		PMD_DRV_LOG(ERR, "Init nic hwdev failed, dev_name: %s",
			    eth_dev->data->name);
		goto init_nic_hwdev_fail;
	}

	err = spnic_get_feature_from_hw(nic_dev->hwdev, &nic_dev->feature_cap, 1);
	if (err) {
		PMD_DRV_LOG(ERR, "Get nic feature from hardware failed, dev_name: %s",
			    eth_dev->data->name);
		goto get_cap_fail;
	}

	err = spnic_init_sw_rxtxqs(nic_dev);
	if (err) {
		PMD_DRV_LOG(ERR, "Init sw rxqs or txqs failed, dev_name: %s",
			    eth_dev->data->name);
		goto init_sw_rxtxqs_fail;
	}

	err = spnic_init_mac_table(eth_dev);
	if (err) {
		PMD_DRV_LOG(ERR, "Init mac table failed, dev_name: %s",
			    eth_dev->data->name);
		goto init_mac_table_fail;
	}

	/* Set hardware feature to default status */
	err = spnic_set_default_hw_feature(nic_dev);
	if (err) {
		PMD_DRV_LOG(ERR, "Set hw default features failed, dev_name: %s",
			    eth_dev->data->name);
		goto set_default_feature_fail;
	}

	err = spnic_copy_mempool_init(nic_dev);
	if (err) {
		PMD_DRV_LOG(ERR, "Create copy mempool failed, dev_name: %s",
			 eth_dev->data->name);
		goto init_mpool_fail;
	}

	spnic_mutex_init(&nic_dev->rx_mode_mutex, NULL);

	rte_bit_relaxed_set32(SPNIC_DEV_INTR_EN, &nic_dev->dev_status);

	rte_bit_relaxed_set32(SPNIC_DEV_INIT, &nic_dev->dev_status);
	PMD_DRV_LOG(INFO, "Initialize %s in primary succeed",
		    eth_dev->data->name);

	return 0;

init_mpool_fail:
set_default_feature_fail:
	spnic_deinit_mac_addr(eth_dev);

init_mac_table_fail:
	spnic_deinit_sw_rxtxqs(nic_dev);

init_sw_rxtxqs_fail:
	spnic_free_nic_hwdev(nic_dev->hwdev);

get_cap_fail:
init_nic_hwdev_fail:
	spnic_free_hwdev(nic_dev->hwdev);
	eth_dev->dev_ops = NULL;

init_hwdev_fail:
	rte_free(nic_dev->hwdev);
	nic_dev->hwdev = NULL;

alloc_hwdev_mem_fail:
	rte_free(nic_dev->mc_list);
	nic_dev->mc_list = NULL;

alloc_mc_list_fail:
	rte_free(eth_dev->data->mac_addrs);
	eth_dev->data->mac_addrs = NULL;

alloc_eth_addr_fail:
	PMD_DRV_LOG(ERR, "Initialize %s in primary failed",
		    eth_dev->data->name);
	return err;
}

static int spnic_dev_init(struct rte_eth_dev *eth_dev)
{
	struct rte_pci_device *pci_dev;

	pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);

	PMD_DRV_LOG(INFO, "Initializing spnic-%.4x:%.2x:%.2x.%x in %s process",
		    pci_dev->addr.domain, pci_dev->addr.bus,
		    pci_dev->addr.devid, pci_dev->addr.function,
		    (rte_eal_process_type() == RTE_PROC_PRIMARY) ?
		    "primary" : "secondary");

	eth_dev->rx_pkt_burst = spnic_recv_pkts;
	eth_dev->tx_pkt_burst = spnic_xmit_pkts;

	return spnic_func_init(eth_dev);
}

static int spnic_dev_uninit(struct rte_eth_dev *dev)
{
	struct spnic_nic_dev *nic_dev;

	nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	rte_bit_relaxed_clear32(SPNIC_DEV_INIT, &nic_dev->dev_status);

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	spnic_dev_close(dev);

	return 0;
}

static struct rte_pci_id pci_id_spnic_map[] = {
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_RAMAXEL, SPNIC_DEV_ID_PF) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_RAMAXEL, SPNIC_DEV_ID_VF) },
	{.vendor_id = 0},
};

static int spnic_pci_probe(__rte_unused struct rte_pci_driver *pci_drv,
			   struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_probe(pci_dev,
					     sizeof(struct spnic_nic_dev),
					     spnic_dev_init);
}

static int spnic_pci_remove(struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_remove(pci_dev, spnic_dev_uninit);
}

static struct rte_pci_driver rte_spnic_pmd = {
	.id_table = pci_id_spnic_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING | RTE_PCI_DRV_INTR_LSC,
	.probe = spnic_pci_probe,
	.remove = spnic_pci_remove,
};

RTE_PMD_REGISTER_PCI(net_spnic, rte_spnic_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_spnic, pci_id_spnic_map);

RTE_INIT(spnic_init_log)
{
	spnic_logtype = rte_log_register("pmd.net.spnic");
	if (spnic_logtype >= 0)
		rte_log_set_level(spnic_logtype, RTE_LOG_INFO);
}

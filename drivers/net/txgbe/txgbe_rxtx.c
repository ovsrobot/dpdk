/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2015-2020
 */

#include <sys/queue.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_ethdev_driver.h>
#include <rte_memzone.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>

#include "txgbe_logs.h"
#include "base/txgbe.h"
#include "txgbe_ethdev.h"
#include "txgbe_rxtx.h"

static int
txgbe_is_vf(struct rte_eth_dev *dev)
{
	struct txgbe_hw *hw = TXGBE_DEV_HW(dev);

	switch (hw->mac.type) {
	case txgbe_mac_raptor_vf:
		return 1;
	default:
		return 0;
	}
}

#ifndef DEFAULT_TX_FREE_THRESH
#define DEFAULT_TX_FREE_THRESH 32
#endif

uint64_t
txgbe_get_rx_queue_offloads(struct rte_eth_dev *dev __rte_unused)
{

	return DEV_RX_OFFLOAD_VLAN_STRIP;
}

uint64_t
txgbe_get_rx_port_offloads(struct rte_eth_dev *dev)
{
	uint64_t offloads;
	struct txgbe_hw *hw = TXGBE_DEV_HW(dev);
	struct rte_eth_dev_sriov *sriov = &RTE_ETH_DEV_SRIOV(dev);

	offloads = DEV_RX_OFFLOAD_IPV4_CKSUM  |
		   DEV_RX_OFFLOAD_UDP_CKSUM   |
		   DEV_RX_OFFLOAD_TCP_CKSUM   |
		   DEV_RX_OFFLOAD_KEEP_CRC    |
		   DEV_RX_OFFLOAD_JUMBO_FRAME |
		   DEV_RX_OFFLOAD_VLAN_FILTER |
		   DEV_RX_OFFLOAD_RSS_HASH |
		   DEV_RX_OFFLOAD_SCATTER;

	if (!txgbe_is_vf(dev))
		offloads |= (DEV_RX_OFFLOAD_VLAN_FILTER |
			     DEV_RX_OFFLOAD_QINQ_STRIP |
			     DEV_RX_OFFLOAD_VLAN_EXTEND);

	/*
	 * RSC is only supported by PF devices in a non-SR-IOV
	 * mode.
	 */
	if ((hw->mac.type == txgbe_mac_raptor) &&
	    !sriov->active)
		offloads |= DEV_RX_OFFLOAD_TCP_LRO;

	if (hw->mac.type == txgbe_mac_raptor)
		offloads |= DEV_RX_OFFLOAD_MACSEC_STRIP;

	offloads |= DEV_RX_OFFLOAD_OUTER_IPV4_CKSUM;

	return offloads;
}

static void __rte_cold
txgbe_tx_queue_release_mbufs(struct txgbe_tx_queue *txq)
{
	unsigned i;

	if (txq->sw_ring != NULL) {
		for (i = 0; i < txq->nb_tx_desc; i++) {
			if (txq->sw_ring[i].mbuf != NULL) {
				rte_pktmbuf_free_seg(txq->sw_ring[i].mbuf);
				txq->sw_ring[i].mbuf = NULL;
			}
		}
	}
}

static void __rte_cold
txgbe_tx_free_swring(struct txgbe_tx_queue *txq)
{
	if (txq != NULL &&
	    txq->sw_ring != NULL)
		rte_free(txq->sw_ring);
}

static void __rte_cold
txgbe_tx_queue_release(struct txgbe_tx_queue *txq)
{
	if (txq != NULL && txq->ops != NULL) {
		txq->ops->release_mbufs(txq);
		txq->ops->free_swring(txq);
		rte_free(txq);
	}
}

void __rte_cold
txgbe_dev_tx_queue_release(void *txq)
{
	txgbe_tx_queue_release(txq);
}

static const struct txgbe_txq_ops def_txq_ops = {
	.release_mbufs = txgbe_tx_queue_release_mbufs,
	.free_swring = txgbe_tx_free_swring,
};

void __rte_cold
txgbe_set_tx_function(struct rte_eth_dev *dev, struct txgbe_tx_queue *txq)
{
	RTE_SET_USED(dev);
	RTE_SET_USED(txq);
}

uint64_t
txgbe_get_tx_queue_offloads(struct rte_eth_dev *dev)
{
	RTE_SET_USED(dev);

	return 0;
}

uint64_t
txgbe_get_tx_port_offloads(struct rte_eth_dev *dev)
{
	uint64_t tx_offload_capa;

	tx_offload_capa =
		DEV_TX_OFFLOAD_VLAN_INSERT |
		DEV_TX_OFFLOAD_IPV4_CKSUM  |
		DEV_TX_OFFLOAD_UDP_CKSUM   |
		DEV_TX_OFFLOAD_TCP_CKSUM   |
		DEV_TX_OFFLOAD_SCTP_CKSUM  |
		DEV_TX_OFFLOAD_TCP_TSO     |
		DEV_TX_OFFLOAD_UDP_TSO	   |
		DEV_TX_OFFLOAD_UDP_TNL_TSO	|
		DEV_TX_OFFLOAD_IP_TNL_TSO	|
		DEV_TX_OFFLOAD_VXLAN_TNL_TSO	|
		DEV_TX_OFFLOAD_GRE_TNL_TSO	|
		DEV_TX_OFFLOAD_IPIP_TNL_TSO	|
		DEV_TX_OFFLOAD_GENEVE_TNL_TSO	|
		DEV_TX_OFFLOAD_MULTI_SEGS;

	if (!txgbe_is_vf(dev))
		tx_offload_capa |= DEV_TX_OFFLOAD_QINQ_INSERT;

	tx_offload_capa |= DEV_TX_OFFLOAD_MACSEC_INSERT;

	tx_offload_capa |= DEV_TX_OFFLOAD_OUTER_IPV4_CKSUM;

	return tx_offload_capa;
}

int __rte_cold
txgbe_dev_tx_queue_setup(struct rte_eth_dev *dev,
			 uint16_t queue_idx,
			 uint16_t nb_desc,
			 unsigned int socket_id,
			 const struct rte_eth_txconf *tx_conf)
{
	const struct rte_memzone *tz;
	struct txgbe_tx_queue *txq;
	struct txgbe_hw     *hw;
	uint16_t tx_free_thresh;
	uint64_t offloads;

	PMD_INIT_FUNC_TRACE();
	hw = TXGBE_DEV_HW(dev);

	offloads = tx_conf->offloads | dev->data->dev_conf.txmode.offloads;

	/*
	 * Validate number of transmit descriptors.
	 * It must not exceed hardware maximum, and must be multiple
	 * of TXGBE_ALIGN.
	 */
	if (nb_desc % TXGBE_TXD_ALIGN != 0 ||
	    (nb_desc > TXGBE_RING_DESC_MAX) ||
	    (nb_desc < TXGBE_RING_DESC_MIN)) {
		return -EINVAL;
	}

	/*
	 * The TX descriptor ring will be cleaned after txq->tx_free_thresh
	 * descriptors are used or if the number of descriptors required
	 * to transmit a packet is greater than the number of free TX
	 * descriptors.
	 * One descriptor in the TX ring is used as a sentinel to avoid a
	 * H/W race condition, hence the maximum threshold constraints.
	 * When set to zero use default values.
	 */
	tx_free_thresh = (uint16_t)((tx_conf->tx_free_thresh) ?
			tx_conf->tx_free_thresh : DEFAULT_TX_FREE_THRESH);
	if (tx_free_thresh >= (nb_desc - 3)) {
		PMD_INIT_LOG(ERR, "tx_free_thresh must be less than the number of "
			     "TX descriptors minus 3. (tx_free_thresh=%u "
			     "port=%d queue=%d)",
			     (unsigned int)tx_free_thresh,
			     (int)dev->data->port_id, (int)queue_idx);
		return -(EINVAL);
	}

	if ((nb_desc % tx_free_thresh) != 0) {
		PMD_INIT_LOG(ERR, "tx_free_thresh must be a divisor of the "
			     "number of TX descriptors. (tx_free_thresh=%u "
			     "port=%d queue=%d)", (unsigned int)tx_free_thresh,
			     (int)dev->data->port_id, (int)queue_idx);
		return -(EINVAL);
	}

	/* Free memory prior to re-allocation if needed... */
	if (dev->data->tx_queues[queue_idx] != NULL) {
		txgbe_tx_queue_release(dev->data->tx_queues[queue_idx]);
		dev->data->tx_queues[queue_idx] = NULL;
	}

	/* First allocate the tx queue data structure */
	txq = rte_zmalloc_socket("ethdev TX queue", sizeof(struct txgbe_tx_queue),
				 RTE_CACHE_LINE_SIZE, socket_id);
	if (txq == NULL)
		return -ENOMEM;

	/*
	 * Allocate TX ring hardware descriptors. A memzone large enough to
	 * handle the maximum ring size is allocated in order to allow for
	 * resizing in later calls to the queue setup function.
	 */
	tz = rte_eth_dma_zone_reserve(dev, "tx_ring", queue_idx,
			sizeof(struct txgbe_tx_desc) * TXGBE_RING_DESC_MAX,
			TXGBE_ALIGN, socket_id);
	if (tz == NULL) {
		txgbe_tx_queue_release(txq);
		return -ENOMEM;
	}

	txq->nb_tx_desc = nb_desc;
	txq->tx_free_thresh = tx_free_thresh;
	txq->pthresh = tx_conf->tx_thresh.pthresh;
	txq->hthresh = tx_conf->tx_thresh.hthresh;
	txq->wthresh = tx_conf->tx_thresh.wthresh;
	txq->queue_id = queue_idx;
	txq->reg_idx = (uint16_t)((RTE_ETH_DEV_SRIOV(dev).active == 0) ?
		queue_idx : RTE_ETH_DEV_SRIOV(dev).def_pool_q_idx + queue_idx);
	txq->port_id = dev->data->port_id;
	txq->offloads = offloads;
	txq->ops = &def_txq_ops;
	txq->tx_deferred_start = tx_conf->tx_deferred_start;

	/*
	 * Modification to set tail pointer for virtual function if vf is detected
	 */
	if (hw->mac.type == txgbe_mac_raptor_vf) {
		txq->tdt_reg_addr = TXGBE_REG_ADDR(hw, TXGBE_TXWP(queue_idx));
		txq->tdc_reg_addr = TXGBE_REG_ADDR(hw, TXGBE_TXCFG(queue_idx));
	} else {
		txq->tdt_reg_addr = TXGBE_REG_ADDR(hw, TXGBE_TXWP(txq->reg_idx));
		txq->tdc_reg_addr = TXGBE_REG_ADDR(hw, TXGBE_TXCFG(txq->reg_idx));
	}

	txq->tx_ring_phys_addr = TMZ_PADDR(tz);
	txq->tx_ring = (struct txgbe_tx_desc *) TMZ_VADDR(tz);

	/* Allocate software ring */
	txq->sw_ring = rte_zmalloc_socket("txq->sw_ring",
				sizeof(struct txgbe_tx_entry) * nb_desc,
				RTE_CACHE_LINE_SIZE, socket_id);
	if (txq->sw_ring == NULL) {
		txgbe_tx_queue_release(txq);
		return -ENOMEM;
	}
	PMD_INIT_LOG(DEBUG, "sw_ring=%p hw_ring=%p dma_addr=0x%"PRIx64,
		     txq->sw_ring, txq->tx_ring, txq->tx_ring_phys_addr);

	/* set up scalar TX function as appropriate */
	txgbe_set_tx_function(dev, txq);

	txq->ops->reset(txq);

	dev->data->tx_queues[queue_idx] = txq;

	return 0;
}

/**
 * txgbe_free_sc_cluster - free the not-yet-completed scattered cluster
 *
 * The "next" pointer of the last segment of (not-yet-completed) RSC clusters
 * in the sw_rsc_ring is not set to NULL but rather points to the next
 * mbuf of this RSC aggregation (that has not been completed yet and still
 * resides on the HW ring). So, instead of calling for rte_pktmbuf_free() we
 * will just free first "nb_segs" segments of the cluster explicitly by calling
 * an rte_pktmbuf_free_seg().
 *
 * @m scattered cluster head
 */
static void __rte_cold
txgbe_free_sc_cluster(struct rte_mbuf *m)
{
	uint16_t i, nb_segs = m->nb_segs;
	struct rte_mbuf *next_seg;

	for (i = 0; i < nb_segs; i++) {
		next_seg = m->next;
		rte_pktmbuf_free_seg(m);
		m = next_seg;
	}
}

static void __rte_cold
txgbe_rx_queue_release_mbufs(struct txgbe_rx_queue *rxq)
{
	unsigned i;

	if (rxq->sw_ring != NULL) {
		for (i = 0; i < rxq->nb_rx_desc; i++) {
			if (rxq->sw_ring[i].mbuf != NULL) {
				rte_pktmbuf_free_seg(rxq->sw_ring[i].mbuf);
				rxq->sw_ring[i].mbuf = NULL;
			}
		}
		if (rxq->rx_nb_avail) {
			for (i = 0; i < rxq->rx_nb_avail; ++i) {
				struct rte_mbuf *mb;

				mb = rxq->rx_stage[rxq->rx_next_avail + i];
				rte_pktmbuf_free_seg(mb);
			}
			rxq->rx_nb_avail = 0;
		}
	}

	if (rxq->sw_sc_ring)
		for (i = 0; i < rxq->nb_rx_desc; i++)
			if (rxq->sw_sc_ring[i].fbuf) {
				txgbe_free_sc_cluster(rxq->sw_sc_ring[i].fbuf);
				rxq->sw_sc_ring[i].fbuf = NULL;
			}
}

static void __rte_cold
txgbe_rx_queue_release(struct txgbe_rx_queue *rxq)
{
	if (rxq != NULL) {
		txgbe_rx_queue_release_mbufs(rxq);
		rte_free(rxq->sw_ring);
		rte_free(rxq->sw_sc_ring);
		rte_free(rxq);
	}
}

void __rte_cold
txgbe_dev_rx_queue_release(void *rxq)
{
	txgbe_rx_queue_release(rxq);
}

/*
 * Check if Rx Burst Bulk Alloc function can be used.
 * Return
 *        0: the preconditions are satisfied and the bulk allocation function
 *           can be used.
 *  -EINVAL: the preconditions are NOT satisfied and the default Rx burst
 *           function must be used.
 */
static inline int __rte_cold
check_rx_burst_bulk_alloc_preconditions(struct txgbe_rx_queue *rxq)
{
	int ret = 0;

	/*
	 * Make sure the following pre-conditions are satisfied:
	 *   rxq->rx_free_thresh >= RTE_PMD_TXGBE_RX_MAX_BURST
	 *   rxq->rx_free_thresh < rxq->nb_rx_desc
	 *   (rxq->nb_rx_desc % rxq->rx_free_thresh) == 0
	 * Scattered packets are not supported.  This should be checked
	 * outside of this function.
	 */
	if (!(rxq->rx_free_thresh >= RTE_PMD_TXGBE_RX_MAX_BURST)) {
		PMD_INIT_LOG(DEBUG, "Rx Burst Bulk Alloc Preconditions: "
			     "rxq->rx_free_thresh=%d, "
			     "RTE_PMD_TXGBE_RX_MAX_BURST=%d",
			     rxq->rx_free_thresh, RTE_PMD_TXGBE_RX_MAX_BURST);
		ret = -EINVAL;
	} else if (!(rxq->rx_free_thresh < rxq->nb_rx_desc)) {
		PMD_INIT_LOG(DEBUG, "Rx Burst Bulk Alloc Preconditions: "
			     "rxq->rx_free_thresh=%d, "
			     "rxq->nb_rx_desc=%d",
			     rxq->rx_free_thresh, rxq->nb_rx_desc);
		ret = -EINVAL;
	} else if (!((rxq->nb_rx_desc % rxq->rx_free_thresh) == 0)) {
		PMD_INIT_LOG(DEBUG, "Rx Burst Bulk Alloc Preconditions: "
			     "rxq->nb_rx_desc=%d, "
			     "rxq->rx_free_thresh=%d",
			     rxq->nb_rx_desc, rxq->rx_free_thresh);
		ret = -EINVAL;
	}

	return ret;
}

/* Reset dynamic txgbe_rx_queue fields back to defaults */
static void __rte_cold
txgbe_reset_rx_queue(struct txgbe_adapter *adapter, struct txgbe_rx_queue *rxq)
{
	static const struct txgbe_rx_desc zeroed_desc = {{{0}, {0} }, {{0}, {0} } };
	unsigned i;
	uint16_t len = rxq->nb_rx_desc;

	/*
	 * By default, the Rx queue setup function allocates enough memory for
	 * TXGBE_RING_DESC_MAX.  The Rx Burst bulk allocation function requires
	 * extra memory at the end of the descriptor ring to be zero'd out.
	 */
	if (adapter->rx_bulk_alloc_allowed)
		/* zero out extra memory */
		len += RTE_PMD_TXGBE_RX_MAX_BURST;

	/*
	 * Zero out HW ring memory. Zero out extra memory at the end of
	 * the H/W ring so look-ahead logic in Rx Burst bulk alloc function
	 * reads extra memory as zeros.
	 */
	for (i = 0; i < len; i++) {
		rxq->rx_ring[i] = zeroed_desc;
	}

	/*
	 * initialize extra software ring entries. Space for these extra
	 * entries is always allocated
	 */
	memset(&rxq->fake_mbuf, 0x0, sizeof(rxq->fake_mbuf));
	for (i = rxq->nb_rx_desc; i < len; ++i) {
		rxq->sw_ring[i].mbuf = &rxq->fake_mbuf;
	}

	rxq->rx_nb_avail = 0;
	rxq->rx_next_avail = 0;
	rxq->rx_free_trigger = (uint16_t)(rxq->rx_free_thresh - 1);
	rxq->rx_tail = 0;
	rxq->nb_rx_hold = 0;
	rxq->pkt_first_seg = NULL;
	rxq->pkt_last_seg = NULL;

}

int __rte_cold
txgbe_dev_rx_queue_setup(struct rte_eth_dev *dev,
			 uint16_t queue_idx,
			 uint16_t nb_desc,
			 unsigned int socket_id,
			 const struct rte_eth_rxconf *rx_conf,
			 struct rte_mempool *mp)
{
	const struct rte_memzone *rz;
	struct txgbe_rx_queue *rxq;
	struct txgbe_hw     *hw;
	uint16_t len;
	struct txgbe_adapter *adapter = TXGBE_DEV_ADAPTER(dev);
	uint64_t offloads;

	PMD_INIT_FUNC_TRACE();
	hw = TXGBE_DEV_HW(dev);

	offloads = rx_conf->offloads | dev->data->dev_conf.rxmode.offloads;

	/*
	 * Validate number of receive descriptors.
	 * It must not exceed hardware maximum, and must be multiple
	 * of TXGBE_ALIGN.
	 */
	if (nb_desc % TXGBE_RXD_ALIGN != 0 ||
			(nb_desc > TXGBE_RING_DESC_MAX) ||
			(nb_desc < TXGBE_RING_DESC_MIN)) {
		return -EINVAL;
	}

	/* Free memory prior to re-allocation if needed... */
	if (dev->data->rx_queues[queue_idx] != NULL) {
		txgbe_rx_queue_release(dev->data->rx_queues[queue_idx]);
		dev->data->rx_queues[queue_idx] = NULL;
	}

	/* First allocate the rx queue data structure */
	rxq = rte_zmalloc_socket("ethdev RX queue", sizeof(struct txgbe_rx_queue),
				 RTE_CACHE_LINE_SIZE, socket_id);
	if (rxq == NULL)
		return -ENOMEM;
	rxq->mb_pool = mp;
	rxq->nb_rx_desc = nb_desc;
	rxq->rx_free_thresh = rx_conf->rx_free_thresh;
	rxq->queue_id = queue_idx;
	rxq->reg_idx = (uint16_t)((RTE_ETH_DEV_SRIOV(dev).active == 0) ?
		queue_idx : RTE_ETH_DEV_SRIOV(dev).def_pool_q_idx + queue_idx);
	rxq->port_id = dev->data->port_id;
	if (dev->data->dev_conf.rxmode.offloads & DEV_RX_OFFLOAD_KEEP_CRC)
		rxq->crc_len = RTE_ETHER_CRC_LEN;
	else
		rxq->crc_len = 0;
	rxq->drop_en = rx_conf->rx_drop_en;
	rxq->rx_deferred_start = rx_conf->rx_deferred_start;
	rxq->offloads = offloads;

	/*
	 * The packet type in RX descriptor is different for different NICs.
	 * So set different masks for different NICs.
	 */
	rxq->pkt_type_mask = TXGBE_PTID_MASK;

	/*
	 * Allocate RX ring hardware descriptors. A memzone large enough to
	 * handle the maximum ring size is allocated in order to allow for
	 * resizing in later calls to the queue setup function.
	 */
	rz = rte_eth_dma_zone_reserve(dev, "rx_ring", queue_idx,
				      RX_RING_SZ, TXGBE_ALIGN, socket_id);
	if (rz == NULL) {
		txgbe_rx_queue_release(rxq);
		return -ENOMEM;
	}

	/*
	 * Zero init all the descriptors in the ring.
	 */
	memset(rz->addr, 0, RX_RING_SZ);

	/*
	 * Modified to setup VFRDT for Virtual Function
	 */
	if (hw->mac.type == txgbe_mac_raptor_vf) {
		rxq->rdt_reg_addr =
			TXGBE_REG_ADDR(hw, TXGBE_RXWP(queue_idx));
		rxq->rdh_reg_addr =
			TXGBE_REG_ADDR(hw, TXGBE_RXRP(queue_idx));
	} else {
		rxq->rdt_reg_addr =
			TXGBE_REG_ADDR(hw, TXGBE_RXWP(rxq->reg_idx));
		rxq->rdh_reg_addr =
			TXGBE_REG_ADDR(hw, TXGBE_RXRP(rxq->reg_idx));
	}

	rxq->rx_ring_phys_addr = TMZ_PADDR(rz);
	rxq->rx_ring = (struct txgbe_rx_desc *)TMZ_VADDR(rz);

	/*
	 * Certain constraints must be met in order to use the bulk buffer
	 * allocation Rx burst function. If any of Rx queues doesn't meet them
	 * the feature should be disabled for the whole port.
	 */
	if (check_rx_burst_bulk_alloc_preconditions(rxq)) {
		PMD_INIT_LOG(DEBUG, "queue[%d] doesn't meet Rx Bulk Alloc "
				    "preconditions - canceling the feature for "
				    "the whole port[%d]",
			     rxq->queue_id, rxq->port_id);
		adapter->rx_bulk_alloc_allowed = false;
	}

	/*
	 * Allocate software ring. Allow for space at the end of the
	 * S/W ring to make sure look-ahead logic in bulk alloc Rx burst
	 * function does not access an invalid memory region.
	 */
	len = nb_desc;
	if (adapter->rx_bulk_alloc_allowed)
		len += RTE_PMD_TXGBE_RX_MAX_BURST;

	rxq->sw_ring = rte_zmalloc_socket("rxq->sw_ring",
					  sizeof(struct txgbe_rx_entry) * len,
					  RTE_CACHE_LINE_SIZE, socket_id);
	if (!rxq->sw_ring) {
		txgbe_rx_queue_release(rxq);
		return -ENOMEM;
	}

	/*
	 * Always allocate even if it's not going to be needed in order to
	 * simplify the code.
	 *
	 * This ring is used in LRO and Scattered Rx cases and Scattered Rx may
	 * be requested in txgbe_dev_rx_init(), which is called later from
	 * dev_start() flow.
	 */
	rxq->sw_sc_ring =
		rte_zmalloc_socket("rxq->sw_sc_ring",
				   sizeof(struct txgbe_scattered_rx_entry) * len,
				   RTE_CACHE_LINE_SIZE, socket_id);
	if (!rxq->sw_sc_ring) {
		txgbe_rx_queue_release(rxq);
		return -ENOMEM;
	}

	PMD_INIT_LOG(DEBUG, "sw_ring=%p sw_sc_ring=%p hw_ring=%p "
			    "dma_addr=0x%"PRIx64,
		     rxq->sw_ring, rxq->sw_sc_ring, rxq->rx_ring,
		     rxq->rx_ring_phys_addr);

	dev->data->rx_queues[queue_idx] = rxq;

	txgbe_reset_rx_queue(adapter, rxq);

	return 0;
}

void __rte_cold
txgbe_set_rx_function(struct rte_eth_dev *dev)
{
	RTE_SET_USED(dev);
}

/**
 * txgbe_get_rscctl_maxdesc
 *
 * @pool Memory pool of the Rx queue
 */
static inline uint32_t
txgbe_get_rscctl_maxdesc(struct rte_mempool *pool)
{
	struct rte_pktmbuf_pool_private *mp_priv = rte_mempool_get_priv(pool);

	uint16_t maxdesc =
		RTE_IPV4_MAX_PKT_LEN /
			(mp_priv->mbuf_data_room_size - RTE_PKTMBUF_HEADROOM);

	if (maxdesc >= 16)
		return TXGBE_RXCFG_RSCMAX_16;
	else if (maxdesc >= 8)
		return TXGBE_RXCFG_RSCMAX_8;
	else if (maxdesc >= 4)
		return TXGBE_RXCFG_RSCMAX_4;
	else
		return TXGBE_RXCFG_RSCMAX_1;
}

/**
 * txgbe_set_rsc - configure RSC related port HW registers
 *
 * Configures the port's RSC related registers.
 *
 * @dev port handle
 *
 * Returns 0 in case of success or a non-zero error code
 */
static int
txgbe_set_rsc(struct rte_eth_dev *dev)
{
	struct rte_eth_rxmode *rx_conf = &dev->data->dev_conf.rxmode;
	struct txgbe_hw *hw = TXGBE_DEV_HW(dev);
	struct rte_eth_dev_info dev_info = { 0 };
	bool rsc_capable = false;
	uint16_t i;
	uint32_t rdrxctl;
	uint32_t rfctl;

	/* Sanity check */
	dev->dev_ops->dev_infos_get(dev, &dev_info);
	if (dev_info.rx_offload_capa & DEV_RX_OFFLOAD_TCP_LRO)
		rsc_capable = true;

	if (!rsc_capable && (rx_conf->offloads & DEV_RX_OFFLOAD_TCP_LRO)) {
		PMD_INIT_LOG(CRIT, "LRO is requested on HW that doesn't "
				   "support it");
		return -EINVAL;
	}

	/* RSC global configuration */

	if ((rx_conf->offloads & DEV_RX_OFFLOAD_KEEP_CRC) &&
	     (rx_conf->offloads & DEV_RX_OFFLOAD_TCP_LRO)) {
		PMD_INIT_LOG(CRIT, "LRO can't be enabled when HW CRC "
				    "is disabled");
		return -EINVAL;
	}

	rfctl = rd32(hw, TXGBE_PSRCTL);
	if (rsc_capable && (rx_conf->offloads & DEV_RX_OFFLOAD_TCP_LRO))
		rfctl &= ~TXGBE_PSRCTL_RSCDIA;
	else
		rfctl |= TXGBE_PSRCTL_RSCDIA;
	wr32(hw, TXGBE_PSRCTL, rfctl);

	/* If LRO hasn't been requested - we are done here. */
	if (!(rx_conf->offloads & DEV_RX_OFFLOAD_TCP_LRO))
		return 0;

	/* Set PSRCTL.RSCACK bit */
	rdrxctl = rd32(hw, TXGBE_PSRCTL);
	rdrxctl |= TXGBE_PSRCTL_RSCACK;
	wr32(hw, TXGBE_PSRCTL, rdrxctl);

	/* Per-queue RSC configuration */
	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		struct txgbe_rx_queue *rxq = dev->data->rx_queues[i];
		uint32_t srrctl =
			rd32(hw, TXGBE_RXCFG(rxq->reg_idx));
		uint32_t psrtype =
			rd32(hw, TXGBE_POOLRSS(rxq->reg_idx));
		uint32_t eitr =
			rd32(hw, TXGBE_ITR(rxq->reg_idx));

		/*
		 * txgbe PMD doesn't support header-split at the moment.
		 */
		srrctl &= ~TXGBE_RXCFG_HDRLEN_MASK;
		srrctl |= TXGBE_RXCFG_HDRLEN(128);

		/*
		 * TODO: Consider setting the Receive Descriptor Minimum
		 * Threshold Size for an RSC case. This is not an obviously
		 * beneficiary option but the one worth considering...
		 */

		srrctl |= TXGBE_RXCFG_RSCENA;
		srrctl &= ~TXGBE_RXCFG_RSCMAX_MASK;
		srrctl |= txgbe_get_rscctl_maxdesc(rxq->mb_pool);
		psrtype |= TXGBE_POOLRSS_L4HDR;

		/*
		 * RSC: Set ITR interval corresponding to 2K ints/s.
		 *
		 * Full-sized RSC aggregations for a 10Gb/s link will
		 * arrive at about 20K aggregation/s rate.
		 *
		 * 2K inst/s rate will make only 10% of the
		 * aggregations to be closed due to the interrupt timer
		 * expiration for a streaming at wire-speed case.
		 *
		 * For a sparse streaming case this setting will yield
		 * at most 500us latency for a single RSC aggregation.
		 */
		eitr &= ~TXGBE_ITR_IVAL_MASK;
		eitr |= TXGBE_ITR_IVAL_10G(TXGBE_QUEUE_ITR_INTERVAL_DEFAULT);
		eitr |= TXGBE_ITR_WRDSA;

		wr32(hw, TXGBE_RXCFG(rxq->reg_idx), srrctl);
		wr32(hw, TXGBE_POOLRSS(rxq->reg_idx), psrtype);
		wr32(hw, TXGBE_ITR(rxq->reg_idx), eitr);

		/*
		 * RSC requires the mapping of the queue to the
		 * interrupt vector.
		 */
		txgbe_set_ivar_map(hw, 0, rxq->reg_idx, i);
	}

	dev->data->lro = 1;

	PMD_INIT_LOG(DEBUG, "enabling LRO mode");

	return 0;
}

/*
 * Initializes Receive Unit.
 */
int __rte_cold
txgbe_dev_rx_init(struct rte_eth_dev *dev)
{
	struct txgbe_hw *hw;
	struct txgbe_rx_queue *rxq;
	uint64_t bus_addr;
	uint32_t fctrl;
	uint32_t hlreg0;
	uint32_t srrctl;
	uint32_t rdrxctl;
	uint32_t rxcsum;
	uint16_t buf_size;
	uint16_t i;
	struct rte_eth_rxmode *rx_conf = &dev->data->dev_conf.rxmode;
	int rc;

	PMD_INIT_FUNC_TRACE();
	hw = TXGBE_DEV_HW(dev);

	/*
	 * Make sure receives are disabled while setting
	 * up the RX context (registers, descriptor rings, etc.).
	 */
	wr32m(hw, TXGBE_MACRXCFG, TXGBE_MACRXCFG_ENA, 0);
	wr32m(hw, TXGBE_PBRXCTL, TXGBE_PBRXCTL_ENA, 0);

	/* Enable receipt of broadcasted frames */
	fctrl = rd32(hw, TXGBE_PSRCTL);
	fctrl |= TXGBE_PSRCTL_BCA;
	wr32(hw, TXGBE_PSRCTL, fctrl);

	/*
	 * Configure CRC stripping, if any.
	 */
	hlreg0 = rd32(hw, TXGBE_SECRXCTL);
	if (rx_conf->offloads & DEV_RX_OFFLOAD_KEEP_CRC)
		hlreg0 &= ~TXGBE_SECRXCTL_CRCSTRIP;
	else
		hlreg0 |= TXGBE_SECRXCTL_CRCSTRIP;
	wr32(hw, TXGBE_SECRXCTL, hlreg0);

	/*
	 * Configure jumbo frame support, if any.
	 */
	if (rx_conf->offloads & DEV_RX_OFFLOAD_JUMBO_FRAME) {
		wr32m(hw, TXGBE_FRMSZ, TXGBE_FRMSZ_MAX_MASK,
			TXGBE_FRMSZ_MAX(rx_conf->max_rx_pkt_len));
	} else {
		wr32m(hw, TXGBE_FRMSZ, TXGBE_FRMSZ_MAX_MASK,
			TXGBE_FRMSZ_MAX(TXGBE_FRAME_SIZE_DFT));
	}

	/*
	 * If loopback mode is configured, set LPBK bit.
	 */
	hlreg0 = rd32(hw, TXGBE_PSRCTL);
	if (hw->mac.type == txgbe_mac_raptor &&
	    dev->data->dev_conf.lpbk_mode)
		hlreg0 |= TXGBE_PSRCTL_LBENA;
	else
		hlreg0 &= ~TXGBE_PSRCTL_LBENA;

	wr32(hw, TXGBE_PSRCTL, hlreg0);

	/*
	 * Assume no header split and no VLAN strip support
	 * on any Rx queue first .
	 */
	rx_conf->offloads &= ~DEV_RX_OFFLOAD_VLAN_STRIP;

	/* Setup RX queues */
	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rxq = dev->data->rx_queues[i];

		/*
		 * Reset crc_len in case it was changed after queue setup by a
		 * call to configure.
		 */
		if (rx_conf->offloads & DEV_RX_OFFLOAD_KEEP_CRC)
			rxq->crc_len = RTE_ETHER_CRC_LEN;
		else
			rxq->crc_len = 0;

		/* Setup the Base and Length of the Rx Descriptor Rings */
		bus_addr = rxq->rx_ring_phys_addr;
		wr32(hw, TXGBE_RXBAL(rxq->reg_idx),
				(uint32_t)(bus_addr & BIT_MASK32));
		wr32(hw, TXGBE_RXBAH(rxq->reg_idx),
				(uint32_t)(bus_addr >> 32));
		wr32(hw, TXGBE_RXRP(rxq->reg_idx), 0);
		wr32(hw, TXGBE_RXWP(rxq->reg_idx), 0);

		srrctl = TXGBE_RXCFG_RNGLEN(rxq->nb_rx_desc);

		/* Set if packets are dropped when no descriptors available */
		if (rxq->drop_en)
			srrctl |= TXGBE_RXCFG_DROP;

		/*
		 * Configure the RX buffer size in the PKTLEN field of
		 * the RXCFG register of the queue.
		 * The value is in 1 KB resolution. Valid values can be from
		 * 1 KB to 16 KB.
		 */
		buf_size = (uint16_t)(rte_pktmbuf_data_room_size(rxq->mb_pool) -
			RTE_PKTMBUF_HEADROOM);
		buf_size = ROUND_UP(buf_size, 0x1 << 10);
		srrctl |= TXGBE_RXCFG_PKTLEN(buf_size);

		wr32(hw, TXGBE_RXCFG(rxq->reg_idx), srrctl);

		/* It adds dual VLAN length for supporting dual VLAN */
		if (dev->data->dev_conf.rxmode.max_rx_pkt_len +
					    2 * TXGBE_VLAN_TAG_SIZE > buf_size)
			dev->data->scattered_rx = 1;
		if (rxq->offloads & DEV_RX_OFFLOAD_VLAN_STRIP)
			rx_conf->offloads |= DEV_RX_OFFLOAD_VLAN_STRIP;
	}

	if (rx_conf->offloads & DEV_RX_OFFLOAD_SCATTER)
		dev->data->scattered_rx = 1;

	/*
	 * Setup the Checksum Register.
	 * Disable Full-Packet Checksum which is mutually exclusive with RSS.
	 * Enable IP/L4 checkum computation by hardware if requested to do so.
	 */
	rxcsum = rd32(hw, TXGBE_PSRCTL);
	rxcsum |= TXGBE_PSRCTL_PCSD;
	if (rx_conf->offloads & DEV_RX_OFFLOAD_CHECKSUM)
		rxcsum |= TXGBE_PSRCTL_L4CSUM;
	else
		rxcsum &= ~TXGBE_PSRCTL_L4CSUM;

	wr32(hw, TXGBE_PSRCTL, rxcsum);

	if (hw->mac.type == txgbe_mac_raptor) {
		rdrxctl = rd32(hw, TXGBE_SECRXCTL);
		if (rx_conf->offloads & DEV_RX_OFFLOAD_KEEP_CRC)
			rdrxctl &= ~TXGBE_SECRXCTL_CRCSTRIP;
		else
			rdrxctl |= TXGBE_SECRXCTL_CRCSTRIP;
		wr32(hw, TXGBE_SECRXCTL, rdrxctl);
	}

	rc = txgbe_set_rsc(dev);
	if (rc)
		return rc;

	txgbe_set_rx_function(dev);

	return 0;
}

/*
 * Initializes Transmit Unit.
 */
void __rte_cold
txgbe_dev_tx_init(struct rte_eth_dev *dev)
{
	struct txgbe_hw     *hw;
	struct txgbe_tx_queue *txq;
	uint64_t bus_addr;
	uint16_t i;

	PMD_INIT_FUNC_TRACE();
	hw = TXGBE_DEV_HW(dev);

	/* Setup the Base and Length of the Tx Descriptor Rings */
	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		txq = dev->data->tx_queues[i];

		bus_addr = txq->tx_ring_phys_addr;
		wr32(hw, TXGBE_TXBAL(txq->reg_idx),
				(uint32_t)(bus_addr & BIT_MASK32));
		wr32(hw, TXGBE_TXBAH(txq->reg_idx),
				(uint32_t)(bus_addr >> 32));
		wr32m(hw, TXGBE_TXCFG(txq->reg_idx), TXGBE_TXCFG_BUFLEN_MASK,
			TXGBE_TXCFG_BUFLEN(txq->nb_tx_desc));
		/* Setup the HW Tx Head and TX Tail descriptor pointers */
		wr32(hw, TXGBE_TXRP(txq->reg_idx), 0);
		wr32(hw, TXGBE_TXWP(txq->reg_idx), 0);
	}
}


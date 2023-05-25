/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Arm Limited.
 */

#include <stdint.h>
#include <ethdev_driver.h>

#include "ixgbe_ethdev.h"
#include "ixgbe_rxtx.h"

#pragma GCC diagnostic ignored "-Wcast-qual"

void
ixgbe_recycle_rx_descriptors_refill_vec(void *rx_queue, uint16_t nb_mbufs)
{
	struct ixgbe_rx_queue *rxq = rx_queue;
	struct ixgbe_rx_entry *rxep;
	volatile union ixgbe_adv_rx_desc *rxdp;
	uint16_t rx_id;
	uint64_t paddr;
	uint64_t dma_addr;
	uint16_t i;

	rxdp = rxq->rx_ring + rxq->rxrearm_start;
	rxep = &rxq->sw_ring[rxq->rxrearm_start];

	for (i = 0; i < nb_mbufs; i++) {
		/* Initialize rxdp descs. */
		paddr = (rxep[i].mbuf)->buf_iova + RTE_PKTMBUF_HEADROOM;
		dma_addr = rte_cpu_to_le_64(paddr);
		/* Flush descriptors with pa dma_addr */
		rxdp[i].read.hdr_addr = 0;
		rxdp[i].read.pkt_addr = dma_addr;
	}

	/* Update the descriptor initializer index */
	rxq->rxrearm_start += nb_mbufs;
	if (rxq->rxrearm_start >= rxq->nb_rx_desc)
		rxq->rxrearm_start = 0;

	rxq->rxrearm_nb -= nb_mbufs;

	rx_id = (uint16_t)((rxq->rxrearm_start == 0) ?
			(rxq->nb_rx_desc - 1) : (rxq->rxrearm_start - 1));

	/* Update the tail pointer on the NIC */
	IXGBE_PCI_REG_WRITE(rxq->rdt_reg_addr, rx_id);
}

uint16_t
ixgbe_recycle_tx_mbufs_reuse_vec(void *tx_queue,
		struct rte_eth_recycle_rxq_info *recycle_rxq_info)
{
	struct ixgbe_tx_queue *txq = tx_queue;
	struct ixgbe_tx_entry *txep;
	struct rte_mbuf **rxep;
	struct rte_mbuf *m[RTE_IXGBE_TX_MAX_FREE_BUF_SZ];
	int i, j, n;
	uint32_t status;
	uint16_t avail = 0;
	uint16_t mbuf_ring_size = recycle_rxq_info->mbuf_ring_size;
	uint16_t mask = recycle_rxq_info->mbuf_ring_size - 1;
	uint16_t refill_requirement = recycle_rxq_info->refill_requirement;
	uint16_t refill_head = *recycle_rxq_info->refill_head;
	uint16_t receive_tail = *recycle_rxq_info->receive_tail;

	/* Get available recycling Rx buffers. */
	avail = (mbuf_ring_size - (refill_head - receive_tail)) & mask;

	/* Check Tx free thresh and Rx available space. */
	if (txq->nb_tx_free > txq->tx_free_thresh || avail <= txq->tx_rs_thresh)
		return 0;

	/* check DD bits on threshold descriptor */
	status = txq->tx_ring[txq->tx_next_dd].wb.status;
	if (!(status & IXGBE_ADVTXD_STAT_DD))
		return 0;

	n = txq->tx_rs_thresh;

	/* Mbufs recycle can only support no ring buffer wrapping around.
	 * Two case for this:
	 *
	 * case 1: The refill head of Rx buffer ring needs to be aligned with
	 * buffer ring size. In this case, the number of Tx freeing buffers
	 * should be equal to refill_requirement.
	 *
	 * case 2: The refill head of Rx ring buffer does not need to be aligned
	 * with buffer ring size. In this case, the update of refill head can not
	 * exceed the Rx buffer ring size.
	 */
	if (refill_requirement != n ||
		(!refill_requirement && (refill_head + n > mbuf_ring_size)))
		return 0;

	/* First buffer to free from S/W ring is at index
	 * tx_next_dd - (tx_rs_thresh-1).
	 */
	txep = &txq->sw_ring[txq->tx_next_dd - (n - 1)];
	rxep = recycle_rxq_info->mbuf_ring;
	rxep += refill_head;

	if (txq->offloads & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) {
		/* Directly put mbufs from Tx to Rx. */
		for (i = 0; i < n; i++, rxep++, txep++)
			*rxep = txep[0].mbuf;
	} else {
		for (i = 0, j = 0; i < n; i++) {
			/* Avoid txq contains buffers from expected mempool. */
			if (unlikely(recycle_rxq_info->mp
						!= txep[i].mbuf->pool))
				return 0;

			m[j] = rte_pktmbuf_prefree_seg(txep[i].mbuf);

			/* In case 1, each of Tx buffers should be the
			 * last reference.
			 */
			if (unlikely(m[j] == NULL && refill_requirement))
				return 0;
			/* In case 2, the number of valid Tx free
			 * buffers should be recorded.
			 */
			j++;
		}
		rte_memcpy(rxep, m, sizeof(void *) * j);
	}

	/* Update counters for Tx. */
	txq->nb_tx_free = (uint16_t)(txq->nb_tx_free + txq->tx_rs_thresh);
	txq->tx_next_dd = (uint16_t)(txq->tx_next_dd + txq->tx_rs_thresh);
	if (txq->tx_next_dd >= txq->nb_tx_desc)
		txq->tx_next_dd = (uint16_t)(txq->tx_rs_thresh - 1);

	return n;
}

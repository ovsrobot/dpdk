/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2026 Qualcomm Technologies, Inc.
 */

#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_io.h>
#include <rte_mbuf.h>

#include "stmmac.h"
#include "stmmac_regs.h"
#include "stmmac_logs.h"

#define STMMAC_RX_BUNDLE	32
#define STMMAC_TX_BUNDLE	32

/* MDIO busy-poll bound, matching stmmac_mdio.c (10000 x 1 us) */
#define STMMAC_MDIO_TIMEOUT_US		10000

/* Index of the TX descriptor the DMA is working on: everything before it is sent. */
static inline uint16_t
stmmac_tx_dma_slot(struct stmmac_tx_queue *txq)
{
	uint32_t cur = rte_read32((uint8_t *)txq->chan_base + DMA_CHAN_OFF_CURTXD);

	return (uint16_t)(((cur - (uint32_t)txq->tx_ring_iova) /
			   sizeof(struct stmmac_desc)) % txq->nb_desc);
}

/*
 * MDIO clause-22 read. Uses the GMAC4 opcode and the address/register field
 * layout from dwmac4_core.c. The CSR clock divider is left at zero.
 */
uint16_t
stmmac_mdio_read(void *mac_base, uint16_t mdio_addr, uint16_t phyreg)
{
	void *addr_reg = (uint8_t *)mac_base + GMAC_MDIO_ADDR;
	void *data_reg = (uint8_t *)mac_base + GMAC_MDIO_DATA;
	uint32_t value;
	unsigned int timeout = STMMAC_MDIO_TIMEOUT_US;

	while ((rte_read32(addr_reg) & MII_BUSY) && timeout > 0) {
		rte_delay_us(1);
		timeout--;
	}
	if (timeout == 0) {
		STMMAC_PMD_ERR("MDIO busy timeout before read");
		return 0xffff;
	}

	value = MII_GMAC4_READ | MII_BUSY;
	value |= ((uint32_t)mdio_addr << MII_ADDR_SHIFT) & MII_ADDR_MASK;
	value |= ((uint32_t)phyreg << MII_REG_SHIFT) & MII_REG_MASK;

	rte_write32(value, addr_reg);

	timeout = STMMAC_MDIO_TIMEOUT_US;
	while ((rte_read32(addr_reg) & MII_BUSY) && timeout > 0) {
		rte_delay_us(1);
		timeout--;
	}
	if (timeout == 0) {
		STMMAC_PMD_ERR("MDIO busy timeout after read");
		return 0xffff;
	}

	return (uint16_t)(rte_read32(data_reg) & MII_DATA_MASK);
}

void
stmmac_mdio_write(void *mac_base, uint16_t mdio_addr, uint16_t phyreg,
		  uint16_t phydata)
{
	void *addr_reg = (uint8_t *)mac_base + GMAC_MDIO_ADDR;
	void *data_reg = (uint8_t *)mac_base + GMAC_MDIO_DATA;
	uint32_t value;
	unsigned int timeout = STMMAC_MDIO_TIMEOUT_US;

	while ((rte_read32(addr_reg) & MII_BUSY) && timeout > 0) {
		rte_delay_us(1);
		timeout--;
	}
	if (timeout == 0) {
		STMMAC_PMD_ERR("MDIO busy timeout before write");
		return;
	}

	rte_write32(phydata, data_reg);

	value = MII_GMAC4_WRITE | MII_BUSY;
	value |= ((uint32_t)mdio_addr << MII_ADDR_SHIFT) & MII_ADDR_MASK;
	value |= ((uint32_t)phyreg << MII_REG_SHIFT) & MII_REG_MASK;

	rte_write32(value, addr_reg);

	timeout = STMMAC_MDIO_TIMEOUT_US;
	while ((rte_read32(addr_reg) & MII_BUSY) && timeout > 0) {
		rte_delay_us(1);
		timeout--;
	}
	if (timeout == 0)
		STMMAC_PMD_ERR("MDIO busy timeout after write");
}

/*
 * Refill 'cleaned_cnt' RX descriptors starting at rx_refill. Mbufs are
 * allocated in bulk, descriptors are written, and each cache line of
 * descriptors is cleaned once. The DMA doorbell moves to the last descriptor
 * handed back. Returns the number refilled; a short count means the mbuf pool
 * ran out, and the remaining slots are retried on the next burst.
 */
static uint16_t
stmmac_refill_rx_ring(struct stmmac_rx_queue *rxq, uint16_t cleaned_cnt)
{
	struct rte_mbuf *m[STMMAC_RX_BUNDLE];
	struct stmmac_desc *grp_start = NULL;
	uint16_t i = rxq->rx_refill;
	uint16_t j;
	uint16_t k = STMMAC_RX_BUNDLE;
	uint16_t grp_cnt = 0;

	for (j = 0; j < cleaned_cnt; j++) {
		struct stmmac_desc *desc = &rxq->rx_ring[i];
		struct rte_mbuf *mb;
		uint64_t iova;

		/* bulk allocation, sized to the descriptors still to refill */
		if (k == STMMAC_RX_BUNDLE) {
			uint16_t m_cnt = RTE_MIN(cleaned_cnt - j, STMMAC_RX_BUNDLE);

			if (rte_pktmbuf_alloc_bulk(rxq->mb_pool, m, m_cnt)) {
				rxq->rx_nombuf++;
				break;
			}
			k = 0;
		}
		mb = m[k++];

		rxq->sw_ring[i] = mb;
		/* drop stale CPU lines over the buffer the DMA is about to write */
		stmmac_dcache_flush(rte_pktmbuf_mtod(mb, void *),
				    rte_pktmbuf_data_room_size(rxq->mb_pool) -
				    RTE_PKTMBUF_HEADROOM);

		/* full 36-bit buffer address: the mbufs live above 4 GiB */
		iova = rte_pktmbuf_iova(mb);
		desc->des[0] = (uint32_t)iova;
		desc->des[1] = (uint32_t)(iova >> 32);
		desc->des[2] = 0;
		rte_io_wmb();
		desc->des[3] = RDES3_OWN | RDES3_BUFFER1_VALID_ADDR |
			       RDES3_INT_ON_COMPLETION_EN;

		/* clean the descriptors one cache line at a time */
		if (grp_cnt == 0)
			grp_start = desc;
		grp_cnt++;
		if (grp_cnt == STMMAC_DESCS_PER_LINE || i == rxq->nb_desc - 1) {
			stmmac_dcache_clean(grp_start, grp_cnt * sizeof(*desc));
			grp_cnt = 0;
		}

		i = (i + 1) % rxq->nb_desc;
	}

	/* clean the partial group left by the last descriptor */
	if (grp_cnt)
		stmmac_dcache_clean(grp_start, grp_cnt * sizeof(struct stmmac_desc));

	rxq->rx_refill = i;

	if (j > 0) {
		uint16_t last = (i + rxq->nb_desc - 1) % rxq->nb_desc;
		uint64_t tail_iova = rxq->rx_ring_iova +
			(uint64_t)last * sizeof(struct stmmac_desc);

		/*
		 * Clear RBU if the DMA suspended on an unavailable descriptor. This
		 * is a write, not a status read: a register read stalls the core.
		 * The DMA only suspends after it has used every slot refilled so
		 * far, so the burst that refills again is where RBU is cleared.
		 */
		rte_write32(DMA_CHAN_STATUS_RBU,
			    (uint8_t *)rxq->chan_base + DMA_CHAN_OFF_STATUS);

		/*
		 * The doorbell is the last descriptor handed back. Writing the
		 * refill index instead would make RXTAIL equal CURRXD, which the
		 * DMA treats as an empty ring. The 36-bit tail is written HI first.
		 */
		rte_write32((uint32_t)(tail_iova >> 32),
			    (uint8_t *)rxq->chan_base + DMA_CHAN_OFF_RX_END_ADDR_HI);
		rte_io_wmb();
		rte_write32((uint32_t)tail_iova,
			    (uint8_t *)rxq->chan_base + DMA_CHAN_OFF_RX_END_ADDR);
	}

	return j;
}

uint16_t
stmmac_rx_pkt_burst_nc(void *rx_queue, struct rte_mbuf **rx_pkts,
		       uint16_t nb_pkts)
{
	struct stmmac_rx_queue *rxq = rx_queue;
	uint16_t nb_rx = 0;
	uint16_t start = rxq->rx_tail;
	uint16_t tail = start;
	uint16_t pending;

	while (nb_rx < nb_pkts) {
		struct stmmac_desc *desc = &rxq->rx_ring[tail];
		struct rte_mbuf *rxm;
		uint32_t des3;
		uint32_t pkt_len;

		/* slot is waiting for a refill (mbuf allocation failed) */
		if (rxq->sw_ring[tail] == NULL)
			break;

		/*
		 * Shikra is not DMA-coherent: invalidate the descriptor line once
		 * per cache line, at the start of the burst and at each line
		 * boundary. A stale OWN bit on a later slot only defers that frame
		 * to the next burst.
		 */
		if (tail == start || tail % STMMAC_DESCS_PER_LINE == 0)
			stmmac_dcache_inval_line(desc);
		des3 = rte_read32_relaxed(&desc->des[3]);

		if (des3 & RDES3_OWN)
			break;

		if (des3 & (RDES3_CONTEXT_DESCRIPTOR | RDES3_ERROR_SUMMARY)) {
			/* not a frame to deliver: free its buffer, refill allocates a new one */
			if (des3 & RDES3_ERROR_SUMMARY)
				rxq->rx_errors++;
			rte_pktmbuf_free(rxq->sw_ring[tail]);
			rxq->sw_ring[tail] = NULL;
			tail = (tail + 1) % rxq->nb_desc;
			continue;
		}

		rxm = rxq->sw_ring[tail];
		rxq->sw_ring[tail] = NULL;
		pkt_len = des3 & RDES3_PACKET_SIZE_MASK;

		/* drop stale CPU lines over the received payload */
		stmmac_dcache_flush((uint8_t *)rxm->buf_addr + RTE_PKTMBUF_HEADROOM,
				    pkt_len);

		rxm->data_off = RTE_PKTMBUF_HEADROOM;
		rxm->pkt_len = pkt_len;
		rxm->data_len = pkt_len;
		rxm->port = rxq->port_id;
		rxm->nb_segs = 1;
		rxm->next = NULL;
		rxm->ol_flags = 0;

		if (desc->des[1] & (RDES1_IPV4_HEADER | RDES1_IPV6_HEADER)) {
			if (desc->des[1] & RDES1_IP_CSUM_ERROR)
				rxm->ol_flags |= RTE_MBUF_F_RX_IP_CKSUM_BAD;
			else
				rxm->ol_flags |= RTE_MBUF_F_RX_IP_CKSUM_GOOD;
		}

		rx_pkts[nb_rx++] = rxm;
		rxq->rx_packets++;
		rxq->rx_bytes += pkt_len;

		tail = (tail + 1) % rxq->nb_desc;
	}

	rxq->rx_tail = tail;

	/* refill what was consumed, plus any slots a failed allocation left pending */
	pending = (tail + rxq->nb_desc - rxq->rx_refill) % rxq->nb_desc;
	if (pending)
		stmmac_refill_rx_ring(rxq, pending);

	return nb_rx;
}

/*
 * Reclaim sent TX frames in bulk, up to the descriptor the DMA is working on.
 * Everything before that slot has been transmitted.
 */
static uint16_t
stmmac_clean_tx_ring(struct stmmac_tx_queue *txq)
{
	struct rte_mbuf *m[STMMAC_TX_BUNDLE];
	uint16_t hwci = stmmac_tx_dma_slot(txq);
	uint16_t i = txq->tx_free;
	uint16_t n = 0;
	uint16_t total = 0;

	while (i != hwci && txq->sw_ring[i] != NULL) {
		if (i == txq->tx_free || i % STMMAC_DESCS_PER_LINE == 0)
			stmmac_dcache_inval_line(&txq->tx_ring[i]);
		if (rte_read32_relaxed(&txq->tx_ring[i].des[3]) & TDES3_ERROR_SUMMARY)
			txq->tx_errors++;

		m[n++] = txq->sw_ring[i];
		txq->sw_ring[i] = NULL;
		if (n == STMMAC_TX_BUNDLE) {
			rte_pktmbuf_free_bulk(m, n);
			total += n;
			n = 0;
		}
		i = (i + 1) % txq->nb_desc;
	}

	if (n) {
		rte_pktmbuf_free_bulk(m, n);
		total += n;
	}
	txq->tx_free = i;
	return total;
}

/* Clean the descriptor lines that hold 'cnt' slots from 'first', once, before the doorbell */
static void
stmmac_tx_clean_range(struct stmmac_tx_queue *txq, uint16_t first, uint16_t cnt)
{
	uint16_t s = first - first % STMMAC_DESCS_PER_LINE;
	uint16_t left = cnt + (first - s);

	left = (left + STMMAC_DESCS_PER_LINE - 1) / STMMAC_DESCS_PER_LINE *
		STMMAC_DESCS_PER_LINE;
	if (left > txq->nb_desc)
		left = txq->nb_desc;

	while (left) {
		uint16_t run = RTE_MIN((uint16_t)(txq->nb_desc - s), left);

		stmmac_dcache_clean(&txq->tx_ring[s], run * sizeof(struct stmmac_desc));
		s = (s + run) % txq->nb_desc;
		left -= run;
	}
}

uint16_t
stmmac_tx_pkt_burst_nc(void *tx_queue, struct rte_mbuf **tx_pkts,
		       uint16_t nb_pkts)
{
	struct stmmac_tx_queue *txq = tx_queue;
	uint16_t nb_tx = 0;
	uint16_t first = txq->tx_tail;
	uint16_t tail = first;

	stmmac_clean_tx_ring(txq);

	/* drop the CPU copy of the first line before filling into it */
	stmmac_dcache_inval_line(&txq->tx_ring[first - first % STMMAC_DESCS_PER_LINE]);

	while (nb_tx < nb_pkts) {
		struct stmmac_desc *desc = &txq->tx_ring[tail];
		struct rte_mbuf *txm = tx_pkts[nb_tx];
		uint32_t tdes3;
		uint64_t iova;

		if (unlikely(txm->nb_segs != 1)) {
			STMMAC_PMD_ERR("multi-segment mbuf not supported");
			break;
		}

		/* ring full: this slot still holds a frame the DMA has not finished */
		if (txq->sw_ring[tail] != NULL) {
			txq->tx_ring_full++;
			break;
		}

		/* entering a new line: drop the CPU copy before writing into it */
		if (tail != first && tail % STMMAC_DESCS_PER_LINE == 0)
			stmmac_dcache_inval_line(desc);

		/* the CPU-written payload must reach memory before the DMA reads it */
		stmmac_dcache_clean(rte_pktmbuf_mtod(txm, void *),
				    rte_pktmbuf_data_len(txm));

		iova = rte_pktmbuf_iova(txm);
		desc->des[0] = (uint32_t)iova;
		desc->des[1] = (uint32_t)(iova >> 32);
		desc->des[2] = rte_pktmbuf_data_len(txm) & TDES2_BUFFER1_SIZE_MASK;

		tdes3 = rte_pktmbuf_pkt_len(txm) & TDES3_PACKET_SIZE_MASK;
		tdes3 |= TDES3_FIRST_DESCRIPTOR | TDES3_LAST_DESCRIPTOR;
		if (txm->ol_flags & (RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_L4_MASK))
			tdes3 |= (TX_CIC_FULL << TDES3_CHECKSUM_INSERTION_SHIFT);

		txq->sw_ring[tail] = txm;

		rte_io_wmb();
		desc->des[3] = tdes3 | TDES3_OWN;

		txq->tx_packets++;
		txq->tx_bytes += rte_pktmbuf_pkt_len(txm);

		tail = (tail + 1) % txq->nb_desc;
		nb_tx++;
	}

	if (nb_tx > 0) {
		uint64_t tail_iova = txq->tx_ring_iova +
			(uint64_t)tail * sizeof(struct stmmac_desc);

		/* the written descriptor lines are cleaned once, then the doorbell moves */
		stmmac_tx_clean_range(txq, first, nb_tx);
		txq->tx_tail = tail;
		rte_write32((uint32_t)tail_iova,
			    (uint8_t *)txq->chan_base + DMA_CHAN_OFF_TX_END_ADDR);
	}

	return nb_tx;
}

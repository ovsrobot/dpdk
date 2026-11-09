/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020-2026 Altera Corporation
 */

#include <string.h>

#include <rte_malloc.h>

#include "mcdma_eth.h"

static uint16_t mcdma_descq_ring_avail(struct mcdma_queue *q)
{
	uint16_t used;

	rte_rmb();
	used = MCDMA_RING_USED_COUNT(q->prod_didx, q->freed_cons_didx, q->num_descs);
	if (used >= q->num_descs - 1)
		return 0;

	/* Reserve one slot to distinguish full from empty. */
	return q->num_descs - 1 - used;
}

/* Ring slots consumed by nb_segs data descriptors, including link slots. */
static uint16_t
mcdma_desc_slots_for_segs(struct mcdma_queue *q, uint16_t nb_segs)
{
	uint16_t prod = MCDMA_NEXT_IDX(mcdma_queue_prod_ring(q), q->num_descs);
	uint16_t slots = 0;
	uint16_t i;

	for (i = 0; i < nb_segs; i++) {
		struct mcdma_desc *d = MCDMA_DESC_PTR(q, prod);

		if (d->link) {
			slots++;
			prod = MCDMA_NEXT_IDX(prod, q->num_descs);
		}
		slots++;
		prod = MCDMA_NEXT_IDX(prod, q->num_descs);
	}
	return slots;
}

/*
 * Link descriptors sit at every page boundary (idx 127, 255, ...).
 * Jump to each link slot instead of walking every ring position.
 */
static uint16_t
mcdma_desc_segs_for_slots(struct mcdma_queue *q, uint16_t slots)
{
	uint16_t prod = MCDMA_NEXT_IDX(mcdma_queue_prod_ring(q), q->num_descs);
	uint16_t links = 0;
	uint16_t remaining = slots;
	uint16_t pos = prod;

	while (remaining > 0) {
		uint16_t off = pos & (MCDMA_NUM_DESC_PER_PAGE - 1);
		uint16_t to_link;

		if (off == MCDMA_NUM_DESC_PER_PAGE - 1) {
			links++;
			pos = MCDMA_NEXT_IDX(pos, q->num_descs);
			remaining--;
			continue;
		}

		to_link = (MCDMA_NUM_DESC_PER_PAGE - 1) - off;
		if (remaining <= to_link)
			break;

		links++;
		remaining -= to_link + 1;
		pos = (pos + to_link + 1) % q->num_descs;
	}

	return slots - links;
}

static uint16_t mcdma_complete_requests(struct mcdma_queue *q,
					struct rte_mbuf **pkts, uint16_t nb_pkts,
					int dir)
{
	struct mcdma_desc *d;
	struct rte_mbuf *mb;
	uint16_t nb_to_free;
	uint16_t idx;

	rte_rmb();
	nb_to_free = MCDMA_RING_USED_COUNT(q->cons_didx,
				q->freed_cons_didx, q->num_descs);

	if (dir == MCDMA_DIR_H2D) {
		uint16_t i;

		for (i = 0; i < nb_to_free; i++) {
			idx = MCDMA_NEXT_IDX(mcdma_queue_freed_ring(q),
					     q->num_descs);
			d = MCDMA_DESC_PTR(q, idx);
			if (!d->link && d->eof && q->sw_ring[idx] != NULL)
				rte_pktmbuf_free(q->sw_ring[idx]);

			q->sw_ring[idx] = NULL;
			q->freed_cons_didx = d->didx;
			if (!d->link)
				q->complete++;
		}

	} else {
		uint16_t nb_returned = 0;
		uint16_t nb_avail = nb_to_free;

		while (nb_avail > 0) {
			idx = MCDMA_NEXT_IDX(mcdma_queue_freed_ring(q),
					     q->num_descs);
			d = MCDMA_DESC_PTR(q, idx);

			if (d->link) {
				q->freed_cons_didx = d->didx;
				nb_avail--;
				continue;
			}

			mb = q->sw_ring[idx];
			/*
			 * Non-scatter Rx: one buffer holds the full frame.
			 * Deliver only on EOF with SOF on the same descriptor.
			 */
			if (mb != NULL && d->eof && d->sof && !d->desc_invalid &&
			    nb_returned >= nb_pkts)
				break;

			q->freed_cons_didx = d->didx;
			nb_avail--;
			q->complete++;

			q->sw_ring[idx] = NULL;
			if (mb == NULL) {
				q->drop_pkts++;
				continue;
			}

			if (!d->eof || !d->sof || d->desc_invalid) {
				rte_pktmbuf_free(mb);
				q->drop_pkts++;
				continue;
			}

			mb->pkt_len = d->rx_pyld_cnt;
			rte_pktmbuf_data_len(mb) = d->rx_pyld_cnt;

			pkts[nb_returned++] = mb;
			q->rx_pkts++;
			q->rx_bytes += mb->pkt_len;
		}
		nb_to_free = nb_returned;
	}

	rte_wmb();

	/* return number of packets processed */
	return nb_to_free;
}

static int mcdma_descq_queue_prepare(struct mcdma_queue *q,
				     struct rte_mbuf *mb, int dir)
{
	struct mcdma_desc *d;
	uint16_t prod_nxt = MCDMA_NEXT_IDX(mcdma_queue_prod_ring(q), q->num_descs);
	uint16_t prod_didx = q->prod_didx;
	uint16_t prod;
	uint8_t first_desc = 1;
	struct rte_mbuf *seg = mb;
	int cnt = 0;

	if (dir == MCDMA_DIR_D2H &&
	    (mb->nb_segs != 1 || mb->next != NULL)) {
		PMD_DRV_LOG(ERR,
			    "Rx queue %u: multi-segment mbuf not supported (nb_segs=%u)",
			    q->qid, mb->nb_segs);
		return -EINVAL;
	}

	for (cnt = 0; cnt < mb->nb_segs; cnt++) {
		prod = prod_nxt;
		d = MCDMA_DESC_PTR(q, prod);
		if (d->link) { /* skip the link desc */
			q->didx = MCDMA_DIDX_NEXT(q->didx, q->num_descs);
			d->didx = q->didx;
			prod = MCDMA_NEXT_IDX(prod, q->num_descs);
			d = MCDMA_DESC_PTR(q, prod);
		}

		memset(d, 0, sizeof(*d));
		if (dir == MCDMA_DIR_D2H) {
			/* Only ST supported for now */
			d->dest = rte_pktmbuf_iova(seg);
			d->len = RTE_MIN(q->rx_seg_len, rte_pktmbuf_tailroom(seg));
		} else {
			uint32_t seg_len = rte_pktmbuf_data_len(seg);

			if (seg_len > MCDMA_IP_MAX_FRAME_LEN)
				seg_len = MCDMA_IP_MAX_FRAME_LEN;

			d->len = seg_len;
			/* Only ST supported for now */
			d->src = rte_pktmbuf_iova(seg);

			/* Default sof on the first mbuf and eof on last */
			if (first_desc) {
				d->sof = 1;
				first_desc = 0;
			}
			if (seg->next == NULL)
				d->eof = 1;
		}

		if (dir == MCDMA_DIR_H2D) {
			/*
			 * One sw_ring owner per packet: head mbuf on the EOF
			 * descriptor so completion frees the whole chain once.
			 */
			q->sw_ring[prod] = d->eof ? mb : NULL;
		} else {
			q->sw_ring[prod] = seg;
		}
		q->didx = MCDMA_DIDX_NEXT(q->didx, q->num_descs);
		d->didx = q->didx;
		prod_didx = q->didx;
		seg = seg->next;
		prod_nxt = MCDMA_NEXT_IDX(prod, q->num_descs);
	}

	q->prod_didx = prod_didx;

	return 0;
}

static void mcdma_descq_queue_submit(struct mcdma_queue *q)
{
	uint16_t hw_tail = q->prod_didx;
	uint16_t hw_submitted = q->submitted_didx;
	uint16_t prod_ring = mcdma_queue_prod_ring(q);
	struct mcdma_desc *d = MCDMA_DESC_PTR(q, prod_ring);

	/* Only writeback supported as of now */
	d->wb_en = MCDMA_COMPL_WB;

	/*
	 * resubmitting the same tail ptr update indicates no data to transfer,
	 * So first submit 1 desc and then rest.
	 */
	if (hw_tail == hw_submitted) {
		uint16_t nudge = MCDMA_NEXT_IDX(hw_submitted, q->num_descs);
		uint32_t count = 0;

		mcdma_qcsr_reg_writel(q->qcsr, MCDMA_QCSR_Q_TAIL_POINTER, nudge);
		do {
			uint32_t head = mcdma_qcsr_reg_readl(q->qcsr,
							     MCDMA_QCSR_Q_HEAD_POINTER);
			volatile uint16_t qhead = mcdma_qcsr_ptr_val(head);

			if (qhead == nudge)
				break;
			count++;
		} while (count < MCDMA_CNT_HEAD_MOVE);
	}

	rte_wmb();
	mcdma_qcsr_reg_writel(q->qcsr, MCDMA_QCSR_Q_TAIL_POINTER, hw_tail);
	q->submitted_didx = hw_tail;
}

uint16_t mcdma_xmit_pkts(void *txq, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	struct mcdma_queue *q = txq;
	uint16_t count;
	uint16_t i;

	mcdma_complete_requests(q, NULL, 0, MCDMA_DIR_H2D);

	for (count = 0; count < nb_pkts; count++) {
		uint16_t need;
		uint16_t nb_avail;
		struct rte_mbuf *mb;

		mb = tx_pkts[count];
		/* return check not required for H2D */

		if (mb->nb_segs == 0)
			break;

		need = mcdma_desc_slots_for_segs(q, mb->nb_segs);
		nb_avail = mcdma_descq_ring_avail(q);
		if (nb_avail < need)
			break;

		if (mcdma_descq_queue_prepare(q, mb, MCDMA_DIR_H2D) != 0)
			break;
	}

	rte_wmb();
	if (count)
		mcdma_descq_queue_submit(q);

	for (i = 0; i < count; i++) {
		q->tx_pkts++;
		q->tx_bytes += rte_pktmbuf_pkt_len(tx_pkts[i]);
	}

	return count;
}

uint16_t mcdma_recv_pkts(void *rxq, struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	struct mcdma_queue *q = rxq;
	struct rte_mbuf *mb;
	struct rte_mbuf **repl;
	uint32_t mb_avail;
	uint16_t cnt, nb_avail, to_submit, can_submit;
	uint16_t i;

	cnt = mcdma_complete_requests(q, rx_pkts, nb_pkts, MCDMA_DIR_D2H);
	q->processed_cur = cnt;

	/* 1 - How much ring avail */
	nb_avail = mcdma_descq_ring_avail(q);
	if (!nb_avail)
		return cnt;

	/* 2 - Limit slot scan to 4 descriptor pages per poll (HW/latency bound). */
	can_submit = mcdma_desc_segs_for_slots(q,
			RTE_MIN(nb_avail, MCDMA_NUM_DESC_PER_PAGE * 4));
	if (can_submit < q->burst_size)
		return cnt;

	to_submit = (can_submit / q->burst_size) * q->burst_size;

	/* 3 - Limit to max mbuf available */
	mb_avail = rte_mempool_avail_count(q->mb_pool);
	if (to_submit > mb_avail)
		to_submit = (mb_avail / q->burst_size) * q->burst_size;

	/* 4 - Support submission only in batches */
	if (to_submit < q->burst_size)
		return cnt;

	repl = rte_malloc_socket(NULL, q->burst_size * sizeof(*repl), 0,
				 q->socket_id);
	if (repl == NULL) {
		PMD_DRV_LOG(ERR, "Failed to allocate repl, queue id = %u, burst_size = %u",
			    q->qid, q->burst_size);
		return cnt;
	}

	q->ring_avail = nb_avail;
	q->ring_to_submit = to_submit;

	while (to_submit > 0) {
		uint16_t batch = RTE_MIN(to_submit, q->burst_size);
		int err;

		err = rte_mempool_get_bulk(q->mb_pool, (void **)repl, batch);
		if (err) {
			q->rx_nombuf += batch;
			PMD_DRV_LOG(ERR, "No MBUFS, queue id = %u, nb_avail = %u, batch: %u, "
				    "mbuf_avail_count = %u, mbuf_in_use_count = %u",
				    q->qid, nb_avail, batch,
				    rte_mempool_avail_count(q->mb_pool),
				    rte_mempool_in_use_count(q->mb_pool));
			break;
		}

		for (i = 0; i < batch; i++) {
			mb = repl[i];
			rte_pktmbuf_reset(mb);
			if (mcdma_descq_queue_prepare(q, mb, MCDMA_DIR_D2H) != 0) {
				rte_mempool_put_bulk(q->mb_pool,
						     (void **)&repl[i],
						     batch - i);
				break;
			}
		}

		if (i < batch) {
			if (i == 0)
				break;
			to_submit -= i;
			break;
		}

		to_submit -= batch;
	}

	rte_wmb();
	if (q->prod_didx != q->submitted_didx)
		mcdma_descq_queue_submit(q);

	rte_free(repl);
	return cnt;
}

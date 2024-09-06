/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 Yunsilicon Technology Co., Ltd.
 */

#include "xsc_log.h"
#include "xsc_defs.h"
#include "xsc_dev.h"
#include "xsc_ethdev.h"
#include "xsc_rxtx.h"
#include "xsc_utils.h"
#include "xsc_ctrl.h"

#define XSC_CQE_OWNER_MASK 0x1
#define XSC_CQE_OWNER_HW   0x2
#define XSC_CQE_OWNER_SW   0x4
#define XSC_CQE_OWNER_ERR  0x8
#define XSC_OPCODE_RAW 0x7
#define XSC_TX_COMP_CQE_HANDLE_MAX 2

#define XSC_MAX_RX_BURST_MBUFS 64

static __rte_always_inline int
check_cqe_own(volatile struct xsc_cqe *cqe, const uint16_t cqe_n,
	      const uint16_t ci)

{
	if (unlikely(((cqe->owner & XSC_CQE_OWNER_MASK) !=
					((ci >> cqe_n) & XSC_CQE_OWNER_MASK))))
		return XSC_CQE_OWNER_HW;

	rte_io_rmb();
	if (cqe->msg_len <= 0 && cqe->is_error)
		return XSC_CQE_OWNER_ERR;

	return XSC_CQE_OWNER_SW;
}

static inline void
xsc_cq_to_mbuf(struct xsc_rxq_data *rxq, struct rte_mbuf *pkt,
	       volatile struct xsc_cqe *cqe)
{
	uint32_t rss_hash_res = 0;
	pkt->port = rxq->port_id;
	if (rxq->rss_hash) {
		rss_hash_res = rte_be_to_cpu_32(cqe->vni);
		if (rss_hash_res) {
			pkt->hash.rss = rss_hash_res;
			pkt->ol_flags |= RTE_MBUF_F_RX_RSS_HASH;
		}
	}
}

static inline int
xsc_rx_poll_len(struct xsc_rxq_data *rxq, volatile struct xsc_cqe *cqe)
{
	int len;

	do {
		len = 0;
		int ret;

		ret = check_cqe_own(cqe, rxq->cqe_n, rxq->cq_ci);
		if (unlikely(ret != XSC_CQE_OWNER_SW)) {
			if (unlikely(ret == XSC_CQE_OWNER_ERR)) {
				++rxq->stats.rx_errors;
				/* TODO */
				if (ret == XSC_CQE_OWNER_HW ||
						ret == -1)
					return 0;
			} else {
				return 0;
			}
		}

		rxq->cq_ci += 1;
		len = rte_le_to_cpu_32(cqe->msg_len);
		return len;
	} while (1);
}

static __rte_always_inline void
xsc_pkt_info_sync(struct rte_mbuf *rep, struct rte_mbuf *seg)
{
	if (rep != NULL && seg != NULL) {
		rep->data_len = seg->data_len;
		rep->pkt_len = seg->pkt_len;
		rep->data_off = seg->data_off;
		rep->port = seg->port;
	}
}

uint16_t
xsc_rx_burst(void *dpdk_rxq, struct rte_mbuf **pkts, uint16_t pkts_n)
{
	struct xsc_rxq_data *rxq = dpdk_rxq;
	const uint32_t wqe_m = rxq->wqe_m;
	const uint32_t cqe_m = rxq->cqe_m;
	const uint32_t sge_n = rxq->sge_n;
	struct rte_mbuf *pkt = NULL;
	struct rte_mbuf *seg = NULL;
	volatile struct xsc_cqe *cqe = &(*rxq->cqes)[rxq->cq_ci & cqe_m];
	uint32_t nb_pkts = 0;
	uint32_t rq_ci = rxq->rq_ci;
	int len = 0;
	uint32_t cq_ci_two = 0;
	int read_cqe_num = 0;
	int read_cqe_num_len = 0;
	volatile struct xsc_cqe_u64 *cqe_u64 = NULL;
	struct rte_mbuf *rep;

	while (pkts_n) {
		uint32_t idx = rq_ci & wqe_m;
		volatile struct xsc_wqe_data_seg *wqe =
			&((volatile struct xsc_wqe_data_seg *)rxq->wqes)[idx << sge_n];
		seg = (*rxq->elts)[idx];
		rte_prefetch0(cqe);
		rte_prefetch0(wqe);

		rep = rte_mbuf_raw_alloc(seg->pool);
		if (unlikely(rep == NULL)) {
			++rxq->stats.rx_nombuf;
			break;
		}

		if (!pkt) {
			if (read_cqe_num) {
				cqe = cqe + 1;
				len = read_cqe_num_len;
				read_cqe_num = 0;
			} else if ((rxq->cq_ci % 2 == 0) && (pkts_n > 1)) {
				cq_ci_two = (rxq->cq_ci & rxq->cqe_m) / 2;
				cqe_u64 = &(*rxq->cqes_u64)[cq_ci_two];
				cqe = (volatile struct xsc_cqe *)cqe_u64;
				len = xsc_rx_poll_len(rxq, cqe);
				if (len > 0) {
					read_cqe_num_len = xsc_rx_poll_len(rxq, cqe + 1);
					if (read_cqe_num_len > 0)
						read_cqe_num = 1;
				}
			} else {
				cqe = &(*rxq->cqes)[rxq->cq_ci & rxq->cqe_m];
				len = xsc_rx_poll_len(rxq, cqe);
			}

			if (!len) {
				rte_mbuf_raw_free(rep);
				break;
			}

			if (len > rte_pktmbuf_data_len(seg)) {
				rte_mbuf_raw_free(rep);
				pkt = NULL;
				++rq_ci;
				continue;
			}

			pkt = seg;
			pkt->ol_flags &= RTE_MBUF_F_EXTERNAL;
			xsc_cq_to_mbuf(rxq, pkt, cqe);

			if (rxq->crc_present)
				len -= RTE_ETHER_CRC_LEN;
			rte_pktmbuf_pkt_len(pkt) = len;
		}

		xsc_pkt_info_sync(rep, seg);
		(*rxq->elts)[idx] = rep;

		/* Fill wqe */
		wqe->va = rte_cpu_to_le_64(rte_pktmbuf_iova(rep));
		rte_pktmbuf_data_len(seg) = len;
		rxq->stats.rx_bytes += rte_pktmbuf_pkt_len(pkt);

		*(pkts++) = pkt;
		pkt = NULL;
		--pkts_n;
		++nb_pkts;
		++rq_ci;
	}

	if (unlikely(nb_pkts == 0 && rq_ci == rxq->rq_ci))
		return 0;

	rxq->rq_ci = rq_ci;
	rxq->nb_rx_hold += nb_pkts;

	if (rxq->nb_rx_hold >= rxq->rx_free_thresh) {
		union xsc_cq_doorbell cq_db = {
			.cq_data = 0
		};
		cq_db.next_cid = rxq->cq_ci;
		cq_db.cq_num = rxq->cqn;

		union xsc_recv_doorbell rq_db = {
			.recv_data = 0
		};
		rq_db.next_pid = (rxq->rq_ci << sge_n);
		rq_db.qp_num = rxq->qpn;

		rte_io_wmb();
		*rxq->cq_db = rte_cpu_to_le_32(cq_db.cq_data);
		rte_io_wmb();
		*rxq->rq_db = rte_cpu_to_le_32(rq_db.recv_data);
		rxq->nb_rx_hold = 0;
	}

	rxq->stats.rx_pkts += nb_pkts;
	return nb_pkts;
}

static __rte_always_inline void
xsc_tx_elts_free(struct xsc_txq_data *__rte_restrict txq, uint16_t tail)
{
	uint16_t elts_n = tail - txq->elts_tail;
	uint32_t free_n;

	do {
		free_n = txq->elts_s - (txq->elts_tail & txq->elts_m);
		free_n = RTE_MIN(free_n, elts_n);
		rte_pktmbuf_free_bulk(&txq->elts[txq->elts_tail & txq->elts_m], free_n);
		txq->elts_tail += free_n;
		elts_n -= free_n;
	} while (elts_n > 0);
}

static void
xsc_tx_cqes_handle(struct xsc_txq_data *__rte_restrict txq)
{
	uint32_t count = XSC_TX_COMP_CQE_HANDLE_MAX;
	volatile struct xsc_cqe *last_cqe = NULL;
	volatile struct xsc_cqe *cqe;
	bool doorbell = false;
	int ret;
	uint16_t tail;

	do {
		cqe = &txq->cqes[txq->cq_ci & txq->cqe_m];
		ret = check_cqe_own(cqe, txq->cqe_n, txq->cq_ci);
		if (unlikely(ret != XSC_CQE_OWNER_SW)) {
			if (likely(ret != XSC_CQE_OWNER_ERR))
				/* No new CQEs in completion queue. */
				break;
			doorbell = true;
			++txq->cq_ci;
			txq->cq_pi = txq->cq_ci;
			last_cqe = NULL;
			++txq->stats.tx_errors;
			continue;
		}

		doorbell = true;
		++txq->cq_ci;
		last_cqe = cqe;
	} while (--count > 0);

	if (likely(doorbell)) {
		union xsc_cq_doorbell cq_db = {
			.cq_data = 0
		};
		cq_db.next_cid = txq->cq_ci;
		cq_db.cq_num = txq->cqn;

		/* Ring doorbell */
		rte_compiler_barrier();
		*txq->cq_db = rte_cpu_to_le_32(cq_db.cq_data);

		/* Release completed elts */
		if (likely(last_cqe != NULL)) {
			txq->wqe_pi = rte_le_to_cpu_16(last_cqe->wqe_id) >> txq->wqe_ds_n;
			tail = txq->fcqs[(txq->cq_ci - 1) & txq->cqe_m];
			if (likely(tail != txq->elts_tail))
				xsc_tx_elts_free(txq, tail);
		}
	}
}

static __rte_always_inline void
xsc_tx_wqe_ctrl_seg_init(struct xsc_txq_data *__rte_restrict txq,
			 struct rte_mbuf *__rte_restrict mbuf,
			 struct xsc_wqe *__rte_restrict wqe)
{
	struct xsc_send_wqe_ctrl_seg *cs = &wqe->cseg;
	int i = 0;
	int ds_max = (1 << txq->wqe_ds_n) - 1;

	cs->msg_opcode = XSC_OPCODE_RAW;
	cs->wqe_id = rte_cpu_to_le_16(txq->wqe_ci << txq->wqe_ds_n);
	cs->has_pph = 0;
	/* clear dseg's seg len */
	if (cs->ds_data_num > 1 && cs->ds_data_num <= ds_max) {
		for (i = 1; i < cs->ds_data_num; i++)
			wqe->dseg[i].seg_len = 0;
	}

	cs->ds_data_num = mbuf->nb_segs;
	if (mbuf->ol_flags & RTE_MBUF_F_TX_IP_CKSUM)
		cs->csum_en = 0x2;
	else
		cs->csum_en = 0;

	if (txq->tso_en == 1 && (mbuf->ol_flags & RTE_MBUF_F_TX_TCP_SEG)) {
		cs->has_pph = 0;
		cs->so_type = 1;
		cs->so_hdr_len = mbuf->l2_len + mbuf->l3_len + mbuf->l4_len;
		cs->so_data_size = rte_cpu_to_le_16(mbuf->tso_segsz);
	}

	cs->msg_len = rte_cpu_to_le_32(rte_pktmbuf_pkt_len(mbuf));
	if (unlikely(cs->msg_len == 0))
		cs->msg_len = rte_cpu_to_le_32(rte_pktmbuf_data_len(mbuf));

	/* do not generate cqe for every pkts */
	cs->ce = 0;
}

static __rte_always_inline void
xsc_tx_wqe_data_seg_init(struct rte_mbuf *mbuf, struct xsc_wqe *wqe)
{
	uint16_t i, nb_segs = mbuf->nb_segs;
	uint32_t data_len;
	rte_iova_t iova;
	struct xsc_wqe_data_seg *dseg;

	for (i = 0; i < nb_segs; ++i) {
		dseg = &wqe->dseg[i];
		iova = rte_pktmbuf_iova(mbuf);
		data_len = rte_pktmbuf_data_len(mbuf);

		dseg->in_line = 0;
		dseg->seg_len = rte_cpu_to_le_32(data_len);
		dseg->lkey = 0;
		dseg->va = rte_cpu_to_le_64(iova);
		mbuf = mbuf->next;
	}
}

static __rte_always_inline struct xsc_wqe *
xsc_tx_wqes_fill(struct xsc_txq_data *__rte_restrict txq,
		 struct rte_mbuf **__rte_restrict pkts,
		 uint32_t pkts_n)
{
	uint32_t i;
	struct xsc_wqe *wqe = NULL;
	struct rte_mbuf *mbuf;

	for (i = 0; i < pkts_n; i++) {
		mbuf = pkts[i];
		rte_prefetch0(mbuf);
		wqe = (struct xsc_wqe *)((struct xsc_send_wqe_ctrl_seg *)txq->wqes +
		      (txq->wqe_ci & txq->wqe_m) * (1 << txq->wqe_ds_n));

		/* init wqe ctrl seg */
		xsc_tx_wqe_ctrl_seg_init(txq, mbuf, wqe);
		/* init wqe data segs */
		xsc_tx_wqe_data_seg_init(mbuf, wqe);
		++txq->wqe_ci;
		txq->stats.tx_bytes += rte_pktmbuf_pkt_len(mbuf);
	}

	return wqe;
}

static __rte_always_inline void
xsc_tx_doorbell_ring(volatile uint32_t *db, uint32_t index,
		     uint32_t qpn, uint16_t ds_n)
{
	union xsc_send_doorbell tx_db;

	rte_io_wmb();
	tx_db.next_pid = index << ds_n;
	tx_db.qp_num = qpn;
	*db  = rte_cpu_to_le_32(tx_db.send_data);

	rte_wmb();
}

static __rte_always_inline void
xsc_tx_elts_store(struct xsc_txq_data *__rte_restrict txq,
		  struct rte_mbuf **__rte_restrict pkts,
		  uint32_t pkts_n)
{
	uint32_t part;
	struct rte_mbuf **elts = (struct rte_mbuf **)txq->elts;

	part = txq->elts_s - (txq->elts_head & txq->elts_m);
	rte_memcpy((void *)(elts + (txq->elts_head & txq->elts_m)),
		   (void *)pkts,
		   RTE_MIN(part, pkts_n) * sizeof(struct rte_mbuf *));

	if (unlikely(part < pkts_n))
		rte_memcpy((void *)elts, (void *)(pkts + part),
			   (pkts_n - part) * sizeof(struct rte_mbuf *));
}

uint16_t
xsc_tx_burst(void *dpdk_txq, struct rte_mbuf **pkts, uint16_t pkts_n)
{
	struct xsc_txq_data *txq = dpdk_txq;
	uint32_t tx_n, remain_n = pkts_n;
	uint16_t idx, elts_free, wqe_free;
	uint16_t elts_head;
	struct xsc_wqe *last_wqe;

	if (unlikely(!pkts_n))
		return 0;
loop:
	xsc_tx_cqes_handle(txq);

	elts_free = txq->elts_s - (uint16_t)(txq->elts_head - txq->elts_tail);
	wqe_free = txq->wqe_s - (((txq->wqe_ci << txq->wqe_ds_n) -
		   (txq->wqe_pi << txq->wqe_ds_n)) >> txq->wqe_ds_n);
	if (unlikely(elts_free == 0 || wqe_free == 0))
		goto exit;

	/* Fill in WQEs */
	tx_n = RTE_MIN(remain_n, wqe_free);
	idx = pkts_n - remain_n;
	last_wqe = xsc_tx_wqes_fill(txq, &pkts[idx], tx_n);
	remain_n -= tx_n;
	last_wqe->cseg.ce = 1;

	/* Update free-cqs, elts_comp */
	elts_head = txq->elts_head;
	elts_head += tx_n;
	if ((uint16_t)(elts_head - txq->elts_comp) > 0) {
		txq->elts_comp = elts_head;
		txq->fcqs[txq->cq_pi++ & txq->cqe_m] = elts_head;
	}

	/* Ring tx doorbell */
	xsc_tx_doorbell_ring(txq->qp_db, txq->wqe_ci,
			txq->qpn, txq->wqe_ds_n);

	xsc_tx_elts_store(txq, &pkts[idx], tx_n);
	txq->elts_head += tx_n;

	if (remain_n > 0)
		/* Try to process cqe, if wqe free is still 0, exit */
		goto loop;

exit:

	txq->stats.tx_pkts += (pkts_n - remain_n);
	return pkts_n - remain_n;
}

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
		if (unlikely(rep == NULL))
			break;

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

	return nb_pkts;
}

uint16_t
xsc_tx_burst(void *dpdk_txq, struct rte_mbuf **pkts, uint16_t pkts_n)
{
	return 0;
}


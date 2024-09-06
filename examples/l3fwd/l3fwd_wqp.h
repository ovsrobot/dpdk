/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Huawei Technologies Co., Ltd
 */

#ifndef L3FWD_WQP_H
#define L3FWD_WQP_H

#include <rte_soring.h>

struct wqelm {
	struct rte_mbuf *mb;
	uint32_t rc;
}  __rte_packed;


void l3fwd_wqp_fini(struct lcore_conf lc[RTE_MAX_LCORE]);
int l3fwd_wqp_init(struct lcore_conf lc[RTE_MAX_LCORE],
	const struct l3fwd_wqp_param *prm);

static inline uint32_t
lcore_wq_submit(const struct lcore_wq_pool *wqp, uint32_t idx,
	struct rte_mbuf * const pkts[MAX_PKT_BURST], uint32_t num)
{
	idx &= wqp->qmask;

	if (wqp->prm.mode == L3FWD_WORKER_UNQUE) {
		struct rte_ring *r = wqp->queue[idx].r[LCORE_WQ_IN];
		return rte_ring_enqueue_burst(r, (void * const *)pkts, num,
				NULL);
	} else if (wqp->prm.mode == L3FWD_WORKER_ORQUE) {
		struct rte_soring *sor = wqp->queue[idx].sor;
		return rte_soring_enqueue_burst(sor, pkts, num, NULL);
	}

	rte_errno = ENOTSUP;
	return 0;
}

static inline uint32_t
lcore_wq_receive(const struct lcore_wq_pool *wqp, uint32_t idx,
	struct rte_mbuf *pkts[MAX_PKT_BURST], uint16_t hops[MAX_PKT_BURST],
	uint32_t num)
{
	uint32_t i, n;
	uint32_t rcs[MAX_PKT_BURST];
	struct wqelm elm[MAX_PKT_BURST];

	idx &= wqp->qmask;

	if (wqp->prm.mode == L3FWD_WORKER_UNQUE) {
		struct rte_ring *r = wqp->queue[idx].r[LCORE_WQ_OUT];

		n = rte_ring_dequeue_burst_elem(r, elm, sizeof(elm[0]), num,
				NULL);
		for (i = 0; i != n; i++) {
			pkts[i] = elm[i].mb;
			hops[i] = elm[i].rc;
		}

		return n;

	} else if (wqp->prm.mode == L3FWD_WORKER_ORQUE) {
		struct rte_soring *sor = wqp->queue[idx].sor;

		n = rte_soring_dequeux_burst(sor, pkts, rcs, num, NULL);
		for (i = 0; i != n; i++)
			hops[i] = rcs[i];

		return n;
	}

	rte_errno = ENOTSUP;
	return 0;
}

static inline uint32_t
lcore_wq_pull(struct lcore_wq_pool *wqp, uint32_t idx,
	struct rte_mbuf *pkts[MAX_PKT_BURST], uint32_t num)
{
	idx &= wqp->qmask;

	if (wqp->prm.mode == L3FWD_WORKER_UNQUE) {
		struct rte_ring *r = wqp->queue[idx].r[LCORE_WQ_IN];
		return rte_ring_dequeue_burst(r, (void **)pkts, num, NULL);

	} else if (wqp->prm.mode == L3FWD_WORKER_ORQUE) {
		struct rte_soring *sor = wqp->queue[idx].sor;
		return rte_soring_acquire_burst(sor, pkts, 0, num,
			&wqp->queue[idx].ftoken, NULL);
	}

	rte_errno = ENOTSUP;
	return 0;
}

static inline uint32_t
lcore_wq_push(const struct lcore_wq_pool *wqp, uint32_t idx,
	struct rte_mbuf * const pkts[MAX_PKT_BURST],
	const uint16_t hops[MAX_PKT_BURST], uint32_t num)
{
	uint32_t i;
	uint32_t rcs[MAX_PKT_BURST];
	struct wqelm elm[MAX_PKT_BURST];

	idx &= wqp->qmask;

	if (wqp->prm.mode == L3FWD_WORKER_UNQUE) {
		struct rte_ring *r = wqp->queue[idx].r[LCORE_WQ_OUT];

		for (i = 0; i != num; i++) {
			elm[i].mb = pkts[i];
			elm[i].rc = hops[i];
		}
		return rte_ring_enqueue_burst_elem(r, elm, sizeof(elm[0]), num,
				NULL);
	} else if (wqp->prm.mode == L3FWD_WORKER_ORQUE) {
		struct rte_soring *sor = wqp->queue[idx].sor;

		for (i = 0; i != num; i++)
			rcs[i] = hops[i];
		rte_soring_releasx(sor, NULL, rcs, 0, num,
			wqp->queue[idx].ftoken);
		return num;
	}

	rte_errno = ENOTSUP;
	return 0;
}

#endif /* L3FWD_WQP_H */

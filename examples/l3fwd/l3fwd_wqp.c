/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Huawei Technologies Co., Ltd
 */

#include "l3fwd.h"
#include "l3fwd_wqp.h"

static int
wqp_ring_init(struct rte_ring **r, uint32_t num, size_t sz, int32_t sid,
	uint32_t flags)
{
	char name[RTE_RING_NAMESIZE];

	*r = rte_zmalloc_socket(NULL, sz, RTE_CACHE_LINE_SIZE, sid);
	if (*r == NULL)
		return -ENOMEM;

	snprintf(name, sizeof(name), "%p", *r);
	return rte_ring_init(*r, name, num, flags);
}

static int
wqp_soring_init(struct rte_soring **r, struct rte_soring_param *prm, size_t sz,
	int32_t sid)
{
	char name[RTE_RING_NAMESIZE];

	*r = rte_zmalloc_socket(NULL, sz, RTE_CACHE_LINE_SIZE, sid);
	if (*r == NULL)
		return -ENOMEM;

	snprintf(name, sizeof(name), "%p", *r);
	prm->name = name;
	return rte_soring_init(*r, prm);
}

static void
wqp_fini(struct lcore_conf *lc)
{
	uint32_t i, j;

	if (lc->n_rx_queue == 0)
		return;

	for (i = 0; i != lc->wqpool.nb_queue; i++) {
		for (j = 0; j != RTE_DIM(lc->wqpool.queue[i].r); j++)
			rte_free(lc->wqpool.queue[i].r[j]);
	}

	memset(&lc->wqpool, 0, sizeof(lc->wqpool));
}

static int
l3fwd_wqp_unque_init(struct lcore_conf *lc, const struct l3fwd_wqp_param *prm,
	uint32_t lcid)
{
	int32_t rc, sid;
	uint32_t i, n, nq;
	size_t szi, szo;

	sid = rte_lcore_to_socket_id(lcid);

	n = rte_align32pow2(prm->qsize);

	szi = rte_ring_get_memsize(n);
	szo = rte_ring_get_memsize_elem(sizeof(struct wqelm), n);

	nq = (prm->single == 0) ? lc->n_rx_queue : 1;
	lc->wqpool.nb_queue = nq;
	lc->wqpool.qmask = (prm->single != 0) ? 0 : UINT32_MAX;

	rc = 0;
	for (i = 0; i != nq; i++) {

		rc = wqp_ring_init(&lc->wqpool.queue[i].r[LCORE_WQ_IN], n, szi,
			sid, RING_F_SP_ENQ);
		if (rc != 0)
			break;

		rc = wqp_ring_init(&lc->wqpool.queue[i].r[LCORE_WQ_OUT], n, szo,
			sid, RING_F_SC_DEQ);
		if (rc != 0)
			break;
	}

	if (i != nq) {
		printf("error: %s failed at %u-th queue, error code: %d\n",
			__func__, i, rc);
		wqp_fini(lc);
	}

	lc->wqpool.prm = *prm;
	return rc;
}

static int
l3fwd_wqp_orque_init(struct lcore_conf *lc, const struct l3fwd_wqp_param *qprm,
	uint32_t lcid)
{
	int32_t rc, sid;
	uint32_t i, n, nq;
	ssize_t sz;
	struct rte_soring_param prm;

	sid = rte_lcore_to_socket_id(lcid);

	memset(&prm, 0, sizeof(prm));

	n = 2 * qprm->qsize;
	prm.elems = n;
	prm.elem_size = sizeof(uintptr_t);
	prm.meta_size = sizeof(uint32_t);
	prm.stages = 1;
	prm.prod_synt = RTE_RING_SYNC_ST;
	prm.cons_synt = RTE_RING_SYNC_ST;

	sz = rte_soring_get_memsize(&prm);
	if (sz < 0)
		return sz;

	nq = (qprm->single == 0) ? lc->n_rx_queue : 1;
	lc->wqpool.nb_queue = nq;
	lc->wqpool.qmask = (qprm->single != 0) ? 0 : UINT32_MAX;

	rc = 0;
	for (i = 0; i != nq; i++) {

		rc = wqp_soring_init(&lc->wqpool.queue[i].sor, &prm, sz, sid);
		if (rc != 0)
			break;
	}

	if (i != nq) {
		printf("error: %s failed at %u-th queue, error code: %d\n",
			__func__, i, rc);
		wqp_fini(lc);
	}

	lc->wqpool.prm = *qprm;
	return rc;
}

static int
wqp_init(struct lcore_conf *lc, const struct l3fwd_wqp_param *prm,
	uint32_t lcid)
{
	/* this is I/O poll lcore */
	if (lc->n_rx_queue != 0) {
		if (prm->mode == L3FWD_WORKER_UNQUE)
			return l3fwd_wqp_unque_init(lc, prm, lcid);
		else if (prm->mode == L3FWD_WORKER_ORQUE)
			return l3fwd_wqp_orque_init(lc, prm, lcid);
		else
			return -ENOTSUP;
	}

	return -ENOTSUP;
}

void
l3fwd_wqp_fini(struct lcore_conf lc[RTE_MAX_LCORE])
{
	uint32_t lcid;

	for (lcid = 0; lcid != RTE_MAX_LCORE; lcid++)
		wqp_fini(lc + lcid);
}

static int
check_set_wqp_param(struct l3fwd_wqp_param *prm)
{
	uint32_t n;

	if (prm->qsize == 0) {
		n = RTE_MAX(nb_rxd, nb_txd);
		n = n + n / 2;
		prm->qsize = n;
	}

	return 0;
}

static void print_wqp_param(const struct l3fwd_wqp_param *prm)
{
	printf("%s(%p): mode=%d, qsize=%u, single=%d\n",
		__func__, prm, prm->mode, prm->qsize, prm->single);
}

int
l3fwd_wqp_init(struct lcore_conf lc[RTE_MAX_LCORE],
	const struct l3fwd_wqp_param *qprm)
{
	int32_t rc;
	uint32_t i, j, k, lcid, m, n, nrxq, nwqt;
	union lcore_wq *wqp;
	struct l3fwd_wqp_param prm;

	if (qprm->mode == L3FWD_WORKER_POLL)
		return 0;

	prm = *qprm;
	rc = check_set_wqp_param(&prm);
	print_wqp_param(&prm);
	if (rc < 0) {
		printf("error: %s invalid paramer values\n", __func__);
		return rc;
	}

	nrxq = 0;
	nwqt = 0;
	for (lcid = 0; lcid != RTE_MAX_LCORE; lcid++) {
		if (rte_lcore_is_enabled(lcid) == 0)
			continue;
		if (lc[lcid].n_rx_queue != 0)
			nrxq += (prm.single != 0) ? 1 : lc[lcid].n_rx_queue;
		nwqt += (lc[lcid].n_rx_queue == 0);
	}

	printf("%s: total worker queues: %u, total WQ threads: %u\n",
			__func__, nrxq, nwqt);
	if (nrxq == 0)
		return 0;

	if (nrxq > nwqt * MAX_RX_QUEUE_PER_LCORE) {
		printf("error: %s not enough WQ threads to handle all RXQs\n",
			__func__);
		return -EINVAL;
	}

	for (lcid = 0; lcid != RTE_MAX_LCORE; lcid++) {
		if (rte_lcore_is_enabled(lcid) == 0 || lc[lcid].n_rx_queue == 0)
			continue;
		rc = wqp_init(lc + lcid, &prm, lcid);
		if (rc != 0)
			break;
	}
	if (rc != 0)
		return rc;

	/* create a temp pool of all RX queues */
	wqp = malloc(sizeof(wqp[0]) * nrxq);
	if (wqp == NULL) {
		l3fwd_wqp_fini(lc);
		return -ENOMEM;
	}

	n = 0;
	for (lcid = 0; lcid != RTE_MAX_LCORE; lcid++) {
		memcpy(wqp + n, lc[lcid].wqpool.queue,
			lc[lcid].wqpool.nb_queue * sizeof(wqp[0]));
		n += lc[lcid].wqpool.nb_queue;
	}

	/* distribute them across all worker threads */
	k = 0;
	m = RTE_MIN(RTE_DIM(lc[lcid].wqpool.queue), n);
	for (lcid = 0; lcid != RTE_MAX_LCORE; lcid++) {
		if (rte_lcore_is_enabled(lcid) == 0 ||
				lc[lcid].wqpool.nb_queue != 0)
			continue;
		j = k;
		for (i = 0; i != m; i++) {
			lc[lcid].wqpool.queue[i] = wqp[j];
			j = (j + 1) % n;
		}
		lc[lcid].wqpool.nb_queue = i;
		lc[lcid].wqpool.qmask = UINT32_MAX;
		lc[lcid].wqpool.prm = prm;
		k = j;
	}

	free(wqp);
	return rc;
}

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Stephen Hemminger
 */

/*
 * Datapath side of capture: the ethdev callbacks that copy packets into the
 * ring, and the callback blocks they run on.
 *
 * Callback lifetime is the awkward part. rte_eth_remove_rx_callback() only
 * unlinks the callback from the port's list; a datapath thread that already
 * loaded the list walks into the callback afterwards, and ethdev gives no
 * point at which that can no longer happen. There are therefore two separate
 * lifetimes to manage, and conflating them is the easy mistake:
 *
 * The block (struct capture_rxtx_cb) is what the late thread lands in, so it
 * is never freed. Blocks are kept on a free list and handed out again, but
 * only to a later capture of the same port, queue and direction, which bounds
 * the pool at the peak number of concurrent captures of one queue. A thread
 * arriving late can then only ever be handed a capture that covers the
 * packets it is already carrying.
 *
 * The capture is freed, so a block points at it through cbs->cap and detach
 * clears that pointer and waits a grace period (rcu.c) before anything is
 * released. After the wait no callback can still be holding the old pointer,
 * and one that starts later loads NULL and returns.
 *
 * The rte_eth_rxtx_callback object that ethdev itself allocated cannot be
 * freed at removal time for the same reason, so it is parked in cbs->stale
 * and released by the next capture that picks up the block. A whole capture
 * session passes in between, which is far longer than any burst.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/queue.h>

#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_pcapng.h>
#include <rte_ring.h>
#include <rte_spinlock.h>
#include <rte_stdatomic.h>

#include "private.h"
#include "rcu.h"

/* Unowned capture blocks */
static struct capture_cb_list capture_cb_freelist = TAILQ_HEAD_INITIALIZER(capture_cb_freelist);

/*
 * Create a clone of mbuf to be placed into ring.
 * Note: for case of lockfree transmit statistics may not be correct due to races.
 */
static inline void
capture_copy_burst(uint16_t port_id, uint16_t queue_id,
		   enum rte_pcapng_direction direction,
		   struct rte_mbuf **pkts, unsigned int nb_pkts,
		   const struct capture *cap,
		   const struct capture_filter_prog *prog,
		   struct capture_stats *stats)
{
	unsigned int i, ring_enq, d_pkts = 0;
	struct rte_mbuf *dup_bufs[CAPTURE_BURST_SIZE]; /* duplicated packets */
	struct rte_ring *ring = cap->ring;
	struct rte_mempool *mp = cap->mp;
	uint32_t snaplen = cap->snaplen;
	struct rte_mbuf *p;

	RTE_ASSERT(nb_pkts <= CAPTURE_BURST_SIZE);

	for (i = 0; i < nb_pkts; i++) {
		/*
		 * This uses same BPF return value convention as socket filter
		 * and pcap_offline_filter. If program returns zero then packet
		 * doesn't match the filter (will be ignored).
		 */
		if (prog != NULL) {
			if (capture_filter_exec(prog, pkts[i]) == 0) {
				stats->filtered++;
				continue;
			}
		}

		p = rte_pcapng_copy(port_id, queue_id, pkts[i], mp, snaplen, direction, NULL);
		if (unlikely(p == NULL))
			stats->nombuf++;
		else
			dup_bufs[d_pkts++] = p;
	}

	if (d_pkts == 0)
		return;

	stats->accepted += d_pkts;

	ring_enq = rte_ring_enqueue_burst(ring, (void *)&dup_bufs[0], d_pkts, NULL);
	if (unlikely(ring_enq < d_pkts)) {
		unsigned int drops = d_pkts - ring_enq;

		stats->ringfull += drops;
		rte_pktmbuf_free_bulk(&dup_bufs[ring_enq], drops);
	}
}

/* Create a clone of mbuf to be placed into ring. */
static inline void
capture_copy(uint16_t port_id, uint16_t queue_id,
	     enum rte_pcapng_direction direction,
	     struct rte_mbuf **pkts, uint16_t nb_pkts,
	     const struct capture *cap,
	     const struct capture_filter_prog *prog,
	     struct capture_stats *stats)
{
	unsigned int offs = 0;

	do {
		unsigned int n = RTE_MIN(nb_pkts - offs, CAPTURE_BURST_SIZE);

		capture_copy_burst(port_id, queue_id, direction, &pkts[offs], n,
				   cap, prog, stats);
		offs += n;
	} while (offs < nb_pkts);
}

/*
 * The block itself is never freed, so it is safe to reach even after the
 * ethdev callback was unlinked. What the read section protects is cap and
 * the program: both are cleared before capture_rcu_sync() in detach, and a
 * reader that sees them non-NULL holds the section until it is done.
 */
static uint16_t
capture_rx(uint16_t port, uint16_t queue,
	struct rte_mbuf **pkts, uint16_t nb_pkts,
	uint16_t max_pkts __rte_unused, void *user_params)
{
	struct capture_rxtx_cb *cbs = user_params;
	unsigned int slot = capture_rcu_slot();
	const struct capture *cap;

	if (unlikely(slot == CAPTURE_RCU_NO_SLOT))
		return nb_pkts;

	capture_rcu_enter(slot);
	cap = rte_atomic_load_explicit(&cbs->cap, rte_memory_order_relaxed);
	if (likely(cap != NULL))
		capture_copy(port, queue, RTE_PCAPNG_DIRECTION_IN,
			     pkts, nb_pkts, cap, cbs->prog, &cbs->stats);
	capture_rcu_exit(slot);

	return nb_pkts;
}

static uint16_t
capture_tx(uint16_t port, uint16_t queue,
	   struct rte_mbuf **pkts, uint16_t nb_pkts, void *user_params)
{
	struct capture_rxtx_cb *cbs = user_params;
	unsigned int slot = capture_rcu_slot();
	const struct capture *cap;

	if (unlikely(slot == CAPTURE_RCU_NO_SLOT))
		return nb_pkts;

	capture_rcu_enter(slot);
	cap = rte_atomic_load_explicit(&cbs->cap, rte_memory_order_relaxed);
	if (likely(cap != NULL))
		capture_copy(port, queue, RTE_PCAPNG_DIRECTION_OUT,
			     pkts, nb_pkts, cap, cbs->prog, &cbs->stats);
	capture_rcu_exit(slot);

	return nb_pkts;
}

/*
 * Take an idle block for a port/queue/direction, allocating one if all are in
 * use. Several captures may cover a queue, each with its own filter and
 * callback, so this hands out one block per capture.
 */
static struct capture_rxtx_cb *
capture_cb_get(struct capture *cap, uint16_t queue, bool is_rx)
{
	struct capture_rxtx_cb *cbs;

	rte_spinlock_lock(&capture_lock);

	TAILQ_FOREACH(cbs, &capture_cb_freelist, next) {
		if (cbs->port_id == cap->port_id && cbs->queue == queue &&
		    cbs->is_rx == is_rx) {
			TAILQ_REMOVE(&capture_cb_freelist, cbs, next);
			break;
		}
	}

	rte_spinlock_unlock(&capture_lock);

	if (cbs == NULL) {
		cbs = rte_zmalloc_socket("capture_cb", sizeof(*cbs),
					 RTE_CACHE_LINE_SIZE, cap->socket_id);
		if (cbs == NULL)
			return NULL;
		cbs->port_id = cap->port_id;
		cbs->queue = queue;
		cbs->is_rx = is_rx;
	}

	return cbs;
}

/* Hand a detached block back for reuse. */
static void
capture_cb_put(struct capture_rxtx_cb *cbs)
{
	rte_spinlock_lock(&capture_lock);
	TAILQ_INSERT_TAIL(&capture_cb_freelist, cbs, next);
	rte_spinlock_unlock(&capture_lock);
}

/* Install one callback; also links the block into cap->attached for stats. */
static struct capture_rxtx_cb *
capture_attach(struct capture *cap, uint16_t queue, bool is_rx,
	       struct capture_filter_prog *prog)
{
	struct capture_rxtx_cb *cbs;

	cbs = capture_cb_get(cap, queue, is_rx);
	if (cbs == NULL) {
		CAPTURE_LOG(ERR, "No callback block for %u:%u %s",
			    cap->port_id, queue, is_rx ? "rx" : "tx");
		return NULL;
	}

	/* the block may have been used by an earlier capture of this queue */
	memset(&cbs->stats, 0, sizeof(cbs->stats));

	/* one program per process per capture, shared by its queues */
	cbs->prog = prog;

	/*
	 * Release the object left by an earlier capture. It cannot be freed at
	 * removal time because ethdev reads cb->next after the callback
	 * returns; deferring to the next attach puts a whole session between.
	 */
	rte_free((void *)(uintptr_t)cbs->stale);
	cbs->stale = NULL;

	/* publish before the callback can be reached by the datapath */
	rte_atomic_store_explicit(&cbs->cap, cap, rte_memory_order_release);

	if (is_rx)
		cbs->cb = rte_eth_add_rx_callback(cap->port_id, queue, capture_rx, cbs);
	else
		cbs->cb = rte_eth_add_tx_callback(cap->port_id, queue, capture_tx, cbs);

	if (cbs->cb == NULL) {
		rte_atomic_store_explicit(&cbs->cap, NULL, rte_memory_order_relaxed);
		capture_cb_put(cbs);
		CAPTURE_LOG(ERR, "Register %s callback for %u:%u failed",
			    is_rx ? "rx" : "tx", cap->port_id, queue);
		return NULL;
	}

	rte_spinlock_lock(&cap->cbs_lock);
	TAILQ_INSERT_TAIL(&cap->attached, cbs, attached);
	rte_spinlock_unlock(&cap->cbs_lock);

	return cbs;
}

/*
 * Install callbacks on every queue this capture covers, recording them in
 * cbs[] for detach. A secondary passes its own array.
 *
 * The filter program is per-process, so it is loaded here and returned in
 * *progp; the caller passes it to capture_detach_queues() to release.
 */
int
capture_attach_queues(struct capture *cap, struct capture_rxtx_cb **cbs, uint16_t *nb_cbs,
		      struct capture_filter_prog **progp)
{
	struct capture_filter_prog *prog = NULL;

	if (cap->filter != NULL) {
		prog = capture_filter_load(cap->filter);
		if (prog == NULL) {
			/*
			 * Attaching without the filter would put unwanted
			 * packets in the capture file, so do not attach.
			 */
			CAPTURE_LOG(ERR, "Could not load filter for port %u",
				    cap->port_id);
			return -1;
		}
	}
	*progp = prog;

	for (uint16_t q = 0; q < cap->tx_queues; q++) {
		if (cap->queue != ALL_QUEUES && cap->queue != q)
			continue;

		cbs[*nb_cbs] = capture_attach(cap, q, false, prog);
		if (cbs[*nb_cbs] == NULL)
			return -1;
		++*nb_cbs;
	}

	for (uint16_t q = 0; q < cap->rx_queues; q++) {
		if (cap->queue != ALL_QUEUES && cap->queue != q)
			continue;

		cbs[*nb_cbs] = capture_attach(cap, q, true, prog);
		if (cbs[*nb_cbs] == NULL)
			return -1;
		++*nb_cbs;
	}
	return 0;
}

/* Install callbacks of the process that created the capture. */
int
capture_add_callbacks(struct capture *cap)
{
	return capture_attach_queues(cap, cap->cbs, &cap->nb_cbs, &cap->prog);
}

static void
capture_sum_one(struct capture_total *t, const struct capture_stats *s)
{
	t->accepted += s->accepted;
	t->filtered += s->filtered;
	t->nombuf   += s->nombuf;
	t->ringfull += s->ringfull;
}

/*
 * Sum the counters of the queues still attached, in any process, plus those
 * already detached. Caller holds cap->cbs_lock.
 */
void
capture_sum_stats(const struct capture *cap, struct capture_total *t)
{
	const struct capture_rxtx_cb *cbs;

	*t = cap->total;

	TAILQ_FOREACH(cbs, &cap->attached, attached)
		capture_sum_one(t, &cbs->stats);
}

/*
 * Detach this process's blocks. Once this returns no datapath thread here can
 * reach the capture.
 */
void
capture_detach_queues(struct capture *cap, struct capture_rxtx_cb **cbs, uint16_t *nb_cbs,
		      struct capture_filter_prog *prog)
{
	for (uint16_t i = 0; i < *nb_cbs; i++) {
		struct capture_rxtx_cb *cb = cbs[i];

		if (cb->is_rx)
			rte_eth_remove_rx_callback(cap->port_id, cb->queue, cb->cb);
		else
			rte_eth_remove_tx_callback(cap->port_id, cb->queue, cb->cb);

		/* freed by the next capture that attaches to this queue */
		cb->stale = cb->cb;
		cb->cb = NULL;

		/* unpublish; a reader that still sees it is waited for below */
		rte_atomic_store_explicit(&cb->cap, NULL, rte_memory_order_relaxed);
	}

	/* one grace period covers every queue of this process */
	capture_rcu_sync();

	for (uint16_t i = 0; i < *nb_cbs; i++)
		cbs[i]->prog = NULL;

	/*
	 * The blocks leave the capture, so fold their counters into the total
	 * first: whoever picks them up next zeroes the stats.
	 */
	rte_spinlock_lock(&cap->cbs_lock);
	for (uint16_t i = 0; i < *nb_cbs; i++) {
		capture_sum_one(&cap->total, &cbs[i]->stats);
		TAILQ_REMOVE(&cap->attached, cbs[i], attached);
	}
	rte_spinlock_unlock(&cap->cbs_lock);

	rte_spinlock_lock(&capture_lock);
	for (uint16_t i = 0; i < *nb_cbs; i++)
		TAILQ_INSERT_TAIL(&capture_cb_freelist, cbs[i], next);
	rte_spinlock_unlock(&capture_lock);

	*nb_cbs = 0;

	/* no datapath thread can reach the program now */
	capture_filter_unload(prog);
}

/* Cleanup callbacks of the process that created the capture. */
void
capture_remove_callbacks(struct capture *cap)
{
	capture_detach_queues(cap, cap->cbs, &cap->nb_cbs, cap->prog);
	cap->prog = NULL;
}

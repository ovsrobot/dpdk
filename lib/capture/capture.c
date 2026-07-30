/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Stephen Hemminger
 */

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_pcapng.h>
#include <rte_pause.h>
#include <rte_ring.h>
#include <rte_spinlock.h>
#include <rte_stdatomic.h>
#include <rte_string_fns.h>
#include <rte_telemetry.h>
#include <rte_thread.h>
#include <rte_version.h>

#include "capture_impl.h"

#define CAPTURE_EXTCAP_PREFIX	"dpdk"
#define CAP_CMD_MAX		1024
#define DEFAULT_SNAPLEN		262144u	/* from tcpdump et.al. */
#define CAPTURE_BURST_SIZE	32u
#define MBUF_POOL_CACHE_SIZE	32
#define CAPTURE_RING_SIZE	256
#define CAPTURE_POOL_SIZE	1024
#define SLEEP_THRESHOLD		100
#define SLEEP_US		100

#define ALL_QUEUES		UINT16_MAX

RTE_LOG_REGISTER_DEFAULT(rte_capture_logtype, NOTICE);

/*
 * List of active captures.
 *
 * This is a control-plane only structure: it is created, walked and torn down
 * from the telemetry handler thread and from the per-capture drain threads,
 * never from the dataplane. A plain spinlock is therefore enough; the EAL
 * shared tailq (rte_tailq) is not used because captures are not visible to
 * secondary processes in this design.
 */
TAILQ_HEAD(capture_list, capture);
static struct capture_list capture_list = TAILQ_HEAD_INITIALIZER(capture_list);
static rte_spinlock_t capture_lock = RTE_SPINLOCK_INITIALIZER;

/* Parameter values: only used on stack inside parsing */
struct capture_config {
	uint16_t port_id;
	uint16_t queue;
	uint32_t snaplen;
	const char *filter_str;
	const char *output;
};

/* Per port/queue/direction counters. */
struct capture_stats {
	uint64_t accepted;	/**< Number of packets accepted by filter. */
	uint64_t filtered;	/**< Number of packets rejected by filter. */
	uint64_t nombuf;	/**< Number of mbuf allocation failures. */
	uint64_t ringfull;	/**< Number of missed packets due to ring full. */
};

/* Aggregate per-queue counters of a capture instance. */
struct capture_total {
	uint64_t accepted;
	uint64_t filtered;
	uint64_t nombuf;
	uint64_t ringfull;
};

/*
 * Data used by callback, one per capture per port/queue/direction.
 *
 * These are allocated on demand and never freed, following the same reasoning
 * as lib/bpf/bpf_pkt.c: rte_eth_remove_{rx,tx}_callback() only unlinks the
 * callback, so a datapath thread that loaded the callback list just before the
 * removal still enters capture_rx()/capture_tx() afterwards. Keeping this block
 * alive for the life of the process gives that thread something valid to
 * synchronize on. The struct capture it points at is freed at teardown, and
 * that is what the handshake below protects.
 *
 * A detached block is recycled, but only by a later capture on the same
 * port/queue/direction. That bounds the pool at the peak number of concurrent
 * captures of a queue, and means a datapath thread arriving late can only ever
 * be handed a capture that covers the packets it already holds.
 */
struct __rte_cache_aligned capture_rxtx_cb {
	/* used by both data and control path */
	RTE_ATOMIC(uint32_t) use_count;
	RTE_ATOMIC(struct capture *) cap;	/* owner, NULL when idle */
	struct capture_stats stats;

	/* used by control path only */
	TAILQ_ENTRY(capture_rxtx_cb) next;	/* links into capture_cb_freelist */
	const struct rte_eth_rxtx_callback *cb;
	const struct rte_eth_rxtx_callback *stale;
	uint16_t port_id;
	uint16_t queue;
	bool is_rx;
};

/*
 * Idle callback blocks, guarded by capture_lock.
 *
 * A block is on this list exactly when no capture owns it; an owned one is
 * reachable only from its owner's cbs[] array. Blocks are moved between the
 * two, never freed.
 */
TAILQ_HEAD(capture_cb_list, capture_rxtx_cb);
static struct capture_cb_list capture_cb_freelist =
	TAILQ_HEAD_INITIALIZER(capture_cb_freelist);

/*
 * Per-capture instance state.
 */
struct capture {
	RTE_ATOMIC(bool) running;
	struct rte_capture_filter *filter;
	struct rte_ring *ring;		/* ring from dataplane to capture thread */
	struct rte_mempool *mp;		/* mempool for capture mbufs */

	uint32_t snaplen;		/* amount of data to copy */
	uint16_t queue;
	uint16_t tx_queues;
	uint16_t rx_queues;
	uint16_t port_id;
	int socket_id;

	uint32_t idx;
	char *output;			/* filename of out */

	TAILQ_ENTRY(capture) next;	/* links into capture_list */

	/* counters of queues already detached; control path only */
	struct capture_total total;

	/* callback blocks attached by this capture; control path only */
	uint16_t nb_cbs;
	struct capture_rxtx_cb *cbs[];
};

/*
 * Detach a callback block and wait for the datapath to let go of it.
 *
 * Clearing cap and then loading use_count is the mirror image of what
 * capture_cb_hold() does (bump use_count, then load cap). With a sequentially
 * consistent fence between the store and the load on both sides, at least one
 * of the two observes the other: either this thread sees an odd use_count and
 * waits for the burst in progress to finish, or that burst sees a NULL cap and
 * returns without ever dereferencing it. Neither can slip through, so once
 * this returns the capture is safe to free.
 */
static void
capture_cb_detach(struct capture_rxtx_cb *cbs)
{
	rte_atomic_store_explicit(&cbs->cap, NULL, rte_memory_order_relaxed);

	/* the store of cap must be visible before the use_count load below */
	rte_atomic_thread_fence(rte_memory_order_seq_cst);

	/* wait until use_count is even (not in use) */
	RTE_WAIT_UNTIL_MASKED(&cbs->use_count, 1, ==, 0, rte_memory_order_acquire);
}

/* Mark datapath iteration in progress: count becomes odd. */
static inline __rte_hot void
capture_cb_hold(struct capture_rxtx_cb *cbs)
{
	rte_atomic_fetch_add_explicit(&cbs->use_count, 1, rte_memory_order_relaxed);

	/* the store of use_count must be visible before the cap load */
	rte_atomic_thread_fence(rte_memory_order_seq_cst);
}

/* Iteration finished: count becomes even again. */
static inline __rte_hot void
capture_cb_release(struct capture_rxtx_cb *cbs)
{
	rte_atomic_fetch_add_explicit(&cbs->use_count, 1, rte_memory_order_release);
}

/* Create a clone of mbuf to be placed into ring. */
static inline __rte_hot void
capture_copy_burst(uint16_t port_id, uint16_t queue_id,
		   enum rte_pcapng_direction direction,
		   struct rte_mbuf **pkts, unsigned int nb_pkts,
		   const struct capture *cap,
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
		if (cap->filter) {
			if (__rte_capture_filter(cap->filter, pkts[i]) == 0) {
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
static __rte_hot inline void
capture_copy(uint16_t port_id, uint16_t queue_id,
	     enum rte_pcapng_direction direction,
	     struct rte_mbuf **pkts, uint16_t nb_pkts,
	     const struct capture *cap,
	     struct capture_stats *stats)
{
	unsigned int offs = 0;

	do {
		unsigned int n = RTE_MIN(nb_pkts - offs, CAPTURE_BURST_SIZE);

		capture_copy_burst(port_id, queue_id, direction, &pkts[offs], n, cap, stats);
		offs += n;
	} while (offs < nb_pkts);
}

static __rte_hot uint16_t
capture_rx(uint16_t port, uint16_t queue,
	struct rte_mbuf **pkts, uint16_t nb_pkts,
	uint16_t max_pkts __rte_unused, void *user_params)
{
	struct capture_rxtx_cb *cbs = user_params;
	const struct capture *cap;

	capture_cb_hold(cbs);

	/*
	 * A NULL owner means the capture was torn down while this burst was on
	 * its way in. See capture_cb_detach() for why this load cannot miss it.
	 * Acquire pairs with the release store in capture_attach(), so a block
	 * recycled by a new capture is fully prepared before it is used here.
	 */
	cap = rte_atomic_load_explicit(&cbs->cap, rte_memory_order_acquire);
	if (likely(cap != NULL))
		capture_copy(port, queue, RTE_PCAPNG_DIRECTION_IN,
			     pkts, nb_pkts, cap, &cbs->stats);

	capture_cb_release(cbs);

	return nb_pkts;
}

static __rte_hot uint16_t
capture_tx(uint16_t port, uint16_t queue,
	   struct rte_mbuf **pkts, uint16_t nb_pkts, void *user_params)
{
	struct capture_rxtx_cb *cbs = user_params;
	const struct capture *cap;

	capture_cb_hold(cbs);

	cap = rte_atomic_load_explicit(&cbs->cap, rte_memory_order_acquire);
	if (likely(cap != NULL))
		capture_copy(port, queue, RTE_PCAPNG_DIRECTION_OUT,
			     pkts, nb_pkts, cap, &cbs->stats);

	capture_cb_release(cbs);

	return nb_pkts;
}


/*
 * Take an idle callback block for a port/queue/direction off the free list,
 * allocating another when every block for that queue is already in use.
 *
 * Several captures may cover the same queue, each with its own filter and its
 * own ethdev callback, so this hands out one block per capture.
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

/* Install one callback, on a block that is now ours. */
static int
capture_attach(struct capture *cap, uint16_t queue, bool is_rx)
{
	struct capture_rxtx_cb *cbs;

	cbs = capture_cb_get(cap, queue, is_rx);
	if (cbs == NULL) {
		CAPTURE_LOG(ERR, "No callback block for %u:%u %s",
			    cap->port_id, queue, is_rx ? "rx" : "tx");
		return -1;
	}

	/* the block may have been used by an earlier capture of this queue */
	memset(&cbs->stats, 0, sizeof(cbs->stats));

	/*
	 * Release the callback object left over by that earlier capture. It
	 * cannot be freed at removal time because ethdev reads cb->next after
	 * our callback returns, so there is no point at which the burst loop is
	 * known to be done with it. Deferring it to the next attach puts a
	 * whole capture session in between, which is ample.
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
		return -1;
	}

	cap->cbs[cap->nb_cbs++] = cbs;
	return 0;
}

/* Install callbacks */
static int
capture_add_callbacks(struct capture *cap)
{
	for (uint16_t q = 0; q < cap->tx_queues; q++) {
		if (cap->queue != ALL_QUEUES && cap->queue != q)
			continue;

		if (capture_attach(cap, q, false) < 0)
			return -1;
	}

	for (uint16_t q = 0; q < cap->rx_queues; q++) {
		if (cap->queue != ALL_QUEUES && cap->queue != q)
			continue;

		if (capture_attach(cap, q, true) < 0)
			return -1;
	}
	return 0;
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
 * Sum the counters of the queues still attached plus those already detached.
 * Caller holds capture_lock.
 */
static void
capture_sum_stats(const struct capture *cap, struct capture_total *t)
{
	*t = cap->total;

	for (uint16_t i = 0; i < cap->nb_cbs; i++)
		capture_sum_one(t, &cap->cbs[i]->stats);
}

/*
 * Cleanup call backs.
 *
 * Once this returns no datapath thread can reach the capture any more, so the
 * caller is free to release it. The callback blocks themselves stay behind for
 * the next capture on the same queue.
 */
static void
capture_remove_callbacks(struct capture *cap)
{
	struct capture_total total;

	for (uint16_t i = 0; i < cap->nb_cbs; i++) {
		struct capture_rxtx_cb *cbs = cap->cbs[i];

		if (cbs->is_rx)
			rte_eth_remove_rx_callback(cap->port_id, cbs->queue, cbs->cb);
		else
			rte_eth_remove_tx_callback(cap->port_id, cbs->queue, cbs->cb);

		/* freed by the next capture that attaches to this queue */
		cbs->stale = cbs->cb;
		cbs->cb = NULL;

		capture_cb_detach(cbs);
	}

	/*
	 * The blocks go back on the free list, so take the final counters
	 * before letting go: whoever picks them up next zeroes the stats.
	 */
	rte_spinlock_lock(&capture_lock);
	capture_sum_stats(cap, &total);
	cap->total = total;
	for (uint16_t i = 0; i < cap->nb_cbs; i++)
		TAILQ_INSERT_TAIL(&capture_cb_freelist, cap->cbs[i], next);
	cap->nb_cbs = 0;
	rte_spinlock_unlock(&capture_lock);
}

/* Helper that returns error to telemetry and logs it */
static void __rte_format_printf(2, 3)
capture_err(struct rte_tel_data *d, const char *format, ...)
{
	va_list ap;
	char msg[1024];

	va_start(ap, format);
	vsnprintf(msg, sizeof(msg), format, ap);
	va_end(ap);

	rte_tel_data_start_dict(d);
	rte_tel_data_add_dict_string(d, "error", msg);

	CAPTURE_LOG(NOTICE, "%s", msg);
}

static int
parse_uint32(const char *str, uint32_t *result, uint32_t limit)
{
	unsigned long val;
	char *endp;

	errno = 0;
	val = strtoul(str, &endp, 10);
	if (errno != 0 || *endp != '\0' || val >= limit)
		return -1;

	*result = val;
	return 0;
}

/*
 * Break the comma separated parameter string into tokens
 * and fill in the capture config structure.
 *
 * Does not use rte_kvargs because that would mangle [] etc in filter expression.
 */
static int
parse_params(char *str, struct capture_config *cfg, struct rte_tel_data *d)
{
	uint32_t snaplen = DEFAULT_SNAPLEN;
	char *args[8];
	int nargs;

	/* Need at least the port id */
	nargs = rte_strsplit(str, strlen(str), args, RTE_DIM(args), ',');
	if (nargs < 1) {
		capture_err(d, "missing parameters '%s'", str);
		return -1;
	}

	/* Parse port id (required) */
	uint32_t port_id;
	if (parse_uint32(args[0], &port_id, RTE_MAX_ETHPORTS) < 0) {
		capture_err(d, "invalid port_id='%s'", args[0]);
		return -1;
	}

	/* parse remainder as name=value parameters */
	for (int i = 1; i < nargs; i++) {
		char *key = args[i];

		/* split at the = */
		char *eq = strchr(args[i], '=');

		/* all current options require argument after = */
		if (eq == NULL || eq[1] == '\0') {
			capture_err(d,  "missing value for '%s'", key);
			return -1;
		}
		*eq = '\0';
		char *value = eq + 1;

		if (strcmp(key, "out") == 0) {
			cfg->output = value;
		} else if (strcmp(key, "filter") == 0) {
			cfg->filter_str = value;
		} else if (strcmp(key, "queue") == 0) {
			uint32_t q;

			if (parse_uint32(value, &q, RTE_MAX_QUEUES_PER_PORT) < 0) {
				capture_err(d, "invalid queue '%s'", value);
				return -1;
			}
			cfg->queue = q;
		} else if (strcmp(key, "snaplen") == 0) {
			if (parse_uint32(value, &snaplen, UINT32_MAX) < 0) {
				capture_err(d, "invalid snaplen '%s'", value);
				return -1;
			}
		} else {
			capture_err(d, "unknown parameter '%s'", key);
			return -1;
		}
	}

	if (cfg->output == NULL) {
		capture_err(d, "missing output parameter");
		return -1;
	}

	cfg->port_id = port_id;

	/*
	 * Default is 256K from tcpdump legacy
	 * using snaplen=0 means everything.
	 */
	cfg->snaplen = snaplen > 0 ? snaplen : UINT32_MAX;
	return 0;
}

static bool is_empty_or_fifo(const struct stat *stb)
{
	if (S_ISFIFO(stb->st_mode))
		return true;
	else if (S_ISREG(stb->st_mode))
		return stb->st_size == 0;
	else
		return false; /* not a FIFO or regular file */
}


/*
 * Create the file handle for pcapng output
 * Note: can't really tell wireshark about errors since this in an
 * independent thread.
 */
static __rte_cold rte_pcapng_t *
capture_pcapng_open(const char *path, int *fd, uint16_t port_id, const char *filter)
{
	rte_pcapng_t *pcapng = NULL;
	char port_name[RTE_ETH_NAME_MAX_LEN];
	char appname[128];
	char ifname[IFNAMSIZ];
	char *ifdescr = NULL;
	struct utsname uts;
	char *osname = NULL;

	/* OS name is optional, just keep going if not found */
	if (uname(&uts) == 0 && asprintf(&osname, "%s %s", uts.sysname, uts.release) < 0)
		osname = NULL;

	/* add DPDK internal name */
	if (rte_eth_dev_get_name_by_port(port_id, port_name) != 0) {
		CAPTURE_LOG(NOTICE, "Could not find port name for %u", port_id);
		goto cleanup;
	}

	/* match name convention used by dpdk-wireshark-extcap.py */
	snprintf(ifname, sizeof(ifname), CAPTURE_EXTCAP_PREFIX ":%u", port_id);
	if (asprintf(&ifdescr, "DPDK %s", port_name) < 0)
		ifdescr = NULL;

	/* mirror what other applications do for name */
	snprintf(appname, sizeof(appname), CAPTURE_EXTCAP_PREFIX " (%s)", rte_version());

	/*
	 * Open the output in non-block mode in case it is a FIFO
	 * without a reader. Wireshark must open the read end before
	 * asking us to capture.
	 */
	*fd = open(path, O_WRONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
	if (*fd < 0) {
		CAPTURE_LOG(ERR, "Could not open %s: %s", path, strerror(errno));
		goto cleanup;
	}

	/* recheck that it is ok to use */
	struct stat sb;
	if (fstat(*fd, &sb) < 0 || !is_empty_or_fifo(&sb)) {
		CAPTURE_LOG(ERR, "Not safe to use %s", path);
		goto close_fd;
	}

	/* writes in the drain loop should block normally */
	int flags = fcntl(*fd, F_GETFL, 0);
	if (flags < 0 || fcntl(*fd, F_SETFL, flags & ~O_NONBLOCK) < 0) {
		CAPTURE_LOG(ERR, "fcntl %s: %s",  path,  strerror(errno));
		goto close_fd;
	}

	/* put pcapng header on and setup */
	pcapng = rte_pcapng_fdopen(*fd, osname, NULL, appname, NULL);
	if (pcapng == NULL) {
		CAPTURE_LOG(ERR, "Add section block failed");
		goto close_fd;
	}

	if (rte_pcapng_add_interface(pcapng, port_id, DLT_EN10MB, ifname, ifdescr, filter) < 0) {
		CAPTURE_LOG(ERR, "Add interface for port %u:%s failed", port_id, ifname);
		rte_pcapng_close(pcapng);  /* closes fd */
		pcapng = NULL;
	}
	goto cleanup;

close_fd:
	close(*fd);
cleanup:
	free(osname);
	free(ifdescr);
	return pcapng;
}

static void
capture_link(struct capture *cap)
{
	rte_spinlock_lock(&capture_lock);
	TAILQ_INSERT_TAIL(&capture_list, cap, next);
	rte_spinlock_unlock(&capture_lock);
}

static void
capture_unlink(struct capture *cap)
{
	rte_spinlock_lock(&capture_lock);
	TAILQ_REMOVE(&capture_list, cap, next);
	rte_spinlock_unlock(&capture_lock);
}

static void
capture_free(struct capture *cap)
{
	if (cap == NULL)
		return;

	free(cap->output);
	__rte_capture_filter_free(cap->filter);
	rte_ring_free(cap->ring);
	rte_mempool_free(cap->mp);
	rte_free(cap);
}

/* Generate unique id for naming and telemetry */
static unsigned int
get_unique_id(void)
{
	static RTE_ATOMIC(unsigned int) capture_instance;

	return rte_atomic_fetch_add_explicit(&capture_instance, 1, rte_memory_order_relaxed);
}

/*
 * Convert configuration into running state
 */
static struct capture *
capture_alloc(const struct capture_config *cfg,
	      const struct rte_eth_dev_info *dev_info,
	      struct rte_tel_data *d)
{
	struct capture *cap;
	char ring_name[RTE_RING_NAMESIZE];
	uint16_t mbuf_size;

	/* try and put capture data struct on same node as device. */
	int socket_id = rte_eth_dev_socket_id(cfg->port_id);
	if (socket_id < 0)
		socket_id = SOCKET_ID_ANY;

	uint16_t num_queues = dev_info->nb_tx_queues + dev_info->nb_rx_queues;
	size_t cb_size = sizeof(*cap) + num_queues * sizeof(cap->cbs[0]);
	cap = rte_zmalloc_socket("capture", cb_size, RTE_CACHE_LINE_SIZE, socket_id);
	if (cap == NULL) {
		capture_err(d, "Could not allocate capture struct");
		goto error;
	}

	cap->idx = get_unique_id();
	snprintf(ring_name, sizeof(ring_name), "capture-%u", cap->idx);
	cap->ring = rte_ring_create(ring_name, CAPTURE_RING_SIZE, socket_id, 0);
	if (cap->ring == NULL) {
		capture_err(d, "Could not create ring");
		goto error;
	}

	/*
	 * If snapshot length is smaller than one mbuf segment then pool
	 * element size can be reduced; otherwise can just use the default
	 * and rte_pktmbuf_copy handle multiple segments.
	 */
	if (cfg->snaplen < RTE_MBUF_DEFAULT_BUF_SIZE)
		mbuf_size = rte_pcapng_mbuf_size(cfg->snaplen);
	else
		mbuf_size = RTE_MBUF_DEFAULT_BUF_SIZE;

	cap->mp = rte_pktmbuf_pool_create_by_ops(ring_name, CAPTURE_POOL_SIZE,
						 MBUF_POOL_CACHE_SIZE, 0, mbuf_size,
						 socket_id, "ring_mp_mc");
	if (cap->mp == NULL) {
		capture_err(d,  "Could not create mempool");
		goto error;
	}

	if (cfg->filter_str) {
		cap->filter = __rte_capture_filter_create(cfg->filter_str);
		if (cap->filter == NULL) {
			capture_err(d,  "Could not compile filter: %s", cfg->filter_str);
			goto error;
		}
	}

	cap->port_id = cfg->port_id;
	cap->output = strdup(cfg->output);
	if (cap->output == NULL) {
		capture_err(d, "Could not strdup '%s'", cfg->output);
		goto error;
	}
	rte_atomic_store_explicit(&cap->running, true, rte_memory_order_relaxed);
	cap->snaplen = cfg->snaplen;
	cap->queue = cfg->queue;
	cap->socket_id = socket_id;
	cap->tx_queues = dev_info->nb_tx_queues;
	cap->rx_queues = dev_info->nb_rx_queues;

	return cap;

error:
	capture_free(cap);
	return NULL;
}

static void
capture_write_stats(rte_pcapng_t *pcapng, const struct capture *cap)
{
	struct capture_total t;
	struct rte_pcapng_interface_stats isb;

	capture_sum_stats(cap, &t);

	/* Unlike libpcap the ifrecv is the total number of packets
	 * and filteraccept is the subset that passed.
	 */
	isb.ifrecv = t.accepted + t.filtered + t.nombuf;
	isb.filteraccept = t.accepted + t.nombuf;
	isb.ifdrop = t.nombuf + t.ringfull;

	rte_pcapng_write_stats(pcapng, cap->port_id, &isb, sizeof(isb), NULL);
}

/* Check that output file is still ok to write (i.e FIFO not closed).
 * Used to detect when wireshark has exited, and idle.
 */
static int
check_fifo_status(int fd)
{
	struct pollfd pfd = { .fd = fd };

	if (poll(&pfd, 1, 0) < 0) {
		CAPTURE_LOG(ERR, "poll failed: %s", strerror(errno));
		return -1;
	}
	if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
		CAPTURE_LOG(NOTICE, "fifo reader closed");
		return -1;
	}
	return 0;
}

static ssize_t
capture_process_ring(struct rte_ring *ring, rte_pcapng_t *pcapng,
		     unsigned int *available)
{
	struct rte_mbuf *pkts[CAPTURE_BURST_SIZE];
	unsigned int n;
	ssize_t written;

	n = rte_ring_sc_dequeue_burst(ring, (void **) pkts,
				      CAPTURE_BURST_SIZE, available);
	if (n == 0)
		return 0;

	written = rte_pcapng_write_packets(pcapng, pkts, n);
	rte_pktmbuf_free_bulk(pkts, n);

	return written;
}

static void
capture_flush_ring(struct rte_ring *ring)
{
	for (;;) {
		struct rte_mbuf *pkts[CAPTURE_BURST_SIZE];
		unsigned int n;

		n = rte_ring_sc_dequeue_burst(ring, (void **) pkts,
					      CAPTURE_BURST_SIZE, NULL);
		if (n == 0)
			break;

		rte_pktmbuf_free_bulk(pkts, n);
	}
}

/* The capture thread that moves packets from ring to the pcapng out */
static uint32_t __rte_hot
capture_thread(void *arg)
{
	struct capture *cap = arg;
	unsigned int empty_count = 0;
	bool reader_gone = false;
	int fd = -1;

	CAPTURE_LOG(INFO, "capture thread starting");

	char name[RTE_THREAD_NAME_SIZE];
	snprintf(name, sizeof(name), "cap-%u", cap->idx);
	rte_thread_set_prefixed_name(rte_thread_self(), name);

	/* This thread wants to detect when file gets closed (for FIFO) */
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	rte_pcapng_t *pcapng = capture_pcapng_open(cap->output, &fd, cap->port_id,
						   __rte_capture_filter_string(cap->filter));
	if (pcapng == NULL) {
		capture_remove_callbacks(cap);
		goto error;
	}

	while (rte_atomic_load_explicit(&cap->running, rte_memory_order_relaxed)) {
		ssize_t written;
		unsigned int avail;

		written = capture_process_ring(cap->ring, pcapng, &avail);
		if (written < 0) {
			if (errno == EPIPE)
				CAPTURE_LOG(DEBUG, "FIFO closed by reader");
			else
				CAPTURE_LOG(ERR, "write to file failed: %s", strerror(errno));

			reader_gone = true;
			break;
		}

		if (written > 0) {
			/* are there more packets? */
			empty_count = (avail == 0);
		} else if (empty_count < SLEEP_THRESHOLD) {
			/* spin a few times before checking */
			++empty_count;
			rte_pause();
		} else if (check_fifo_status(fd) == 0) {
			/* avoid consuming 100% CPU polling */
			rte_delay_us_sleep(SLEEP_US);
		} else {
			/* output FIFO has closed */
			reader_gone = true;
			break;
		}
	}

	/* Capture exiting */
	CAPTURE_LOG(INFO, "capture thread stopping");
	capture_remove_callbacks(cap);

	/* Process residual */
	if (reader_gone)
		capture_flush_ring(cap->ring);
	else {
		while (capture_process_ring(cap->ring, pcapng, NULL) > 0)
			continue;

		capture_write_stats(pcapng, cap);
	}

	rte_pcapng_close(pcapng);

error:
	capture_unlink(cap);
	capture_free(cap);

	return 0;
}

/*
 * Callback handler for telemetry library to start capture.
 *
 * Need to handle: <iface>,snaplen=<n>,filter=<str>
 */
static int
capture_start_req(const char *cmd, const char *params, struct rte_tel_data *d)
{
	struct capture *cap = NULL;
	struct capture_config cfg = { .queue = ALL_QUEUES };
	struct rte_eth_dev_info dev_info;

	if (params == NULL || *params == '\0') {
		CAPTURE_LOG(ERR, "missing parameters");
		return -1;
	}

	CAPTURE_LOG(DEBUG, "telemetry: %s %s", cmd, params);

	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		CAPTURE_LOG(ERR, "capture can only be started from primary");
		return -1;
	}

	/* Note: params is const so need non-const copy for parsing
	 * Alternative would be to change telemetry to allow this.
	 */
	char tmp[CAP_CMD_MAX];
	if (strlcpy(tmp, params, CAP_CMD_MAX) >= CAP_CMD_MAX) {
		CAPTURE_LOG(ERR, "params too long");
		return -1;
	}

	if (parse_params(tmp, &cfg, d) < 0)
		return 0;

	/* Lookup number of queues etc, also validates port_id */
	if (rte_eth_dev_info_get(cfg.port_id, &dev_info) < 0) {
		capture_err(d, "can not get info for port %u", cfg.port_id);
		return 0;
	}

	if (cfg.queue != ALL_QUEUES &&
	    cfg.queue >= RTE_MAX(dev_info.nb_rx_queues, dev_info.nb_tx_queues)) {
		capture_err(d, "queue %d out of range", cfg.queue);
		return 0;
	}

	struct stat sb;
	if (stat(cfg.output, &sb) < 0) {
		capture_err(d, "output %s:%s", cfg.output, strerror(errno));
		return 0;
	}

	if (!is_empty_or_fifo(&sb)) {
		capture_err(d, "output %s is not empty", cfg.output);
		return 0;
	}

	cap = capture_alloc(&cfg, &dev_info, d);
	if (cap == NULL)
		return 0;

	if (capture_add_callbacks(cap) < 0) {
		capture_err(d, "can not register callbacks");
		goto error_callback_remove;
	}

	/*
	 * Publish into the active list before starting the drain thread so the
	 * thread is guaranteed to find itself there when it removes itself on
	 * exit (it may exit immediately, e.g. if the FIFO reader is already
	 * gone). On thread-create failure we undo the insertion here.
	 */
	uint32_t idx = cap->idx;
	capture_link(cap);

	/*
	 * Make a new thread to do the capture work
	 * Thread will inherit affinity from the telemetry handler that calls us
	 */
	rte_thread_t thread_id;
	int ret = rte_thread_create(&thread_id, NULL, capture_thread, cap);
	if (ret != 0) {
		capture_err(d, "thread start failed: %s", strerror(ret));
		goto error_unlink;
	}

	rte_thread_detach(thread_id);

	/* Return id back for later use. */
	rte_tel_data_start_dict(d);
	rte_tel_data_add_dict_uint(d, "id", idx);
	rte_tel_data_add_dict_string(d, "status", "running");
	return 0;

error_unlink:
	capture_unlink(cap);
error_callback_remove:
	capture_remove_callbacks(cap);
	capture_free(cap);

	/* return 0 since error reported "error":"XXX" in response */
	return 0;
}

/* Telemetry: stop active capture. */
static int
capture_stop_req(const char *cmd, const char *params, struct rte_tel_data *d)
{
	if (params == NULL || *params == '\0') {
		CAPTURE_LOG(ERR, "missing parameters");
		return -1;
	}

	CAPTURE_LOG(DEBUG, "telemetry %s %s", cmd, params);

	uint32_t idx;
	if (parse_uint32(params, &idx, UINT32_MAX) < 0) {
		capture_err(d, "invalid capture index '%s'", params);
		return 0;
	}

	rte_spinlock_lock(&capture_lock);
	struct capture *cap;
	TAILQ_FOREACH(cap, &capture_list, next) {
		if (cap->idx == idx)
			break;
	}
	if (cap == NULL) {
		rte_spinlock_unlock(&capture_lock);
		CAPTURE_LOG(DEBUG, "capture index %" PRIu32 " not found", idx);
		return 0;
	}

	rte_atomic_store_explicit(&cap->running, false, rte_memory_order_relaxed);
	rte_spinlock_unlock(&capture_lock);

	rte_tel_data_start_dict(d);
	rte_tel_data_add_dict_string(d, "status", "stopped");
	return 0;
}

/* Telemetry: list the ids of all active captures. */
static int
capture_list_req(const char *cmd __rte_unused, const char *params __rte_unused,
		 struct rte_tel_data *d)
{
	struct capture *cap;

	CAPTURE_LOG(DEBUG, "telemetry %s", cmd);
	rte_tel_data_start_array(d, RTE_TEL_UINT_VAL);

	rte_spinlock_lock(&capture_lock);
	TAILQ_FOREACH(cap, &capture_list, next)
		rte_tel_data_add_array_uint(d, cap->idx);
	rte_spinlock_unlock(&capture_lock);

	return 0;
}


/* Telemetry: report configuration and counters for one capture. */
static int
capture_stats_req(const char *cmd, const char *params,
		  struct rte_tel_data *d)
{
	struct capture *cap;
	struct capture_total t;

	if (params == NULL || *params == '\0') {
		CAPTURE_LOG(ERR, "missing parameters");
		return -1;
	}

	CAPTURE_LOG(DEBUG, "telemetry %s %s", cmd, params);

	uint32_t idx;
	if (parse_uint32(params, &idx, UINT32_MAX) < 0) {
		capture_err(d, "invalid capture index '%s'", params);
		return 0;
	}

	/* Find the instance and snapshot what we need while holding the lock. */
	rte_spinlock_lock(&capture_lock);
	TAILQ_FOREACH(cap, &capture_list, next) {
		if (cap->idx == idx)
			break;
	}
	if (cap == NULL) {
		rte_spinlock_unlock(&capture_lock);
		capture_err(d, "capture index %" PRIu32 " not found", idx);
		return 0;
	}

	rte_tel_data_start_dict(d);
	rte_tel_data_add_dict_uint(d, "port_id", cap->port_id);
	if (cap->filter)
		rte_tel_data_add_dict_string(d, "filter",
					     __rte_capture_filter_string(cap->filter));
	rte_tel_data_add_dict_int(d, "running",
				  rte_atomic_load_explicit(&cap->running,
							   rte_memory_order_relaxed));
	rte_tel_data_add_dict_uint(d, "snaplen", cap->snaplen);
	rte_tel_data_add_dict_uint(d, "rx_queues", cap->rx_queues);
	rte_tel_data_add_dict_uint(d, "tx_queues", cap->tx_queues);
	capture_sum_stats(cap, &t);
	rte_spinlock_unlock(&capture_lock);

	rte_tel_data_add_dict_uint(d, "accepted", t.accepted);
	rte_tel_data_add_dict_uint(d, "filtered", t.filtered);
	rte_tel_data_add_dict_uint(d, "nombuf", t.nombuf);
	rte_tel_data_add_dict_uint(d, "ringfull", t.ringfull);

	return 0;
}

RTE_INIT(capture_telemetry)
{
	rte_telemetry_register_cmd("/ethdev/capture/list", capture_list_req,
		"List ids of active captures. Takes no parameters.");
	rte_telemetry_register_cmd("/ethdev/capture/stats", capture_stats_req,
		"Report configuration and counters for a capture. Parameters: id");
	rte_telemetry_register_cmd("/ethdev/capture/start", capture_start_req,
		"Start capture. Parameters: "
		"port_id,out=<path>,snaplen=N(optional),queue=N(optional),filter=string(optional)");
	rte_telemetry_register_cmd("/ethdev/capture/stop", capture_stop_req,
				   "Stop an active capture. Parameters: id");
}

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Stephen Hemminger
 */

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/queue.h>
#include <sys/utsname.h>
#include <net/if.h>
#include <unistd.h>

#include <rte_branch_prediction.h>
#include <rte_common.h>
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
#include <rte_version.h>

#include "capture_impl.h"

#ifndef DLT_EN10MB
#define DLT_EN10MB 1
#endif

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

#define DEFAULT_SNAPLEN		262144u	/* from tcpdump et.al. */
#define CAPTURE_BURST_SIZE	32u
#define MBUF_POOL_CACHE_SIZE	32
#define CAPTURE_RING_SIZE	256
#define CAPTURE_POOL_SIZE	1024
#define SLEEP_THRESHOLD		100
#define SLEEP_US		100

/* Parameter values: only used on stack inside parsing */
struct capture_config {
	uint16_t port_id;
	uint32_t snaplen;
	const char *filter_str;
};

/*
 * Data used by callback
 * This per-queue to avoid cache thrashing
 */
struct __rte_cache_aligned capture_rxtx_cb {
	RTE_ATOMIC(uint32_t) use_count;
	const struct rte_eth_rxtx_callback *cb;

	struct capture_stats {
		RTE_ATOMIC(uint64_t) accepted; /**< Number of packets accepted by filter. */
		RTE_ATOMIC(uint64_t) filtered; /**< Number of packets rejected by filter. */
		RTE_ATOMIC(uint64_t) nombuf;   /**< Number of mbuf allocation failures. */
		RTE_ATOMIC(uint64_t) ringfull; /**< Number of missed packets due to ring full. */
	} stats;
};

/*
 * Per-capture instance state.
 */
struct capture {
	TAILQ_ENTRY(capture) next;	/* links into capture_list */
	unsigned int idx;
	RTE_ATOMIC(bool) running;
	int fd;				/* file descriptor of FIFO */
	struct rte_capture_filter *filter;
	struct rte_ring *ring;		/* ring from dataplane to capture thread */
	struct rte_mempool *mp;		/* mempool for capture mbufs */

	uint32_t snaplen;	      	/* amount of data to copy */
	uint16_t port_id;
	uint16_t tx_queues;
	uint16_t rx_queues;

	/* per-queue data sized to max(tx_queue, rx_queues) */
	struct capture_cbs {
		struct capture_rxtx_cb tx_cb;
		struct capture_rxtx_cb rx_cb;
	} cbs[];
};

/* Wait for callbacks to be idle before free */
static void
capture_cb_wait(struct capture_rxtx_cb *cbs)
{
	/* wait until use_count is even (not in use) */
	RTE_WAIT_UNTIL_MASKED(&cbs->use_count, 1, ==, 0, rte_memory_order_acquire);
}

/* Hold a reference to callback while active */
static inline __rte_hot void
capture_cb_hold(struct capture_rxtx_cb *cbs)
{
	rte_atomic_fetch_add_explicit(&cbs->use_count, 1, rte_memory_order_acquire);
}

/* Drop reference to callback when done */
static inline __rte_hot void
capture_cb_release(struct capture_rxtx_cb *cbs)
{
	rte_atomic_fetch_sub_explicit(&cbs->use_count, 1, rte_memory_order_release);
}

/* Cleanup call backs */
static void __rte_cold
capture_cb_cleanup(struct capture *cap)
{

	for (unsigned int q = 0; q < cap->tx_queues; q++) {
		struct capture_rxtx_cb *tx_cb = &cap->cbs[q].tx_cb;
		if (tx_cb->cb) {
			rte_eth_remove_tx_callback(cap->port_id, q, tx_cb->cb);
			capture_cb_wait(tx_cb);
			tx_cb->cb = NULL;
		}
	}

	for (unsigned int q = 0; q < cap->rx_queues; q++) {
		struct capture_rxtx_cb *rx_cb = &cap->cbs[q].rx_cb;
		if (rx_cb->cb) {
			rte_eth_remove_rx_callback(cap->port_id, q, rx_cb->cb);
			capture_cb_wait(rx_cb);
			rx_cb->cb = NULL;
		}
	}
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
		 * This uses same BPF return value convention as socket filter and pcap_offline_filter.
		 * if program returns zero then packet doesn't match the filter (will be ignored).
		 */
		if (cap->filter) {
			uint64_t rc = __rte_capture_filter(cap->filter, pkts[i]);
			if (rc == 0) {
				rte_atomic_fetch_add_explicit(&stats->filtered, 1,
							      rte_memory_order_relaxed);
				continue;
			}
		}

		p = rte_pcapng_copy(port_id, queue_id, pkts[i], mp,
				    snaplen, direction, NULL);

		if (unlikely(p == NULL))
			rte_atomic_fetch_add_explicit(&stats->nombuf, 1,
						      rte_memory_order_relaxed);
		else
			dup_bufs[d_pkts++] = p;
	}

	if (d_pkts == 0)
		return;

	rte_atomic_fetch_add_explicit(&stats->accepted, d_pkts, rte_memory_order_relaxed);

	ring_enq = rte_ring_enqueue_burst(ring, (void *)&dup_bufs[0], d_pkts, NULL);
	if (unlikely(ring_enq < d_pkts)) {
		unsigned int drops = d_pkts - ring_enq;

		rte_atomic_fetch_add_explicit(&stats->ringfull, drops, rte_memory_order_relaxed);
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
	struct capture *cap = user_params;
	struct capture_rxtx_cb *cbs = &cap->cbs[queue].rx_cb;

	capture_cb_hold(cbs);
	capture_copy(port, queue, RTE_PCAPNG_DIRECTION_IN, pkts, nb_pkts, cap, &cbs->stats);
	capture_cb_release(cbs);

	return nb_pkts;
}

static __rte_hot uint16_t
capture_tx(uint16_t port, uint16_t queue,
	   struct rte_mbuf **pkts, uint16_t nb_pkts, void *user_params)
{
	struct capture *capture = user_params;
	struct capture_rxtx_cb *cbs = &capture->cbs[queue].tx_cb;

	capture_cb_hold(cbs);
	capture_copy(port, queue, RTE_PCAPNG_DIRECTION_OUT, pkts, nb_pkts, capture, &cbs->stats);
	capture_cb_release(cbs);

	return nb_pkts;
}

/*
 * Break the comma separated parameter string into tokens
 * and fill in the capture config structure.
 *
 * Does not use rte_kvargs because that would mangle [] etc in filter expression.
 */
static __rte_cold int
parse_params(char *str, struct capture_config *cfg)
{
	uint32_t snaplen = DEFAULT_SNAPLEN;

	char *args[4];
	int nargs = rte_strsplit(str, strlen(str), args, RTE_DIM(args), ',');
	/* Need at least the port id */
	if (nargs < 1) {
		CAPTURE_LOG(ERR, "missing parameters '%s'", str);
		return -1;
	}

	/* Parse port id (required) */
	char *endp;
	errno = 0;
	unsigned long port_id = strtoul(args[0], &endp, 10);
	if (errno != 0 || port_id >= RTE_MAX_ETHPORTS) {
		CAPTURE_LOG(ERR, "invalid port_id=%s", args[0]);
		return -1;
	}
	if (*endp != '\0') {
		CAPTURE_LOG(ERR, "garbage after port_id value");
		return -1;
	}

	/* parse remainder as name=value parameters */
	for (int i = 1; i < nargs; i++) {
		char *key = args[i];

		/* split at the = */
		char *eq = strchr(args[i], '=');

		/* all current options require argument after = */
		if (eq == NULL || eq[1] == '\0') {
			CAPTURE_LOG(ERR, "missing value for '%s'", key);
			return -1;
		}
		*eq = '\0';
		char *value = eq + 1;

		if (strcmp(key, "filter") == 0) {
			cfg->filter_str = value;
		} else if (strcmp(key, "snaplen") == 0) {
			errno = 0;
			unsigned long len = strtoul(value, &endp, 10);
			if (errno != 0 || *endp != '\0' || len >= UINT32_MAX) {
				CAPTURE_LOG(ERR, "invalid snaplen '%lu'", len);
				return -1;
			}
			snaplen = len;
		} else {
			CAPTURE_LOG(ERR, "unknown parameter '%s'", key);
			return -1;
		}
	}

	cfg->port_id = port_id;

	/*
	 * Default is 256K from tcpdump legacy
	 * using snaplen=0 means everything.
	 */
	cfg->snaplen = snaplen > 0 ? snaplen : UINT32_MAX;

	return 0;
}

/*
 * Open pcapng handle.
 * Look up OS name and add DPDK version.
 */
static __rte_cold rte_pcapng_t *
capture_pcapng_open(int fd, uint16_t port_id, const char *filter)
{
	rte_pcapng_t *pcapng = NULL;
	char port_name[RTE_ETH_NAME_MAX_LEN];
	char ifname[IFNAMSIZ];
	char *ifdescr = NULL;
	struct utsname uts;
	char *osname = NULL;

	/* OS name is optional, just keep going if not found */
	if (uname(&uts) == 0 &&
	    asprintf(&osname, "%s %s", uts.sysname, uts.release) < 0)
		osname = NULL;

	/* add DPDK internal name */
	if (rte_eth_dev_get_name_by_port(port_id, port_name) != 0) {
		CAPTURE_LOG(NOTICE, "Could not find port name for %u", port_id);
		goto close_fd;
	}

	/* match name convention used by dpdk-wireshark-extcap.py */
	snprintf(ifname, sizeof(ifname), "dpdk:%u", port_id);
	if (asprintf(&ifdescr, "DPDK %s (port %u)", port_name, port_id) < 0)
		ifdescr = NULL;

	pcapng = rte_pcapng_fdopen(fd, osname, NULL, rte_version(), NULL);
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
	close(fd);
cleanup:
	free(osname);
	free(ifdescr);
	return pcapng;
}

static __rte_cold void
capture_link(struct capture *cap)
{
	rte_spinlock_lock(&capture_lock);
	TAILQ_INSERT_TAIL(&capture_list, cap, next);
	rte_spinlock_unlock(&capture_lock);
}

static __rte_cold void
capture_unlink(struct capture *cap)
{
	rte_spinlock_lock(&capture_lock);
	TAILQ_REMOVE(&capture_list, cap, next);
	rte_spinlock_unlock(&capture_lock);
}

static __rte_cold void
capture_free(struct capture *cap)
{
	if (cap == NULL)
		return;

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
capture_alloc(const struct capture_config *cfg, int fd,
	      const struct rte_eth_dev_info *dev_info,
	      int socket_id)
{
	struct capture *cap;
	char ring_name[RTE_RING_NAMESIZE];
	uint16_t mbuf_size;
	uint16_t num_queues = RTE_MAX(dev_info->nb_tx_queues, dev_info->nb_rx_queues);
	size_t cb_size = sizeof(*cap) + num_queues * sizeof(cap->cbs[0]);

	cap = rte_zmalloc_socket("capture", cb_size, RTE_CACHE_LINE_SIZE, socket_id);
	if (cap == NULL) {
		CAPTURE_LOG(ERR, "Could not allocate capture struct");
		goto err_close_fd;
	}

	cap->idx = get_unique_id();

	snprintf(ring_name, sizeof(ring_name), "capture-%u", cap->idx);
	cap->ring = rte_ring_create(ring_name, CAPTURE_RING_SIZE, socket_id, 0);
	if (cap->ring == NULL) {
		CAPTURE_LOG(ERR, "Could not create ring");
		goto err_close_fd;
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
		CAPTURE_LOG(ERR, "Could not create mempool");
		goto err_close_fd;
	}

	if (cfg->filter_str) {
		cap->filter = __rte_capture_filter_create(cfg->filter_str);
		if (cap->filter == NULL) {
			CAPTURE_LOG(ERR, "Could not compile filter: %s", cfg->filter_str);
			goto err_close_fd;
		}
	}

	cap->fd = fd;
	cap->port_id = cfg->port_id;
	rte_atomic_store_explicit(&cap->running, true, rte_memory_order_relaxed);
	cap->snaplen = cfg->snaplen;
	cap->tx_queues = dev_info->nb_tx_queues;
	cap->rx_queues = dev_info->nb_rx_queues;

	for (unsigned int q = 0; q < cap->tx_queues; q++) {
		struct capture_rxtx_cb *tx_cb = &cap->cbs[q].tx_cb;
		tx_cb->cb = rte_eth_add_tx_callback(cfg->port_id, q, capture_tx, cap);
		if (tx_cb->cb == NULL)
			CAPTURE_LOG(ERR, "Register tx callback for %u:%u failed",
				    cfg->port_id, q);
	}

	for (unsigned int q = 0; q < cap->rx_queues; q++) {
		struct capture_rxtx_cb *rx_cb = &cap->cbs[q].rx_cb;
		rx_cb->cb = rte_eth_add_rx_callback(cfg->port_id, q, capture_rx, cap);
		if (rx_cb->cb == NULL)
			CAPTURE_LOG(ERR, "Register rx callback for %u:%u failed",
				    cfg->port_id, q);
	}

	return cap;

err_close_fd:
	close(fd);
	capture_free(cap);
	return NULL;
}

/*
 * The capture thread that moves packets from ring into the FIFO
 */
static void *
capture_thread(void *arg)
{
	struct capture *cap = arg;
	unsigned int empty_count = 0;

	CAPTURE_LOG(INFO, "capture thread starting");

	/* This thread wants to detect when FIFO gets closed */
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	rte_pcapng_t *pcapng = capture_pcapng_open(cap->fd, cap->port_id,
					   __rte_capture_filter_string(cap->filter));
	if (pcapng == NULL)
		goto error;

	while (rte_atomic_load_explicit(&cap->running, rte_memory_order_relaxed)) {
		unsigned int avail, n;
		struct rte_mbuf *pkts[CAPTURE_BURST_SIZE];

		n = rte_ring_sc_dequeue_burst(cap->ring, (void **) pkts, CAPTURE_BURST_SIZE, &avail);

		/*
		 * If the ring is empty, apply simple heuristic to keep this
		 * thread from fully consuming the CPU.
		 */
		if (n == 0) {
			/* repeat a few times before waiting */
			if (empty_count < SLEEP_THRESHOLD) {
				++empty_count;
			} else {
				struct pollfd pfd = { .fd = cap->fd };
				struct timespec ts = { .tv_nsec = SLEEP_US * 1000 };

				if (ppoll(&pfd, 1, &ts, NULL) > 0 &&
				    (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))) {
					CAPTURE_LOG(NOTICE, "fifo reader closed");
					break;	/* reader is gone */
				}
			}
			continue;
		}

		/* If this drained the ring count it as first emptying */
		empty_count = (avail == 0);

		if (unlikely(rte_pcapng_write_packets(pcapng, pkts, n) < 0)) {
			CAPTURE_LOG(NOTICE, "write to fifo failed: %s", strerror(errno));
			break;
		}
	}

	rte_atomic_store_explicit(&cap->running, false, rte_memory_order_relaxed);

	/* Capture exiting */
	CAPTURE_LOG(INFO, "capture thread stopping");
	rte_pcapng_close(pcapng);

error:

	capture_cb_cleanup(cap);
	capture_unlink(cap);
	capture_free(cap);

	return NULL;
}

/*
 * Callback handler for telemetry library to start capture.
 *
 * Need to handle: <iface>,snaplen=<n>,filter=<str>
 */
static int
capture_start_req(const char *cmd, const char *params, void *arg __rte_unused,
		  const int *fds, unsigned int n_fds, struct rte_tel_data *d)
{
	struct capture *cap = NULL;
	struct capture_config cfg = { };
	struct rte_eth_dev_info dev_info;

	CAPTURE_LOG(DEBUG, "telemetry: %s %s", cmd, params);

	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		CAPTURE_LOG(ERR, "capture can only be started from primary");
		goto error;
	}

	if (params == NULL || !isdigit((unsigned char)*params))
		goto error;

	/* Note: params is const so need non-const copy for parsing */
	if (parse_params(strdupa(params), &cfg) < 0)
		goto error;

	/* Need one fd for output */
	if (n_fds != 1) {
		if (n_fds == 0)
			CAPTURE_LOG(ERR, "missing output fd");
		else
			CAPTURE_LOG(ERR, "too many fds");
		goto error;
	}

	/* Lookup number of queues etc, also validates port_id */
	if (rte_eth_dev_info_get(cfg.port_id, &dev_info) < 0) {
		CAPTURE_LOG(ERR, "can not get info for port %u", cfg.port_id);
		goto error;
	}

	int socket_id = rte_eth_dev_socket_id(cfg.port_id);
	if (socket_id < 0) {
		CAPTURE_LOG(NOTICE, "could not determine socket for port %u", cfg.port_id);
		socket_id = SOCKET_ID_ANY;
	}

	cap = capture_alloc(&cfg, fds[0], &dev_info, socket_id);
	if (cap == NULL)
		return -1; /* fd already closed by capture_alloc */

	/*
	 * Publish into the active list before starting the drain thread so the
	 * thread is guaranteed to find itself there when it removes itself on
	 * exit (it may exit immediately, e.g. if the FIFO reader is already
	 * gone). On thread-create failure we undo the insertion here.
	 */
	unsigned int idx = cap->idx;
	capture_link(cap);

	/*
	 * Make a new thread to do the capture work
	 * Thread will inherit affinity from the telemetry handler that calls us
	 */
	pthread_t thread_id;
	if (pthread_create(&thread_id, NULL, capture_thread, cap) != 0) {
		CAPTURE_LOG(ERR, "Capture thread start failed: %s", strerror(errno));

		close(cap->fd);
		capture_unlink(cap);
		capture_cb_cleanup(cap);
		capture_free(cap);
		return -1;
	}

	/* Nothing will be waiting for this thread. */
	pthread_detach(thread_id);

	/* Return id back for later use. */
	rte_tel_data_start_dict(d);
	rte_tel_data_add_dict_uint(d, "id", idx);
	rte_tel_data_add_dict_string(d, "status", "running");
	return 0;

error:
	for (unsigned int i = 0; i < n_fds; i++)
		close(fds[i]);
	return -1;
}



/* Telemetry: stop active capture. */
static int
capture_stop_req(const char *cmd, const char *params, struct rte_tel_data *d)
{

	CAPTURE_LOG(DEBUG, "telemetry %s %s", cmd, params);

	if (params == NULL || *params == '\0')
		return -EINVAL;

	errno = 0;
	char *endp;
	unsigned long idx = strtoul(params, &endp, 10);
	if (errno != 0 || *endp != '\0')
		return -EINVAL;

	rte_spinlock_lock(&capture_lock);
	struct capture *cap;
	TAILQ_FOREACH(cap, &capture_list, next) {
		if (cap->idx == idx)
			break;
	}
	if (cap == NULL) {
		CAPTURE_LOG(ERR, "Capture index %lu not found", idx);
		rte_spinlock_unlock(&capture_lock);
		return -ENOENT;
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

	CAPTURE_LOG(DEBUG, "telemetry %s %s", cmd, params);
	rte_tel_data_start_array(d, RTE_TEL_UINT_VAL);

	rte_spinlock_lock(&capture_lock);
	TAILQ_FOREACH(cap, &capture_list, next)
		rte_tel_data_add_array_uint(d, cap->idx);
	rte_spinlock_unlock(&capture_lock);

	return 0;
}

/* Aggregate per-queue counters of a capture instance. */
struct capture_total {
	uint64_t accepted;
	uint64_t filtered;
	uint64_t nombuf;
	uint64_t ringfull;
};

static void
capture_sum_one(struct capture_total *t, const struct capture_stats *s)
{
	t->accepted += rte_atomic_load_explicit(&s->accepted, rte_memory_order_relaxed);
	t->filtered += rte_atomic_load_explicit(&s->filtered, rte_memory_order_relaxed);
	t->nombuf   += rte_atomic_load_explicit(&s->nombuf, rte_memory_order_relaxed);
	t->ringfull += rte_atomic_load_explicit(&s->ringfull, rte_memory_order_relaxed);
}

/* Sum the rx and tx counters across all queues. Caller holds capture_lock. */
static void
capture_sum_stats(const struct capture *cap, struct capture_total *t)
{
	*t = (struct capture_total){ };

	for (unsigned int q = 0; q < cap->rx_queues; q++)
		capture_sum_one(t, &cap->cbs[q].rx_cb.stats);
	for (unsigned int q = 0; q < cap->tx_queues; q++)
		capture_sum_one(t, &cap->cbs[q].tx_cb.stats);
}

/* Telemetry: report configuration and counters for one capture. */
static int
capture_stats_req(const char *cmd, const char *params,
		  struct rte_tel_data *d)
{
	struct capture *cap;
	struct capture_total t;
	char *endp;

	CAPTURE_LOG(DEBUG, "telemetry %s %s", cmd, params);
	if (params == NULL || *params == '\0')
		return -EINVAL;

	errno = 0;
	unsigned long idx = strtoul(params, &endp, 10);
	if (errno != 0 || *endp != '\0')
		return -EINVAL;

	/* Find the instance and snapshot what we need while holding the lock. */
	rte_spinlock_lock(&capture_lock);
	TAILQ_FOREACH(cap, &capture_list, next) {
		if (cap->idx == idx)
			break;
	}
	if (cap == NULL) {
		CAPTURE_LOG(ERR, "Capture index %lu not found", idx);
		rte_spinlock_unlock(&capture_lock);
		return -ENOENT;
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
	rte_telemetry_register_cmd_fd_arg("/ethdev/capture/start", capture_start_req, NULL,
		"Start capture."
		"Parameters: port_id,snaplen=N(optional),filter=string(optional)");
	rte_telemetry_register_cmd("/ethdev/capture/stop", capture_stop_req,
				   "Stop an active capture. Parameters: id");
}

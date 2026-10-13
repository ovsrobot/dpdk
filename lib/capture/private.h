/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Stephen Hemminger
 */
#ifndef CAPTURE_PRIVATE_H
#define CAPTURE_PRIVATE_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/queue.h>
#include <sys/stat.h>

#include <rte_spinlock.h>
#include <rte_stdatomic.h>

#define RTE_LOGTYPE_CAPTURE rte_capture_logtype
extern int rte_capture_logtype;
#define CAPTURE_LOG(level, ...) \
	RTE_LOG_LINE_PREFIX(level, CAPTURE, "%s(): ", __func__, __VA_ARGS__)

/* Shared between the control, datapath, output and multi-process parts. */
#define ALL_QUEUES		UINT16_MAX
#define CAPTURE_BURST_SIZE	32u
#define CAPTURE_EXTCAP_PREFIX	"dpdk"
#define SLEEP_THRESHOLD		100
#define SLEEP_US		100

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
 * Callback data, one per capture per port/queue/direction.
 *
 * Never freed, as in lib/bpf/bpf_pkt.c: rte_eth_remove_{rx,tx}_callback()
 * only unlinks, so a datapath thread can still enter the callback afterwards
 * and needs something valid to synchronize on. Recycled only by a later
 * capture of the same port/queue/direction.
 */
struct __rte_cache_aligned capture_rxtx_cb {
	/* used by both data and control path */
	RTE_ATOMIC(uint32_t) use_count;
	RTE_ATOMIC(struct capture *) cap;	/* owner, NULL when idle */
	struct capture_stats stats;

	/* owner's attached list, guarded by cap->cbs_lock; this is how the
	 * primary sees a secondary's counters. Separate from 'next' because an
	 * idle block is on the free list at the same time.
	 */
	TAILQ_ENTRY(capture_rxtx_cb) attached;

	/* filter loaded by this process, NULL if the capture has none */
	struct capture_filter_prog *prog;

	/* used by control path only, in the process that attached this block */
	TAILQ_ENTRY(capture_rxtx_cb) next;	/* links into capture_cb_freelist */
	const struct rte_eth_rxtx_callback *cb;
	const struct rte_eth_rxtx_callback *stale;
	uint16_t port_id;
	uint16_t queue;
	bool is_rx;
};

/*
 * Idle callback blocks, guarded by capture_lock. Per-process: cb and stale
 * are only meaningful in the process that registered the ethdev callback.
 */
TAILQ_HEAD(capture_cb_list, capture_rxtx_cb);

/*
 * Per-capture state, in shared memory. A secondary gets this pointer in the
 * IPC request. It must not follow filter (process-private eBPF) or touch the
 * creator-only fields marked below.
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
	char *output;			/* filename of out, creator only */

	TAILQ_ENTRY(capture) next;	/* links into capture_list, creator only */

	/* blocks attached by any process, so the lock cannot be capture_lock */
	rte_spinlock_t cbs_lock;
	struct capture_cb_list attached;

	/* counters of queues already detached; guarded by cbs_lock */
	struct capture_total total;

	/* what this process attached; sized for one process's queues, so a
	 * secondary keeps its own record. Creator only.
	 */
	struct capture_filter_prog *prog;
	uint16_t nb_cbs;
	struct capture_rxtx_cb *cbs[];
};

/* Captures owned by this process. The lock also guards the cb free list. */
TAILQ_HEAD(capture_list, capture);
extern rte_spinlock_t capture_lock;

/* The application may be privileged and extcap not, so only write to a FIFO. */
static inline bool
is_fifo(const struct stat *stb)
{
	return S_ISFIFO(stb->st_mode);
}

/* datapath.c */
int capture_attach_queues(struct capture *cap, struct capture_rxtx_cb **cbs,
			  uint16_t *nb_cbs, struct capture_filter_prog **progp);
void capture_detach_queues(struct capture *cap, struct capture_rxtx_cb **cbs,
			   uint16_t *nb_cbs, struct capture_filter_prog *prog);
int capture_add_callbacks(struct capture *cap);
void capture_remove_callbacks(struct capture *cap);
void capture_sum_stats(const struct capture *cap, struct capture_total *t);

/* capture.c */
void capture_unlink(struct capture *cap);
void capture_free(struct capture *cap);

/* output.c */
uint32_t capture_thread(void *arg);

/* multiproc.c */
enum capture_mp_op {
	CAPTURE_MP_START,
	CAPTURE_MP_STOP,
};

void capture_mp_register(void);
int capture_mp_broadcast(struct capture *cap, enum capture_mp_op op);

/* Shared eBPF instructions, plus the per-process loaded program. */
struct rte_capture_filter;
struct capture_filter_prog;

#ifdef RTE_HAS_LIBPCAP
struct rte_capture_filter *__rte_capture_filter_create(const char *str);
const char *__rte_capture_filter_string(struct rte_capture_filter *filter);
void __rte_capture_filter_free(struct rte_capture_filter *filter);

struct capture_filter_prog *__rte_capture_filter_load(const struct rte_capture_filter *filter);
void __rte_capture_filter_unload(struct capture_filter_prog *prog);
uint64_t __rte_capture_filter(const struct capture_filter_prog *prog, struct rte_mbuf *mb);

#else /* !RTE_HAS_LIBPCAP */

/* Stub version if pcap is not available */
static inline struct rte_capture_filter *
__rte_capture_filter_create(const char *str)
{
	RTE_SET_USED(str);
	return NULL; /* not supported */
}

static inline const char *
__rte_capture_filter_string(struct rte_capture_filter *filter)
{
	RTE_SET_USED(filter);
	return NULL;
}

static inline void
__rte_capture_filter_free(struct rte_capture_filter *filter)
{
	RTE_SET_USED(filter);
}

static inline struct capture_filter_prog *
__rte_capture_filter_load(const struct rte_capture_filter *filter)
{
	RTE_SET_USED(filter);
	return NULL;
}

static inline void
__rte_capture_filter_unload(struct capture_filter_prog *prog)
{
	RTE_SET_USED(prog);
}

/* Zero if the packet does not match the filter. */
static inline uint64_t
__rte_capture_filter(const struct capture_filter_prog *prog, struct rte_mbuf *mb)
{
	RTE_SET_USED(prog);
	RTE_SET_USED(mb);
	return 1;
}

#endif  /* !RTE_HAS_LIBPCAP */
#endif /* CAPTURE_PRIVATE_H */

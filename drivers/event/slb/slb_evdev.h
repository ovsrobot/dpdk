/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Pravin Pathak <pravin.pathak.dev@gmail.com>
 */

#ifndef _SLB_EVDEV_H_
#define _SLB_EVDEV_H_

#include <rte_bitops.h>
#include <rte_bitset.h>
#include <rte_event_ring.h>
#include <rte_eventdev.h>
#include <rte_spinlock.h>
#include <rte_stdatomic.h>
#include <eventdev_pmd.h>

#define SLB_PMD_NAME RTE_STR(event_slb)

#define SLB_MAX_PORTS (64)
#define SLB_MAX_PORT_DEQUEUE_DEPTH (128u)
#define SLB_MAX_PORT_ENQUEUE_DEPTH (128u)

#define SLB_MAX_QUEUES (64)

#define SLB_MAX_EVENTS (16384)

#define SLB_MAX_FLOWS_BITS (16)
#define SLB_MAX_FLOWS (1 << (SLB_MAX_FLOWS_BITS))
#define SLB_MAX_FLOWS_MASK (SLB_MAX_FLOWS - 1)

/* Avoid making small 'loans' from the central in-flight event credit pool */
#define SLB_MIN_CREDIT_LOAN (256)
#define SLB_PORT_MAX_CREDITS (2 * SLB_MIN_CREDIT_LOAN)
#define SLB_PORT_MIN_CREDITS (SLB_MIN_CREDIT_LOAN)

#define SLB_IN_RING_SIZE (SLB_MAX_EVENTS)

/* Maximum number of queues that can be linked to a port per priority */
#define SLB_PORT_MAX_Q_MAP_PER_PRIO (SLB_MAX_QUEUES)
/* Number of priority levels supported by SLB. Currently fixed to 2 */
#ifndef SLB_MAX_PRIORITIES
#define SLB_MAX_PRIORITIES 2
#endif

#if (SLB_MAX_PRIORITIES != 2)
#error "SLB_MAX_PRIORITIES must be set to 2 for now"
#endif

/* Total max mapping slots (per-prio * priorities) */
#define SLB_PORT_MAX_Q_MAP (SLB_PORT_MAX_Q_MAP_PER_PRIO * SLB_MAX_PRIORITIES)

struct slb_queue;

/* Pre-resolved queue dequeue entry for core-local port access */
struct slb_port_q_entry {
	struct rte_event_ring *dq_ring;
	struct slb_queue *queue;
	uint8_t queue_id;
	uint8_t schedule_type;
	uint8_t pad[6];
};

#define SLB_PORT_HISTORY_SIZE 256
#define SLB_PORT_HISTORY_MAX_TOKENS (SLB_PORT_HISTORY_SIZE - 1)
#define SLB_PORT_HISTORY_FREE_END 0xFFFF

struct slb_history_entry {
	uint32_t flow_id;
	uint16_t seq_slot;
	uint16_t next_free;
	uint8_t orig_queue_id;
	uint8_t enq_port_id;
	uint8_t sched_type;
	bool active;
};

enum slb_reorder_state {
	SLB_REORDER_EMPTY = 0,
	SLB_REORDER_READY = 1,
	SLB_REORDER_RELEASED = 2
};

struct slb_reorder_entry {
	struct rte_event event;
	RTE_ATOMIC(uint8_t) state;
};

#define SLB_ATOMIC_FLOWS 2048
#define SLB_ATOMIC_FLOWS_MASK (SLB_ATOMIC_FLOWS - 1)
#define SLB_HOLD_BUFFER_SIZE (SLB_MAX_PORT_DEQUEUE_DEPTH * 64)
#define SLB_MIGRATION_LOAD_THRESHOLD 16
#define SLB_MIGRATION_COOLDOWN_MS 500

/* Per-flow entry for atomic scheduling affinity */
struct slb_flow {
	RTE_ATOMIC(int32_t) port_id; /* Port this flow is pinned to */
};

/* Flow-to-port affinity mapping table */
struct slb_flow_map {
	struct slb_flow flows[SLB_ATOMIC_FLOWS];
};

/* Per-port counters for an atomic queue */
struct __rte_cache_aligned slb_atomic_port_stats {
	uint32_t load_counter; /* Incremented when full, decremented when space available */
	uint32_t flow_count;   /* Number of active flows mapped to this port */
	uint64_t q_enqueued;   /* Events scheduled into this port's atomic port-Q */
	uint64_t q_returned;   /* Events returned (FORWARD/RELEASE) by this port */
};

/* Active migration state for an atomic queue */
struct slb_migration_state {
	bool in_progress;
	uint8_t port_id;       /* Source port being drained */
	uint32_t flow_idx;     /* Flow hash index being migrated */
};

/* Dynamically allocated state for atomic queues */
struct slb_atomic_state {
	struct slb_flow_map flow_map;
	uint32_t next_port_rr;
	rte_spinlock_t refill_lock;
	uint16_t hold_count;
	struct slb_migration_state migration;
	uint64_t migrations_count;
	uint64_t flow_last_migrated[SLB_ATOMIC_FLOWS];
	alignas(RTE_CACHE_LINE_SIZE)
	struct slb_atomic_port_stats port_stats[SLB_MAX_PORTS];
	uint8_t hold_ports[SLB_HOLD_BUFFER_SIZE];
	struct rte_event hold_buffer[SLB_HOLD_BUFFER_SIZE];
};

struct __rte_cache_aligned slb_port {
	/* --- Cacheline 0: Hot Rx & Tx scheduling control (64 bytes) --- */
	uint16_t id;
	uint16_t history_head;
	uint16_t history_avail;
	uint16_t pending_releases;
	int32_t inflight_credits;
	int32_t new_event_threshold;
	uint16_t num_q[SLB_MAX_PRIORITIES];
	uint16_t next_q[SLB_MAX_PRIORITIES];
	bool is_single_linked;
	bool implicit_release;
	bool credits_drained;
	bool is_loaded; /* Port marked loaded for atomic flow migration */
	uint8_t pad_port[4];
	struct rte_event_ring *single_linked_ring;
	struct slb_evdev *slb;

	/* --- Cachelines 1..6: Pre-resolved queue mappings for dequeue --- */
	alignas(RTE_CACHE_LINE_SIZE)
	struct slb_port_q_entry q_entries[SLB_MAX_PRIORITIES][SLB_PORT_MAX_Q_MAP_PER_PRIO];

	/* --- Cachelines 7+: Per-port history buffer --- */
	alignas(RTE_CACHE_LINE_SIZE)
	struct slb_history_entry history[SLB_PORT_HISTORY_SIZE];

	/* --- Cold Section: Statistics counters and config --- */
	alignas(RTE_CACHE_LINE_SIZE)
	uint16_t dequeue_depth;
	uint16_t enqueue_depth;
	struct slb_queue *single_linked_q;
	uint64_t flow_migrations;
	uint64_t migrations_in;
	uint64_t migrations_out;
	uint64_t last_migrated_time;
	uint64_t enqueue_calls;
	uint64_t new_enqueued;
	uint64_t forward_enqueued;
	uint64_t release_enqueued;
	uint64_t dequeue_calls;
	uint64_t dequeued;
	uint64_t empty_dequeues;
	uint64_t total_dequeues;
	uint64_t queue_enqueued[SLB_MAX_QUEUES];
	uint64_t queue_dequeued[SLB_MAX_QUEUES];
};

struct slb_queue {
	uint8_t schedule_type;
	bool is_single_link;
	uint16_t num_serving_ports;
	uint64_t serving_ports_mask;
	alignas(RTE_CACHE_LINE_SIZE) struct rte_event_ring *q_ring;
	/* Per-port rings for atomic queues */
	struct rte_event_ring *per_port_rings[SLB_MAX_PORTS];
	/* For atomic queues (dynamically allocated) */
	struct slb_atomic_state *atomic_state;
	/* For ordered queues (dynamically allocated) */
	struct slb_reorder_entry *reorder_buffer;
	uint32_t reorder_drain_idx;
	rte_spinlock_t reorder_lock;
};

/* Limited by the size of 64-bit port and queue bitmasks */
static_assert(SLB_MAX_PORTS <= 64, "Max compile-time port count exceeded");
static_assert(SLB_MAX_QUEUES <= 64, "Max compile-time queue count exceeded");

struct slb_evdev {
	struct rte_eventdev_data *data;

	struct slb_port ports[SLB_MAX_PORTS];
	uint16_t num_ports;
	struct slb_queue queues[SLB_MAX_QUEUES];
	uint8_t num_queues;
	int32_t max_inflight;
	uint64_t migration_cooldown_cycles;

	alignas(RTE_CACHE_LINE_SIZE) RTE_ATOMIC(int32_t) credits_on_loan;
};

uint16_t slb_event_enqueue_burst(void *port,
				 const struct rte_event events[],
				 uint16_t events_len);
uint16_t slb_event_enqueue_new_burst(void *port,
				     const struct rte_event events[],
				     uint16_t events_len);
uint16_t slb_event_enqueue_forward_burst(void *port,
					 const struct rte_event events[],
					 uint16_t events_len);

uint16_t slb_event_dequeue_burst(void *port, struct rte_event *events,
				 uint16_t num, uint64_t wait);

void slb_port_return_credits(struct slb_evdev *slb, struct slb_port *port,
			     int32_t credits);

void slb_reorder_drain(struct slb_evdev *slb, struct slb_queue *queue);

void slb_dump(struct rte_eventdev *dev, FILE *f);

int slb_xstats_get_names(const struct rte_eventdev *dev,
			 enum rte_event_dev_xstats_mode mode,
			 uint8_t queue_port_id,
			 struct rte_event_dev_xstats_name *xstats_names,
			 uint64_t *ids, unsigned int capacity);
int slb_xstats_get(const struct rte_eventdev *dev,
		   enum rte_event_dev_xstats_mode mode, uint8_t queue_port_id,
		   const uint64_t ids[], uint64_t values[], unsigned int n);
uint64_t slb_xstats_get_by_name(const struct rte_eventdev *dev,
				const char *name, uint64_t *id);

int test_slb_eventdev(void);

static inline struct slb_evdev *
slb_pmd_priv(const struct rte_eventdev *eventdev)
{
	return eventdev->data->dev_private;
}

extern int event_slb_logtype;
#define RTE_LOGTYPE_EVENT_SLB event_slb_logtype
#define SLB_LOG_LINE(level, ...) \
	RTE_LOG_LINE(level, EVENT_SLB, __VA_ARGS__)
#define SLB_LOG_DP_LINE(level, fmt, ...)				\
	RTE_LOG_DP_LINE(level, EVENT_SLB, "%s() line %u: " fmt,		\
		   __func__, __LINE__, ## __VA_ARGS__)

#define SLB_LOG_DP_PORT_LINE(level, port_id, fmt, ...)			\
	SLB_LOG_DP_LINE(level, "<Port %d> " fmt, port_id, ## __VA_ARGS__)

#endif /* _SLB_EVDEV_H_ */

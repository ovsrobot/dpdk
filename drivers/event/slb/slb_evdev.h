/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Pravin Pathak <pravin.pathak.dev@gmail.com>
 */

#ifndef _SLB_EVDEV_H_
#define _SLB_EVDEV_H_

#include <rte_bitops.h>
#include <rte_bitset.h>
#include <rte_event_ring.h>
#include <rte_eventdev.h>
#include <rte_stdatomic.h>
#include <eventdev_pmd.h>

#define SLB_PMD_NAME RTE_STR(event_slb)

#define SLB_MAX_PORTS (64)
#define SLB_MAX_PORT_DEQUEUE_DEPTH (128)
#define SLB_MAX_PORT_ENQUEUE_DEPTH (128)

#define SLB_MAX_QUEUES (64)

#define SLB_MAX_EVENTS (16384)

#define SLB_MAX_FLOWS_BITS (16)
#define SLB_MAX_FLOWS (1 << (SLB_MAX_FLOWS_BITS))
#define SLB_MAX_FLOWS_MASK (SLB_MAX_FLOWS - 1)

/* Avoid making small 'loans' from the central in-flight event credit pool */
#define SLB_MIN_CREDIT_LOAN (512)
#define SLB_PORT_MAX_CREDITS (2 * SLB_MIN_CREDIT_LOAN)
#define SLB_PORT_MIN_CREDITS (SLB_MIN_CREDIT_LOAN)

#define SLB_IN_RING_SIZE (SLB_MAX_EVENTS)

/* Maximum number of queues that can be linked to a port per priority */
#define SLB_PORT_MAX_Q_MAP_PER_PRIO (SLB_MAX_QUEUES)
/* Number of priority levels supported by SLB. Configure 1..4. */
#ifndef SLB_MAX_PRIORITIES
#define SLB_MAX_PRIORITIES 2
#endif

#if (SLB_MAX_PRIORITIES < 1) || (SLB_MAX_PRIORITIES > 4)
#error "SLB_MAX_PRIORITIES must be between 1 and 4"
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

struct __rte_cache_aligned slb_port {
	/* --- Cacheline 0: Hot Rx & Tx scheduling control (64 bytes) --- */
	uint16_t id;
	int32_t inflight_credits;
	int32_t new_event_threshold;
	RTE_ATOMIC(uint64_t) active_queues;
	uint16_t num_q[SLB_MAX_PRIORITIES];
	uint16_t next_q[SLB_MAX_PRIORITIES];
	bool is_single_linked;
	bool implicit_release;
	bool credits_drained;
	bool remap_input_q;
	uint8_t pad_port[4];
	struct rte_event_ring *single_linked_ring;
	struct slb_evdev *slb;

	/* --- Cachelines 1..6: Pre-resolved queue mappings for dequeue --- */
	alignas(RTE_CACHE_LINE_SIZE)
	struct slb_port_q_entry q_entries[SLB_MAX_PRIORITIES][SLB_PORT_MAX_Q_MAP_PER_PRIO];

	/* --- Cold Section: Statistics counters and config --- */
	alignas(RTE_CACHE_LINE_SIZE)
	uint16_t dequeue_depth;
	uint16_t enqueue_depth;
	struct slb_queue *single_linked_q;
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
};

/* Limited by the size of 'serving_ports_mask' and 'active_queues' bitmasks */
static_assert(SLB_MAX_PORTS <= 64, "Max compile-time port count exceeded");
static_assert(SLB_MAX_QUEUES <= 64, "Max compile-time queue count exceeded");

struct slb_evdev {
	struct rte_eventdev_data *data;

	struct slb_port ports[SLB_MAX_PORTS];
	uint16_t num_ports;
	struct slb_queue queues[SLB_MAX_QUEUES];
	uint8_t num_queues;
	int32_t max_inflight;

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

void slb_dump(struct rte_eventdev *dev, FILE *f);

static inline struct slb_evdev *
slb_pmd_priv(const struct rte_eventdev *eventdev)
{
	return eventdev->data->dev_private;
}

extern int event_slb_logtype;
#define RTE_LOGTYPE_EVENT_SLB event_slb_logtype
#define SLB_LOG_DP_LINE(level, fmt, ...)				\
	RTE_LOG_DP_LINE(level, EVENT_SLB, "%s() line %u: " fmt,		\
		   __func__, __LINE__, ## __VA_ARGS__)

#define SLB_LOG_DP_PORT_LINE(level, port_id, fmt, ...)			\
	SLB_LOG_DP_LINE(level, "<Port %d> " fmt, port_id, ## __VA_ARGS__)

/* Obtain serving port masks for the specified queue and set corresponding
 * active queue bits for all served ports.
 */
static inline void
slb_port_wakeup_queues(struct slb_evdev *slb, struct slb_queue *queue)
{
	uint8_t queue_id = queue - slb->queues;
	uint64_t port_mask = queue->serving_ports_mask;
	struct slb_port *port;
	uint8_t port_id;

	while (port_mask) {
		port_id = rte_ctz64(port_mask);
		port = &slb->ports[port_id];
		rte_atomic_fetch_or_explicit(&port->active_queues,
					     (1ULL << queue_id),
					     rte_memory_order_release);
		port_mask &= ~(1ULL << port_id);
	}
}

#endif /* _SLB_EVDEV_H_ */

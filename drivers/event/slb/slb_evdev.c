/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Pravin Pathak <pravin.pathak.dev@gmail.com>
 */

#include <stdbool.h>
#include <inttypes.h>
#include <rte_bitops.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_ring_elem.h>
#include <rte_errno.h>
#include <rte_stdatomic.h>
#include <eventdev_pmd.h>
#include <eventdev_pmd_vdev.h>

#include "slb_evdev.h"

#define EVENTDEV_NAME_SLB_PMD event_slb

/* Reset history tracking table for a port.
 * Token 0 is reserved for parallel and single-link events without history.
 * Tokens 1 to 255 (255 total) are available for ordered and atomic queue events.
 */
static void
slb_port_reset_history(struct slb_port *port)
{
	port->history[0].active = false;
	port->history[0].next_free = SLB_PORT_HISTORY_FREE_END;
	/* 1 -> 2 -> 3 ..... 255 -> END */
	for (int i = 1; i < SLB_PORT_HISTORY_SIZE; i++) {
		port->history[i].active = false;
		port->history[i].next_free = i + 1;
	}
	port->history[SLB_PORT_HISTORY_SIZE - 1].next_free =
		SLB_PORT_HISTORY_FREE_END;
	port->history_head = 1;
	port->history_avail = SLB_PORT_HISTORY_MAX_TOKENS;
}

/* Setup Eventdev port. Reset all mapped queues and history tracking */
static int
slb_port_setup(struct rte_eventdev *dev, uint8_t port_id,
	       const struct rte_event_port_conf *conf)
{
	struct slb_evdev *slb = slb_pmd_priv(dev);
	struct slb_port *port;
	bool implicit_release;
	uint16_t deq_depth;
	uint16_t enq_depth;

	port = &slb->ports[port_id];

	implicit_release =
	    !(conf->event_port_cfg & RTE_EVENT_PORT_CFG_DISABLE_IMPL_REL);

	deq_depth = conf->dequeue_depth;
	if (deq_depth == 0 || deq_depth > SLB_MAX_PORT_DEQUEUE_DEPTH)
		deq_depth = SLB_MAX_PORT_DEQUEUE_DEPTH;

	enq_depth = conf->enqueue_depth;
	if (enq_depth == 0 || enq_depth > SLB_MAX_PORT_ENQUEUE_DEPTH)
		enq_depth = SLB_MAX_PORT_ENQUEUE_DEPTH;

	*port = (struct slb_port) {
		.id = port_id,
		.slb = slb,
		.dequeue_depth = deq_depth,
		.enqueue_depth = enq_depth,
		.new_event_threshold = conf->new_event_threshold,
		.implicit_release = implicit_release,
		.is_single_linked = conf->event_port_cfg &
				   RTE_EVENT_PORT_CFG_SINGLE_LINK,
		.inflight_credits = 0,
		.credits_drained = false,
		.total_dequeues = 0,
		.empty_dequeues = 0,
		.pending_releases = 0,
		.is_loaded = false,
		.single_linked_q = NULL,
		.single_linked_ring = NULL,
		.flow_migrations = 0,
		.migrations_in = 0,
		.migrations_out = 0,
		.last_migrated_time = 0,
	};

	dev->data->ports[port_id] = port;

	/* Reset all queues mapped to this port */
	for (int p = 0; p < SLB_MAX_PRIORITIES; p++) {
		port->next_q[p] = 0;
		port->num_q[p] = 0;
		memset(port->q_entries[p], 0, sizeof(port->q_entries[p]));
	}

	slb_port_reset_history(port);

	return 0;
}

/* Default Eventdev port configuration for SLB */
static void
slb_port_def_conf(struct rte_eventdev *dev,
		  uint8_t port_id __rte_unused,
		  struct rte_event_port_conf *port_conf)
{
	int32_t threshold = SLB_IN_RING_SIZE / 4;

	if (dev->data->dev_conf.nb_events_limit > 0 &&
	    threshold > dev->data->dev_conf.nb_events_limit)
		threshold = dev->data->dev_conf.nb_events_limit;

	*port_conf = (struct rte_event_port_conf) {
		.new_event_threshold = threshold,
		.dequeue_depth = SLB_MAX_PORT_DEQUEUE_DEPTH / 4,
		.enqueue_depth = SLB_MAX_PORT_ENQUEUE_DEPTH / 4
	};
}

static void
slb_port_release(void *p __rte_unused)
{
}

/* Called to free queue resources on device close or reconfiguration */
static void
slb_queue_release(struct rte_eventdev *dev, uint8_t queue_id)
{
	struct slb_evdev *slb = slb_pmd_priv(dev);
	struct slb_queue *queue = &slb->queues[queue_id];

	if (queue->atomic_state) {
		rte_free(queue->atomic_state);
		queue->atomic_state = NULL;
	}
	if (queue->reorder_buffer) {
		rte_free(queue->reorder_buffer);
		queue->reorder_buffer = NULL;
	}
	if (queue->q_ring) {
		rte_event_ring_free(queue->q_ring);
		queue->q_ring = NULL;
	}
	for (int i = 0; i < SLB_MAX_PORTS; i++) {
		if (queue->per_port_rings[i]) {
			rte_event_ring_free(queue->per_port_rings[i]);
			queue->per_port_rings[i] = NULL;
		}
	}
}

/* Setup Eventdev queue. Eventdev queues are implemented as DPDK rings.
 *  SLB Supports single-link, atomic, parallel, and ordered queues.
 */
static int
slb_queue_setup(struct rte_eventdev *dev, uint8_t queue_id,
		const struct rte_event_queue_conf *conf)
{
	struct slb_evdev *slb = slb_pmd_priv(dev);
	struct slb_queue *queue = &slb->queues[queue_id];
	struct rte_event_ring *ring;
	char ring_name[RTE_RING_NAMESIZE];
	uint32_t q_size = (slb->max_inflight > 0) ?
			  (uint32_t)slb->max_inflight : SLB_IN_RING_SIZE;

	/* Release existing queue resources if reconfiguring */
	slb_queue_release(dev, queue_id);

	snprintf(ring_name, sizeof(ring_name), "slb%d_q%u", dev->data->dev_id,
		 queue_id);

	if (conf->event_queue_cfg & RTE_EVENT_QUEUE_CFG_SINGLE_LINK) {
		/* MP -> SC ring for single-link queues */
		queue->is_single_link = true;
		ring = rte_event_ring_create(ring_name, q_size,
			dev->data->socket_id, RING_F_SC_DEQ | RING_F_EXACT_SZ);
	} else if (conf->schedule_type == RTE_SCHED_TYPE_ATOMIC) {
		/* MP -> SC ring for atomic queues main ring */
		queue->is_single_link = false;
		ring = rte_event_ring_create(ring_name, q_size,
			dev->data->socket_id, RING_F_SC_DEQ | RING_F_EXACT_SZ);
	} else if (conf->schedule_type == RTE_SCHED_TYPE_PARALLEL ||
		   conf->schedule_type == RTE_SCHED_TYPE_ORDERED) {
		/* MP -> MC ring for parallel or ordered queues */
		queue->is_single_link = false;
		ring = rte_event_ring_create(ring_name, q_size,
			dev->data->socket_id, RING_F_EXACT_SZ);
	} else {
		SLB_LOG_DP_LINE(ERR, "Unsupported schedule_type %u",
				conf->schedule_type);
		return -ENOTSUP;
	}

	if (ring == NULL)
		return -ENOMEM;

	queue->q_ring = ring;
	queue->schedule_type = conf->schedule_type;
	queue->serving_ports_mask = 0;
	queue->num_serving_ports = 0;

	/* Atomic queue state allocation */
	if (!queue->is_single_link &&
	    conf->schedule_type == RTE_SCHED_TYPE_ATOMIC) {
		for (int i = 0; i < SLB_MAX_PORTS; i++)
			queue->per_port_rings[i] = NULL;

		queue->atomic_state = rte_zmalloc_socket("slb_atomic_state",
			sizeof(struct slb_atomic_state),
			RTE_CACHE_LINE_SIZE, dev->data->socket_id);
		if (queue->atomic_state == NULL) {
			rte_event_ring_free(ring);
			return -ENOMEM;
		}
		for (int i = 0; i < SLB_ATOMIC_FLOWS; i++)
			rte_atomic_store_explicit(
				&queue->atomic_state->flow_map.flows[i].port_id,
				-1, rte_memory_order_relaxed);
		queue->atomic_state->next_port_rr = 0;
		rte_spinlock_init(&queue->atomic_state->refill_lock);
		queue->atomic_state->hold_count = 0;
		queue->atomic_state->migration.in_progress = false;
		queue->atomic_state->migrations_count = 0;
		memset(queue->atomic_state->port_stats, 0,
		       sizeof(queue->atomic_state->port_stats));
		memset(queue->atomic_state->flow_last_migrated, 0,
		       sizeof(queue->atomic_state->flow_last_migrated));
	} else {
		queue->atomic_state = NULL;
	}

	/* Ordered queue reorder buffer allocation */
	if (!queue->is_single_link &&
	    conf->schedule_type == RTE_SCHED_TYPE_ORDERED) {
		queue->reorder_buffer = rte_zmalloc_socket("slb_reorder_buf",
			sizeof(struct slb_reorder_entry) * ring->r.size,
			RTE_CACHE_LINE_SIZE, dev->data->socket_id);
		if (queue->reorder_buffer == NULL) {
			rte_event_ring_free(ring);
			return -ENOMEM;
		}
		queue->reorder_drain_idx = 0;
		rte_spinlock_init(&queue->reorder_lock);
	} else {
		queue->reorder_buffer = NULL;
	}

	return 0;
}

/* Settings for default Eventdev queue configuration */
static void
slb_queue_def_conf(struct rte_eventdev *dev __rte_unused,
		   uint8_t queue_id __rte_unused,
		   struct rte_event_queue_conf *queue_conf)
{
	*queue_conf = (struct rte_event_queue_conf) {
		.nb_atomic_flows = 4096,
		.schedule_type = RTE_SCHED_TYPE_PARALLEL,
		.priority = RTE_EVENT_DEV_PRIORITY_NORMAL
	};
}

static void
slb_port_unlink_queue_from_prio(struct slb_port *port, int prio, int slot)
{
	/* Shift the queue entries to overwriting the unlinked queue slot */
	for (int k = slot; k < port->num_q[prio] - 1; k++)
		port->q_entries[prio][k] = port->q_entries[prio][k + 1];

	/* Decrement mapped queue count and Clear the last slot after shifting */
	port->num_q[prio]--;
	memset(&port->q_entries[prio][port->num_q[prio]], 0,
	       sizeof(struct slb_port_q_entry));
	/* Adjust the next queue index if it points beyond the new count */
	if (port->next_q[prio] >= port->num_q[prio])
		port->next_q[prio] = 0;
}

/* Find the slot of a queue in a specific priority level, returning -1 if not found */
static int
slb_port_find_queue_slot(struct slb_port *port, int prio, uint8_t qid)
{
	for (int s = 0; s < port->num_q[prio]; s++) {
		if (port->q_entries[prio][s].queue_id == qid)
			return s;
	}
	return -1;
}

/* Link a queue to a port at a specific priority level */
static int
slb_port_link_one(struct slb_port *port, struct slb_queue *queue,
		  uint8_t qid, uint8_t app_prio, bool has_prio)
{
	struct rte_event_ring *dq_ring;
	uint16_t slot;
	int prio;

	if (port->is_single_linked) {
		/* Only a single-link queue can be linked to a single-linked port */
		if (!queue->is_single_link) {
			rte_errno = EINVAL;
			return -EINVAL;
		}
		/* Only one queue can be linked to a single-linked port */
		if (port->single_linked_q != NULL) {
			if (port->single_linked_q == queue)
				return 0;
			rte_errno = EINVAL;
			return -EINVAL;
		}
		/* A single-link queue can only be linked to one port */
		if (queue->serving_ports_mask != 0) {
			rte_errno = EINVAL;
			return -EINVAL;
		}
		port->single_linked_q = queue;
		port->single_linked_ring = queue->q_ring;
	} else {
		/* A single-link queue cannot be linked to a regular port */
		if (queue->is_single_link) {
			rte_errno = EINVAL;
			return -EINVAL;
		}

		/* Convert application priority to internal priority level (0 or 1) */
		if (has_prio)
			prio = (app_prio < RTE_EVENT_DEV_PRIORITY_NORMAL) ? 0 : 1;
		else
			prio = SLB_MAX_PRIORITIES - 1;

		/* Check if queue is already mapped to this port at requested priority */
		for (int pr = 0; pr < SLB_MAX_PRIORITIES; pr++) {
			if (slb_port_find_queue_slot(port, pr, qid) >= 0) {
				if (pr == prio)
					return 0;
				rte_errno = EINVAL;
				return -EINVAL;
			}
		}

		/* Ensure a free mapping slot is available at the requested priority */
		slot = port->num_q[prio];
		if (slot >= SLB_PORT_MAX_Q_MAP_PER_PRIO) {
			rte_errno = ENOSPC;
			return -ENOSPC;
		}

		/* Allocate per-port ring when linking an atomic queue */
		if (queue->schedule_type == RTE_SCHED_TYPE_ATOMIC &&
		    queue->per_port_rings[port->id] == NULL) {
			char ring_name[RTE_RING_NAMESIZE];
			struct rte_event_ring *ring;

			snprintf(ring_name, sizeof(ring_name),
				 "slb%d_q%u_p%u", port->slb->data->dev_id,
				 qid, port->id);
			ring = rte_event_ring_create(
				ring_name,
				SLB_MAX_PORT_DEQUEUE_DEPTH * 4,
				port->slb->data->socket_id,
				RING_F_SP_ENQ | RING_F_SC_DEQ);
			if (ring == NULL) {
				rte_errno = ENOMEM;
				return -ENOMEM;
			}
			queue->per_port_rings[port->id] = ring;
		}

		dq_ring = (queue->schedule_type == RTE_SCHED_TYPE_ATOMIC) ?
			  queue->per_port_rings[port->id] : queue->q_ring;

		port->q_entries[prio][slot].dq_ring = dq_ring;
		port->q_entries[prio][slot].queue = queue;
		port->q_entries[prio][slot].queue_id = qid;
		port->q_entries[prio][slot].schedule_type = queue->schedule_type;
		port->num_q[prio]++;
	}

	/* Add newly linked port to the queue's serving ports mask */
	queue->serving_ports_mask |= (1ULL << port->id);
	queue->num_serving_ports = rte_popcount64(queue->serving_ports_mask);
	return 0;
}

/* Unlink a queue from a port */
static int
slb_port_unlink_one(struct slb_port *port, struct slb_queue *queue, uint8_t qid)
{
	bool found = false;

	if (port->is_single_linked) {
		if (port->single_linked_q != queue) {
			rte_errno = EINVAL;
			return -EINVAL;
		}
		port->single_linked_q = NULL;
		port->single_linked_ring = NULL;
	} else { /* Unlink queue by finding its slot */
		for (int prio = 0; prio < SLB_MAX_PRIORITIES; prio++) {
			int s = slb_port_find_queue_slot(port, prio, qid);

			if (s >= 0) {
				slb_port_unlink_queue_from_prio(port, prio, s);
				found = true;
				break;
			}
		}
		if (!found) { /* No link found */
			rte_errno = EINVAL;
			return -EINVAL;
		}

		/* For atomic queues, free the per-port ring if it exists */
		if (queue->schedule_type == RTE_SCHED_TYPE_ATOMIC &&
		    queue->per_port_rings[port->id] != NULL) {
			rte_event_ring_free(queue->per_port_rings[port->id]);
			queue->per_port_rings[port->id] = NULL;
		}
	}

	queue->serving_ports_mask &= ~(1ULL << port->id);
	queue->num_serving_ports = rte_popcount64(queue->serving_ports_mask);
	return 0;
}

/* Link all queues to a port at specific priorities */
static int
slb_port_link(struct rte_eventdev *dev, void *p, const uint8_t queues[],
	      const uint8_t priorities[], uint16_t num)
{
	struct slb_port *port = p;
	struct slb_evdev *slb = slb_pmd_priv(dev);
	uint16_t i;

	for (i = 0; i < num; i++) {
		uint8_t qid = queues[i];
		struct slb_queue *queue = &slb->queues[qid];
		uint8_t prio = (priorities != NULL) ? priorities[i] : 0;
		int ret = slb_port_link_one(port, queue, qid, prio,
					    priorities != NULL);

		if (ret < 0)
			return i;
	}
	return num;
}

/* Unlink all queues from a port */
static int
slb_port_unlink(struct rte_eventdev *dev, void *p, uint8_t queues[],
		uint16_t num)
{
	struct slb_port *port = p;
	struct slb_evdev *slb = slb_pmd_priv(dev);
	uint16_t i;

	for (i = 0; i < num; i++) {
		uint8_t qid = queues[i];
		struct slb_queue *queue = &slb->queues[qid];
		int ret = slb_port_unlink_one(port, queue, qid);

		if (ret < 0)
			return i;
	}
	return num;
}

/* Get information about the event device */
static void
slb_info_get(struct rte_eventdev *dev __rte_unused,
	     struct rte_event_dev_info *info)
{
	*info = (struct rte_event_dev_info) {
		.driver_name = SLB_PMD_NAME,
		.max_event_queues = SLB_MAX_QUEUES,
		.max_event_queue_flows = SLB_MAX_FLOWS,
		.max_event_queue_priority_levels = SLB_MAX_PRIORITIES,
		.max_event_priority_levels = 1,
		.max_event_ports = SLB_MAX_PORTS,
		.max_event_port_dequeue_depth = SLB_MAX_PORT_DEQUEUE_DEPTH,
		.max_event_port_enqueue_depth = SLB_MAX_PORT_ENQUEUE_DEPTH,
		.max_num_events = SLB_MAX_EVENTS,
		.max_profiles_per_port = 1,
		.event_dev_cap = RTE_EVENT_DEV_CAP_BURST_MODE |
		RTE_EVENT_DEV_CAP_PARALLEL |
		RTE_EVENT_DEV_CAP_ATOMIC |
		RTE_EVENT_DEV_CAP_ORDERED |
		RTE_EVENT_DEV_CAP_DISTRIBUTED_SCHED |
		RTE_EVENT_DEV_CAP_IMPLICIT_RELEASE_DISABLE |
		RTE_EVENT_DEV_CAP_NONSEQ_MODE |
		RTE_EVENT_DEV_CAP_MULTIPLE_QUEUE_PORT |
		RTE_EVENT_DEV_CAP_CARRY_FLOW_ID |
		RTE_EVENT_DEV_CAP_MAINTENANCE_FREE |
		RTE_EVENT_DEV_CAP_INDEPENDENT_ENQ
	};
}

/* Configure the event device */
static int
slb_configure(const struct rte_eventdev *dev)
{
	struct slb_evdev *slb = slb_pmd_priv(dev);
	const struct rte_event_dev_config *conf = &dev->data->dev_conf;
	int32_t min_max_in_flight;

	if (conf->nb_events_limit <= 0 ||
	    conf->nb_events_limit > SLB_MAX_EVENTS) {
		SLB_LOG_DP_LINE(INFO,
			"nb_events_limit (%d) invalid, max is %d",
			conf->nb_events_limit, SLB_MAX_EVENTS);
		return -EINVAL;
	}

	/* Validate max event ports and queues that SLB can support */
	if (conf->nb_event_ports == 0 ||
	    conf->nb_event_ports > SLB_MAX_PORTS) {
		SLB_LOG_DP_LINE(INFO,
			"nb_event_ports (%u) invalid, max is %d",
			conf->nb_event_ports, SLB_MAX_PORTS);
		return -EINVAL;
	}

	if (conf->nb_event_queues == 0 ||
	    conf->nb_event_queues > SLB_MAX_QUEUES) {
		SLB_LOG_DP_LINE(INFO,
			"nb_event_queues (%u) invalid, max is %d",
			conf->nb_event_queues, SLB_MAX_QUEUES);
		return -EINVAL;
	}

	slb->num_ports = conf->nb_event_ports;
	slb->num_queues = conf->nb_event_queues;

	/* Compute minimum credits required to avoid deadlock */
	min_max_in_flight = conf->nb_event_ports * SLB_PORT_MAX_CREDITS;
	if (min_max_in_flight > SLB_MAX_EVENTS)
		min_max_in_flight = SLB_MAX_EVENTS;

	/* Set credit pool size to max of nb_events_limit and minimum required to avoid deadlock */
	slb->max_inflight = RTE_MAX(conf->nb_events_limit, min_max_in_flight);
	slb->migration_cooldown_cycles =
		(rte_get_timer_hz() * SLB_MIGRATION_COOLDOWN_MS) / 1000;
	return 0;
}

/* Start the event device */
static int
slb_start(struct rte_eventdev *dev)
{
	struct slb_evdev *slb = slb_pmd_priv(dev);

	/* Make sure all queues are set up and have at least one linked port */
	for (int i = 0; i < slb->num_queues; i++) {
		if (slb->queues[i].q_ring == NULL ||
		    slb->queues[i].serving_ports_mask == 0) {
			SLB_LOG_DP_LINE(ERR,
				"Queue %d is not configured or has no linked ports",
				i);
			return -ENOLINK;
		}
	}

	/* No events in flight */
	rte_atomic_store_explicit(&slb->credits_on_loan, 0,
				  rte_memory_order_relaxed);

	/* Reset port states */
	for (int i = 0; i < slb->num_ports; i++) {
		struct slb_port *port = &slb->ports[i];
		port->inflight_credits = 0;
		port->credits_drained = false;
		for (int p = 0; p < SLB_MAX_PRIORITIES; p++)
			port->next_q[p] = 0;
	}

	return 0;
}

/* Empty the event queue */
static void
slb_drain_ring(uint8_t dev_id, struct rte_event_ring *ring,
	       eventdev_stop_flush_t flush, void *flush_arg)
{
	struct rte_event ev;

	if (ring == NULL)
		return;

	/* Dequeue all events from the ring and call user callback if provided */
	while (rte_event_ring_dequeue_burst(ring, &ev, 1, NULL)) {
		if (flush != NULL)
			flush(dev_id, ev, flush_arg);
	}
	rte_ring_reset(&ring->r);
}

/* Stop the event device */
static void
slb_stop(struct rte_eventdev *dev)
{
	struct slb_evdev *slb = slb_pmd_priv(dev);
	uint8_t dev_id = dev->data->dev_id;
	eventdev_stop_flush_t flush = dev->dev_ops->dev_stop_flush;
	void *flush_arg = dev->data->dev_stop_flush_arg;

	for (uint8_t qid = 0; qid < slb->num_queues; qid++) {
		struct slb_queue *q = &slb->queues[qid];

		if (q->schedule_type == RTE_SCHED_TYPE_ATOMIC &&
		    q->atomic_state != NULL) {
			struct slb_atomic_state *astate = q->atomic_state;

			/* Call user callback for each held event */
			for (uint16_t h = 0; h < astate->hold_count; h++) {
				if (flush != NULL)
					flush(dev_id, astate->hold_buffer[h],
					      flush_arg);
			}
			astate->hold_count = 0;
			astate->next_port_rr = 0;
			astate->migration.in_progress = false;

			/* Reset flow to port mapping */
			for (int f = 0; f < SLB_ATOMIC_FLOWS; f++) {
				rte_atomic_store_explicit(
					&astate->flow_map.flows[f].port_id,
					-1, rte_memory_order_relaxed);
				astate->flow_last_migrated[f] = 0;
			}

			memset(astate->port_stats, 0,
			       sizeof(astate->port_stats));

			/* Drain all events from per-port rings */
			for (uint16_t pid = 0; pid < slb->num_ports; pid++) {
				if (q->per_port_rings[pid] != NULL)
					slb_drain_ring(dev_id,
						       q->per_port_rings[pid],
						       flush, flush_arg);
			}
		} else if (q->schedule_type == RTE_SCHED_TYPE_ORDERED &&
			   q->reorder_buffer != NULL && q->q_ring != NULL) {
			for (uint32_t s = 0; s < q->q_ring->r.size; s++) {
				uint8_t st = rte_atomic_load_explicit(
					&q->reorder_buffer[s].state,
					rte_memory_order_relaxed);
				/* Flush all ready events from the reorder buffer. */
				if (st == SLB_REORDER_READY && flush != NULL)
					flush(dev_id,
					      q->reorder_buffer[s].event,
					      flush_arg);
				/* Mark freed slot as empty */
				rte_atomic_store_explicit(
					&q->reorder_buffer[s].state,
					SLB_REORDER_EMPTY,
					rte_memory_order_relaxed);
			}
			q->reorder_drain_idx = 0;
		}

		if (q->q_ring != NULL)
			slb_drain_ring(dev_id, q->q_ring, flush, flush_arg);
	}

	/* Reset each port's state, history lists and queue mappings */
	for (int i = 0; i < slb->num_ports; i++) {
		struct slb_port *port = &slb->ports[i];
		port->inflight_credits = 0;
		port->credits_drained = false;
		port->pending_releases = 0;
		port->is_loaded = false;
		port->last_migrated_time = 0;
		slb_port_reset_history(port);
		for (int p = 0; p < SLB_MAX_PRIORITIES; p++)
			port->next_q[p] = 0;
	}

	/* Reset the credit pool to all available */
	rte_atomic_store_explicit(&slb->credits_on_loan, 0,
				  rte_memory_order_relaxed);
}

/* Close the event device */
static int
slb_close(struct rte_eventdev *dev)
{
	struct slb_evdev *slb = slb_pmd_priv(dev);

	/* Release all resources acquired by the queues */
	for (int i = 0; i < slb->num_queues; i++)
		slb_queue_release(dev, i);

	return 0;
}

/* Dump the event device current state and statistics */
void
slb_dump(struct rte_eventdev *dev, FILE *f)
{
	struct slb_evdev *slb = slb_pmd_priv(dev);
	int32_t pool_on_loan, pool_avail;
	uint64_t total_mig_in = 0, total_mig_out = 0;
	int i;

	if (dev == NULL || f == NULL)
		return;

	pool_on_loan = rte_atomic_load_explicit(&slb->credits_on_loan,
						rte_memory_order_relaxed);
	pool_avail = slb->max_inflight - pool_on_loan;

	fprintf(f, "\n[SLB EVENTDEV DEBUG STATS]\n");
	fprintf(f, "  Device ID: %u, Driver: %s\n", dev->data->dev_id,
		SLB_PMD_NAME);
	fprintf(f, "  Credit Pool: %d on_loan / %d max_inflight (%d available)\n",
		pool_on_loan, slb->max_inflight, pool_avail);

	fprintf(f, "\n  PORT FLOW MIGRATION COUNTERS:\n");
	for (i = 0; i < slb->num_ports; i++) {
		struct slb_port *p = &slb->ports[i];

		total_mig_in += p->migrations_in;
		total_mig_out += p->migrations_out;
		fprintf(f,
			"    Port %2u: Migrated-In: %6" PRIu64
			" | Migrated-Out: %6" PRIu64 " | Net: %+5" PRId64 "\n",
			i, p->migrations_in, p->migrations_out,
			(int64_t)p->migrations_in - (int64_t)p->migrations_out);
	}
	fprintf(f, "    Total Flow Migrations: IN=%" PRIu64 ", OUT=%" PRIu64 "\n",
		total_mig_in, total_mig_out);

	fprintf(f, "\n  PORT STATISTICS & QUEUE LINKAGES:\n");
	for (i = 0; i < slb->num_ports; i++) {
		struct slb_port *p = &slb->ports[i];
		int linked_count = 0;

		fprintf(f,
			"    Port %2u (credits=%3d, loaded=%d"
			", mig_in=%" PRIu64 ", mig_out=%" PRIu64 "): ",
			i, p->inflight_credits, p->is_loaded,
			p->migrations_in, p->migrations_out);

		if (p->is_single_linked) {
			if (p->single_linked_q) {
				int qid = p->single_linked_q - slb->queues;

				fprintf(f, "Q%d (single-link)", qid);
				linked_count++;
			}
		} else {
			for (int pr = 0; pr < SLB_MAX_PRIORITIES; pr++) {
				for (int s = 0; s < p->num_q[pr]; s++) {
					int qid = p->q_entries[pr][s].queue_id;

					if (linked_count > 0)
						fprintf(f, ", ");
					fprintf(f, "Q%d(p%d)", qid, pr);
					linked_count++;
				}
			}
		}
		if (linked_count == 0)
			fprintf(f, "(no queues linked)");
		fprintf(f, "\n");
		fprintf(f,
			"            stats: enq_calls=%" PRIu64
			", new_enq=%" PRIu64 ", fwd_enq=%" PRIu64
			", rel_enq=%" PRIu64 ", deq_calls=%" PRIu64
			", deq=%" PRIu64 "\n",
			p->enqueue_calls, p->new_enqueued,
			p->forward_enqueued, p->release_enqueued,
			p->dequeue_calls, p->dequeued);
	}

	fprintf(f, "\n  ALL QUEUES STATUS:\n");
	for (i = 0; i < slb->num_queues; i++) {
		struct slb_queue *q = &slb->queues[i];
		uint32_t count = rte_event_ring_count(q->q_ring);
		uint32_t ring_size = rte_event_ring_get_capacity(q->q_ring);

		fprintf(f,
			"    Queue %2u: %6u/%6u events, serving_ports=0x%016" PRIx64
			" (count=%u), sched_type=%u, single_link=%d\n",
			i, count, ring_size, q->serving_ports_mask,
			q->num_serving_ports, q->schedule_type,
			q->is_single_link);
		if (!q->is_single_link &&
		    q->schedule_type == RTE_SCHED_TYPE_ATOMIC) {
			if (q->atomic_state) {
				fprintf(f,
					"      Atomic State: total_migrations=%" PRIu64
					", hold_count=%u\n",
					q->atomic_state->migrations_count,
					q->atomic_state->hold_count);
				if (q->atomic_state->migration.in_progress) {
					fprintf(f,
						"      MIGRATION IN PROGRESS: from port %u, flow_idx=%u\n",
						q->atomic_state->migration.port_id,
						q->atomic_state->migration.flow_idx);
				}
				for (int j = 0; j < slb->num_ports; j++) {
					if (q->per_port_rings[j]) {
						struct slb_atomic_port_stats *ps =
							&q->atomic_state->port_stats[j];

						fprintf(f,
							"      Per-port ring %d: %u events"
							" (load_counter=%u, flows=%u,"
							" enq=%" PRIu64 ", ret=%" PRIu64 ")\n",
							j,
							rte_event_ring_count(q->per_port_rings[j]),
							ps->load_counter,
							ps->flow_count,
							ps->q_enqueued,
							ps->q_returned);
					}
				}
			}
		} else if (!q->is_single_link &&
			   q->schedule_type == RTE_SCHED_TYPE_ORDERED) {
			fprintf(f, "      Ordered reorder_drain_idx=%u\n",
				q->reorder_drain_idx);
		}
		if (count > 0 && q->serving_ports_mask == 0)
			fprintf(f,
				"      ^^^ PROBLEM: Queue has %u events but serving_ports_mask=0!\n",
				count);
		if (count == 0 && q->serving_ports_mask == 0)
			fprintf(f, "      (unused queue)\n");
	}
	fprintf(f, "[END DEBUG]\n\n");
	fflush(f);
}

static struct eventdev_ops slb_evdev_ops = {
	.port_setup = slb_port_setup,
	.port_def_conf = slb_port_def_conf,
	.port_release = slb_port_release,
	.queue_setup = slb_queue_setup,
	.queue_def_conf = slb_queue_def_conf,
	.queue_release = slb_queue_release,
	.port_link = slb_port_link,
	.port_unlink = slb_port_unlink,
	.dev_infos_get = slb_info_get,
	.dev_configure = slb_configure,
	.dev_start = slb_start,
	.dev_stop = slb_stop,
	.dev_close = slb_close,
	.dump = slb_dump,
	.xstats_get = slb_xstats_get,
	.xstats_get_names = slb_xstats_get_names,
	.xstats_get_by_name = slb_xstats_get_by_name,
	.dev_selftest = test_slb_eventdev,
};

static int
slb_probe(struct rte_vdev_device *vdev)
{
	const char *name = rte_vdev_device_name(vdev);
	struct rte_eventdev *dev;
	struct slb_evdev *slb;

	dev = rte_event_pmd_vdev_init(name, sizeof(struct slb_evdev),
				      rte_socket_id(), vdev);
	if (dev == NULL)
		return -EFAULT;

	dev->dev_ops = &slb_evdev_ops;
	dev->enqueue_burst = slb_event_enqueue_burst;
	dev->enqueue_new_burst = slb_event_enqueue_new_burst;
	dev->enqueue_forward_burst = slb_event_enqueue_forward_burst;
	dev->dequeue_burst = slb_event_dequeue_burst;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	slb = dev->data->dev_private;
	slb->data = dev->data;

	event_dev_probing_finish(dev);
	return 0;
}

static int
slb_remove(struct rte_vdev_device *vdev)
{
	const char *name = rte_vdev_device_name(vdev);

	if (name == NULL)
		return -EINVAL;

	return rte_event_pmd_vdev_uninit(name);
}

static struct rte_vdev_driver evdev_slb_pmd_drv = {
	.probe = slb_probe,
	.remove = slb_remove
};

RTE_PMD_REGISTER_VDEV(EVENTDEV_NAME_SLB_PMD, evdev_slb_pmd_drv);
RTE_LOG_REGISTER_DEFAULT(event_slb_logtype, NOTICE);

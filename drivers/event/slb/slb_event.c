/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Pravin Pathak <pravin.pathak.dev@gmail.com>
 */

#include <stdbool.h>
#include <limits.h>
#include <rte_bitops.h>
#include <rte_cycles.h>
#include <rte_ring_elem.h>
#include <rte_stdatomic.h>

#include "slb_evdev.h"

/* Port Acquiring credits for new events. Serve from local cache if possible. */
static bool
slb_port_acquire_credits(struct slb_evdev *slb, struct slb_port *port,
			 int32_t credits)
{
	int32_t inflight_credits = port->inflight_credits;
	int32_t remaining_credits = inflight_credits - credits;
	int32_t total_inflight;
	int32_t available;
	int32_t required_credits;
	int32_t new_total_inflight;

	/* If port has enough credits, update and return true */
	if (likely(remaining_credits >= 0)) {
		port->inflight_credits = remaining_credits;
		return true;
	}

	total_inflight = rte_atomic_load_explicit(&slb->credits_on_loan,
						  rte_memory_order_relaxed);
	available = slb->max_inflight - total_inflight;
	required_credits = RTE_MAX(abs(remaining_credits), SLB_PORT_MIN_CREDITS);

	/* Pool does not have enough credits */
	if (available < required_credits)
		return false;

	/* Take credits from the pool */
	new_total_inflight =
		rte_atomic_fetch_add_explicit(&slb->credits_on_loan,
					      required_credits,
					      rte_memory_order_relaxed) +
					      required_credits;
	/* Check if the new total exceeds the maximum allowed */
	if (unlikely(new_total_inflight > slb->max_inflight)) {
		rte_atomic_fetch_sub_explicit(&slb->credits_on_loan,
					      required_credits,
					      rte_memory_order_relaxed);
		return false;
	}
	/* Update the port's credit counts*/
	port->inflight_credits += required_credits;
	port->inflight_credits -= credits;

	return true;
}

/* Port returning credits (Terminated events). Keep local cache.
 * If local cache exceeds the threshold, return excess credits to the pool
 */
void
slb_port_return_credits(struct slb_evdev *slb, struct slb_port *port,
			int32_t credits)
{
	port->inflight_credits += credits; /* Local credit cache */

	if (unlikely(port->inflight_credits >= SLB_PORT_MAX_CREDITS)) {
		int32_t return_credits = port->inflight_credits -
					 SLB_PORT_MIN_CREDITS;
		port->inflight_credits = SLB_PORT_MIN_CREDITS;

		rte_atomic_fetch_sub_explicit(&slb->credits_on_loan,
					      return_credits,
					      rte_memory_order_release);
	}
}

/* Port enqueue statistics */
static void
slb_port_enqueue_stats(struct slb_port *port, uint16_t num_new,
		       uint16_t num_forward, uint16_t num_release)
{
	port->new_enqueued += num_new;
	port->forward_enqueued += num_forward;
	port->release_enqueued += num_release;
}

static void
slb_port_queue_enqueue_stats(struct slb_port *source_port, uint8_t queue_id)
{
	source_port->queue_enqueued[queue_id]++;
}

static void
slb_port_queue_enqueue_burst_stats(struct slb_port *source_port,
				   uint8_t queue_id, uint16_t num)
{
	source_port->queue_enqueued[queue_id] += num;
}

#define REORDER_BURST_SZ 64

/* Drain contiguous ready events from ordered queue's reorder buffer */
void
slb_reorder_drain(struct slb_evdev *slb, struct slb_queue *queue)
{
	if (queue == NULL || queue->reorder_buffer == NULL)
		return;

	/* Only one thread can drain the reorder buffer at a time */
	if (!rte_spinlock_trylock(&queue->reorder_lock))
		return;

	uint32_t drain_idx = queue->reorder_drain_idx;
	uint32_t mask = queue->q_ring->r.mask;
	struct slb_reorder_entry *buf = queue->reorder_buffer;
	uint8_t state;

	/* Drain events from the current drain index till an empty slot.
	 * Released event slots need no processing except marking them as empty.
	 */
	while ((state = rte_atomic_load_explicit(&buf[drain_idx].state,
						 rte_memory_order_acquire)) !=
	       SLB_REORDER_EMPTY) {
		if (state == SLB_REORDER_RELEASED) {
			rte_atomic_store_explicit(&buf[drain_idx].state,
						  SLB_REORDER_EMPTY,
						  rte_memory_order_relaxed);
			drain_idx = (drain_idx + 1) & mask;
			continue;
		}

		/* Gather contiguous READY events destined to same target_qid */
		struct rte_event burst[REORDER_BURST_SZ];
		uint16_t burst_size = 0;
		uint8_t target_qid = buf[drain_idx].event.queue_id;

		do {
			burst[burst_size++] = buf[drain_idx].event;
			rte_atomic_store_explicit(&buf[drain_idx].state,
						  SLB_REORDER_EMPTY,
						  rte_memory_order_relaxed);
			drain_idx = (drain_idx + 1) & mask;
		} while (burst_size < REORDER_BURST_SZ &&
			 rte_atomic_load_explicit(&buf[drain_idx].state,
						  rte_memory_order_acquire) ==
			 SLB_REORDER_READY &&
			 buf[drain_idx].event.queue_id == target_qid);

		/* Target queue is sized to max_inflight and can never be full */
		rte_event_ring_enqueue_burst(slb->queues[target_qid].q_ring,
					     burst, burst_size, NULL);
	}

	queue->reorder_drain_idx = drain_idx;
	rte_spinlock_unlock(&queue->reorder_lock);
}

/* Hash 20-bit flow ID into atomic flow slot index (SLB_ATOMIC_FLOWS) */
static inline uint32_t
slb_flow_hash(uint32_t flow_id)
{
	return (flow_id * 2654435761U) & SLB_ATOMIC_FLOWS_MASK;
}

/* Find the lightest flow on a given port to migrate */
static int32_t
slb_find_lightest_flow_on_port(struct slb_queue *queue, uint8_t port_id,
			       uint64_t now, uint64_t cooldown_cycles)
{
	struct rte_event_ring *ering = queue->per_port_rings[port_id];
	struct slb_atomic_state *astate = queue->atomic_state;
	struct rte_ring *r;
	uint32_t cons;
	uint32_t prod;
	uint32_t count;
	uint16_t counts[SLB_ATOMIC_FLOWS];
	int32_t best_flow_idx = -1;
	uint32_t min_events = UINT32_MAX;

	if (unlikely(ering == NULL || astate == NULL))
		return -1;

	if (astate->port_stats[port_id].flow_count <= 1)
		return -1;

	r = &ering->r;
	cons = rte_atomic_load_explicit(&r->cons.tail, rte_memory_order_relaxed);
	prod = rte_atomic_load_explicit(&r->prod.tail, rte_memory_order_relaxed);
	count = prod - cons; /* Number of atomic events in the per port ring */

	memset(counts, 0, sizeof(counts));
	if (count > 0) {
		/* Skip over the ring header and point to events */
		struct rte_event *ring_events = (struct rte_event *)(r + 1);

		/* Count events for each flow in per port queue */
		for (uint32_t i = 0; i < count; i++) {
			uint32_t slot = (cons + i) & r->mask;
			uint32_t f_idx = slb_flow_hash(ring_events[slot].flow_id);

			counts[f_idx]++;
		}
	}

	/* Find the flow with the minimum number of events */
	for (uint32_t f = 0; f < SLB_ATOMIC_FLOWS; f++) {
		if (rte_atomic_load_explicit(&astate->flow_map.flows[f].port_id,
					     rte_memory_order_relaxed) == (int32_t)port_id) {
			/* Skip flows that have been migrated recently */
			if (astate->flow_last_migrated[f] != 0 &&
			    (now - astate->flow_last_migrated[f]) < cooldown_cycles)
				continue;

			if (counts[f] < min_events) {
				min_events = counts[f];
				best_flow_idx = (int32_t)f;
			}
		}
	}

	return best_flow_idx;
}

/* Check if port is loaded and migration is necessary. Start the flow
 * migration processes if required.
 */
static void
slb_check_and_trigger_migration(struct slb_evdev *slb, struct slb_queue *queue,
				struct slb_atomic_state *astate, uint8_t full_port_id)
{
	struct slb_atomic_port_stats *pstats = &astate->port_stats[full_port_id];
	uint64_t cooldown_cycles = slb->migration_cooldown_cycles;
	uint64_t now;
	int32_t flow_to_migrate;

	/* Check if the port has crossed load threshold */
	pstats->load_counter++;
	if (pstats->load_counter < SLB_MIGRATION_LOAD_THRESHOLD)
		return;

	if (astate->migration.in_progress)
		return;

	/* Already marked for migration */
	if (slb->ports[full_port_id].is_loaded)
		return;

	if (pstats->flow_count <= 1) /* Not enough flows to migrate */
		return;

	now = rte_get_timer_cycles();

	/* Port is still in cooldown period */
	if (slb->ports[full_port_id].last_migrated_time != 0 &&
	    (now - slb->ports[full_port_id].last_migrated_time) < cooldown_cycles)
		return;

	/* Find flow to migrate*/
	flow_to_migrate = slb_find_lightest_flow_on_port(
		queue, full_port_id, now, cooldown_cycles);
	if (flow_to_migrate < 0)
		return;

	pstats->load_counter = 0;
	slb->ports[full_port_id].is_loaded = true;
	astate->migration.in_progress = true;
	astate->migration.port_id = full_port_id;
	astate->migration.flow_idx = (uint32_t)flow_to_migrate;
}

/* Find the target port (one with minimum flows) for flow migration */
static inline int
slb_find_migration_target_port(struct slb_evdev *slb, struct slb_queue *queue,
			       struct slb_atomic_state *astate, uint8_t mig_port,
			       uint64_t now, uint64_t cooldown_cycles)
{
	uint64_t temp_mask = queue->serving_ports_mask;
	int target_port = -1;
	int min_flows = INT_MAX;

	while (temp_mask != 0) {
		uint8_t cand_port = rte_ctz64(temp_mask);
		struct slb_port *cp = &slb->ports[cand_port];

		temp_mask &= ~(1ULL << cand_port);
		if (cand_port == mig_port || cp->is_loaded)
			continue;

		if (cp->last_migrated_time == 0 ||
		    (now - cp->last_migrated_time) >= cooldown_cycles) {
			if ((int)astate->port_stats[cand_port].flow_count < min_flows) {
				min_flows = (int)astate->port_stats[cand_port].flow_count;
				target_port = cand_port;
			}
		} else if (target_port == -1) {
			target_port = cand_port;
		}
	}
	return target_port;
}

/* Complete the flow migration process from original port to target port */
static inline void
slb_complete_flow_migration(struct slb_evdev *slb, struct slb_atomic_state *astate,
			    uint8_t mig_port, int target_port, uint64_t now)
{
	uint32_t f_idx = astate->migration.flow_idx;

	/* Switch the flow mapping to the target port */
	rte_atomic_store_explicit(&astate->flow_map.flows[f_idx].port_id,
				  target_port, rte_memory_order_release);

	/* Switch all events in hold buffer to the target port */
	for (uint16_t h = 0; h < astate->hold_count; h++) {
		if (astate->hold_ports[h] == mig_port &&
		    slb_flow_hash(astate->hold_buffer[h].flow_id) == f_idx) {
			astate->hold_ports[h] = (uint8_t)target_port;
		}
	}

	/* Update migration timestamps */
	astate->flow_last_migrated[f_idx] = now;
	slb->ports[mig_port].last_migrated_time = now;
	slb->ports[target_port].last_migrated_time = now;

	/* Update flow counts */
	if (astate->port_stats[mig_port].flow_count > 0)
		astate->port_stats[mig_port].flow_count--;
	astate->port_stats[target_port].flow_count++;
	astate->migrations_count++;

	/* Update migration counters */
	slb->ports[mig_port].flow_migrations++;
	slb->ports[mig_port].migrations_out++;
	slb->ports[target_port].migrations_in++;

	/* Mark migration as complete */
	astate->port_stats[mig_port].load_counter = 0;
	slb->ports[mig_port].is_loaded = false;
	astate->migration.in_progress = false;
}

/* Assign a port to unmapped flow */
static inline uint8_t
slb_assign_unmapped_flow_port(struct slb_evdev *slb, struct slb_atomic_state *astate,
			      uint64_t serving_mask, uint16_t num_serving_ports)
{
	uint32_t rr_counter = astate->next_port_rr++;
	int port_offset = rr_counter % num_serving_ports; /* Pick next port */
	uint64_t temp_mask = serving_mask;
	uint8_t assigned_port = 0;

	/* Convert offset to port ID */
	for (int j = 0; j <= port_offset; j++) {
		assigned_port = rte_ctz64(temp_mask);
		temp_mask &= (temp_mask - 1);
	}

	/* If next port in RR selection is loaded then find an unloaded port */
	if (slb->ports[assigned_port].is_loaded) {
		uint64_t cand_mask = serving_mask;

		while (cand_mask != 0) {
			uint8_t cp = rte_ctz64(cand_mask);

			cand_mask &= (cand_mask - 1);
			if (!slb->ports[cp].is_loaded) {
				assigned_port = cp;
				break;
			}
		}
	}
	return assigned_port;
}

/* If per port atomic queue is empty, pull events from the main atomic queue to fill
 * up all port queues. Handle migration and hold buffer processing.
 */
static void
slb_atomic_refill(struct slb_port *port, struct slb_queue *queue)
{
	struct slb_evdev *slb = port->slb;
	struct rte_event rcv_events[SLB_MAX_PORT_DEQUEUE_DEPTH];
	uint16_t n_deq;
	uint16_t i;
	uint64_t full_ports_mask = 0;
	struct slb_atomic_state *astate = queue->atomic_state;
	uint64_t serving_mask;
	uint16_t num_serving_ports;

	if (unlikely(astate == NULL))
		return;

	/* Only one thread can refill at a time */
	if (!rte_spinlock_trylock(&astate->refill_lock))
		return;

	/* 0. Handle migration in progress before hold buffer processing */
	if (astate->migration.in_progress) {
		uint8_t mig_port = astate->migration.port_id;
		uint64_t enq_cnt = astate->port_stats[mig_port].q_enqueued;
		uint64_t ret_cnt = astate->port_stats[mig_port].q_returned;

		/* Check if it is safe to migrate. i.e. no pending events */
		if (enq_cnt == ret_cnt) {
			uint64_t now = rte_get_timer_cycles();
			int target_port = slb_find_migration_target_port(
				slb, queue, astate, mig_port, now,
				slb->migration_cooldown_cycles);

			if (target_port != -1)
				slb_complete_flow_migration(
					slb, astate, mig_port, target_port, now);
			else { /* If no suitable target port found, cancel migration */
				astate->port_stats[mig_port].load_counter = 0;
				slb->ports[mig_port].is_loaded = false;
				astate->migration.in_progress = false;
			}
		}
	}

	/* Add the migration port to the full ports mask to avoid scheduling events to it */
	if (astate->migration.in_progress)
		full_ports_mask |= (1ULL << astate->migration.port_id);

	/* 1. Process Hold Buffer events */
	if (astate->hold_count > 0) {
		uint16_t retained = 0;
		uint16_t count = astate->hold_count;

		i = 0;
		while (i < count) {
			uint8_t dest_port_id = astate->hold_ports[i];
			uint16_t burst_len = 1;

			/* Collect consecutive events for the same destination port */
			while ((i + burst_len) < count &&
			       astate->hold_ports[i + burst_len] == dest_port_id)
				burst_len++;

			/* If destination port is full, retain the event in hold buffer*/
			if (full_ports_mask & (1ULL << dest_port_id)) {
				if (retained != i) {
					memmove(&astate->hold_buffer[retained],
						&astate->hold_buffer[i],
						burst_len * sizeof(struct rte_event));
					memmove(&astate->hold_ports[retained],
						&astate->hold_ports[i],
						burst_len);
				}
				retained += burst_len;
				i += burst_len;
				continue;
			}

			/* Enqueue events to the destination port */
			uint16_t enqueued = rte_event_ring_enqueue_burst(
				queue->per_port_rings[dest_port_id],
				&astate->hold_buffer[i], burst_len, NULL);
			astate->port_stats[dest_port_id].q_enqueued += enqueued;

			/* If enqueue was successful then decrement the load counter */
			if (enqueued > 0 &&
			    astate->port_stats[dest_port_id].load_counter > 0)
				astate->port_stats[dest_port_id].load_counter--;

			/* If enqueue was not successful, retain the event in hold buffer */
			if (enqueued < burst_len) {
				uint16_t rem = burst_len - enqueued;
				uint16_t start_idx = i + enqueued;

				full_ports_mask |= (1ULL << dest_port_id);
				if (retained != start_idx) {
					memmove(&astate->hold_buffer[retained],
						&astate->hold_buffer[start_idx],
						rem * sizeof(struct rte_event));
					memmove(&astate->hold_ports[retained],
						&astate->hold_ports[start_idx],
						rem);
				}
				retained += rem;
				/* If no events were enqueued, trigger migration */
				if (enqueued == 0)
					slb_check_and_trigger_migration(
						slb, queue, astate, dest_port_id);
			}

			i += burst_len;
		}

		astate->hold_count = retained;
		/* Return without pulling events from main atomic queue
		 * if hold buffer does not have enough free space.
		 */
		if (SLB_HOLD_BUFFER_SIZE - astate->hold_count <
		    3 * RTE_DIM(rcv_events)) {
			rte_spinlock_unlock(&astate->refill_lock);
			return;
		}
	}

	/* 2. Dequeue events from main atomic queue in batches */
	serving_mask = queue->serving_ports_mask;
	num_serving_ports = queue->num_serving_ports;

	for (int iter = 0; iter < 2; iter++) {
		if (SLB_HOLD_BUFFER_SIZE - astate->hold_count <
		    RTE_DIM(rcv_events))
			break;

		n_deq = rte_event_ring_dequeue_burst(
			queue->q_ring, rcv_events, RTE_DIM(rcv_events), NULL);

		if (n_deq == 0)
			break;

		uint8_t dest_ports[SLB_MAX_PORT_DEQUEUE_DEPTH];
		uint16_t port_counts[SLB_MAX_PORTS];
		uint16_t insert_pos[SLB_MAX_PORTS];
		uint16_t port_offsets[SLB_MAX_PORTS];
		struct rte_event sorted_events[SLB_MAX_PORT_DEQUEUE_DEPTH];
		uint64_t batch_ports_mask = 0;

		/* Dequeue events from main atomic queue, sort events,
		 * enqueue events to destination port queues. If destination port queue
		 * is full, retain events in hold buffer
		 */
		for (i = 0; i < n_deq; i++) {
			struct rte_event *ev = &rcv_events[i];
			uint32_t flow_idx = slb_flow_hash(ev->flow_id);
			int32_t dest_port_id =
				rte_atomic_load_explicit(
					&astate->flow_map.flows[flow_idx].port_id,
					rte_memory_order_acquire);

			/* If flow is unmapped, map it to a port */
			if (unlikely(dest_port_id == -1)) {
				dest_port_id = slb_assign_unmapped_flow_port(
					slb, astate, serving_mask, num_serving_ports);
				rte_atomic_store_explicit(
					&astate->flow_map.flows[flow_idx].port_id,
					dest_port_id, rte_memory_order_release);
				astate->port_stats[dest_port_id].flow_count++;
			}

			dest_ports[i] = (uint8_t)dest_port_id;
			uint64_t p_bit = (1ULL << dest_port_id);

			/* Count events for each destination port */
			if (!(batch_ports_mask & p_bit)) {
				batch_ports_mask |= p_bit;
				port_counts[dest_port_id] = 1;
			} else {
				port_counts[dest_port_id]++;
			}
		}

		uint16_t current_offset = 0;
		uint64_t pmask = batch_ports_mask;

		/* Calculate offsets for each destination port */
		while (pmask != 0) {
			uint8_t p = rte_ctz64(pmask);

			pmask &= (pmask - 1);
			port_offsets[p] = current_offset;
			insert_pos[p] = current_offset;
			current_offset += port_counts[p];
		}

		/* Sort events by destination port */
		for (i = 0; i < n_deq; i++) {
			uint8_t p = dest_ports[i];

			sorted_events[insert_pos[p]++] = rcv_events[i];
		}

		pmask = batch_ports_mask;
		while (pmask != 0) {
			uint8_t p = rte_ctz64(pmask);
			uint16_t p_count = port_counts[p];
			uint16_t p_start = port_offsets[p];

			pmask &= (pmask - 1);

			/* If destination port is full, retain events in hold buffer */
			if (full_ports_mask & (1ULL << p)) {
				rte_memcpy(&astate->hold_buffer[astate->hold_count],
					   &sorted_events[p_start],
					   p_count * sizeof(struct rte_event));
				memset(&astate->hold_ports[astate->hold_count], p, p_count);
				astate->hold_count += p_count;
				continue;
			}

			/* Enqueue events to the destination port */
			uint16_t enqueued = rte_event_ring_enqueue_burst(
				queue->per_port_rings[p], &sorted_events[p_start], p_count, NULL);
			astate->port_stats[p].q_enqueued += enqueued;

			/* If all events were enqueued successfully, decrement load counter */
			if (enqueued == p_count) {
				if (unlikely(astate->port_stats[p].load_counter > 0))
					astate->port_stats[p].load_counter--;
			} else {
				uint16_t rem = p_count - enqueued;
				/* Mark the destination port as full and retain remaining events */
				full_ports_mask |= (1ULL << p);
				rte_memcpy(&astate->hold_buffer[astate->hold_count],
					   &sorted_events[p_start + enqueued],
					   rem * sizeof(struct rte_event));
				memset(&astate->hold_ports[astate->hold_count], p, rem);
				astate->hold_count += rem;
				/* If not a single event was enqueued, check for migration */
				if (enqueued == 0)
					slb_check_and_trigger_migration(
						slb, queue, astate, p);
			}
		}
	}

	rte_spinlock_unlock(&astate->refill_lock);
}

static inline uint16_t
slb_event_enqueue_burst_generic(struct slb_port *source_port,
				const struct rte_event events[],
				uint16_t events_len, bool op_types_known,
				uint16_t num_new, uint16_t num_forward,
				uint16_t num_release)
{
	struct slb_evdev *slb = source_port->slb;
	uint16_t cur_pending;

	if (unlikely(events_len == 0))
		return 0;

	/* If operation types are not known, count them */
	if (!op_types_known) {
		for (uint16_t i = 0; i < events_len; i++) {
			switch (events[i].op) {
			case RTE_EVENT_OP_NEW:
				num_new++;
				break;
			case RTE_EVENT_OP_FORWARD:
				num_forward++;
				break;
			case RTE_EVENT_OP_RELEASE:
				num_release++;
				break;
			}
		}
	}

	/* Check credit threshold if there are NEW events */
	if (num_new > 0) {
		if (unlikely(rte_atomic_load_explicit(&slb->credits_on_loan,
						      rte_memory_order_relaxed) >
			     source_port->new_event_threshold))
			return 0;

		if (unlikely(!slb_port_acquire_credits(slb, source_port,
						       num_new)))
			return 0;
	}

	/* Return credits for RELEASE events */
	if (num_release > 0)
		slb_port_return_credits(slb, source_port, num_release);

	/* Check for release underflow and balance pending releases */
	cur_pending = source_port->pending_releases;
	RTE_VERIFY(num_forward + num_release <= cur_pending);
	source_port->pending_releases = cur_pending - (num_forward + num_release);

	slb_port_enqueue_stats(source_port, num_new, num_forward, num_release);

	/* Unified zero-copy fast path: when burst does not have past ordered/atomic
	 * events being forwarded and there are no RELEASE events. This means no
	 * history list entries are present.
	 */
	if (likely(source_port->history_avail == SLB_PORT_HISTORY_MAX_TOKENS &&
		   num_release == 0)) {
		uint8_t q0 = events[0].queue_id;
		uint16_t burst_size = 1;

		/* Collect events going to the same queue in a burst */
		while (burst_size < events_len &&
		       events[burst_size].queue_id == q0)
			burst_size++;

		/* Enqueue the entire burst if going to the same queue */
		if (likely(burst_size == events_len)) {
			rte_event_ring_enqueue_burst(slb->queues[q0].q_ring,
						     events, events_len, NULL);
			slb_port_queue_enqueue_burst_stats(source_port, q0,
							   events_len);
		} else { /* Sort events by destination queue */
			uint8_t dest_queues[SLB_MAX_PORT_ENQUEUE_DEPTH];
			uint16_t queue_counts[SLB_MAX_QUEUES];
			uint16_t insert_pos[SLB_MAX_QUEUES];
			uint16_t queue_offsets[SLB_MAX_QUEUES];
			struct rte_event sorted_events[SLB_MAX_PORT_ENQUEUE_DEPTH];
			uint64_t batch_queues_mask = (1ULL << q0);
			uint64_t qmask;
			uint16_t current_offset = 0;

			queue_counts[q0] = burst_size;
			for (uint16_t k = 0; k < burst_size; k++)
				dest_queues[k] = q0;

			for (uint16_t k = burst_size; k < events_len; k++) {
				uint8_t qid = events[k].queue_id;
				uint64_t q_bit = (1ULL << qid);

				dest_queues[k] = qid;
				if (!(batch_queues_mask & q_bit)) {
					batch_queues_mask |= q_bit;
					queue_counts[qid] = 1;
				} else {
					queue_counts[qid]++;
				}
			}

			qmask = batch_queues_mask;
			while (qmask != 0) {
				uint8_t q = rte_ctz64(qmask);

				qmask &= (qmask - 1);
				queue_offsets[q] = current_offset;
				insert_pos[q] = current_offset;
				current_offset += queue_counts[q];
			}

			for (uint16_t k = 0; k < events_len; k++) {
				uint8_t q = dest_queues[k];

				sorted_events[insert_pos[q]++] = events[k];
			}

			/* Enqueue events to their respective queues */
			qmask = batch_queues_mask;
			while (qmask != 0) {
				uint8_t q = rte_ctz64(qmask);
				uint16_t count = queue_counts[q];
				uint16_t offset = queue_offsets[q];

				qmask &= (qmask - 1);
				rte_event_ring_enqueue_burst(slb->queues[q].q_ring,
							     &sorted_events[offset],
							     count, NULL);
				slb_port_queue_enqueue_burst_stats(source_port, q,
								   count);
			}
		}

		SLB_LOG_DP_PORT_LINE(DEBUG, source_port->id,
				     "%d events accepted.", events_len);
		return events_len;
	}

	/* General path for bursts with any mix of events */
	uint64_t ordered_drain_mask = 0;
	uint16_t freed_count = 0;
	uint16_t head = source_port->history_head;
	uint16_t n_enq = 0;
	uint8_t dest_queues[SLB_MAX_PORT_ENQUEUE_DEPTH];
	const struct rte_event *enq_events[SLB_MAX_PORT_ENQUEUE_DEPTH];
	uint16_t queue_counts[SLB_MAX_QUEUES];
	uint64_t batch_queues_mask = 0;
	bool has_history = (source_port->history_avail <
			    SLB_PORT_HISTORY_MAX_TOKENS);

	for (uint16_t idx = 0; idx < events_len; idx++) {
		const struct rte_event *ev = &events[idx];
		/* History list index 0 is used by NEW, parallel, and single-link events */
		uint8_t h_idx = (has_history && ev->op != RTE_EVENT_OP_NEW) ?
				ev->impl_opaque : 0;
		struct slb_history_entry *hist =
			(h_idx != 0 && source_port->history[h_idx].active) ?
			&source_port->history[h_idx] : NULL;

		/* Ordered event is being forwarded/released. */
		if (hist != NULL && hist->sched_type == RTE_SCHED_TYPE_ORDERED) {
			struct slb_queue *orig_q = &slb->queues[hist->orig_queue_id];

			if (orig_q->reorder_buffer) {
				uint16_t slot = hist->seq_slot;

				if (ev->op == RTE_EVENT_OP_RELEASE) {
					/* Release the reorder buffer entry */
					rte_atomic_store_explicit(
						&orig_q->reorder_buffer[slot].state,
						SLB_REORDER_RELEASED,
						rte_memory_order_release);
				} else {
					/* Put event in reorder buffer */
					orig_q->reorder_buffer[slot].event = *ev;
					rte_atomic_store_explicit(
						&orig_q->reorder_buffer[slot].state,
						SLB_REORDER_READY,
						rte_memory_order_release);
				}
				/* Mark the ordered queue for draining */
				ordered_drain_mask |= (1ULL << hist->orig_queue_id);
			}
			/* Free the history entry */
			hist->active = false;
			hist->next_free = head;
			head = h_idx;
			freed_count++;
			slb_port_queue_enqueue_stats(source_port, ev->queue_id);
		} else if (ev->op == RTE_EVENT_OP_RELEASE) {
			/* Atomic or parallel event being released */
			if (hist != NULL) {
				/* Count atomic events being returned */
				if (hist->sched_type == RTE_SCHED_TYPE_ATOMIC) {
					struct slb_queue *orig_q =
						&slb->queues[hist->orig_queue_id];
					if (orig_q->atomic_state) {
						uint8_t ep = hist->enq_port_id;
						orig_q->atomic_state->port_stats[ep].q_returned++;
					}
				}
				/* Free the history entry */
				hist->active = false;
				hist->next_free = head;
				head = h_idx;
				freed_count++;
			}
			slb_port_queue_enqueue_stats(source_port, ev->queue_id);
		} else {
			/* Atomic/Parallel event being forwarded*/
			if (hist != NULL) {
				/* Count atomic events being returned */
				if (hist->sched_type == RTE_SCHED_TYPE_ATOMIC) {
					struct slb_queue *orig_q =
						&slb->queues[hist->orig_queue_id];
					if (orig_q->atomic_state) {
						uint8_t ep = hist->enq_port_id;
						orig_q->atomic_state->port_stats[ep].q_returned++;
					}
				}
				/* Free the history entry */
				hist->active = false;
				hist->next_free = head;
				head = h_idx;
				freed_count++;
			}

			uint8_t qid = ev->queue_id;
			uint64_t q_bit = (1ULL << qid);

			dest_queues[n_enq] = qid;
			enq_events[n_enq] = ev;
			n_enq++;

			/* Count the number of events going to each queue */
			if (!(batch_queues_mask & q_bit)) {
				batch_queues_mask |= q_bit;
				queue_counts[qid] = 1;
			} else {
				queue_counts[qid]++;
			}
		}
	}

	if (n_enq > 0) { /* There are events to enqueue */
		if (likely((batch_queues_mask & (batch_queues_mask - 1)) == 0 &&
			   n_enq == events_len)) {
			/* Entire batch is going to a single queue */
			uint8_t q = rte_ctz64(batch_queues_mask);

			rte_event_ring_enqueue_burst(slb->queues[q].q_ring,
						     events, events_len, NULL);
			slb_port_queue_enqueue_burst_stats(source_port, q,
							   events_len);
		} else {
			uint16_t queue_offsets[SLB_MAX_QUEUES];
			uint16_t insert_pos[SLB_MAX_QUEUES];
			struct rte_event sorted_events[SLB_MAX_PORT_ENQUEUE_DEPTH];
			uint16_t current_offset = 0;
			uint64_t qmask = batch_queues_mask;

			/* Calculate the offset for each queue */
			while (qmask != 0) {
				uint8_t q = rte_ctz64(qmask);

				qmask &= (qmask - 1);
				queue_offsets[q] = current_offset;
				insert_pos[q] = current_offset;
				current_offset += queue_counts[q];
			}

			/* Sort events by queue */
			for (uint16_t k = 0; k < n_enq; k++) {
				uint8_t q = dest_queues[k];

				sorted_events[insert_pos[q]++] = *enq_events[k];
			}

			/* Enqueue events for each queue */
			qmask = batch_queues_mask;
			while (qmask != 0) {
				uint8_t q = rte_ctz64(qmask);
				uint16_t count = queue_counts[q];
				uint16_t offset = queue_offsets[q];

				qmask &= (qmask - 1);
				rte_event_ring_enqueue_burst(slb->queues[q].q_ring,
							     &sorted_events[offset],
							     count, NULL);
				slb_port_queue_enqueue_burst_stats(source_port, q,
								   count);
			}
		}
	}

	/* Update the history list head once after all frees*/
	if (freed_count > 0) {
		source_port->history_head = head;
		source_port->history_avail += freed_count;
	}

	/* If events are added to reorder buffers, call the drain function */
	while (ordered_drain_mask != 0) {
		uint8_t qid = rte_ctz64(ordered_drain_mask);

		ordered_drain_mask &= ~(1ULL << qid);
		slb_reorder_drain(slb, &slb->queues[qid]);
	}

	SLB_LOG_DP_PORT_LINE(DEBUG, source_port->id,
			     "%d events accepted.", events_len);
	return events_len;
}

/* Enqueue burst of mix event type. (NEW, FORWARDED, RELEASED) */
uint16_t
slb_event_enqueue_burst(void *port, const struct rte_event events[],
			uint16_t events_len)
{
	struct slb_port *source_port = port;

	return slb_event_enqueue_burst_generic(source_port, events, events_len,
					       false, 0, 0, 0);
}

/* Enqueue burst of all new events */
uint16_t
slb_event_enqueue_new_burst(void *port, const struct rte_event events[],
			    uint16_t events_len)
{
	struct slb_port *source_port = port;

	return slb_event_enqueue_burst_generic(source_port, events, events_len,
					       true, events_len, 0, 0);
}

/* Enqueue burst of all forwarded events */
uint16_t
slb_event_enqueue_forward_burst(void *port, const struct rte_event events[],
				uint16_t events_len)
{
	struct slb_port *source_port = port;

	return slb_event_enqueue_burst_generic(source_port, events, events_len,
					       true, 0, events_len, 0);
}

/* Dequeue events from an ordered queue. Event's slot in the ring is
 * used as its sequence number
 */
static inline uint16_t
slb_ordered_ring_dequeue_burst(struct rte_event_ring *r,
			       struct rte_event *events,
			       uint16_t num, uint32_t *start_slot)
{
	uint32_t cons_head, cons_next;
	uint32_t entries;
	uint16_t n;

	n = __rte_ring_move_cons_head(&r->r, 0, num,
				      RTE_RING_QUEUE_VARIABLE,
				      &cons_head, &cons_next, &entries);
	if (n == 0)
		return 0;

	*start_slot = cons_head & r->r.mask;

	__rte_ring_dequeue_elems(&r->r, cons_head, events,
				 sizeof(struct rte_event), n);

	__rte_ring_update_tail(&r->r.cons, cons_head, cons_next, 0);

	return n;
}

/* Create history entries for events dequeued from a queue_id of type sched_type */
static inline void
slb_port_record_dequeued_history(struct slb_port *port, struct rte_event events[],
				 uint16_t dequeued, uint8_t queue_id,
				 uint8_t sched_type, uint32_t start_slot,
				 uint32_t ring_mask)
{
	uint16_t head = port->history_head;
	bool is_ordered = (sched_type == RTE_SCHED_TYPE_ORDERED);

	for (uint16_t j = 0; j < dequeued; j++) {
		uint16_t h_idx = head;
		struct slb_history_entry *h = &port->history[h_idx];

		head = h->next_free;
		h->orig_queue_id = queue_id;
		h->sched_type = sched_type;
		if (is_ordered) {
			h->seq_slot = (start_slot + j) & ring_mask;
		} else {
			h->enq_port_id = (uint8_t)port->id;
			h->flow_id = events[j].flow_id;
		}
		h->active = true;
		events[j].impl_opaque = (uint8_t)h_idx;
	}
	port->history_head = head;
	port->history_avail -= dequeued;
}

/* Dequeue events from the port */
static inline uint16_t
slb_port_dequeue(struct slb_port *port, struct rte_event events[],
		 uint16_t num)
{
	uint16_t dequeued = 0;

	/* If port is single-linked, it is simple dequeue from the linked queue */
	if (port->is_single_linked) {
		if (unlikely(port->single_linked_ring == NULL))
			return 0;
		dequeued = rte_event_ring_dequeue_burst(port->single_linked_ring,
							events, num, NULL);
		for (uint16_t j = 0; j < dequeued; j++)
			events[j].impl_opaque = 0;
		return dequeued;
	}

	for (int pr = 0; pr < SLB_MAX_PRIORITIES; pr++) {
		int slots = port->num_q[pr];

		if (slots == 0)
			continue; /* No queues mapped at this priority */

		/* Start from where we left off */
		int start = port->next_q[pr];

		if (unlikely(start >= slots))
			start = 0;

		for (int s = 0; s < slots; s++) {
			int idx = start + s;

			if (idx >= slots)
				idx -= slots;

			struct slb_port_q_entry *qent = &port->q_entries[pr][idx];
			uint8_t queue_id = qent->queue_id;
			struct rte_event_ring *ring_to_dq = qent->dq_ring;

			if (unlikely(ring_to_dq == NULL))
				continue;

			uint8_t sched_type = qent->schedule_type;
			bool is_ordered = (sched_type == RTE_SCHED_TYPE_ORDERED);
			bool is_atomic = (sched_type == RTE_SCHED_TYPE_ATOMIC);

			if (is_ordered || is_atomic) {
				if (unlikely(port->history_avail == 0))
					continue; /* No available history entries */

				uint16_t dequeue_num = RTE_MIN(num,
							       port->history_avail);
				uint32_t start_slot = 0;

				if (is_ordered) {
					dequeued = slb_ordered_ring_dequeue_burst(
						ring_to_dq, events, dequeue_num,
						&start_slot);
				} else { /* Atomic queue */
					dequeued = rte_event_ring_dequeue_burst(
						ring_to_dq, events, dequeue_num,
						NULL);
					if (dequeued == 0) {
						/* Per port queue is empty, call for refill */
						slb_atomic_refill(port, qent->queue);
						dequeued = rte_event_ring_dequeue_burst(
							ring_to_dq, events, dequeue_num,
							NULL);
					}
				}

				/* Create history entries for dequeued events */
				if (dequeued > 0)
					slb_port_record_dequeued_history(
						port, events, dequeued, queue_id,
						sched_type, start_slot,
						ring_to_dq->r.mask);
			} else { /* Parallel queue */
				dequeued = rte_event_ring_dequeue_burst(
					ring_to_dq, events, num, NULL);
				for (uint16_t j = 0; j < dequeued; j++)
					events[j].impl_opaque = 0;
			}

			/* If dequeued non-zero events successfully, move to the next queue
			 * for the next dequeue call and return
			 */
			if (dequeued > 0) {
				idx++;
				port->next_q[pr] = (idx >= slots) ? 0 : idx;
				return dequeued;
			}
		}
	}
	return 0;
}

/* Process pending releases for the port */
static inline void
slb_port_process_implicit_release(struct slb_port *port, struct slb_evdev *slb,
				  uint16_t pending)
{
	uint16_t head;
	uint64_t ordered_drain_mask = 0;

	slb_port_return_credits(slb, port, pending);
	port->pending_releases = 0;

	if (port->is_single_linked ||
	    port->history_avail >= SLB_PORT_HISTORY_MAX_TOKENS)
		return;

	/* Process all history entries */
	head = port->history_head;
	for (int i = 1; i < SLB_PORT_HISTORY_SIZE; i++) {
		struct slb_history_entry *hist = &port->history[i];

		if (!hist->active)
			continue;

		/* Ordered releases will free the reorder buffer slot*/
		if (hist->sched_type == RTE_SCHED_TYPE_ORDERED) {
			struct slb_queue *oq = &slb->queues[hist->orig_queue_id];

			if (oq->reorder_buffer) {
				rte_atomic_store_explicit(
					&oq->reorder_buffer[hist->seq_slot].state,
					SLB_REORDER_RELEASED,
					rte_memory_order_release);
				ordered_drain_mask |= (1ULL << hist->orig_queue_id);
			}
		} else if (hist->sched_type == RTE_SCHED_TYPE_ATOMIC) {
			/* Atomic releases are counted as returned events */
			struct slb_queue *oq = &slb->queues[hist->orig_queue_id];

			if (oq->atomic_state) {
				uint8_t ep = hist->enq_port_id;

				oq->atomic_state->port_stats[ep].q_returned++;
			}
		}
		/* Free the history entries */
		hist->active = false;
		hist->next_free = head;
		head = (uint16_t)i;
		port->history_avail++;
	}
	port->history_head = head;

	/* If there are ordered releases, call the reorder drain function */
	while (ordered_drain_mask != 0) {
		uint8_t qid = rte_ctz64(ordered_drain_mask);

		ordered_drain_mask &= ~(1ULL << qid);
		slb_reorder_drain(slb, &slb->queues[qid]);
	}
}

/* Eventdev dequeue burst function */
uint16_t
slb_event_dequeue_burst(void *p, struct rte_event events[], uint16_t num,
			uint64_t wait __rte_unused)
{
	struct slb_port *port = p;
	struct slb_evdev *slb = port->slb;
	uint16_t pending = port->pending_releases;
	uint16_t n;

	/* Handle pending releases */
	if (port->implicit_release && pending > 0)
		slb_port_process_implicit_release(port, slb, pending);

	if (unlikely(num > port->dequeue_depth))
		num = port->dequeue_depth;

	port->dequeue_calls++;
	n = slb_port_dequeue(port, events, num);
	if (n > 0)
		port->pending_releases += n;
	port->dequeued += n;

	if (n == 0)
		port->empty_dequeues++;

	return n;
}

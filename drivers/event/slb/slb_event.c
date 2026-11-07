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

/* Acquire credits for new events */
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

	if (available < required_credits)
		return false;

	new_total_inflight =
		rte_atomic_fetch_add_explicit(&slb->credits_on_loan,
					      required_credits,
					      rte_memory_order_relaxed) +
					      required_credits;

	if (unlikely(new_total_inflight > slb->max_inflight)) {
		rte_atomic_fetch_sub_explicit(&slb->credits_on_loan,
					      required_credits,
					      rte_memory_order_relaxed);
		return false;
	}

	port->inflight_credits += required_credits;
	port->inflight_credits -= credits;

	return true;
}

/* Return accumulated credits (Terminated events) */
void
slb_port_return_credits(struct slb_evdev *slb, struct slb_port *port,
			int32_t credits)
{
	port->inflight_credits += credits;

	if (unlikely(port->inflight_credits >= SLB_PORT_MAX_CREDITS)) {
		int32_t return_credits = port->inflight_credits -
					 SLB_PORT_MIN_CREDITS;
		port->inflight_credits = SLB_PORT_MIN_CREDITS;

		rte_atomic_fetch_sub_explicit(&slb->credits_on_loan,
					      return_credits,
					      rte_memory_order_release);
	}
}

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

/* Drain in-order contiguous ready events from ordered queue's reorder buffer */
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

	/* Drain from current drain index till hitting an empty slot.
	 * Released slots need no processing except marking them empty.
	 */
	while ((state = rte_atomic_load_explicit(&buf[drain_idx].state,
						 rte_memory_order_acquire)) !=
	       SLB_REORDER_EMPTY) {
		if (state == SLB_REORDER_RELEASED) {
			rte_atomic_store_explicit(&buf[drain_idx].state,
						  SLB_REORDER_EMPTY,
						  rte_memory_order_release);
			drain_idx = (drain_idx + 1) & mask;
			continue;
		}

		/* Gather contiguous READY events destined for same target_qid */
		struct rte_event burst[REORDER_BURST_SZ];
		uint16_t burst_size = 0;
		uint8_t target_qid = buf[drain_idx].event.queue_id;

		while (burst_size < REORDER_BURST_SZ &&
		       rte_atomic_load_explicit(&buf[drain_idx].state,
						rte_memory_order_acquire) ==
		       SLB_REORDER_READY &&
		       buf[drain_idx].event.queue_id == target_qid) {
			burst[burst_size++] = buf[drain_idx].event;
			rte_atomic_store_explicit(&buf[drain_idx].state,
						  SLB_REORDER_EMPTY,
						  rte_memory_order_release);
			drain_idx = (drain_idx + 1) & mask;
		}

		if (burst_size == 0)
			break;

		/* Target queue is sized to max_inflight and can never be full */
		rte_event_ring_enqueue_burst(slb->queues[target_qid].q_ring,
					     burst, burst_size, NULL);
	}

	queue->reorder_drain_idx = drain_idx;
	rte_spinlock_unlock(&queue->reorder_lock);
}

/* Hash flow ID to atomic flow slot index */
static inline uint32_t
slb_flow_hash(uint32_t flow_id)
{
	return (flow_id * 2654435761U) & SLB_ATOMIC_FLOWS_MASK;
}

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
	count = prod - cons;

	memset(counts, 0, sizeof(counts));
	if (count > 0) {
		struct rte_event *ring_events = (struct rte_event *)(r + 1);

		for (uint32_t i = 0; i < count; i++) {
			uint32_t slot = (cons + i) & r->mask;
			uint32_t f_idx = slb_flow_hash(ring_events[slot].flow_id);

			counts[f_idx]++;
		}
	}

	for (uint32_t f = 0; f < SLB_ATOMIC_FLOWS; f++) {
		if (rte_atomic_load_explicit(&astate->flow_map.flows[f].port_id,
					     rte_memory_order_relaxed) == (int32_t)port_id) {
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

static void
slb_check_and_trigger_migration(struct slb_evdev *slb, struct slb_queue *queue,
				struct slb_atomic_state *astate, uint8_t full_port_id)
{
	struct slb_atomic_port_stats *pstats = &astate->port_stats[full_port_id];
	uint64_t now;
	uint64_t hz;
	uint64_t cooldown_cycles;
	int32_t flow_to_migrate;

	pstats->load_counter++;
	if (pstats->load_counter < SLB_MIGRATION_LOAD_THRESHOLD)
		return;

	if (astate->migration.in_progress)
		return;

	if (slb->ports[full_port_id].is_loaded)
		return;

	if (pstats->flow_count <= 1)
		return;

	now = rte_get_timer_cycles();
	hz = rte_get_timer_hz();
	cooldown_cycles = (hz * SLB_MIGRATION_COOLDOWN_MS) / 1000;

	if (slb->ports[full_port_id].last_migrated_time != 0 &&
	    (now - slb->ports[full_port_id].last_migrated_time) < cooldown_cycles)
		return;

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

static inline void
slb_complete_flow_migration(struct slb_evdev *slb, struct slb_atomic_state *astate,
			    uint8_t mig_port, int target_port, uint64_t now)
{
	uint32_t f_idx = astate->migration.flow_idx;

	rte_atomic_store_explicit(&astate->flow_map.flows[f_idx].port_id,
				  target_port, rte_memory_order_release);

	for (uint16_t h = 0; h < astate->hold_count; h++) {
		if (astate->hold_ports[h] == mig_port &&
		    slb_flow_hash(astate->hold_buffer[h].flow_id) == f_idx) {
			astate->hold_ports[h] = (uint8_t)target_port;
		}
	}

	astate->flow_last_migrated[f_idx] = now;
	slb->ports[mig_port].last_migrated_time = now;
	slb->ports[target_port].last_migrated_time = now;

	if (astate->port_stats[mig_port].flow_count > 0)
		astate->port_stats[mig_port].flow_count--;
	astate->port_stats[target_port].flow_count++;
	astate->migrations_count++;

	slb->ports[mig_port].flow_migrations++;
	slb->ports[mig_port].migrations_out++;
	slb->ports[target_port].migrations_in++;

	astate->port_stats[mig_port].load_counter = 0;
	slb->ports[mig_port].is_loaded = false;
	astate->migration.in_progress = false;
}

static inline uint8_t
slb_assign_unmapped_flow_port(struct slb_evdev *slb, struct slb_atomic_state *astate,
			      uint64_t serving_mask, uint16_t num_serving_ports)
{
	uint32_t rr_counter = astate->next_port_rr++;
	int port_offset = rr_counter % num_serving_ports;
	uint64_t temp_mask = serving_mask;
	uint8_t assigned_port = 0;

	for (int j = 0; j <= port_offset; j++) {
		assigned_port = rte_ctz64(temp_mask);
		temp_mask &= (temp_mask - 1);
	}

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

/* If port queue is empty for an atomic queue, pull events from main atomic queue to fill
 * up port queues.
 */
static void
slb_atomic_refill(struct slb_port *port, struct slb_queue *queue)
{
	struct slb_evdev *slb = port->slb;
	struct rte_event master_events[SLB_MAX_PORT_DEQUEUE_DEPTH];
	uint16_t n_deq;
	uint16_t i;
	uint64_t full_ports_mask = 0;
	struct slb_atomic_state *astate = queue->atomic_state;
	uint64_t serving_mask;
	uint16_t num_serving_ports;

	if (unlikely(astate == NULL))
		return;

	if (!rte_spinlock_trylock(&astate->refill_lock))
		return;

	/* 0. Detect migration in progress before hold buffer processing */
	if (astate->migration.in_progress) {
		uint8_t mig_port = astate->migration.port_id;
		uint64_t enq_cnt = astate->port_stats[mig_port].q_enqueued;
		uint64_t ret_cnt = astate->port_stats[mig_port].q_returned;

		if (enq_cnt == ret_cnt) {
			uint64_t now = rte_get_timer_cycles();
			uint64_t hz = rte_get_timer_hz();
			uint64_t cooldown_cycles =
				(hz * SLB_MIGRATION_COOLDOWN_MS) / 1000;
			int target_port = slb_find_migration_target_port(
				slb, queue, astate, mig_port, now,
				cooldown_cycles);

			if (target_port != -1)
				slb_complete_flow_migration(
					slb, astate, mig_port, target_port, now);
			else {
				astate->port_stats[mig_port].load_counter = 0;
				slb->ports[mig_port].is_loaded = false;
				astate->migration.in_progress = false;
			}
		}
	}

	if (astate->migration.in_progress)
		full_ports_mask |= (1ULL << astate->migration.port_id);

	/* 1. Process Hold Buffer first */
	if (astate->hold_count > 0) {
		uint16_t retained = 0;
		uint16_t count = astate->hold_count;

		i = 0;
		while (i < count) {
			uint8_t dest_port_id = astate->hold_ports[i];
			uint16_t burst_len = 1;

			while ((i + burst_len) < count &&
			       astate->hold_ports[i + burst_len] == dest_port_id)
				burst_len++;

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

			uint16_t enqueued = rte_event_ring_enqueue_burst(
				queue->per_port_rings[dest_port_id],
				&astate->hold_buffer[i], burst_len, NULL);
			astate->port_stats[dest_port_id].q_enqueued += enqueued;

			if (enqueued > 0 &&
			    astate->port_stats[dest_port_id].load_counter > 0)
				astate->port_stats[dest_port_id].load_counter--;

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
				if (enqueued == 0)
					slb_check_and_trigger_migration(
						slb, queue, astate, dest_port_id);
			}

			i += burst_len;
		}

		astate->hold_count = retained;
		if (astate->hold_count > 0) {
			rte_spinlock_unlock(&astate->refill_lock);
			return;
		}
	}

	/* 2. Dequeue events from main atomic queue in batches */
	serving_mask = queue->serving_ports_mask;
	num_serving_ports = queue->num_serving_ports;

	if (num_serving_ports == 0) {
		rte_spinlock_unlock(&astate->refill_lock);
		return;
	}

	for (int iter = 0; iter < 2; iter++) {
		n_deq = rte_event_ring_dequeue_burst(
			queue->q_ring, master_events, RTE_DIM(master_events), NULL);

		if (n_deq == 0)
			break;

		uint8_t dest_ports[SLB_MAX_PORT_DEQUEUE_DEPTH];
		uint16_t port_counts[SLB_MAX_PORTS];
		uint16_t insert_pos[SLB_MAX_PORTS];
		uint16_t port_offsets[SLB_MAX_PORTS];
		struct rte_event sorted_events[SLB_MAX_PORT_DEQUEUE_DEPTH];
		uint64_t batch_ports_mask = 0;

		for (i = 0; i < n_deq; i++) {
			struct rte_event *ev = &master_events[i];
			uint32_t flow_idx = slb_flow_hash(ev->flow_id);
			int32_t dest_port_id =
				rte_atomic_load_explicit(
					&astate->flow_map.flows[flow_idx].port_id,
					rte_memory_order_acquire);

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

			if (!(batch_ports_mask & p_bit)) {
				batch_ports_mask |= p_bit;
				port_counts[dest_port_id] = 1;
			} else {
				port_counts[dest_port_id]++;
			}
		}

		uint16_t current_offset = 0;
		uint64_t pmask = batch_ports_mask;

		while (pmask != 0) {
			uint8_t p = rte_ctz64(pmask);

			pmask &= (pmask - 1);
			port_offsets[p] = current_offset;
			insert_pos[p] = current_offset;
			current_offset += port_counts[p];
		}

		for (i = 0; i < n_deq; i++) {
			uint8_t p = dest_ports[i];

			sorted_events[insert_pos[p]++] = master_events[i];
		}

		pmask = batch_ports_mask;
		while (pmask != 0) {
			uint8_t p = rte_ctz64(pmask);
			uint16_t p_count = port_counts[p];
			uint16_t p_start = port_offsets[p];

			pmask &= (pmask - 1);

			if (full_ports_mask & (1ULL << p)) {
				uint16_t space = SLB_HOLD_BUFFER_SIZE - astate->hold_count;
				uint16_t to_copy = RTE_MIN(p_count, space);

				if (to_copy > 0) {
					rte_memcpy(&astate->hold_buffer[astate->hold_count],
						   &sorted_events[p_start],
						   to_copy * sizeof(struct rte_event));
					memset(&astate->hold_ports[astate->hold_count], p, to_copy);
					astate->hold_count += to_copy;
				}
				continue;
			}

			uint16_t enqueued = rte_event_ring_enqueue_burst(
				queue->per_port_rings[p], &sorted_events[p_start], p_count, NULL);
			astate->port_stats[p].q_enqueued += enqueued;

			if (enqueued == p_count) {
				if (unlikely(astate->port_stats[p].load_counter > 0))
					astate->port_stats[p].load_counter--;
			} else {
				uint16_t rem = p_count - enqueued;
				uint16_t space = SLB_HOLD_BUFFER_SIZE - astate->hold_count;
				uint16_t to_copy = RTE_MIN(rem, space);

				full_ports_mask |= (1ULL << p);
				if (to_copy > 0) {
					rte_memcpy(&astate->hold_buffer[astate->hold_count],
						   &sorted_events[p_start + enqueued],
						   to_copy * sizeof(struct rte_event));
					memset(&astate->hold_ports[astate->hold_count], p, to_copy);
					astate->hold_count += to_copy;
				}
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

	/* Check credit threshold for NEW events */
	if (num_new > 0) {
		if (unlikely(rte_atomic_load_explicit(&slb->credits_on_loan,
						      rte_memory_order_relaxed) >
			     source_port->new_event_threshold))
			return 0;

		if (unlikely(!slb_port_acquire_credits(slb, source_port,
						       num_new)))
			return 0;
	}

	if (num_release > 0)
		slb_port_return_credits(slb, source_port, num_release);

	cur_pending = source_port->pending_releases;
	RTE_VERIFY(num_forward + num_release <= cur_pending);

	slb_port_enqueue_stats(source_port, num_new, num_forward, num_release);

	/* Unified zero-copy fast path: when port has no in-flight ordered/atomic events
	 * and no release ops.
	 */
	if (likely(source_port->history_avail == SLB_PORT_HISTORY_MAX_TOKENS &&
		   num_release == 0)) {
		uint8_t q0 = events[0].queue_id;
		uint16_t burst_size = 1;

		while (burst_size < events_len &&
		       events[burst_size].queue_id == q0)
			burst_size++;

		if (likely(burst_size == events_len)) {
			rte_event_ring_enqueue_burst(slb->queues[q0].q_ring,
						     events, events_len, NULL);
			slb_port_queue_enqueue_burst_stats(source_port, q0,
							   events_len);
		} else {
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

		if (num_forward > 0)
			source_port->pending_releases -= num_forward;

		SLB_LOG_DP_PORT_LINE(DEBUG, source_port->id,
				     "%d events accepted.", events_len);
		return events_len;
	}

	/* General path for bursts with in-flight ordered/atomic events or releases */
	uint64_t ordered_drain_mask = 0;
	uint16_t freed_count = 0;
	uint16_t head = source_port->history_head;
	uint16_t n_enq = 0;
	uint8_t dest_queues[SLB_MAX_PORT_ENQUEUE_DEPTH];
	const struct rte_event *enq_events[SLB_MAX_PORT_ENQUEUE_DEPTH];
	uint16_t queue_counts[SLB_MAX_QUEUES];
	uint64_t batch_queues_mask = 0;

	for (uint16_t idx = 0; idx < events_len; idx++) {
		const struct rte_event *ev = &events[idx];
		uint8_t h_idx = (ev->op != RTE_EVENT_OP_NEW) ? ev->impl_opaque : 0;
		struct slb_history_entry *hist =
			(h_idx != 0 && source_port->history[h_idx].active) ?
			&source_port->history[h_idx] : NULL;

		if (hist != NULL && hist->sched_type == RTE_SCHED_TYPE_ORDERED) {
			struct slb_queue *orig_q = &slb->queues[hist->orig_queue_id];

			if (orig_q->reorder_buffer) {
				uint16_t slot = hist->seq_slot;

				if (ev->op == RTE_EVENT_OP_RELEASE) {
					rte_atomic_store_explicit(
						&orig_q->reorder_buffer[slot].state,
						SLB_REORDER_RELEASED,
						rte_memory_order_release);
				} else {
					orig_q->reorder_buffer[slot].event = *ev;
					rte_atomic_store_explicit(
						&orig_q->reorder_buffer[slot].state,
						SLB_REORDER_READY,
						rte_memory_order_release);
				}
				ordered_drain_mask |= (1ULL << hist->orig_queue_id);
			}
			hist->active = false;
			hist->next_free = head;
			head = h_idx;
			freed_count++;
			slb_port_queue_enqueue_stats(source_port, ev->queue_id);
		} else if (ev->op == RTE_EVENT_OP_RELEASE) {
			if (hist != NULL) {
				if (hist->sched_type == RTE_SCHED_TYPE_ATOMIC) {
					struct slb_queue *orig_q =
						&slb->queues[hist->orig_queue_id];
					if (orig_q->atomic_state) {
						uint8_t ep = hist->enq_port_id;
						orig_q->atomic_state->port_stats[ep].q_returned++;
					}
				}
				hist->active = false;
				hist->next_free = head;
				head = h_idx;
				freed_count++;
			}
			slb_port_queue_enqueue_stats(source_port, ev->queue_id);
		} else {
			if (hist != NULL) {
				if (hist->sched_type == RTE_SCHED_TYPE_ATOMIC) {
					struct slb_queue *orig_q =
						&slb->queues[hist->orig_queue_id];
					if (orig_q->atomic_state) {
						uint8_t ep = hist->enq_port_id;
						orig_q->atomic_state->port_stats[ep].q_returned++;
					}
				}
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

			if (!(batch_queues_mask & q_bit)) {
				batch_queues_mask |= q_bit;
				queue_counts[qid] = 1;
			} else {
				queue_counts[qid]++;
			}
		}
	}

	if (n_enq > 0) {
		if (likely((batch_queues_mask & (batch_queues_mask - 1)) == 0 &&
			   n_enq == events_len)) {
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

			while (qmask != 0) {
				uint8_t q = rte_ctz64(qmask);

				qmask &= (qmask - 1);
				queue_offsets[q] = current_offset;
				insert_pos[q] = current_offset;
				current_offset += queue_counts[q];
			}

			for (uint16_t k = 0; k < n_enq; k++) {
				uint8_t q = dest_queues[k];

				sorted_events[insert_pos[q]++] = *enq_events[k];
			}

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

	if (freed_count > 0) {
		source_port->history_head = head;
		source_port->history_avail += freed_count;
	}

	while (ordered_drain_mask != 0) {
		uint8_t qid = rte_ctz64(ordered_drain_mask);

		ordered_drain_mask &= ~(1ULL << qid);
		slb_reorder_drain(slb, &slb->queues[qid]);
	}

	if (num_forward + num_release > 0)
		source_port->pending_releases -= (num_forward + num_release);

	SLB_LOG_DP_PORT_LINE(DEBUG, source_port->id,
			     "%d events accepted.", events_len);
	return events_len;
}

uint16_t
slb_event_enqueue_burst(void *port, const struct rte_event events[],
			uint16_t events_len)
{
	struct slb_port *source_port = port;

	return slb_event_enqueue_burst_generic(source_port, events, events_len,
					       false, 0, 0, 0);
}

uint16_t
slb_event_enqueue_new_burst(void *port, const struct rte_event events[],
			    uint16_t events_len)
{
	struct slb_port *source_port = port;

	return slb_event_enqueue_burst_generic(source_port, events, events_len,
					       true, events_len, 0, 0);
}

uint16_t
slb_event_enqueue_forward_burst(void *port, const struct rte_event events[],
				uint16_t events_len)
{
	struct slb_port *source_port = port;

	return slb_event_enqueue_burst_generic(source_port, events, events_len,
					       true, 0, events_len, 0);
}

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

static inline uint16_t
slb_port_dequeue(struct slb_port *port, struct rte_event events[],
		 uint16_t num)
{
	uint16_t dequeued = 0;

	if (port->is_single_linked) {
		if (unlikely(port->single_linked_ring == NULL))
			return 0;
		dequeued = rte_event_ring_dequeue_burst(port->single_linked_ring,
							events, num, NULL);
		for (uint16_t j = 0; j < dequeued; j++) {
			events[j].sched_type = RTE_SCHED_TYPE_ATOMIC;
			events[j].impl_opaque = 0;
		}
		return dequeued;
	}

	uint64_t active_queues = rte_atomic_load_explicit(
		&port->active_queues, rte_memory_order_acquire);
	if (!active_queues)
		return 0;

	for (int pr = 0; pr < SLB_MAX_PRIORITIES; pr++) {
		int slots = port->num_q[pr];

		if (slots == 0)
			continue;

		int start = port->next_q[pr];

		if (unlikely(start >= slots))
			start = 0;

		for (int s = 0; s < slots; s++) {
			int idx = start + s;

			if (idx >= slots)
				idx -= slots;

			struct slb_port_q_entry *qent = &port->q_entries[pr][idx];
			uint8_t queue_id = qent->queue_id;

			if (!((active_queues >> queue_id) & 1))
				continue;

			struct rte_event_ring *ring_to_dq = qent->dq_ring;

			if (unlikely(ring_to_dq == NULL))
				continue;

			uint8_t sched_type = qent->schedule_type;
			bool is_single_link = qent->is_single_link;
			bool is_ordered = !is_single_link &&
					  (sched_type == RTE_SCHED_TYPE_ORDERED);
			bool is_atomic = !is_single_link &&
					 (sched_type == RTE_SCHED_TYPE_ATOMIC);

			if (is_ordered || is_atomic) {
				if (unlikely(port->history_avail == 0))
					continue;

				uint16_t dequeue_num = RTE_MIN(num,
							       port->history_avail);
				uint32_t start_slot = 0;

				if (is_ordered) {
					dequeued = slb_ordered_ring_dequeue_burst(
						ring_to_dq, events, dequeue_num,
						&start_slot);
				} else {
					dequeued = rte_event_ring_dequeue_burst(
						ring_to_dq, events, dequeue_num,
						NULL);
					if (dequeued == 0) {
						slb_atomic_refill(port, qent->queue);
						dequeued = rte_event_ring_dequeue_burst(
							ring_to_dq, events, dequeue_num,
							NULL);
					}
				}

				if (dequeued > 0)
					slb_port_record_dequeued_history(
						port, events, dequeued, queue_id,
						sched_type, start_slot,
						ring_to_dq->r.mask);
			} else {
				dequeued = rte_event_ring_dequeue_burst(
					ring_to_dq, events, num, NULL);
				if (is_single_link) {
					for (uint16_t j = 0; j < dequeued; j++) {
						events[j].sched_type =
							RTE_SCHED_TYPE_ATOMIC;
						events[j].impl_opaque = 0;
					}
				} else {
					for (uint16_t j = 0; j < dequeued; j++)
						events[j].impl_opaque = 0;
				}
			}

			if (dequeued > 0) {
				idx++;
				port->next_q[pr] = (idx >= slots) ? 0 : idx;
				return dequeued;
			}
		}
	}
	return 0;
}

static inline void
slb_port_process_implicit_release(struct slb_port *port, struct slb_evdev *slb,
				  uint16_t pending)
{
	uint16_t head;
	uint64_t ordered_drain_mask = 0;

	if (port->is_single_linked ||
	    port->history_avail >= SLB_PORT_HISTORY_MAX_TOKENS)
		goto done;

	head = port->history_head;
	for (int i = 1; i < SLB_PORT_HISTORY_SIZE; i++) {
		struct slb_history_entry *hist = &port->history[i];

		if (!hist->active)
			continue;

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
			struct slb_queue *oq = &slb->queues[hist->orig_queue_id];

			if (oq->atomic_state) {
				uint8_t ep = hist->enq_port_id;

				oq->atomic_state->port_stats[ep].q_returned++;
			}
		}
		hist->active = false;
		hist->next_free = head;
		head = (uint16_t)i;
		port->history_avail++;
	}
	port->history_head = head;

	while (ordered_drain_mask != 0) {
		uint8_t qid = rte_ctz64(ordered_drain_mask);

		ordered_drain_mask &= ~(1ULL << qid);
		slb_reorder_drain(slb, &slb->queues[qid]);
	}

done:
	slb_port_return_credits(slb, port, pending);
	port->pending_releases = 0;
}

uint16_t
slb_event_dequeue_burst(void *p, struct rte_event events[], uint16_t num,
			uint64_t wait __rte_unused)
{
	struct slb_port *port = p;
	struct slb_evdev *slb = port->slb;
	uint16_t pending = port->pending_releases;
	uint16_t n;

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

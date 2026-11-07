/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Pravin Pathak <pravin.pathak.dev@gmail.com>
 */

#include <stdbool.h>
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
slb_port_queue_enqueue_burst_stats(struct slb_port *source_port,
				   uint8_t queue_id, uint16_t num)
{
	source_port->queue_enqueued[queue_id] += num;
}

static inline uint16_t
slb_event_enqueue_burst_generic(struct slb_port *source_port,
				const struct rte_event events[],
				uint16_t events_len, bool op_types_known,
				uint16_t num_new, uint16_t num_forward,
				uint16_t num_release)
{
	struct slb_evdev *slb = source_port->slb;
	uint16_t enqueued = 0;
	uint16_t idx = 0;

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

	slb_port_enqueue_stats(source_port, num_new, num_forward, num_release);

	/* Enqueue contiguous chunks targeting the same queue */
	while (idx < events_len) {
		if (events[idx].op == RTE_EVENT_OP_RELEASE) {
			idx++;
			enqueued++;
			continue;
		}

		uint8_t qid = events[idx].queue_id;
		uint16_t chunk_len = 1;

		while (idx + chunk_len < events_len &&
		       events[idx + chunk_len].queue_id == qid &&
		       events[idx + chunk_len].op != RTE_EVENT_OP_RELEASE) {
			chunk_len++;
		}

		struct slb_queue *queue = &slb->queues[qid];
		uint16_t actual_enq = rte_event_ring_enqueue_burst(queue->q_ring,
								  &events[idx],
								  chunk_len,
								  NULL);
		slb_port_queue_enqueue_burst_stats(source_port, qid, actual_enq);
		enqueued += actual_enq;

		if (actual_enq < chunk_len) {
			/* If queue ring is full, return unused credits for dropped NEW events */
			uint16_t dropped_new = 0;
			for (uint16_t d = actual_enq; d < chunk_len; d++) {
				if (events[idx + d].op == RTE_EVENT_OP_NEW)
					dropped_new++;
			}
			if (dropped_new > 0)
				slb_port_return_credits(slb, source_port, dropped_new);
			break;
		}

		idx += chunk_len;
	}

	return enqueued;
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
slb_port_dequeue(struct slb_port *port, struct rte_event events[],
		 uint16_t num)
{
	uint16_t total_deq = 0;

	/* Single-link direct fast path */
	if (port->is_single_linked) {
		if (unlikely(!port->single_linked_ring))
			return 0;

		total_deq = rte_event_ring_dequeue_burst(port->single_linked_ring,
							events, num, NULL);
		if (total_deq > 0) {
			port->total_dequeues += total_deq;
			if (port->implicit_release)
				slb_port_return_credits(port->slb, port,
							total_deq);
		}
		return total_deq;
	}

	/* Parallel queue dequeue across priority levels */
	for (int p = 0; p < SLB_MAX_PRIORITIES; p++) {
		uint16_t num_q = port->num_q[p];
		if (num_q == 0)
			continue;

		uint16_t q_idx = port->next_q[p];
		for (uint16_t i = 0; i < num_q; i++) {
			struct slb_port_q_entry *entry = &port->q_entries[p][q_idx];
			uint16_t req = num - total_deq;
			uint16_t deq = rte_event_ring_dequeue_burst(entry->dq_ring,
								   &events[total_deq],
								   req, NULL);
			if (deq > 0) {
				port->queue_dequeued[entry->queue_id] += deq;
				total_deq += deq;
			}

			q_idx++;
			if (q_idx >= num_q)
				q_idx = 0;

			if (total_deq == num)
				break;
		}
		port->next_q[p] = q_idx;

		if (total_deq > 0)
			break;
	}

	port->total_dequeues += total_deq;
	return total_deq;
}

uint16_t
slb_event_dequeue_burst(void *p, struct rte_event events[], uint16_t num,
			uint64_t wait __rte_unused)
{
	struct slb_port *port = p;

	port->dequeue_calls++;
	uint16_t dequeued = slb_port_dequeue(port, events, num);
	port->dequeued += dequeued;

	if (dequeued == 0)
		port->empty_dequeues++;

	return dequeued;
}

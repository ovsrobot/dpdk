/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2010-2017 Intel Corporation
 * Copyright (c) 2007-2009 Kip Macy kmacy@freebsd.org
 * All rights reserved.
 * Derived from FreeBSD's bufring.h
 * Used as BSD-3 Licensed with permission from Kip Macy.
 */

#ifndef _RTE_RING_GENERIC_PVT_H_
#define _RTE_RING_GENERIC_PVT_H_

/**
 * @file rte_ring_generic_pvt.h
 * It is not recommended to include this file directly,
 * include <rte_ring.h> instead.
 * Contains internal helper functions for MP/SP and MC/SC ring modes.
 * For more information please refer to <rte_ring.h>.
 */

/**
 * @internal This function updates tail values.
 */
static __rte_always_inline void
__rte_ring_update_tail(struct rte_ring_headtail *ht, uint32_t old_val,
		uint32_t new_val, uint32_t single,
		uint32_t enqueue __rte_unused)
{
	/*
	 * If there are other enqueues/dequeues in progress that preceded us,
	 * we need to wait for them to complete
	 */
	if (!single)
		rte_wait_until_equal_32((volatile uint32_t *)(uintptr_t)&ht->tail,
			old_val, rte_memory_order_relaxed);

	/*
	 * Release ordering on the tail store ensures that the slot reads
	 * (dequeue) or writes (enqueue) performed by this thread are visible
	 * to the other side before the new tail value is observed.
	 * Pairs with the acquire load of the counterpart's tail in
	 * __rte_ring_headtail_move_head().
	 */
	rte_atomic_store_explicit(&ht->tail, new_val, rte_memory_order_release);
}

/**
 * @internal This is a helper function that moves the producer/consumer head
 *
 * @param d
 *   A pointer to the headtail structure with head value to be moved
 * @param s
 *   A pointer to the counter-part headtail structure. Note that this
 *   function only reads tail value from it
 * @param capacity
 *   Either ring capacity value (for producer), or zero (for consumer)
 * @param is_st
 *   Indicates whether multi-thread safe path is needed or not
 * @param n
 *   The number of elements we want to move head value on
 * @param behavior
 *   RTE_RING_QUEUE_FIXED:    Move on a fixed number of items
 *   RTE_RING_QUEUE_VARIABLE: Move on as many items as possible
 * @param old_head
 *   Returns head value as it was before the move
 * @param new_head
 *   Returns the new head value
 * @param entries
 *   Returns the number of ring entries available BEFORE head was moved
 * @return
 *   Actual number of objects the head was moved on
 *   If behavior == RTE_RING_QUEUE_FIXED, this will be 0 or n only
 */
static __rte_always_inline unsigned int
__rte_ring_headtail_move_head(struct rte_ring_headtail *d,
		const struct rte_ring_headtail *s, uint32_t capacity,
		unsigned int is_st, unsigned int n,
		enum rte_ring_queue_behavior behavior,
		uint32_t *old_head, uint32_t *new_head, uint32_t *entries)
{
	unsigned int max = n;
	int success;
	uint32_t tail;

	do {
		/* Reset n to the initial burst count */
		n = max;

		/*
		 * Acquire load: orders this load before the load of s->tail
		 * below (replaces rte_smp_rmb() in the previous version) and
		 * re-establishes ordering after a failed CAS on retry.
		 */
		*old_head = rte_atomic_load_explicit(&d->head,
				rte_memory_order_acquire);

		/*
		 * Acquire load on the counterpart's tail pairs with the
		 * release store in __rte_ring_update_tail() on the other
		 * side, ensuring slot operations performed there are visible
		 * before the caller accesses the reserved slots.
		 */
		tail = rte_atomic_load_explicit(&s->tail, rte_memory_order_acquire);

		/*
		 *  The subtraction is done between two unsigned 32bits value
		 * (the result is always modulo 32 bits even if we have
		 * *old_head > tail). So 'entries' is always between 0
		 * and capacity (which is < size).
		 */
		*entries = (capacity + tail - *old_head);

		/* check that we have enough room in ring */
		if (unlikely(n > *entries))
			n = (behavior == RTE_RING_QUEUE_FIXED) ?
					0 : *entries;

		if (n == 0)
			return 0;

		*new_head = *old_head + n;
		if (is_st) {
			rte_atomic_store_explicit(&d->head, *new_head, rte_memory_order_relaxed);
			success = 1;
		} else {
			/*
			 * Weak CAS: the outer do-while handles spurious
			 * failures, so we avoid the strong variant's
			 * internal retry (which on arm64 wraps the LL/SC
			 * pair in a hidden inner loop).
			 *
			 * Relaxed on both success and failure: this CAS
			 * does not publish data. Slot data visibility is
			 * provided by the acquire loads above and the
			 * release store of tail in __rte_ring_update_tail().
			 */
			success = rte_atomic_compare_exchange_weak_explicit(
				&d->head, old_head, *new_head,
				rte_memory_order_relaxed, rte_memory_order_relaxed);
		}
	} while (unlikely(success == 0));
	return n;
}

#endif /* _RTE_RING_GENERIC_PVT_H_ */

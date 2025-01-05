/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2010-2020 Intel Corporation
 * Copyright (c) 2007-2009 Kip Macy kmacy@freebsd.org
 * All rights reserved.
 * Derived from FreeBSD's bufring.h
 * Used as BSD-3 Licensed with permission from Kip Macy.
 */

#ifndef _RTE_RING_RTS_ELEM_PVT_H_
#define _RTE_RING_RTS_ELEM_PVT_H_

/**
 * @file rte_ring_rts_elem_pvt.h
 * It is not recommended to include this file directly,
 * include <rte_ring.h> instead.
 * Contains internal helper functions for Relaxed Tail Sync (RTS) ring mode.
 * For more information please refer to <rte_ring_rts.h>.
 */

/**
 * @internal This function updates tail values.
 */
static __rte_always_inline void
__rte_ring_rts_update_tail(struct rte_ring_rts_headtail *ht)
{
	union __rte_ring_rts_poscnt h, ot, nt;

	/*
	 * If there are other enqueues/dequeues in progress that
	 * might preceded us, then don't update tail with new value.
	 */

	ot.raw = rte_atomic_load_explicit(&ht->tail.raw, rte_memory_order_acquire);

	do {
		/* on 32-bit systems we have to do atomic read here */
		h.raw = rte_atomic_load_explicit(&ht->head.raw, rte_memory_order_relaxed);

		nt.raw = ot.raw;
		if (++nt.val.cnt == h.val.cnt)
			nt.val.pos = h.val.pos;

	} while (rte_atomic_compare_exchange_strong_explicit(&ht->tail.raw,
			(uint64_t *)(uintptr_t)&ot.raw, nt.raw,
			rte_memory_order_release, rte_memory_order_acquire) == 0);
}

/**
 * @file rte_ring_rts_elem_pvt.h
 * It is not recommended to include this file directly,
 * include <rte_ring.h> instead.
 * Contains internal helper functions for Relaxed Tail Sync (RTS) ring mode.
 * For more information please refer to <rte_ring_rts.h>.
 */

/**
 * @internal This function updates tail values.
 */
static __rte_always_inline void
__rte_ring_rts_v2_update_tail(struct rte_ring_rts_headtail *ht,
	uint32_t old_tail, uint32_t num, uint32_t mask)
{
	union __rte_ring_rts_poscnt ot, nt;

	ot.val.cnt = nt.val.cnt = 0;
	ot.val.pos = old_tail;
	nt.val.pos = old_tail + num;

	/*
	 * If the tail is equal to the current enqueues/dequeues, update
	 * the tail with new value and then continue to try to update the
	 * tail until the num of the cache is 0, otherwise write the num of
	 * the current enqueues/dequeues to the cache.
	 */

	if (rte_atomic_compare_exchange_strong_explicit(&ht->tail.raw,
				(uint64_t *)(uintptr_t)&ot.raw, nt.raw,
				rte_memory_order_release, rte_memory_order_acquire) == 0) {
		ot.val.pos = old_tail;

		/*
		 * Write the num of the current enqueues/dequeues to the
		 * corresponding cache.
		 */
		rte_atomic_store_explicit(&ht->rts_cache[ot.val.pos & mask].num,
			num, rte_memory_order_release);

		/*
		 * There may be competition with another enqueues/dequeues
		 * for the update tail. The winner continues to try to update
		 * the tail, and the loser exits.
		 */
		if (rte_atomic_compare_exchange_strong_explicit(&ht->tail.raw,
					(uint64_t *)(uintptr_t)&ot.raw, nt.raw,
					rte_memory_order_release, rte_memory_order_acquire) == 0)
			return;

		/*
		 * Set the corresponding cache to 0 for next use.
		 */
		rte_atomic_store_explicit(&ht->rts_cache[ot.val.pos & mask].num,
			0, rte_memory_order_release);
	}

	/*
	 * Try to update the tail until the num of the corresponding cache is 0.
	 * Getting here means that the current enqueues/dequeues is trying to update
	 * the tail of another enqueues/dequeues.
	 */
	while (1) {
		num = rte_atomic_load_explicit(&ht->rts_cache[nt.val.pos & mask].num,
			rte_memory_order_acquire);
		if (num == 0)
			break;

		ot.val.pos = nt.val.pos;
		nt.val.pos += num;

		/*
		 * There may be competition with another enqueues/dequeues
		 * for the update tail. The winner continues to try to update
		 * the tail, and the loser exits.
		 */
		if (rte_atomic_compare_exchange_strong_explicit(&ht->tail.raw,
					(uint64_t *)(uintptr_t)&ot.raw, nt.raw,
					rte_memory_order_release, rte_memory_order_acquire) == 0)
			return;

		rte_atomic_store_explicit(&ht->rts_cache[ot.val.pos & mask].num,
			0, rte_memory_order_release);
	};
}

/**
 * @internal This function waits till head/tail distance wouldn't
 * exceed pre-defined max value.
 */
static __rte_always_inline void
__rte_ring_rts_head_wait(const struct rte_ring_rts_headtail *ht,
	union __rte_ring_rts_poscnt *h)
{
	uint32_t max;

	max = ht->htd_max;

	while (h->val.pos - ht->tail.val.pos > max) {
		rte_pause();
		h->raw = rte_atomic_load_explicit(&ht->head.raw, rte_memory_order_acquire);
	}
}

/**
 * @internal This function updates the producer head for enqueue.
 */
static __rte_always_inline uint32_t
__rte_ring_rts_move_prod_head(struct rte_ring *r, uint32_t num,
	enum rte_ring_queue_behavior behavior, uint32_t *old_head,
	uint32_t *free_entries)
{
	uint32_t n;
	union __rte_ring_rts_poscnt nh, oh;

	const uint32_t capacity = r->capacity;

	oh.raw = rte_atomic_load_explicit(&r->rts_prod.head.raw, rte_memory_order_acquire);

	do {
		/* Reset n to the initial burst count */
		n = num;

		/*
		 * wait for prod head/tail distance,
		 * make sure that we read prod head *before*
		 * reading cons tail.
		 */
		__rte_ring_rts_head_wait(&r->rts_prod, &oh);

		/*
		 *  The subtraction is done between two unsigned 32bits value
		 * (the result is always modulo 32 bits even if we have
		 * *old_head > cons_tail). So 'free_entries' is always between 0
		 * and capacity (which is < size).
		 */
		*free_entries = capacity + r->cons.tail - oh.val.pos;

		/* check that we have enough room in ring */
		if (unlikely(n > *free_entries))
			n = (behavior == RTE_RING_QUEUE_FIXED) ?
					0 : *free_entries;

		if (n == 0)
			break;

		nh.val.pos = oh.val.pos + n;
		nh.val.cnt = oh.val.cnt + 1;

	/*
	 * this CAS(ACQUIRE, ACQUIRE) serves as a hoist barrier to prevent:
	 *  - OOO reads of cons tail value
	 *  - OOO copy of elems to the ring
	 */
	} while (rte_atomic_compare_exchange_strong_explicit(&r->rts_prod.head.raw,
			(uint64_t *)(uintptr_t)&oh.raw, nh.raw,
			rte_memory_order_acquire, rte_memory_order_acquire) == 0);

	*old_head = oh.val.pos;
	return n;
}

/**
 * @internal This function updates the consumer head for dequeue
 */
static __rte_always_inline unsigned int
__rte_ring_rts_move_cons_head(struct rte_ring *r, uint32_t num,
	enum rte_ring_queue_behavior behavior, uint32_t *old_head,
	uint32_t *entries)
{
	uint32_t n;
	union __rte_ring_rts_poscnt nh, oh;

	oh.raw = rte_atomic_load_explicit(&r->rts_cons.head.raw, rte_memory_order_acquire);

	/* move cons.head atomically */
	do {
		/* Restore n as it may change every loop */
		n = num;

		/*
		 * wait for cons head/tail distance,
		 * make sure that we read cons head *before*
		 * reading prod tail.
		 */
		__rte_ring_rts_head_wait(&r->rts_cons, &oh);

		/* The subtraction is done between two unsigned 32bits value
		 * (the result is always modulo 32 bits even if we have
		 * cons_head > prod_tail). So 'entries' is always between 0
		 * and size(ring)-1.
		 */
		*entries = r->prod.tail - oh.val.pos;

		/* Set the actual entries for dequeue */
		if (n > *entries)
			n = (behavior == RTE_RING_QUEUE_FIXED) ? 0 : *entries;

		if (unlikely(n == 0))
			break;

		nh.val.pos = oh.val.pos + n;
		nh.val.cnt = oh.val.cnt + 1;

	/*
	 * this CAS(ACQUIRE, ACQUIRE) serves as a hoist barrier to prevent:
	 *  - OOO reads of prod tail value
	 *  - OOO copy of elems from the ring
	 */
	} while (rte_atomic_compare_exchange_strong_explicit(&r->rts_cons.head.raw,
			(uint64_t *)(uintptr_t)&oh.raw, nh.raw,
			rte_memory_order_acquire, rte_memory_order_acquire) == 0);

	*old_head = oh.val.pos;
	return n;
}

/**
 * @internal Enqueue several objects on the RTS ring.
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_table
 *   A pointer to a table of objects.
 * @param esize
 *   The size of ring element, in bytes. It must be a multiple of 4.
 *   This must be the same value used while creating the ring. Otherwise
 *   the results are undefined.
 * @param n
 *   The number of objects to add in the ring from the obj_table.
 * @param behavior
 *   RTE_RING_QUEUE_FIXED:    Enqueue a fixed number of items from a ring
 *   RTE_RING_QUEUE_VARIABLE: Enqueue as many items as possible from ring
 * @param free_space
 *   returns the amount of space after the enqueue operation has finished
 * @return
 *   Actual number of objects enqueued.
 *   If behavior == RTE_RING_QUEUE_FIXED, this will be 0 or n only.
 */
static __rte_always_inline unsigned int
__rte_ring_do_rts_enqueue_elem(struct rte_ring *r, const void *obj_table,
	uint32_t esize, uint32_t n, enum rte_ring_queue_behavior behavior,
	uint32_t *free_space)
{
	uint32_t free, head;

	n =  __rte_ring_rts_move_prod_head(r, n, behavior, &head, &free);

	if (n != 0) {
		__rte_ring_enqueue_elems(r, head, obj_table, esize, n);
		__rte_ring_rts_update_tail(&r->rts_prod);
	}

	if (free_space != NULL)
		*free_space = free - n;
	return n;
}

/**
 * @internal Enqueue several objects on the RTS ring.
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_table
 *   A pointer to a table of objects.
 * @param esize
 *   The size of ring element, in bytes. It must be a multiple of 4.
 *   This must be the same value used while creating the ring. Otherwise
 *   the results are undefined.
 * @param n
 *   The number of objects to add in the ring from the obj_table.
 * @param behavior
 *   RTE_RING_QUEUE_FIXED:    Enqueue a fixed number of items from a ring
 *   RTE_RING_QUEUE_VARIABLE: Enqueue as many items as possible from ring
 * @param free_space
 *   returns the amount of space after the enqueue operation has finished
 * @return
 *   Actual number of objects enqueued.
 *   If behavior == RTE_RING_QUEUE_FIXED, this will be 0 or n only.
 */
static __rte_always_inline unsigned int
__rte_ring_do_rts_v2_enqueue_elem(struct rte_ring *r, const void *obj_table,
	uint32_t esize, uint32_t n, enum rte_ring_queue_behavior behavior,
	uint32_t *free_space)
{
	uint32_t free, head;

	n =  __rte_ring_rts_move_prod_head(r, n, behavior, &head, &free);

	if (n != 0) {
		__rte_ring_enqueue_elems(r, head, obj_table, esize, n);
		__rte_ring_rts_v2_update_tail(&r->rts_prod, head, n, r->mask);
	}

	if (free_space != NULL)
		*free_space = free - n;
	return n;
}

/**
 * @internal Dequeue several objects from the RTS ring.
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_table
 *   A pointer to a table of objects.
 * @param esize
 *   The size of ring element, in bytes. It must be a multiple of 4.
 *   This must be the same value used while creating the ring. Otherwise
 *   the results are undefined.
 * @param n
 *   The number of objects to pull from the ring.
 * @param behavior
 *   RTE_RING_QUEUE_FIXED:    Dequeue a fixed number of items from a ring
 *   RTE_RING_QUEUE_VARIABLE: Dequeue as many items as possible from ring
 * @param available
 *   returns the number of remaining ring entries after the dequeue has finished
 * @return
 *   - Actual number of objects dequeued.
 *     If behavior == RTE_RING_QUEUE_FIXED, this will be 0 or n only.
 */
static __rte_always_inline unsigned int
__rte_ring_do_rts_dequeue_elem(struct rte_ring *r, void *obj_table,
	uint32_t esize, uint32_t n, enum rte_ring_queue_behavior behavior,
	uint32_t *available)
{
	uint32_t entries, head;

	n = __rte_ring_rts_move_cons_head(r, n, behavior, &head, &entries);

	if (n != 0) {
		__rte_ring_dequeue_elems(r, head, obj_table, esize, n);
		__rte_ring_rts_update_tail(&r->rts_cons);
	}

	if (available != NULL)
		*available = entries - n;
	return n;
}

/**
 * @internal Dequeue several objects from the RTS ring.
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_table
 *   A pointer to a table of objects.
 * @param esize
 *   The size of ring element, in bytes. It must be a multiple of 4.
 *   This must be the same value used while creating the ring. Otherwise
 *   the results are undefined.
 * @param n
 *   The number of objects to pull from the ring.
 * @param behavior
 *   RTE_RING_QUEUE_FIXED:    Dequeue a fixed number of items from a ring
 *   RTE_RING_QUEUE_VARIABLE: Dequeue as many items as possible from ring
 * @param available
 *   returns the number of remaining ring entries after the dequeue has finished
 * @return
 *   - Actual number of objects dequeued.
 *     If behavior == RTE_RING_QUEUE_FIXED, this will be 0 or n only.
 */
static __rte_always_inline unsigned int
__rte_ring_do_rts_v2_dequeue_elem(struct rte_ring *r, void *obj_table,
	uint32_t esize, uint32_t n, enum rte_ring_queue_behavior behavior,
	uint32_t *available)
{
	uint32_t entries, head;

	n = __rte_ring_rts_move_cons_head(r, n, behavior, &head, &entries);

	if (n != 0) {
		__rte_ring_dequeue_elems(r, head, obj_table, esize, n);
		__rte_ring_rts_v2_update_tail(&r->rts_cons, head, n, r->mask);
	}

	if (available != NULL)
		*available = entries - n;
	return n;
}

#endif /* _RTE_RING_RTS_ELEM_PVT_H_ */

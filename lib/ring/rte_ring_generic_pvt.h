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

static __rte_always_inline void
__rte_ring_update_tail(struct rte_ring_headtail *ht, uint32_t old_val,
		uint32_t new_val, uint32_t single, uint32_t enqueue)
{
	if (enqueue)
		rte_smp_wmb();
	else
		rte_smp_rmb();
	/*
	 * If there are other enqueues/dequeues in progress that preceded us,
	 * we need to wait for them to complete
	 */
	if (!single)
		rte_wait_until_equal_32((volatile uint32_t *)(uintptr_t)&ht->tail, old_val,
			rte_memory_order_relaxed);

	ht->tail = new_val;
}

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
	union __rte_ring_head_cft nh, oh;

	oh.raw = rte_atomic_load_explicit(&d->head.raw,
			rte_memory_order_acquire);

	do {
		/* Reset n to the initial burst count */
		n = max;

		*old_head = oh.val.pos;
		tail = oh.val.cft;

		/*
		 *  The subtraction is done between two unsigned 32bits value
		 * (the result is always modulo 32 bits even if we have
		 * *old_head > s->tail). So 'free_entries' is always between 0
		 * and capacity (which is < size).
		 */
		*entries = (capacity + tail - *old_head);

		/* attempt #1: check that we have enough room with
		 * cached-foreign-tail value.
		 * Note that actual tail value can go forward till we cached
		 * it, in that case we might have to update our cached value.
		 */
		if (unlikely(n > *entries)) {

			tail = rte_atomic_load_explicit(&s->tail,
				rte_memory_order_relaxed);
			*entries = (capacity + tail - *old_head);

			/* attempt #2: check that we have enough room in ring */
			if (unlikely(n > *entries))
				n = (behavior == RTE_RING_QUEUE_FIXED) ?
					0 : *entries;
		}

		if (n == 0)
			return 0;

		*new_head = *old_head + n;
		nh.val.pos = *new_head;
		nh.val.cft = tail;

		if (is_st) {
			d->head.raw = nh.raw;
			success = 1;
		} else
			success = rte_atomic_compare_exchange_strong_explicit(
				&d->head.raw, (uint64_t *)(uintptr_t)&oh.raw,
				nh.raw, rte_memory_order_acquire,
				rte_memory_order_acquire);

	} while (unlikely(success == 0));
	return n;
}

#endif /* _RTE_RING_GENERIC_PVT_H_ */

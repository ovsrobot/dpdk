/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2017,2018 HXT-semitech Corporation.
 * Copyright (c) 2007-2009 Kip Macy kmacy@freebsd.org
 * Copyright (c) 2021 Arm Limited
 * All rights reserved.
 * Derived from FreeBSD's bufring.h
 * Used as BSD-3 Licensed with permission from Kip Macy.
 */

#ifndef _RTE_RING_C11_PVT_H_
#define _RTE_RING_C11_PVT_H_

static __rte_always_inline void
__rte_ring_update_tail(struct rte_ring_headtail *ht, uint32_t old_val,
		uint32_t new_val, uint32_t single, uint32_t enqueue)
{
	RTE_SET_USED(enqueue);

	/*
	 * If there are other enqueues/dequeues in progress that preceded us,
	 * we need to wait for them to complete
	 */
	if (!single)
		rte_wait_until_equal_32((uint32_t *)(uintptr_t)&ht->tail, old_val,
			rte_memory_order_relaxed);

	rte_atomic_store_explicit(&ht->tail, new_val, rte_memory_order_release);
}

static __rte_always_inline unsigned int
__rte_ring_headtail_move_head(struct rte_ring_headtail *d,
		const struct rte_ring_headtail *s, uint32_t capacity,
		unsigned int is_st, unsigned int n,
		enum rte_ring_queue_behavior behavior,
		uint32_t *old_head, uint32_t *new_head, uint32_t *entries)
{
	uint32_t stail;
	int success;
	unsigned int max = n;

	*old_head = rte_atomic_load_explicit(&d->head,
			rte_memory_order_relaxed);
	do {
		/* Reset n to the initial burst count */
		n = max;

		/* Ensure the head is read before tail */
		rte_atomic_thread_fence(rte_memory_order_acquire);

		/* load-acquire synchronize with store-release of ht->tail
		 * in update_tail.
		 */
		stail = rte_atomic_load_explicit(&s->tail,
					rte_memory_order_acquire);

		/* The subtraction is done between two unsigned 32bits value
		 * (the result is always modulo 32 bits even if we have
		 * *old_head > s->tail). So 'free_entries' is always between 0
		 * and capacity (which is < size).
		 */
		*entries = (capacity + stail - *old_head);

		/* check that we have enough room in ring */
		if (unlikely(n > *entries))
			n = (behavior == RTE_RING_QUEUE_FIXED) ?
					0 : *entries;

		if (n == 0)
			return 0;

		*new_head = *old_head + n;
		if (is_st) {
			d->head = *new_head;
			success = 1;
		} else
			/* on failure, *old_head is updated */
			success = rte_atomic_compare_exchange_strong_explicit(
					&d->head, old_head, *new_head,
					rte_memory_order_relaxed,
					rte_memory_order_relaxed);
	} while (unlikely(success == 0));
	return n;
}

#endif /* _RTE_RING_C11_PVT_H_ */

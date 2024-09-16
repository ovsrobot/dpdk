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

	do {
		/* Reset n to the initial burst count */
		n = max;

		*old_head = d->head;

		/* add rmb barrier to avoid load/load reorder in weak
		 * memory model. It is noop on x86
		 */
		rte_smp_rmb();

		/*
		 *  The subtraction is done between two unsigned 32bits value
		 * (the result is always modulo 32 bits even if we have
		 * *old_head > s->tail). So 'free_entries' is always between 0
		 * and capacity (which is < size).
		 */
		*entries = (capacity + s->tail - *old_head);

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
			success = rte_atomic32_cmpset(
					(uint32_t *)(uintptr_t)&d->head,
					*old_head, *new_head);
	} while (unlikely(success == 0));
	return n;
}

#endif /* _RTE_RING_GENERIC_PVT_H_ */

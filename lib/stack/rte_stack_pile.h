/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 SmartShare Systems
 */

#ifndef _RTE_STACK_PILE_H_
#define _RTE_STACK_PILE_H_

#include <rte_memcpy.h>

#include "rte_stack_lf.h"
#ifdef RTE_STACK_LF_SUPPORTED
/**
 * Indicates that RTE_STACK_F_PILE is supported.
 */
#define RTE_STACK_PILE_SUPPORTED
#endif

static __rte_always_inline unsigned int
__rte_stack_pile_count(struct rte_stack *s)
{
	/* stack_lf_push() and stack_lf_pop() do not update the list's contents
	 * and stack_lf->len atomically, which can cause the list to appear
	 * shorter than it actually is if this function is called while other
	 * threads are modifying the list.
	 *
	 * However, given the inherently approximate nature of the get_count
	 * callback -- even if the list and its size were updated atomically,
	 * the size could change between when get_count executes and when the
	 * value is returned to the caller -- this is acceptable.
	 *
	 * The stack_lf->len updates are placed such that the list may appear to
	 * have fewer elements than it does, but will never appear to have more
	 * elements. If the mempool is near-empty to the point that this is a
	 * concern, the user should consider increasing the mempool size.
	 */
#ifdef RTE_USE_C11_MEM_MODEL
	return RTE_MIN((unsigned int)s->capacity,
			(unsigned int)rte_atomic_load_explicit(&s->stack_pile.bulk.len,
			rte_memory_order_relaxed) * RTE_STACK_PILE_BULK_SIZE +
			(unsigned int)rte_atomic_load_explicit(&s->stack_pile.solo.len,
			rte_memory_order_relaxed));
#else /* FIXME: Remove if removed from lock-free stack. */
	/* NOTE: review for potential ordering optimization */
	return RTE_MIN((unsigned int)s->capacity,
			(unsigned int)rte_atomic_load_explicit(&s->stack_pile.bulk.len,
			rte_memory_order_seq_cst) * RTE_STACK_PILE_BULK_SIZE +
			(unsigned int)rte_atomic_load_explicit(&s->stack_pile.solo.len,
			rte_memory_order_seq_cst));
#endif
}

static __rte_always_inline void
__rte_stack_pile_bulk_push_elems(struct rte_stack_lf_list *list,
		struct rte_stack_pile_bulk_elem *first,
		struct rte_stack_pile_bulk_elem *last,
		unsigned int num)
{
	__rte_stack_lf_push_elems(list,
		(struct rte_stack_lf_elem *)first,
		(struct rte_stack_lf_elem *)last,
		num);
}

static __rte_always_inline struct rte_stack_pile_bulk_elem *
__rte_stack_pile_bulk_pop_elems(struct rte_stack_lf_list *list,
		unsigned int num,
		void ** __rte_restrict obj_table,
		struct rte_stack_pile_bulk_elem **last)
{
	struct rte_stack_pile_bulk_elem *first = (struct rte_stack_pile_bulk_elem *)
			__rte_stack_lf_pop_elems(list, num, NULL,
			(struct rte_stack_lf_elem **)last);
	if (first == NULL)
		return NULL;

	if (obj_table != NULL) {
		/* Traverse the list to copy the bulks. */
		struct rte_stack_pile_bulk_elem *tmp = first;
		for (unsigned int i = 0; i < num; i++, tmp = tmp->next)
			rte_memcpy(&obj_table[i * RTE_STACK_PILE_BULK_SIZE], tmp->objs,
					sizeof(void *) * RTE_STACK_PILE_BULK_SIZE);
	}

	return first;
}

/**
 * Push several objects on the pile (lock-free, MT-safe).
 *
 * @param pile
 *   A pointer to the pile structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects).
 * @param n
 *   The number of objects to push on the pile from the obj_table.
 * @return
 *   Actual number of objects pushed (either 0 or *n*).
 */
static __rte_always_inline unsigned int
__rte_stack_pile_push(struct rte_stack *s,
		void * const * __rte_restrict obj_table,
		unsigned int n)
{
	RTE_ASSERT(s != NULL);
	RTE_ASSERT(obj_table != NULL);

	struct rte_stack_pile *pile = &s->stack_pile;
	struct rte_stack_pile_bulk_elem *bulk_first = NULL, *bulk_last = NULL, *tmp_bulk;
	struct rte_stack_lf_elem *solo_first = NULL, *solo_last = NULL, *tmp_solo;
	unsigned int n_bulk = n / RTE_STACK_PILE_BULK_SIZE;
	unsigned int n_solo = n & (RTE_STACK_PILE_BULK_SIZE - 1);
	unsigned int i;

	if (unlikely(n_bulk == 0)) {
		if (unlikely(n_solo == 0))
			return 0;
		goto solo;
	}

	/* Allocate n_bulk elements from the free list. */
	bulk_first = __rte_stack_pile_bulk_pop_elems(&pile->free_bulk, n_bulk, NULL, &bulk_last);
	if (unlikely(bulk_first == NULL))
		return 0; /* Failed. */

	if (likely(n_solo == 0))
		goto bulk;

solo:
	/* Allocate n_solo elements from the free list. */
	solo_first = __rte_stack_lf_pop_elems(&pile->free_solo, n_solo, NULL, &solo_last);
	if (unlikely(solo_first == NULL)) {
		/* Failed. Roll back. */
		if (n_bulk > 0)
			__rte_stack_pile_bulk_push_elems(&pile->free_bulk,
					bulk_first, bulk_last, n_bulk);
		return 0;
	}

	/*
	 * Construct the solo elements.
	 * Copy the objects, but ignore the object order.
	 */
	tmp_solo = solo_first;
	__rte_assume(n_solo > 0);
	__rte_assume(n_solo < RTE_STACK_PILE_BULK_SIZE);
	for (i = 0; i < n_solo; i++, tmp_solo = tmp_solo->next)
		tmp_solo->data = obj_table[n_bulk * RTE_STACK_PILE_BULK_SIZE + i];

	/* Push them to the solo list. */
	__rte_stack_lf_push_elems(&pile->solo, solo_first, solo_last, n_solo);

	if (unlikely(n_bulk == 0))
		return n; /* Done. */

bulk:
	/*
	 * Construct the bulk elements.
	 * Copy bulks in reverse order, but ignore the object order within each bulk.
	 */
	tmp_bulk = bulk_first;
	__rte_assume(n_bulk > 0);
	for (i = 0; i < n_bulk; i++, tmp_bulk = tmp_bulk->next)
		rte_memcpy(tmp_bulk->objs, &obj_table[(n_bulk - i - 1) * RTE_STACK_PILE_BULK_SIZE],
				sizeof(void *) * RTE_STACK_PILE_BULK_SIZE);

	/* Push them to the bulk list. */
	__rte_stack_pile_bulk_push_elems(&pile->bulk, bulk_first, bulk_last, n_bulk);

	return n;
}

/**
 * Pop several objects from the pile (lock-free, MT-safe).
 *
 * @param pile
 *   A pointer to the pile structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects).
 * @param n
 *   The number of objects to pull from the pile.
 * @return
 *   Actual number of objects popped (either 0 or *n*).
 */
static __rte_always_inline unsigned int
__rte_stack_pile_pop(struct rte_stack *s,
		void ** __rte_restrict obj_table,
		unsigned int n)
{
	RTE_ASSERT(s != NULL);
	RTE_ASSERT(obj_table != NULL);

	struct rte_stack_pile *pile = &s->stack_pile;
	struct rte_stack_pile_bulk_elem *bulk_first = NULL, *bulk_last = NULL;
	struct rte_stack_lf_elem *solo_first = NULL, *solo_last = NULL;
	unsigned int n_bulk = n / RTE_STACK_PILE_BULK_SIZE;
	unsigned int n_solo = n & (RTE_STACK_PILE_BULK_SIZE - 1);
	unsigned int i;

	if (unlikely(n_bulk == 0)) {
		if (unlikely(n_solo == 0))
			return 0;
		goto solo;
	}

bulk:
	/* Fetch n_bulk * RTE_STACK_PILE_BULK_SIZE objects as bulk elements. */
	bulk_first = __rte_stack_pile_bulk_pop_elems(&pile->bulk, n_bulk, obj_table, &bulk_last);
	if (unlikely(bulk_first == NULL)) {
		/*
		 * Not available.
		 * Retry with fewer bulk elements; objects to be fetched as solo elements instead.
		 */
		n_solo += RTE_STACK_PILE_BULK_SIZE;
		n_bulk--;
		if (n_bulk > 0)
			goto bulk;
		else
			goto solo;
	}

	if (likely(n_solo == 0))
		goto done;

solo:
	/* Fetch n_solo objects as solo elements. */
	solo_first = __rte_stack_lf_pop_elems(&pile->solo, n_solo,
			&obj_table[n_bulk * RTE_STACK_PILE_BULK_SIZE], &solo_last);
	if (solo_first != NULL)
		goto done;

	/* Solo elements not available. Try fragmentation. */
	alignas(RTE_CACHE_LINE_SIZE) void *obj_frag[RTE_STACK_PILE_BULK_SIZE];
	struct rte_stack_pile_bulk_elem *frag;

	/* Fetch a fragmentation element as a bulk element. */
	frag = __rte_stack_pile_bulk_pop_elems(&pile->bulk, 1, obj_frag, NULL);
	if (unlikely(frag == NULL)) {
		/* Failed. Roll back. */
		if (n_bulk > 0)
			__rte_stack_pile_bulk_push_elems(&pile->bulk,
					bulk_first, bulk_last, n_bulk);
		return 0;
	}

	/* Get n_solo objects from the fragmentation element. */
	__rte_assume(n_solo > 0);
	__rte_assume(n_solo < RTE_STACK_PILE_BULK_SIZE);
	for (i = 0; i < n_solo; i++)
		obj_table[n_bulk * RTE_STACK_PILE_BULK_SIZE + i] = obj_frag[i];

	/* Fetch free elements for the excess objects. */
	__rte_assume(RTE_STACK_PILE_BULK_SIZE - n_solo > 0);
	__rte_assume(RTE_STACK_PILE_BULK_SIZE - n_solo < RTE_STACK_PILE_BULK_SIZE - 1);
	solo_first = __rte_stack_lf_pop_elems(&pile->free_solo,
			RTE_STACK_PILE_BULK_SIZE - n_solo, NULL, &solo_last);
	if (unlikely(solo_first == NULL)) {
		/* Failed. Roll back. */
		if (n_bulk > 0) {
			/* Attach the fragmentation element after the bulk elements. */
			bulk_last->next = frag;
		} else {
			bulk_first = frag;
			bulk_last = frag;
		}
		__rte_stack_pile_bulk_push_elems(&pile->bulk, bulk_first, bulk_last, 1 + n_bulk);
		return 0;
	}

	/* Construct the solo elements from the excess objects. */
	struct rte_stack_lf_elem *tmp = solo_first;
	__rte_assume(n_solo > 0);
	__rte_assume(n_solo < RTE_STACK_PILE_BULK_SIZE);
	for (i = n_solo; i < RTE_STACK_PILE_BULK_SIZE; i++, tmp = tmp->next)
		tmp->data = obj_frag[i];

	/* Push the excess objects as solo elements. */
	__rte_stack_lf_push_elems(&pile->solo, solo_first, solo_last,
			RTE_STACK_PILE_BULK_SIZE - n_solo);
	n_solo = 0;

	/* Add the fragmentation element in front of the bulk elements, so it can be freed. */
	if (n_bulk > 0)
		frag->next = bulk_first;
	else
		bulk_last = frag;
	bulk_first = frag;
	n_bulk++;

done:
	/* Success. Free the elements. */
	if (n_bulk > 0)
		__rte_stack_pile_bulk_push_elems(&pile->free_bulk, bulk_first, bulk_last, n_bulk);
	if (n_solo > 0)
		__rte_stack_lf_push_elems(&pile->free_solo, solo_first, solo_last, n_solo);

	return n;
}

/**
 * @internal Initialize a pile stack.
 *
 * @param s
 *   A pointer to the stack structure.
 * @param count
 *   The size of the stack.
 */
void
rte_stack_pile_init(struct rte_stack *s, unsigned int count);

/**
 * @internal Return the memory required for a pile stack.
 *
 * @param count
 *   The size of the stack.
 * @return
 *   The bytes to allocate for a pile stack.
 */
ssize_t
rte_stack_pile_get_memsize(unsigned int count);

#endif /* _RTE_STACK_PILE_H_ */

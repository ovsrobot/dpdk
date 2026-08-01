/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 SmartShare Systems
 */

#include "rte_stack.h"

void
rte_stack_pile_init(struct rte_stack *s, unsigned int count)
{
    unsigned int bulk = (count + RTE_STACK_PILE_BULK_SIZE - 1) / RTE_STACK_PILE_BULK_SIZE;
	struct rte_stack_pile_bulk_elem * bulk_elems = (struct rte_stack_pile_bulk_elem *)(&s->stack_pile + 1);
	struct rte_stack_lf_elem * solo_elems = (struct rte_stack_lf_elem *)&bulk_elems[bulk];
	unsigned int i;

	for (i = 0; i < bulk; i++)
		__rte_stack_pile_bulk_push_elems(&s->stack_pile.free_bulk,
					  &bulk_elems[i], &bulk_elems[i], 1);
	for (i = 0; i < count; i++)
		__rte_stack_lf_push_elems(&s->stack_pile.free_solo,
					  &solo_elems[i], &solo_elems[i], 1);
}

ssize_t
rte_stack_pile_get_memsize(unsigned int count)
{
    unsigned int bulk = (count + RTE_STACK_PILE_BULK_SIZE - 1) / RTE_STACK_PILE_BULK_SIZE;
	ssize_t sz = sizeof(struct rte_stack); /* Already cache line aligned. */
	sz += bulk * sizeof(struct rte_stack_pile_bulk_elem); /* Already cache line aligned. */
	sz += RTE_CACHE_LINE_ROUNDUP(count * sizeof(struct rte_stack_lf_elem));
	sz += RTE_CACHE_GUARD_LINES * RTE_CACHE_LINE_SIZE;

	return sz;
}

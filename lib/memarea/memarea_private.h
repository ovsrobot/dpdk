/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 HiSilicon Limited
 */

#ifndef MEMAREA_PRIVATE_H
#define MEMAREA_PRIVATE_H

#include <rte_memarea.h>

#define MEMAREA_FREE_ELEM_COOKIE	0xFFFFFFFF

struct memarea_elem {
	size_t   size;
	uint32_t cookie;
	int32_t  refcnt; /* Non-zero indicates that it has been allocated */
	TAILQ_ENTRY(memarea_elem) elem_node;
	TAILQ_ENTRY(memarea_elem) free_node;
} __rte_cache_aligned;

TAILQ_HEAD(memarea_elem_list, memarea_elem);

struct memarea_private {
	struct rte_memarea_param init;
	rte_spinlock_t           lock;
	void                    *area_addr;
	struct memarea_elem_list elem_list;
	struct memarea_elem_list free_list;

	uint64_t alloc_fails;
	uint64_t refcnt_check_fails;
} __rte_cache_aligned;

#endif /* MEMAREA_PRIVATE_H */

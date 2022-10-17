/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 HiSilicon Limited
 */

#ifndef MEMAREA_PRIVATE_H
#define MEMAREA_PRIVATE_H

#include <rte_memarea.h>

#define MEMAREA_AVAILABLE_ELEM_MAGIC	0xbeef1234
#define MEMAREA_ALLOCATED_ELEM_MAGIC	0xbeef1230
#define MEMAREA_AVAILABLE_ELEM_COOKIE	0xffffffff

struct memarea_elem {
	TAILQ_ENTRY(memarea_elem) elem_node;
	TAILQ_ENTRY(memarea_elem) free_node;
	size_t   size;
	uint32_t magic;
	uint32_t cookie;
	int32_t  refcnt; /* Non-zero indicates that it has been allocated */
} __rte_cache_aligned;

TAILQ_HEAD(memarea_elem_list, memarea_elem);

struct rte_memarea {
	struct rte_memarea_param init;
	rte_spinlock_t           lock;
	void                    *area_addr;
	struct memarea_elem_list elem_list;
	struct memarea_elem_list free_list;
} __rte_cache_aligned;

#endif /* MEMAREA_PRIVATE_H */

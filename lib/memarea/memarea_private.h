/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 HiSilicon Limited
 */

#ifndef MEMAREA_PRIVATE_H
#define MEMAREA_PRIVATE_H

#include <rte_memarea.h>

#define MEMAREA_OBJECT_ALLOCATED_MAGIC	0xbeef1234
#define MEMAREA_OBJECT_FREE_MAGIC	0xbeefabcd

/*
 * The internal layout of free memory object:
 * ------------------------------------------------------------------------------------
 * | object-1 |                                                        | object-2 | ...
 * ------------------------------------------------------------------------------------
 *          ->|                object-1's size                         |<-
 *
 *
 * The internal layout of allocated memory object:
 * ------------------------------------------------------------------------------------
 * | object-1 | space-A | offset |   application-allocated   | space-B | object-2 | ...
 * ------------------------------------------------------------------------------------
 *          ->|                object-1's size                         |<-
 *                             ->|   object-1's alloc_size   |<-
 * The memory object's sub-region:
 *  - space-A: space used to align the pointer which returned by alloc API.
 *  - offset : 4bytes used to hold the offset of object-1 relative to the
 *             pointer returned by alloc API.
 *  - application-allocated: region applied by application invoking alloc API.
 *  - space-B: space used to align the next object.
 *
 */
struct memarea_obj {
	TAILQ_ENTRY(memarea_obj) obj_node;
	TAILQ_ENTRY(memarea_obj) free_node;
	size_t                   size;
	size_t                   alloc_size;
	uint32_t                 magic;
};

TAILQ_HEAD(memarea_obj_list, memarea_obj);

struct rte_memarea {
	struct rte_memarea_param init;
	rte_spinlock_t           lock;
	void                    *area_addr;
	struct memarea_obj_list  obj_list;
	struct memarea_obj_list  free_list;

	uint64_t                 alloc_fails;
	uint64_t                 magic_check_fails;
} __rte_cache_aligned;

#endif /* MEMAREA_PRIVATE_H */

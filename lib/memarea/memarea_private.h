/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 HiSilicon Limited
 */

#ifndef MEMAREA_PRIVATE_H
#define MEMAREA_PRIVATE_H

#include <rte_memarea.h>

#define MEMAREA_OBJECT_SIZE_ALIGN	8

#define MEMAREA_OBJECT_HEADER_AVAILABLE_COOKIE	0xbeef1234beef1234ULL
#define MEMAREA_OBJECT_HEADER_ALLOCATED_COOKIE	0x12345678abcdef12ULL
#define MEMAREA_OBJECT_TRAILER_COOKIE		0xabcd1234abcd5678ULL

#define MEMAREA_OBJECT_IS_ALLOCATED(hdr)	(TAILQ_NEXT((hdr), avail_next) == (void *)-1)
#define MEMAREA_OBJECT_MARK_ALLOCATED(hdr)	(TAILQ_NEXT((hdr), avail_next) = (void *)-1)

#ifdef RTE_LIBRTE_MEMAREA_DEBUG
#define MEMAREA_OBJECT_GET_SIZE(hdr) \
		((uintptr_t)TAILQ_NEXT((hdr), obj_next) - (uintptr_t)(hdr) - \
		 sizeof(struct memarea_objhdr) - sizeof(struct memarea_objtlr))
#else
#define MEMAREA_OBJECT_GET_SIZE(hdr) \
		((uintptr_t)TAILQ_NEXT((hdr), obj_next) - (uintptr_t)(hdr) - \
		 sizeof(struct memarea_objhdr))
#endif

struct memarea_objhdr {
	/** The obj_next list is an address ascending ordered linked list. */
	TAILQ_ENTRY(memarea_objhdr) obj_next;
	/** The avail_next list is an unordered linked list. If it's tqe_next
	 * is -1, means it has been allocated.
	 */
	TAILQ_ENTRY(memarea_objhdr) avail_next;
#ifdef RTE_LIBRTE_MEMAREA_DEBUG
	uint64_t                    cookie; /**< Debug cookie */
#endif
};

#ifdef RTE_LIBRTE_MEMAREA_DEBUG
struct memarea_objtlr {
	uint64_t cookie; /**< Debug cookie */
};
#endif

TAILQ_HEAD(memarea_objhdr_list, memarea_objhdr);

struct rte_memarea {
	struct rte_memarea_param   init;
	rte_spinlock_t             lock;
	void                      *area_base;
	struct memarea_objhdr     *guard_hdr;
	struct memarea_objhdr_list obj_list;
	struct memarea_objhdr_list avail_list;
} __rte_cache_aligned;

#endif /* MEMAREA_PRIVATE_H */

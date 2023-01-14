/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 HiSilicon Limited
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_spinlock.h>

#include "rte_memarea.h"
#include "memarea_private.h"

static int
memarea_check_param(const struct rte_memarea_param *init)
{
#define MEMAREA_MIN_SIZE	1024
	size_t len;

	if (init == NULL) {
		RTE_LOG(ERR, MEMAREA, "memarea init param is NULL!\n");
		return -EINVAL;
	}

	len = strnlen(init->name, RTE_MEMAREA_NAMESIZE);
	if (len == 0 || len >= RTE_MEMAREA_NAMESIZE) {
		RTE_LOG(ERR, MEMAREA, "memarea name size %zu invalid!\n", len);
		return -EINVAL;
	}

	if (init->source != RTE_MEMAREA_SOURCE_HEAP &&
	    init->source != RTE_MEMAREA_SOURCE_LIBC &&
	    init->source != RTE_MEMAREA_SOURCE_MEMAREA) {
		RTE_LOG(ERR, MEMAREA, "memarea: %s source: %d not supported!\n",
			init->name, init->source);
		return -EINVAL;
	}

	if (init->total_sz < MEMAREA_MIN_SIZE) {
		RTE_LOG(ERR, MEMAREA, "memarea: %s total-size: %zu too small!\n",
			init->name, init->total_sz);
		return -EINVAL;
	}

	if (init->source == RTE_MEMAREA_SOURCE_MEMAREA && init->src_memarea == NULL) {
		RTE_LOG(ERR, MEMAREA, "memarea: %s source memarea is NULL!\n", init->name);
		return -EINVAL;
	}

	if (init->alg != RTE_MEMAREA_ALGORITHM_NEXTFIT) {
		RTE_LOG(ERR, MEMAREA, "memarea: %s algorithm: %d not supported!\n",
			init->name, init->alg);
		return -EINVAL;
	}

	return 0;
}

static void *
memarea_alloc_from_libc(size_t size)
{
#ifndef RTE_EXEC_ENV_WINDOWS
	void *ptr = NULL;
	int ret;
	ret = posix_memalign(&ptr, RTE_CACHE_LINE_SIZE, size);
	if (ret)
		return NULL;
	return ptr;
#else
	/* Windows platform don't support posix_memalign() */
	return malloc(size);
#endif
}

static void *
memarea_alloc_area(const struct rte_memarea_param *init)
{
	void *ptr = NULL;

	if (init->source == RTE_MEMAREA_SOURCE_HEAP)
		ptr = rte_malloc_socket(NULL, init->total_sz, RTE_CACHE_LINE_SIZE,
					init->numa_socket);
	else if (init->source == RTE_MEMAREA_SOURCE_LIBC)
		ptr = memarea_alloc_from_libc(init->total_sz);
	else if (init->source == RTE_MEMAREA_SOURCE_MEMAREA)
		ptr = rte_memarea_alloc(init->src_memarea, init->total_sz, 0);

	return ptr;
}

static void
memarea_free_area(const struct rte_memarea_param *init, void *ptr)
{
	if (init->source == RTE_MEMAREA_SOURCE_HEAP)
		rte_free(ptr);
	else if (init->source == RTE_MEMAREA_SOURCE_LIBC)
		free(ptr);
	else if (init->source == RTE_MEMAREA_SOURCE_MEMAREA)
		rte_memarea_free(init->src_memarea, ptr);
}

struct rte_memarea *
rte_memarea_create(const struct rte_memarea_param *init)
{
	struct memarea_obj *obj;
	struct rte_memarea *ma;
	size_t unaligns;
	void *addr;
	int ret;

	ret = memarea_check_param(init);
	if (ret)
		return NULL;

	addr = memarea_alloc_area(init);
	if (addr == NULL) {
		RTE_LOG(ERR, MEMAREA, "memarea: %s alloc memory area fail!\n", init->name);
		return NULL;
	}

	ma = rte_zmalloc(NULL, sizeof(struct rte_memarea), RTE_CACHE_LINE_SIZE);
	if (ma == NULL) {
		memarea_free_area(init, addr);
		RTE_LOG(ERR, MEMAREA, "malloc memarea: %s management obj fail!\n", init->name);
		return NULL;
	}

	ma->init = *init;
	rte_spinlock_init(&ma->lock);
	TAILQ_INIT(&ma->obj_list);
	TAILQ_INIT(&ma->free_list);
	ma->area_addr = addr;
	/* The address returned by the windows platform may not be cache-line aligned.
	 * In this case, the object address and total_sz should be adjusted.
	 */
	unaligns = ((uintptr_t)addr) & (RTE_CACHE_LINE_SIZE - 1);
	if (unaligns > 0) {
		obj = RTE_PTR_ADD(addr, RTE_CACHE_LINE_SIZE - unaligns);
		ma->init.total_sz -= (RTE_CACHE_LINE_SIZE - unaligns);
	} else {
		obj = addr;
	}
	TAILQ_INSERT_TAIL(&ma->obj_list, obj, obj_node);
	TAILQ_INSERT_TAIL(&ma->free_list, obj, free_node);
	obj->size = init->total_sz - sizeof(struct memarea_obj);
	obj->alloc_size = 0;
	obj->magic = MEMAREA_OBJECT_FREE_MAGIC;

	return ma;
}

void
rte_memarea_destroy(struct rte_memarea *ma)
{
	if (ma == NULL)
		return;
	memarea_free_area(&ma->init, ma->area_addr);
	rte_free(ma);
}

static inline void
memarea_lock(struct rte_memarea *ma)
{
	if (ma->init.mt_safe)
		rte_spinlock_lock(&ma->lock);
}

static inline void
memarea_unlock(struct rte_memarea *ma)
{
	if (ma->init.mt_safe)
		rte_spinlock_unlock(&ma->lock);
}

static inline uint32_t
memarea_calc_align_space(struct memarea_obj *obj, uint32_t align)
{
	if (align == 0)
		return 0;
	return align - (((uintptr_t)obj + sizeof(struct memarea_obj) + sizeof(uint32_t)) &
			(align - 1));
}

static inline bool
memarea_whether_add_node(size_t obj_size, size_t need_size)
{
	return (obj_size - need_size) > sizeof(struct memarea_obj) + RTE_CACHE_LINE_SIZE;
}

static inline void
memarea_add_node(struct rte_memarea *ma, struct memarea_obj *obj, size_t used_size)
{
	size_t align_size = RTE_ALIGN_CEIL(used_size, sizeof(void *));
	struct memarea_obj *new_obj;

	new_obj = (struct memarea_obj *)RTE_PTR_ADD(obj, sizeof(struct memarea_obj) +
							 align_size);
	new_obj->size = obj->size - align_size - sizeof(struct memarea_obj);
	new_obj->alloc_size = 0;
	new_obj->magic = MEMAREA_OBJECT_FREE_MAGIC;
	TAILQ_INSERT_AFTER(&ma->obj_list, obj, new_obj, obj_node);
	TAILQ_INSERT_AFTER(&ma->free_list, obj, new_obj, free_node);
	obj->size = align_size;
}

void *
rte_memarea_alloc(struct rte_memarea *ma, size_t size, uint32_t align)
{
	size_t size_req = size + align + sizeof(uint32_t); /* use to check size overflow */
	struct memarea_obj *obj;
	uint32_t align_space;
	void *ptr = NULL;

	if (unlikely(ma == NULL || size == 0 || size_req < size ||
		(align && !rte_is_power_of_2(align))))
		return ptr;

	memarea_lock(ma);
	TAILQ_FOREACH(obj, &ma->free_list, free_node) {
		if (unlikely(obj->magic != MEMAREA_OBJECT_FREE_MAGIC)) {
			ma->magic_check_fails++;
			RTE_LOG(ERR, MEMAREA, "memarea: %s magic: 0x%x check fail when alloc object!\n",
				ma->init.name, obj->magic);
			break;
		}
		align_space = memarea_calc_align_space(obj, align);
		if (obj->size < size + align_space)
			continue;
		if (memarea_whether_add_node(obj->size, size + align_space))
			memarea_add_node(ma, obj, size + align_space);
		obj->alloc_size = size;
		obj->magic = MEMAREA_OBJECT_ALLOCATED_MAGIC;
		TAILQ_REMOVE(&ma->free_list, obj, free_node);
		ptr = RTE_PTR_ADD(obj, sizeof(struct memarea_obj) + align_space + sizeof(uint32_t));
		*(uint32_t *)RTE_PTR_SUB(ptr, sizeof(uint32_t)) = (uintptr_t)ptr - (uintptr_t)obj;
		break;
	}
	if (unlikely(ptr == NULL))
		ma->alloc_fails++;
	memarea_unlock(ma);

	return ptr;
}

static inline void
memarea_merge_node(struct rte_memarea *ma, struct memarea_obj *curr,
		   struct memarea_obj *next, bool del_next_from_free,
		   bool add_curr_to_free)
{
	curr->size += next->size + sizeof(struct memarea_obj);
	next->alloc_size = 0;
	next->magic = 0;
	TAILQ_REMOVE(&ma->obj_list, next, obj_node);
	if (del_next_from_free)
		TAILQ_REMOVE(&ma->free_list, next, free_node);
	if (add_curr_to_free) {
		curr->alloc_size = 0;
		curr->magic = MEMAREA_OBJECT_FREE_MAGIC;
		TAILQ_INSERT_TAIL(&ma->free_list, curr, free_node);
	}
}

void
rte_memarea_free(struct rte_memarea *ma, void *ptr)
{
	struct memarea_obj *obj, *prev, *next;
	bool merged = false;
	uint32_t offset;

	if (unlikely(ma == NULL || ptr == NULL))
		return;

	offset = *(uint32_t *)RTE_PTR_SUB(ptr, sizeof(uint32_t));
	obj = (struct memarea_obj *)RTE_PTR_SUB(ptr, offset);
	if (unlikely(obj->magic != MEMAREA_OBJECT_ALLOCATED_MAGIC)) {
		ma->magic_check_fails++;
		RTE_LOG(ERR, MEMAREA, "memarea: %s magic: 0x%x check fail when free object!\n",
			ma->init.name, obj->magic);
		return;
	}

	memarea_lock(ma);
	prev = TAILQ_PREV(obj, memarea_obj_list, obj_node);
	next = TAILQ_NEXT(obj, obj_node);
	if (prev != NULL && prev->magic == MEMAREA_OBJECT_FREE_MAGIC) {
		memarea_merge_node(ma, prev, obj, false, false);
		obj = prev;
		merged = true;
	}
	if (next != NULL && next->magic == MEMAREA_OBJECT_FREE_MAGIC) {
		memarea_merge_node(ma, obj, next, true, !merged);
		merged = true;
	}
	if (!merged) {
		obj->alloc_size = 0;
		obj->magic = MEMAREA_OBJECT_FREE_MAGIC;
		TAILQ_INSERT_TAIL(&ma->free_list, obj, free_node);
	}
	memarea_unlock(ma);
}

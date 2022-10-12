/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 HiSilicon Limited
 */

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

	if (init->total_sz <= sizeof(struct memarea_elem)) {
		RTE_LOG(ERR, MEMAREA, "memarea: %s total-size: %zu too small!\n",
			init->name, init->total_sz);
		return -EINVAL;
	}

	if (init->source == RTE_MEMAREA_SOURCE_MEMAREA && init->src_memarea == NULL) {
		RTE_LOG(ERR, MEMAREA, "memarea: %s source memarea is NULL!\n", init->name);
		return -EINVAL;
	}

	if (init->alg != RTE_MEMAREA_ALG_NEXTFIT) {
		RTE_LOG(ERR, MEMAREA, "memarea: %s alg: %d not supported!\n",
			init->name, init->alg);
		return -EINVAL;
	}

	return 0;
}

static void *
memarea_alloc_from_libc(size_t size)
{
	void *ptr = NULL;
	int ret;

	ret = posix_memalign(&ptr, RTE_CACHE_LINE_SIZE, size);
	if (ret)
		return NULL;
	return ptr;
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

	if (ptr == NULL)
		RTE_LOG(ERR, MEMAREA, "memarea: %s alloc memory area fail!\n", init->name);

	return ptr;
}

struct rte_memarea *
rte_memarea_create(const struct rte_memarea_param *init)
{
	struct memarea_elem *elem;
	struct rte_memarea *ma;
	void *addr;
	int ret;

	ret = memarea_check_param(init);
	if (ret)
		return NULL;

	addr = memarea_alloc_area(init);
	if (addr == NULL)
		return NULL;

	ma = rte_zmalloc(NULL, sizeof(struct rte_memarea), RTE_CACHE_LINE_SIZE);
	if (ma == NULL) {
		RTE_LOG(ERR, MEMAREA, "malloc memarea: %s management obj fail!\n", init->name);
		return NULL;
	}

	ma->init = *init;
	rte_spinlock_init(&ma->lock);
	TAILQ_INIT(&ma->elem_list);
	TAILQ_INIT(&ma->free_list);
	ma->area_addr = addr;
	elem = addr;
	TAILQ_INSERT_TAIL(&ma->elem_list, elem, elem_node);
	TAILQ_INSERT_TAIL(&ma->free_list, elem, free_node);
	elem->size = init->total_sz - sizeof(struct memarea_elem);
	elem->magic = MEMAREA_AVAILABLE_ELEM_MAGIC;
	elem->cookie = MEMAREA_AVAILABLE_ELEM_COOKIE;
	elem->refcnt = 0;

	return ma;
}

static void
memarea_free_area(struct rte_memarea *ma)
{
	if (ma->init.source == RTE_MEMAREA_SOURCE_HEAP)
		rte_free(ma->area_addr);
	else if (ma->init.source == RTE_MEMAREA_SOURCE_LIBC)
		free(ma->area_addr);
	else if (ma->init.source == RTE_MEMAREA_SOURCE_MEMAREA)
		rte_memarea_free(ma->init.src_memarea, ma->area_addr);
}

void
rte_memarea_destroy(struct rte_memarea *ma)
{
	if (ma == NULL)
		return;
	memarea_free_area(ma);
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

static inline bool
memarea_whether_add_node(size_t free_size, size_t need_size)
{
	size_t align_size = RTE_ALIGN_CEIL(need_size, RTE_CACHE_LINE_SIZE);
	return free_size > align_size && (free_size - align_size) > sizeof(struct memarea_elem);
}

static inline void
memarea_add_node(struct rte_memarea *ma, struct memarea_elem *elem, size_t need_size)
{
	size_t align_size = RTE_ALIGN_CEIL(need_size, RTE_CACHE_LINE_SIZE);
	struct memarea_elem *new_elem;

	new_elem = (struct memarea_elem *)RTE_PTR_ADD(elem, sizeof(struct memarea_elem) +
							    align_size);
	new_elem->size = elem->size - align_size - sizeof(struct memarea_elem);
	new_elem->magic = MEMAREA_AVAILABLE_ELEM_MAGIC;
	new_elem->cookie = MEMAREA_AVAILABLE_ELEM_COOKIE;
	new_elem->refcnt = 0;
	TAILQ_INSERT_AFTER(&ma->elem_list, elem, new_elem, elem_node);
	TAILQ_INSERT_AFTER(&ma->free_list, elem, new_elem, free_node);
	elem->size = align_size;
}

void *
rte_memarea_alloc(struct rte_memarea *ma, size_t size, uint32_t cookie)
{
	struct memarea_elem *elem;
	void *ptr = NULL;

	if (unlikely(ma == NULL || size == 0))
		return NULL;

	memarea_lock(ma);
	TAILQ_FOREACH(elem, &ma->free_list, free_node) {
		if (unlikely(elem->magic != MEMAREA_AVAILABLE_ELEM_MAGIC))
			break;
		if (elem->size < size)
			continue;
		if (memarea_whether_add_node(elem->size, size))
			memarea_add_node(ma, elem, size);
		elem->magic = MEMAREA_ALLOCATED_ELEM_MAGIC;
		elem->cookie = cookie;
		elem->refcnt = 1;
		TAILQ_REMOVE(&ma->free_list, elem, free_node);
		ptr = RTE_PTR_ADD(elem, sizeof(struct memarea_elem));
		break;
	}
	if (unlikely(ptr == NULL))
		ma->alloc_fails++;
	memarea_unlock(ma);

	return ptr;
}

void
rte_memarea_free(struct rte_memarea *ma, void *ptr)
{
	if (unlikely(ma == NULL || ptr == NULL))
		return;

	rte_memarea_refcnt_update(ma, ptr, -1);
}

static inline void
memarea_merge_node(struct rte_memarea *ma, struct memarea_elem *curr,
		   struct memarea_elem *next, bool del_next_from_free,
		   bool add_curr_to_free)
{
	curr->size += next->size + sizeof(struct memarea_elem);
	next->size = 0;
	next->magic = 0;
	next->cookie = 0;
	TAILQ_REMOVE(&ma->elem_list, next, elem_node);
	if (del_next_from_free)
		TAILQ_REMOVE(&ma->free_list, next, free_node);
	if (add_curr_to_free) {
		curr->magic = MEMAREA_AVAILABLE_ELEM_MAGIC;
		curr->cookie = MEMAREA_AVAILABLE_ELEM_COOKIE;
		TAILQ_INSERT_TAIL(&ma->free_list, curr, free_node);
	}
}

static inline void
memarea_free_elem(struct rte_memarea *ma, struct memarea_elem *elem)
{
	struct memarea_elem *prev, *next;
	bool merged = false;

	prev = TAILQ_PREV(elem, memarea_elem_list, elem_node);
	next = TAILQ_NEXT(elem, elem_node);
	if (prev != NULL && prev->refcnt == 0) {
		memarea_merge_node(ma, prev, elem, false, false);
		elem = prev;
		merged = true;
	}
	if (next != NULL && next->refcnt == 0) {
		memarea_merge_node(ma, elem, next, true, !merged);
		merged = true;
	}
	if (!merged) {
		elem->magic = MEMAREA_AVAILABLE_ELEM_MAGIC;
		elem->cookie = MEMAREA_AVAILABLE_ELEM_COOKIE;
		TAILQ_INSERT_TAIL(&ma->free_list, elem, free_node);
	}
}

void
rte_memarea_refcnt_update(struct rte_memarea *ma, void *ptr, int32_t value)
{
	struct memarea_elem *elem = (struct memarea_elem *)RTE_PTR_SUB(ptr,
							    sizeof(struct memarea_elem));

	memarea_lock(ma);
	if (unlikely(elem->magic != MEMAREA_ALLOCATED_ELEM_MAGIC)) {
		RTE_LOG(ERR, MEMAREA, "memarea: %s magic: 0x%x check fail!\n",
			ma->init.name, elem->magic);
		memarea_unlock(ma);
		return;
	}

	if (unlikely(elem->refcnt <= 0 || elem->refcnt + value < 0)) {
		RTE_LOG(ERR, MEMAREA,
			"memarea: %s cookie: 0x%x curr refcnt: %d update refcnt: %d check fail!\n",
			ma->init.name, elem->cookie, elem->refcnt, value);
		ma->refcnt_check_fails++;
		if (elem->refcnt > 0)
			elem->refcnt += value;
		memarea_unlock(ma);
		return;
	}

	elem->refcnt += value;
	if (elem->refcnt == 0)
		memarea_free_elem(ma, elem);
	memarea_unlock(ma);
}

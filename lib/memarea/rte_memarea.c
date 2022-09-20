/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 HiSilicon Limited
 */

#include <stdio.h>
#include <sys/queue.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memarea.h>
#include <rte_spinlock.h>

#include "memarea_private.h"

static int
memarea_check_param(const struct rte_memarea_param *init)
{
	size_t len;

	len = strnlen(init->name, RTE_MEMAREA_NAMESIZE);
	if (len == 0 || len >= RTE_MEMAREA_NAMESIZE) {
		RTE_LOG(ERR, MEMAREA, "memarea name invalid!\n");
		return -EINVAL;
	}

	if (init->source >= RTE_MEMAREA_SOURCE_BUTT) {
		RTE_LOG(ERR, MEMAREA, "memarea source invalid!\n");
		return -EINVAL;
	}

	if (init->total_sz <= sizeof(struct memarea_elem)) {
		RTE_LOG(ERR, MEMAREA, "memarea total size invalid!\n");
		return -EINVAL;
	}

	if (init->source == RTE_MEMAREA_SOURCE_USER_ADDR && init->user_addr == NULL) {
		RTE_LOG(ERR, MEMAREA, "memarea user provided addr invalid!\n");
		return -EINVAL;
	}

	if (init->source == RTE_MEMAREA_SOURCE_USER_ADDR &&
	    ((uintptr_t)init->user_addr & (RTE_CACHE_LINE_SIZE - 1))) {
		RTE_LOG(ERR, MEMAREA, "memarea user provided addr align invalid!\n");
		return -EINVAL;
	}

	if (init->source == RTE_MEMAREA_SOURCE_USER_MEMAREA && init->user_memarea == NULL) {
		RTE_LOG(ERR, MEMAREA, "memarea user provided memarea invalid!\n");
		return -EINVAL;
	}

	return 0;
}

static void *
memarea_alloc_from_system_api(size_t size)
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

	if (init->source == RTE_MEMAREA_SOURCE_SYSTEM_API)
		ptr = memarea_alloc_from_system_api(init->total_sz);
	else if (init->source == RTE_MEMAREA_SOURCE_USER_ADDR)
		ptr = init->user_addr;
	else if (init->source == RTE_MEMAREA_SOURCE_USER_MEMAREA)
		ptr = rte_memarea_alloc(init->user_memarea, init->total_sz, 0);

	if (ptr == NULL)
		RTE_LOG(ERR, MEMAREA, "memarea alloc memory area fail!\n");

	return ptr;
}

struct rte_memarea *
rte_memarea_create(const struct rte_memarea_param *init)
{
	struct memarea_private *priv;
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
	priv = rte_zmalloc(NULL, sizeof(struct memarea_private), RTE_CACHE_LINE_SIZE);
	if (ma == NULL || priv == NULL) {
		RTE_LOG(ERR, MEMAREA, "malloc memarea management obj fail!\n");
		rte_free(ma);
		rte_free(priv);
		return NULL;
	}

	ma->private_data = priv;
	priv->init = *init;
	rte_spinlock_init(&priv->lock);
	TAILQ_INIT(&priv->elem_list);
	TAILQ_INIT(&priv->free_list);
	priv->area_addr = addr;
	elem = addr;
	elem->size = init->total_sz - sizeof(struct memarea_elem);
	elem->cookie = MEMAREA_FREE_ELEM_COOKIE;
	elem->refcnt = 0;
	TAILQ_INSERT_TAIL(&priv->elem_list, elem, elem_node);
	TAILQ_INSERT_TAIL(&priv->free_list, elem, free_node);

	return ma;
}

static void
memarea_free_area(struct memarea_private *priv)
{
	if (priv->init.source == RTE_MEMAREA_SOURCE_SYSTEM_API)
		free(priv->area_addr);
	else if (priv->init.source == RTE_MEMAREA_SOURCE_USER_MEMAREA)
		rte_memarea_free(priv->init.user_memarea, priv->area_addr);
}

void
rte_memarea_destroy(struct rte_memarea *ma)
{
	if (ma == NULL)
		return;
	memarea_free_area(ma->private_data);
	rte_free(ma->private_data);
	rte_free(ma);
}

static inline void
memarea_lock(struct memarea_private *priv)
{
	if (priv->init.mt_safe)
		rte_spinlock_lock(&priv->lock);
}

static inline void
memarea_unlock(struct memarea_private *priv)
{
	if (priv->init.mt_safe)
		rte_spinlock_unlock(&priv->lock);
}

#define roundup(val, align) ((((val) + ((align) - 1)) / (align)) * (align))

static inline bool
memarea_whether_add_node(size_t free_size, size_t need_size)
{
	size_t align_size = roundup(need_size, RTE_CACHE_LINE_SIZE);
	return free_size > align_size && (free_size - align_size) > sizeof(struct memarea_elem);
}

static inline void
memarea_add_node(struct memarea_private *priv, struct memarea_elem *elem, size_t need_size)
{
	size_t align_size = roundup(need_size, RTE_CACHE_LINE_SIZE);
	struct memarea_elem *new_elem;
	new_elem = (struct memarea_elem *)((uintptr_t)elem + sizeof(struct memarea_elem) +
					   align_size);
	new_elem->size = elem->size - align_size - sizeof(struct memarea_elem);
	new_elem->cookie = MEMAREA_FREE_ELEM_COOKIE;
	new_elem->refcnt = 0;
	TAILQ_INSERT_AFTER(&priv->elem_list, elem, new_elem, elem_node);
	TAILQ_INSERT_AFTER(&priv->free_list, elem, new_elem, free_node);
	elem->size = align_size;
}

void *
rte_memarea_alloc(struct rte_memarea *ma, size_t size, uint32_t cookie)
{
	struct memarea_private *priv;
	struct memarea_elem *elem;
	void *ptr = NULL;

	if (unlikely(ma == NULL || size == 0))
		return NULL;

	priv = ma->private_data;
	memarea_lock(priv);
	TAILQ_FOREACH(elem, &priv->free_list, free_node) {
		if (elem->size < size)
			continue;
		if (memarea_whether_add_node(elem->size, size))
			memarea_add_node(priv, elem, size);
		elem->cookie = cookie;
		elem->refcnt = 1;
		TAILQ_REMOVE(&priv->free_list, elem, free_node);
		ptr = (void *)((uintptr_t)elem + sizeof(struct memarea_elem));
		break;
	}
	if (unlikely(ptr == NULL))
		priv->alloc_fails++;
	memarea_unlock(priv);

	return ptr;
}

void
rte_memarea_free(struct rte_memarea *ma, void *ptr)
{
	rte_memarea_update_refcnt(ma, ptr, -1);
}

static inline void
memarea_merge_node(struct memarea_private *priv, struct memarea_elem *curr,
		   struct memarea_elem *next, bool del_next_from_free,
		   bool add_curr_to_free)
{
	curr->size += next->size + sizeof(struct memarea_elem);
	next->size = 0;
	next->cookie = 0;
	TAILQ_REMOVE(&priv->elem_list, next, elem_node);
	if (del_next_from_free)
		TAILQ_REMOVE(&priv->free_list, next, free_node);
	if (add_curr_to_free)
		TAILQ_INSERT_TAIL(&priv->free_list, curr, free_node);
}

static inline void
memarea_free_elem(struct memarea_private *priv, struct memarea_elem *elem)
{
	struct memarea_elem *prev, *next;
	bool merged = false;
	prev = TAILQ_PREV(elem, memarea_elem_list, elem_node);
	next = TAILQ_NEXT(elem, elem_node);
	if (prev != NULL && prev->refcnt == 0) {
		memarea_merge_node(priv, prev, elem, false, false);
		elem = prev;
		merged = true;
	}
	if (next != NULL && next->refcnt == 0) {
		memarea_merge_node(priv, elem, next, true, !merged);
		merged = true;
	}
	if (!merged) {
		elem->cookie = MEMAREA_FREE_ELEM_COOKIE;
		TAILQ_INSERT_TAIL(&priv->free_list, elem, free_node);
	}
}

void
rte_memarea_update_refcnt(struct rte_memarea *ma, void *ptr, int16_t value)
{
	struct memarea_elem *elem = (struct memarea_elem *)((uintptr_t)ptr -
							    sizeof(struct memarea_elem));
	struct memarea_private *priv = ma->private_data;

	memarea_lock(priv);
	if (unlikely(elem->refcnt <= 0 || elem->refcnt + value < 0)) {
		RTE_LOG(ERR, MEMAREA,
			"memarea cookie: %u curr refcnt: %d update refcnt: %d check fail!\n",
			elem->cookie, elem->refcnt, value);
		priv->refcnt_check_fails++;
		if (elem->refcnt > 0)
			elem->refcnt += value;
		memarea_unlock(priv);
		return;
	}
	elem->refcnt += value;
	if (elem->refcnt == 0)
		memarea_free_elem(priv, elem);
	memarea_unlock(priv);
}

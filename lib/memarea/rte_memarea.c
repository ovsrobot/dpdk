/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 HiSilicon Limited
 */

#include <stdio.h>
#include <stdlib.h>

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

	if (init->source != RTE_MEMAREA_SOURCE_RTE_MEMORY &&
	    init->source != RTE_MEMAREA_SOURCE_SYSTEM_API &&
	    init->source != RTE_MEMAREA_SOURCE_USER_ADDR &&
	    init->source != RTE_MEMAREA_SOURCE_USER_MEMAREA) {
		RTE_LOG(ERR, MEMAREA, "memarea: %s source: %d not supported!\n",
			init->name, init->source);
		return -EINVAL;
	}

	if (init->total_sz <= sizeof(struct memarea_elem)) {
		RTE_LOG(ERR, MEMAREA, "memarea: %s total-size: %zu too small!\n",
			init->name, init->total_sz);
		return -EINVAL;
	}

	if (init->source == RTE_MEMAREA_SOURCE_USER_ADDR && init->user_addr == NULL) {
		RTE_LOG(ERR, MEMAREA, "memarea: %s user provided addr is NULL!\n", init->name);
		return -EINVAL;
	}

	if (init->source == RTE_MEMAREA_SOURCE_USER_ADDR &&
	    ((uintptr_t)init->user_addr & (RTE_CACHE_LINE_SIZE - 1))) {
		RTE_LOG(ERR, MEMAREA, "memarea: %s user provided addr should align: %d!\n",
			init->name, RTE_CACHE_LINE_SIZE);
		return -EINVAL;
	}

	if (init->source == RTE_MEMAREA_SOURCE_USER_MEMAREA && init->user_memarea == NULL) {
		RTE_LOG(ERR, MEMAREA, "memarea: %s user provided memarea is NULL!\n", init->name);
		return -EINVAL;
	}

	if (init->alg != RTE_MEMAREA_ALG_DEFAULT) {
		RTE_LOG(ERR, MEMAREA, "memarea: %s alg: %d not supported!\n",
			init->name, init->alg);
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

	if (init->source == RTE_MEMAREA_SOURCE_RTE_MEMORY)
		ptr = rte_malloc_socket(NULL, init->total_sz, RTE_CACHE_LINE_SIZE,
					init->numa_socket);
	else if (init->source == RTE_MEMAREA_SOURCE_SYSTEM_API)
		ptr = memarea_alloc_from_system_api(init->total_sz);
	else if (init->source == RTE_MEMAREA_SOURCE_USER_ADDR)
		ptr = init->user_addr;

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
	elem->size = init->total_sz - sizeof(struct memarea_elem);
	elem->cookie = MEMAREA_FREE_ELEM_COOKIE;
	elem->refcnt = 0;
	TAILQ_INSERT_TAIL(&ma->elem_list, elem, elem_node);
	TAILQ_INSERT_TAIL(&ma->free_list, elem, free_node);

	return ma;
}

static void
memarea_free_area(struct rte_memarea *ma)
{
	if (ma->init.source == RTE_MEMAREA_SOURCE_RTE_MEMORY)
		rte_free(ma->area_addr);
	else if (ma->init.source == RTE_MEMAREA_SOURCE_SYSTEM_API)
		free(ma->area_addr);
}

void
rte_memarea_destroy(struct rte_memarea *ma)
{
	if (ma == NULL)
		return;
	memarea_free_area(ma);
	rte_free(ma);
}

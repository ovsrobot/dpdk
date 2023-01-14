/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 HiSilicon Limited
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

	return ptr;
}

static void
memarea_free_area(const struct rte_memarea_param *init, void *ptr)
{
	if (init->source == RTE_MEMAREA_SOURCE_HEAP)
		rte_free(ptr);
	else if (init->source == RTE_MEMAREA_SOURCE_LIBC)
		free(ptr);
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


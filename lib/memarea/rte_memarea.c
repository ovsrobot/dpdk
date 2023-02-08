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

RTE_LOG_REGISTER_DEFAULT(rte_memarea_logtype, INFO);
#define RTE_MEMAREA_LOG(level, ...) \
	rte_log(RTE_LOG_ ## level, rte_memarea_logtype, RTE_FMT("memarea: " \
		RTE_FMT_HEAD(__VA_ARGS__,) "\n", RTE_FMT_TAIL(__VA_ARGS__,)))

static int
memarea_check_param(const struct rte_memarea_param *init)
{
#define MEMAREA_MIN_SIZE	1024
	size_t len;

	if (init == NULL) {
		RTE_MEMAREA_LOG(ERR, "init param is NULL!");
		return -EINVAL;
	}

	len = strnlen(init->name, RTE_MEMAREA_NAMESIZE);
	if (len == 0 || len >= RTE_MEMAREA_NAMESIZE) {
		RTE_MEMAREA_LOG(ERR, "name size: %zu invalid!", len);
		return -EINVAL;
	}

	if (init->source != RTE_MEMAREA_SOURCE_HEAP &&
	    init->source != RTE_MEMAREA_SOURCE_LIBC &&
	    init->source != RTE_MEMAREA_SOURCE_MEMAREA) {
		RTE_MEMAREA_LOG(ERR, "%s source: %d not supported!",
			init->name, init->source);
		return -EINVAL;
	}

	if (init->total_sz < MEMAREA_MIN_SIZE) {
		RTE_MEMAREA_LOG(ERR, "%s total-size: %zu too small!",
			init->name, init->total_sz);
		return -EINVAL;
	}

	if (init->source == RTE_MEMAREA_SOURCE_MEMAREA && init->src_ma == NULL) {
		RTE_MEMAREA_LOG(ERR, "%s source memarea is NULL!", init->name);
		return -EINVAL;
	}

	if (init->alg != RTE_MEMAREA_ALGORITHM_NEXTFIT) {
		RTE_MEMAREA_LOG(ERR, "%s algorithm: %d not supported!",
			init->name, init->alg);
		return -EINVAL;
	}

	return 0;
}

static void *
memarea_alloc_from_libc(size_t size)
{
#ifdef RTE_EXEC_ENV_WINDOWS
	return _aligned_malloc(size, RTE_CACHE_LINE_SIZE);
#else
	void *ptr = NULL;
	int ret;
	ret = posix_memalign(&ptr, RTE_CACHE_LINE_SIZE, size);
	if (ret)
		return NULL;
	return ptr;
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
	struct memarea_objhdr *hdr, *guard_hdr;
#ifdef RTE_LIBRTE_MEMAREA_DEBUG
	struct memarea_objtlr *tlr;
#endif
	struct rte_memarea *ma;
	size_t align_sz;
	void *ptr;
	int ret;

	ret = memarea_check_param(init);
	if (ret)
		return NULL;

	ptr = memarea_alloc_area(init);
	if (ptr == NULL) {
		RTE_MEMAREA_LOG(ERR, "%s alloc memory area fail!", init->name);
		return NULL;
	}

	ma = rte_zmalloc(NULL, sizeof(struct rte_memarea), RTE_CACHE_LINE_SIZE);
	if (ma == NULL) {
		memarea_free_area(init, ptr);
		RTE_MEMAREA_LOG(ERR, "malloc %s management object fail!", init->name);
		return NULL;
	}

	hdr = ptr;
	align_sz = RTE_ALIGN_FLOOR(init->total_sz, MEMAREA_OBJECT_SIZE_ALIGN);
	guard_hdr = RTE_PTR_ADD(ptr, align_sz - sizeof(struct memarea_objhdr));

	ma->init = *init;
	rte_spinlock_init(&ma->lock);
	ma->area_base = ptr;
	ma->guard_hdr = guard_hdr;
	TAILQ_INIT(&ma->obj_list);
	TAILQ_INIT(&ma->avail_list);

	TAILQ_INSERT_TAIL(&ma->obj_list, hdr, obj_next);
	TAILQ_INSERT_TAIL(&ma->avail_list, hdr, avail_next);
#ifdef RTE_LIBRTE_MEMAREA_DEBUG
	hdr->cookie = MEMAREA_OBJECT_HEADER_AVAILABLE_COOKIE;
	tlr = RTE_PTR_SUB(guard_hdr, sizeof(struct memarea_objtlr));
	tlr->cookie = MEMAREA_OBJECT_TRAILER_COOKIE;
#endif

	memset(guard_hdr, 0, sizeof(struct memarea_objhdr));
	TAILQ_INSERT_AFTER(&ma->obj_list, hdr, guard_hdr, obj_next);
	MEMAREA_OBJECT_MARK_ALLOCATED(guard_hdr);
#ifdef RTE_LIBRTE_MEMAREA_DEBUG
	guard_hdr->cookie = MEMAREA_OBJECT_HEADER_ALLOCATED_COOKIE;
	/* The guard object have no trailer cookie. */
#endif

	return ma;
}

void
rte_memarea_destroy(struct rte_memarea *ma)
{
	if (ma == NULL)
		return;
	memarea_free_area(&ma->init, ma->area_base);
	rte_free(ma);
}


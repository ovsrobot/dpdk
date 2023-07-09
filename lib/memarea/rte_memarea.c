/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 HiSilicon Limited
 */

#include <stdio.h>
#include <stdlib.h>

#include <rte_common.h>
#include <rte_errno.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_spinlock.h>

#include "rte_memarea.h"
#include "memarea_private.h"

RTE_LOG_REGISTER_DEFAULT(rte_memarea_logtype, INFO);
#define RTE_MEMAREA_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, rte_memarea_logtype, \
		"MEMAREA: %s(): " fmt "\n", __func__, ## args)

static int
memarea_check_param(const struct rte_memarea_param *init)
{
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

	if (init->total_sz < MEMAREA_MINIMUM_TOTAL_SIZE) {
		RTE_MEMAREA_LOG(ERR, "%s total-size: %zu too small!",
			init->name, init->total_sz);
		return -EINVAL;
	}

	if (init->source == RTE_MEMAREA_SOURCE_MEMAREA && init->ma.src == NULL) {
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
	if (ret != 0)
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
					init->heap.socket_id);
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

/**
 * Set cookie.
 *
 * @param status
 *   - 0: object is set to be available, but don't set tailer cookie.
 *   - 1: object is set to be allocated, but don't set tailer cookie.
 *   - 2: object is new split, the header cookie will set to be available,
 *        the tailer cookie of the previous object will be set.
 *   - 3: object is new split, the header cookie will set to be allocated,
 *        the tailer cookie of the previous object will be set.
 *   - 4: object is to be merged, it will no longer exist. the header cookie
 *        is cleared and the tailer cookie of the previous object is cleared.
 */
static inline void
memarea_set_cookie(struct memarea_objhdr *hdr, int status)
{
#ifdef RTE_LIBRTE_MEMAREA_DEBUG
	struct memarea_objtlr *tlr;

	if (status == 0) {
		hdr->cookie = MEMAREA_OBJECT_HEADER_AVAILABLE_COOKIE;
	} else if (status == 1) {
		hdr->cookie = MEMAREA_OBJECT_HEADER_ALLOCATED_COOKIE;
	} else if (status == 2) {
		hdr->cookie = MEMAREA_OBJECT_HEADER_AVAILABLE_COOKIE;
		tlr = RTE_PTR_SUB(hdr, sizeof(struct memarea_objtlr));
		tlr->cookie = MEMAREA_OBJECT_TRAILER_COOKIE;
	} else if (status == 3) {
		hdr->cookie = MEMAREA_OBJECT_HEADER_ALLOCATED_COOKIE;
		tlr = RTE_PTR_SUB(hdr, sizeof(struct memarea_objtlr));
		tlr->cookie = MEMAREA_OBJECT_TRAILER_COOKIE;
	} else if (status == 4) {
		hdr->cookie = 0;
		tlr = RTE_PTR_SUB(hdr, sizeof(struct memarea_objtlr));
		tlr->cookie = 0;
	}
#else
	RTE_SET_USED(hdr);
	RTE_SET_USED(status);
#endif
}

struct rte_memarea *
rte_memarea_create(const struct rte_memarea_param *init)
{
	struct memarea_objhdr *hdr, *guard_hdr;
	struct rte_memarea *ma;
	size_t align_sz;
	void *ptr;
	int ret;

	/** 1st: check parameter valid. */
	ret = memarea_check_param(init);
	if (ret != 0) {
		rte_errno = -ret;
		return NULL;
	}

	/** 2nd: alloc the memarea data region. */
	ptr = memarea_alloc_area(init);
	if (ptr == NULL) {
		RTE_MEMAREA_LOG(ERR, "%s alloc memory area fail!", init->name);
		rte_errno = ENOMEM;
		return NULL;
	}

	/** 3rd: alloc the memare management struct. */
	ma = rte_zmalloc(NULL, sizeof(struct rte_memarea), RTE_CACHE_LINE_SIZE);
	if (ma == NULL) {
		memarea_free_area(init, ptr);
		RTE_MEMAREA_LOG(ERR, "%s alloc management object fail!", init->name);
		rte_errno = ENOMEM;
		return NULL;
	}

	/** 4th: backup init parameter, initialize the lock and list. */
	ma->init = *init;
	rte_spinlock_init(&ma->lock);
	TAILQ_INIT(&ma->obj_list);
	TAILQ_INIT(&ma->avail_list);

	/** 5th: initialize the first object and last guard object. */
	hdr = ptr;
	align_sz = RTE_ALIGN_FLOOR(init->total_sz, MEMAREA_OBJECT_SIZE_ALIGN);
	guard_hdr = RTE_PTR_ADD(ptr, align_sz - sizeof(struct memarea_objhdr));
	ma->area_base = ptr;
	ma->guard_hdr = guard_hdr;

	/** 5.1: hook the first object to both obj_list and avail_list. */
	TAILQ_INSERT_TAIL(&ma->obj_list, hdr, obj_next);
	TAILQ_INSERT_TAIL(&ma->avail_list, hdr, avail_next);
	memarea_set_cookie(hdr, 0);

	/** 5.2: hook the guard object to only obj_list. */
	memset(guard_hdr, 0, sizeof(struct memarea_objhdr));
	TAILQ_INSERT_AFTER(&ma->obj_list, hdr, guard_hdr, obj_next);
	MEMAREA_OBJECT_MARK_ALLOCATED(guard_hdr);
	memarea_set_cookie(guard_hdr, 3);

	return ma;
}

void
rte_memarea_destroy(struct rte_memarea *ma)
{
	if (ma == NULL) {
		rte_errno = EINVAL;
		return;
	}
	memarea_free_area(&ma->init, ma->area_base);
	rte_free(ma);
}

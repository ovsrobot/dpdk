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

RTE_LOG_REGISTER_DEFAULT(rte_memarea_logtype, INFO);
#define RTE_MEMAREA_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, rte_memarea_logtype, \
		"MEMAREA: %s(): " fmt "\n", __func__, ## args)

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
	else if (init->source == RTE_MEMAREA_SOURCE_MEMAREA)
		ptr = rte_memarea_alloc(init->src_ma, init->total_sz);

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
		rte_memarea_free(init->src_ma, ptr);
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
		RTE_MEMAREA_LOG(ERR, "%s alloc management object fail!", init->name);
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

/**
 * Check cookie or panic.
 *
 * @param status
 *   - 0: object is supposed to be available
 *   - 1: object is supposed to be allocated
 *   - 2: just check that cookie is valid (available or allocated)
 */
static inline void
memarea_check_cookie(const struct rte_memarea *ma, const struct memarea_objhdr *hdr, int status)
{
#ifdef RTE_LIBRTE_MEMAREA_DEBUG
	static const char *const str[] = { "PASS", "FAILED" };
	struct memarea_objtlr *tlr;
	bool hdr_fail, tlr_fail;

	if (unlikely(hdr == ma->guard_hdr))
		return;

	tlr = RTE_PTR_SUB(TAILQ_NEXT(hdr, obj_next), sizeof(struct memarea_objtlr));
	hdr_fail = (status == 0 && hdr->cookie != MEMAREA_OBJECT_HEADER_AVAILABLE_COOKIE) ||
		   (status == 1 && hdr->cookie != MEMAREA_OBJECT_HEADER_ALLOCATED_COOKIE) ||
		   (status == 2 && (hdr->cookie != MEMAREA_OBJECT_HEADER_AVAILABLE_COOKIE &&
				    hdr->cookie != MEMAREA_OBJECT_HEADER_ALLOCATED_COOKIE));
	tlr_fail = (tlr->cookie != MEMAREA_OBJECT_TRAILER_COOKIE);
	if (!hdr_fail && !tlr_fail)
		return;

	rte_panic("MEMAREA: %s check cookies failed! addr-%p header-cookie<0x%" PRIx64 " %s> trailer-cookie<0x%" PRIx64 " %s>\n",
		ma->init.name, RTE_PTR_ADD(hdr, sizeof(struct memarea_objhdr)),
		hdr->cookie, str[hdr_fail], tlr->cookie, str[tlr_fail]);
#else
	RTE_SET_USED(ma);
	RTE_SET_USED(hdr);
	RTE_SET_USED(status);
#endif
}

static inline bool
memarea_whether_add_node(size_t avail_sz, size_t alloc_sz)
{
	return (avail_sz - alloc_sz) > (sizeof(struct memarea_objhdr) +
					MEMAREA_OBJECT_SIZE_ALIGN
#ifdef RTE_LIBRTE_MEMAREA_DEBUG
					+ sizeof(struct memarea_objtlr)

#endif
					);
}

static inline void
memarea_add_node(struct rte_memarea *ma, struct memarea_objhdr *hdr, size_t alloc_sz)
{
#ifdef RTE_LIBRTE_MEMAREA_DEBUG
	struct memarea_objtlr *cur_tlr;
#endif
	struct memarea_objhdr *new_hdr;

#ifdef RTE_LIBRTE_MEMAREA_DEBUG
	cur_tlr = RTE_PTR_ADD(hdr, sizeof(struct memarea_objhdr) + alloc_sz);
	cur_tlr->cookie = MEMAREA_OBJECT_TRAILER_COOKIE;
	new_hdr = RTE_PTR_ADD(cur_tlr, sizeof(struct memarea_objtlr));
	new_hdr->cookie = MEMAREA_OBJECT_HEADER_AVAILABLE_COOKIE;
#else
	new_hdr = RTE_PTR_ADD(hdr, sizeof(struct memarea_objhdr) + alloc_sz);
#endif
	TAILQ_INSERT_AFTER(&ma->obj_list, hdr, new_hdr, obj_next);
	TAILQ_INSERT_AFTER(&ma->avail_list, hdr, new_hdr, avail_next);
}

void *
rte_memarea_alloc(struct rte_memarea *ma, size_t size)
{
	size_t align_sz = RTE_ALIGN(size, MEMAREA_OBJECT_SIZE_ALIGN);
	struct memarea_objhdr *hdr;
	size_t avail_sz;
	void *ptr = NULL;

	if (unlikely(ma == NULL || size == 0 || align_sz < size))
		return ptr;

	memarea_lock(ma);
	TAILQ_FOREACH(hdr, &ma->avail_list, avail_next) {
		memarea_check_cookie(ma, hdr, 0);
		avail_sz = MEMAREA_OBJECT_GET_SIZE(hdr);
		if (avail_sz < align_sz)
			continue;
		if (memarea_whether_add_node(avail_sz, align_sz))
			memarea_add_node(ma, hdr, align_sz);
		TAILQ_REMOVE(&ma->avail_list, hdr, avail_next);
		MEMAREA_OBJECT_MARK_ALLOCATED(hdr);
#ifdef RTE_LIBRTE_MEMAREA_DEBUG
		hdr->cookie = MEMAREA_OBJECT_HEADER_ALLOCATED_COOKIE;
#endif
		ptr = RTE_PTR_ADD(hdr, sizeof(struct memarea_objhdr));
		break;
	}
	memarea_unlock(ma);

	return ptr;
}

static inline void
memarea_merge_node(struct rte_memarea *ma, struct memarea_objhdr *curr,
		   struct memarea_objhdr *next)
{
#ifdef RTE_LIBRTE_MEMAREA_DEBUG
	struct memarea_objtlr *tlr;
#endif
	RTE_SET_USED(curr);
	TAILQ_REMOVE(&ma->obj_list, next, obj_next);
	TAILQ_REMOVE(&ma->avail_list, next, avail_next);
#ifdef RTE_LIBRTE_MEMAREA_DEBUG
	next->cookie = 0;
	tlr = RTE_PTR_SUB(next, sizeof(struct memarea_objtlr));
	tlr->cookie = 0;
#endif
}

void
rte_memarea_free(struct rte_memarea *ma, void *ptr)
{
	struct memarea_objhdr *hdr, *prev, *next;

	if (unlikely(ma == NULL || ptr == NULL))
		return;

	hdr = RTE_PTR_SUB(ptr, sizeof(struct memarea_objhdr));
	if (unlikely(!MEMAREA_OBJECT_IS_ALLOCATED(hdr))) {
		RTE_MEMAREA_LOG(ERR, "detect invalid object in %s!", ma->init.name);
		return;
	}
	memarea_check_cookie(ma, hdr, 1);

	memarea_lock(ma);

	/** 1st: add to avail list. */
#ifdef RTE_LIBRTE_MEMAREA_DEBUG
	hdr->cookie = MEMAREA_OBJECT_HEADER_AVAILABLE_COOKIE;
#endif
	TAILQ_INSERT_HEAD(&ma->avail_list, hdr, avail_next);

	/** 2nd: merge if previous object is avail. */
	prev = TAILQ_PREV(hdr, memarea_objhdr_list, obj_next);
	if (prev != NULL && !MEMAREA_OBJECT_IS_ALLOCATED(prev)) {
		memarea_check_cookie(ma, prev, 0);
		memarea_merge_node(ma, prev, hdr);
		hdr = prev;
	}

	/** 3rd: merge if next object is avail. */
	next = TAILQ_NEXT(hdr, obj_next);
	if (next != NULL && !MEMAREA_OBJECT_IS_ALLOCATED(next)) {
		memarea_check_cookie(ma, next, 0);
		memarea_merge_node(ma, hdr, next);
	}

	memarea_unlock(ma);
}

static const char *
memarea_source_name(enum rte_memarea_source source)
{
	if (source == RTE_MEMAREA_SOURCE_HEAP)
		return "heap";
	else if (source == RTE_MEMAREA_SOURCE_LIBC)
		return "libc";
	else if (source == RTE_MEMAREA_SOURCE_MEMAREA)
		return "memarea";
	else
		return "unknown";
}

static const char *
memarea_alg_name(enum rte_memarea_algorithm alg)
{
	if (alg == RTE_MEMAREA_ALGORITHM_NEXTFIT)
		return "nextfit";
	else
		return "unknown";
}

static void
memarea_dump_objects_brief(struct rte_memarea *ma, FILE *f)
{
	uint32_t total_objs = 0, total_avail_objs = 0;
	struct memarea_objhdr *hdr;
	size_t total_avail_sz = 0;

	TAILQ_FOREACH(hdr, &ma->obj_list, obj_next) {
		if (hdr == ma->guard_hdr)
			break;
		memarea_check_cookie(ma, hdr, 2);
		total_objs++;
		if (!MEMAREA_OBJECT_IS_ALLOCATED(hdr)) {
			total_avail_objs++;
			total_avail_sz += MEMAREA_OBJECT_GET_SIZE(hdr);
		}
	}
	fprintf(f, "  total-objects: %u\n", total_objs);
	fprintf(f, "  total-avail-objects: %u\n", total_avail_objs);
	fprintf(f, "  total-avail-objects-size: 0x%zx\n", total_avail_sz);
}

static void
memarea_dump_objects_detail(struct rte_memarea *ma, FILE *f)
{
	struct memarea_objhdr *hdr;
	size_t offset;
	void *ptr;

	fprintf(f, "  objects:\n");
	TAILQ_FOREACH(hdr, &ma->obj_list, obj_next) {
		if (hdr == ma->guard_hdr)
			break;
		memarea_check_cookie(ma, hdr, 2);
		ptr = RTE_PTR_ADD(hdr, sizeof(struct memarea_objhdr));
		offset = RTE_PTR_DIFF(ptr, ma->area_base);
#ifdef RTE_LIBRTE_MEMAREA_DEBUG
		fprintf(f, "    %p off: 0x%zx size: 0x%zx %s\n",
			ptr, offset, MEMAREA_OBJECT_GET_SIZE(hdr),
			MEMAREA_OBJECT_IS_ALLOCATED(hdr) ? "allocated" : "");
#else
		fprintf(f, "    off: 0x%zx size: 0x%zx %s\n",
			offset, MEMAREA_OBJECT_GET_SIZE(hdr),
			MEMAREA_OBJECT_IS_ALLOCATED(hdr) ? "allocated" : "");
#endif
	}
}

int
rte_memarea_dump(struct rte_memarea *ma, FILE *f, bool dump_all)
{
	if (ma == NULL || f == NULL)
		return -EINVAL;

	memarea_lock(ma);
	fprintf(f, "memarea name: %s\n", ma->init.name);
	fprintf(f, "  source: %s\n", memarea_source_name(ma->init.source));
	if (ma->init.source == RTE_MEMAREA_SOURCE_HEAP)
		fprintf(f, "  heap-numa-socket: %d\n", ma->init.numa_socket);
	else if (ma->init.source == RTE_MEMAREA_SOURCE_MEMAREA)
		fprintf(f, "  source-memarea: %s\n", ma->init.src_ma->init.name);
	fprintf(f, "  algorithm: %s\n", memarea_alg_name(ma->init.alg));
	fprintf(f, "  total-size: 0x%zx\n", ma->init.total_sz);
	fprintf(f, "  mt-safe: %s\n", ma->init.mt_safe ? "yes" : "no");
#ifdef RTE_LIBRTE_MEMAREA_DEBUG
	fprintf(f, "  area-base: %p\n", ma->area_base);
	fprintf(f, "  guard-header: %p\n", ma->guard_hdr);
#endif
	memarea_dump_objects_brief(ma, f);
	if (dump_all)
		memarea_dump_objects_detail(ma, f);
	memarea_unlock(ma);

	return 0;
}

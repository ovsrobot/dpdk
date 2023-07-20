/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 HiSilicon Limited
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>

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

	if (init->reserved_bits != 0 || init->reserved_64s[0] != 0 ||
	    init->reserved_64s[1] != 0) {
		RTE_MEMAREA_LOG(ERR, "%s reserved field not zero!", init->name);
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
	if (ret != 0)
		return NULL;
	return ptr;
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
	else if (init->source == RTE_MEMAREA_SOURCE_MEMAREA)
		ptr = rte_memarea_alloc(init->ma.src, init->total_sz);

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
		rte_memarea_free(init->ma.src, ptr);
}

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
	memarea_set_cookie(hdr, COOKIE_TARGET_STATUS_AVAILABLE);

	/** 5.2: hook the guard object to only obj_list. */
	memset(guard_hdr, 0, sizeof(struct memarea_objhdr));
	TAILQ_INSERT_AFTER(&ma->obj_list, hdr, guard_hdr, obj_next);
	MEMAREA_OBJECT_MARK_ALLOCATED(guard_hdr);
	memarea_set_cookie(guard_hdr, COOKIE_TARGET_STATUS_NEW_ALLOCATED);

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

static inline void
memarea_check_cookie(const struct rte_memarea *ma, const struct memarea_objhdr *hdr, int status)
{
#ifdef RTE_LIBRTE_MEMAREA_DEBUG
	static const char *const str[] = { "PASS", "FAILED" };
	struct memarea_objtlr *tlr;
	bool hdr_fail, tlr_fail;

	if (hdr == ma->guard_hdr)
		return;

	tlr = RTE_PTR_SUB(TAILQ_NEXT(hdr, obj_next), sizeof(struct memarea_objtlr));
	hdr_fail = (status == COOKIE_EXPECT_STATUS_AVAILABLE &&
		    hdr->cookie != MEMAREA_OBJECT_HEADER_AVAILABLE_COOKIE) ||
		   (status == COOKIE_EXPECT_STATUS_ALLOCATED &&
		    hdr->cookie != MEMAREA_OBJECT_HEADER_ALLOCATED_COOKIE) ||
		   (status == COOKIE_EXPECT_STATUS_VALID &&
		    (hdr->cookie != MEMAREA_OBJECT_HEADER_AVAILABLE_COOKIE &&
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

static inline void
memarea_split_object(struct rte_memarea *ma, struct memarea_objhdr *hdr, size_t alloc_sz)
{
	struct memarea_objhdr *split_hdr;

	split_hdr = MEMAREA_SPLIT_OBJECT_GET_HEADER(hdr, alloc_sz);
	memarea_set_cookie(split_hdr, COOKIE_TARGET_STATUS_NEW_AVAILABLE);
	TAILQ_INSERT_AFTER(&ma->obj_list, hdr, split_hdr, obj_next);
	TAILQ_INSERT_AFTER(&ma->avail_list, hdr, split_hdr, avail_next);
}

void *
rte_memarea_alloc(struct rte_memarea *ma, size_t size)
{
	size_t align_sz = RTE_ALIGN(size, MEMAREA_OBJECT_SIZE_ALIGN);
	struct memarea_objhdr *hdr;
	size_t avail_sz;
	void *ptr = NULL;

	if (ma == NULL || size == 0 || align_sz < size) {
		rte_errno = EINVAL;
		return ptr;
	}

	memarea_lock(ma);

	/** traverse every available object, return the first satisfied one. */
	TAILQ_FOREACH(hdr, &ma->avail_list, avail_next) {
		/** 1st: check whether the object size meets. */
		memarea_check_cookie(ma, hdr, COOKIE_EXPECT_STATUS_AVAILABLE);
		avail_sz = MEMAREA_OBJECT_GET_SIZE(hdr);
		if (avail_sz < align_sz)
			continue;

		/** 2nd: if the object size is too long, a new object can be split. */
		if (avail_sz - align_sz > MEMAREA_SPLIT_OBJECT_MIN_SIZE)
			memarea_split_object(ma, hdr, align_sz);

		/** 3rd: allocate successful. */
		TAILQ_REMOVE(&ma->avail_list, hdr, avail_next);
		MEMAREA_OBJECT_MARK_ALLOCATED(hdr);
		memarea_set_cookie(hdr, COOKIE_TARGET_STATUS_ALLOCATED);

		ptr = RTE_PTR_ADD(hdr, sizeof(struct memarea_objhdr));
		break;
	}

	memarea_unlock(ma);

	if (ptr == NULL)
		rte_errno = ENOMEM;
	return ptr;
}

static inline void
memarea_merge_object(struct rte_memarea *ma, struct memarea_objhdr *curr,
		   struct memarea_objhdr *next)
{
	RTE_SET_USED(curr);
	TAILQ_REMOVE(&ma->obj_list, next, obj_next);
	TAILQ_REMOVE(&ma->avail_list, next, avail_next);
	memarea_set_cookie(next, COOKIE_TARGET_STATUS_CLEARED);
}

void
rte_memarea_free(struct rte_memarea *ma, void *ptr)
{
	struct memarea_objhdr *hdr, *prev, *next;

	if (ma == NULL || ptr == NULL) {
		rte_errno = EINVAL;
		return;
	}

	hdr = RTE_PTR_SUB(ptr, sizeof(struct memarea_objhdr));
	if (!MEMAREA_OBJECT_IS_ALLOCATED(hdr)) {
		RTE_MEMAREA_LOG(ERR, "detect invalid object in %s!", ma->init.name);
		rte_errno = EFAULT;
		return;
	}
	memarea_check_cookie(ma, hdr, COOKIE_EXPECT_STATUS_ALLOCATED);

	memarea_lock(ma);

	/** 1st: add to avail list. */
	TAILQ_INSERT_HEAD(&ma->avail_list, hdr, avail_next);
	memarea_set_cookie(hdr, COOKIE_TARGET_STATUS_AVAILABLE);

	/** 2nd: merge if previous object is avail. */
	prev = TAILQ_PREV(hdr, memarea_objhdr_list, obj_next);
	if (prev != NULL && !MEMAREA_OBJECT_IS_ALLOCATED(prev)) {
		memarea_check_cookie(ma, prev, COOKIE_EXPECT_STATUS_AVAILABLE);
		memarea_merge_object(ma, prev, hdr);
		hdr = prev;
	}

	/** 3rd: merge if next object is avail. */
	next = TAILQ_NEXT(hdr, obj_next);
	if (next != NULL && !MEMAREA_OBJECT_IS_ALLOCATED(next)) {
		memarea_check_cookie(ma, next, COOKIE_EXPECT_STATUS_AVAILABLE);
		memarea_merge_object(ma, hdr, next);
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
		memarea_check_cookie(ma, hdr, COOKIE_EXPECT_STATUS_VALID);
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
		memarea_check_cookie(ma, hdr, COOKIE_EXPECT_STATUS_VALID);
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
	if (ma == NULL || f == NULL) {
		rte_errno = EINVAL;
		return -1;
	}

	memarea_lock(ma);
	fprintf(f, "memarea name: %s\n", ma->init.name);
	fprintf(f, "  source: %s\n", memarea_source_name(ma->init.source));
	if (ma->init.source == RTE_MEMAREA_SOURCE_HEAP)
		fprintf(f, "  heap-numa-socket: %d\n", ma->init.heap.socket_id);
	else if (ma->init.source == RTE_MEMAREA_SOURCE_MEMAREA)
		fprintf(f, "  source-memarea: %s\n", ma->init.ma.src->init.name);
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

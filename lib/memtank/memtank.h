/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Intel Corporation
 * Copyright(c) 2025 Huawei Technologies Co., Ltd
 */

#ifndef	_MEMTANK_H_
#define	_MEMTANK_H_

#include <rte_memtank.h>
#include <rte_atomic.h>
#include <rte_spinlock.h>
#include <rte_log.h>
#include <stdalign.h>
#include <errno.h>

extern int memtank_logtype;
#define RTE_LOGTYPE_MTANK memtank_logtype
#define MTANK_LOG(level, ...) \
	 RTE_LOG_LINE(level, MTANK, "" __VA_ARGS__)

struct memobj {
	uint64_t red_zone1;
	struct memchunk *chunk; /* ptr to the chunk it belongs to */
	struct {
		uint32_t nb_alloc;
		uint32_t nb_free;
	} dbg;
	uint64_t red_zone2;
};

#define RED_ZONE_V1	UINT64_C(0xBADECAFEBADECAFE)
#define RED_ZONE_V2	UINT64_C(0xDEADBEEFDEADBEEF)

struct memchunk {
	TAILQ_ENTRY(memchunk) link;  /* link to the next chunk in the tank */
	void *raw;		     /* un-aligned ptr returned by alloc() */
	uint32_t nb_total;           /* total number of objects in the chunk */
	uint32_t nb_free;            /* number of free object in the chunk */
	void *free[];                /* array of free objects */
} __rte_cache_aligned;


TAILQ_HEAD(mchunk_head, memchunk);

struct mchunk_list {
	rte_spinlock_t lock;
	struct mchunk_head chunk;  /* list of chunks */
} __rte_cache_aligned;

enum {
	MC_FULL,  /* all memchunk objs are free */
	MC_USED,  /* some of memchunk objs are allocated */
	MC_NUM,
};

struct memtank_free {
	rte_spinlock_t lock;
	uint32_t min_free;
	uint32_t max_free;
	uint32_t nb_free;
	void *free[];
} __rte_cache_aligned;

struct rte_memtank {
	/* user provided data */
	struct rte_memtank_prm prm;

	/*run-time data */
	void *raw;		        /* un-aligned ptr returned by alloc() */
	size_t chunk_size;              /* full size of each memchunk */
	uint32_t obj_size;	        /* full size of each memobj */
	uint32_t max_chunk;             /* max allowed number of chunks */
	uint32_t flags;                 /* behavior flags */
	RTE_ATOMIC(uint32_t) nb_chunks; /* number of allocated chunks */
	struct mchunk_list chl[MC_NUM]; /* lists of memchunks */
	struct memtank_free mtf;        /* cached free objects */
};

/**
 * Obtain pointer to internal memobj struct from public one
 */
static inline struct memobj *
obj_pub_full(uintptr_t p, uint32_t obj_sz)
{
	uintptr_t v;

	v = p + obj_sz - sizeof(struct memobj);
	return (struct memobj *)v;
}

/**
 * Fast check: does given object belongs to that memchunk.
 * Returns zero, if object is within the chunk, non-zero value otherwise.
 */
static inline int
obj_check_chunk(uintptr_t obj, size_t obj_sz, uintptr_t chn, size_t chn_sz)
{
	return (obj <= chn || obj + obj_sz > chn + chn_sz);
}

static inline int
memobj_verify(const struct memobj *mo, uint32_t finc)
{
	if (mo->red_zone1 != RED_ZONE_V1 || mo->red_zone2 != RED_ZONE_V2 ||
			mo->dbg.nb_alloc != mo->dbg.nb_free + finc)
		return -EINVAL;
	return 0;
}

#endif	/* _MEMTANK_H_ */

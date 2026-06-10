/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Intel Corporation
 * Copyright(c) 2025 Huawei Technologies Co., Ltd
 */

#ifndef _RTE_MEMTANK_H_
#define _RTE_MEMTANK_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>
#include <rte_compat.h>
#include <stdio.h>

/**
 * @file
 * RTE memtank
 *
 * Same a s mempool it allows to alloc/free objects of fixed size
 * in a lightweight manner (probably not as lightweight as mempool,
 * but hopefully close enough).
 * But in addition it can grow/shrink dynamically plus provides extra
 * additional API for higher flexibility:
 *	- manual grow()/shrink() functions
 *	- different alloc/free policies
 *        (can be specified by user via flags parameter).
 *
 * Internally it consists of:
 *	- LIFO queue (fast allocator/deallocator)
 *	- lists of memchunks (USED, FREE).
 *
 * For performance reasons memtank tries to allocate memory in
 * relatively big chunks (memchunks) and then split each memchunk
 * in dozens (or hundreds) of objects.
 * There are two thresholds:
 *	- min_free (grow threshold)
 *	- max_free (shrink threshold)
 */

struct rte_memtank;

/** generic memtank behavior flags */
enum {
	/** Enable obj debugging */
	RTE_MTANK_OBJ_DBG = 1,
};

struct rte_memtank_prm {
	/** min number of free objs in the ring (grow threshold). */
	uint32_t min_free;
	uint32_t max_free;  /**< max number of free objs (empty threshold) */
	uint32_t max_obj; /**< max number of objs (grow limit) */
	uint32_t obj_size;  /**< size of each mem object */
	uint32_t obj_align;  /**< alignment of each mem object */
	uint32_t nb_obj_chunk; /**< number of objects per chunk */
	uint32_t flags; /**< behavior flags */
	/** user provided function to alloc chunk of memory */
	void * (*alloc)(size_t len, void *udata);
	/** user provided function to free chunk of memory */
	void (*free)(void *mem, void *udata);
	/** user provided function to initialiaze an object */
	void (*init)(void *obj[], uint32_t num, void *udata);
	void *udata;        /**< opaque user data for alloc/free/init */
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Allocate and intitialize new memtank instance, based on the
 * parameters provided. Note that it uses user-provided *alloc()* function
 * to allocate space for the memtank metadata.
 * @param prm
 *   Parameters used to create and initialise new memtank.
 * @return
 *   - Pointer to new memtank insteance created, if operation completed
 *     successfully.
 *   - NULL on error with rte_errno set appropriately.
 */
__rte_experimental
struct rte_memtank *
rte_memtank_create(const struct rte_memtank_prm *prm);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Destroy the memtank and free all memory referenced by the memtank.
 * The objects must not be used by other cores as they will be freed.
 *
 * @param t
 *   A pointer to the memtank instance.
 */
__rte_experimental
void
rte_memtank_destroy(struct rte_memtank *t);


/** alloc flags */
enum {
	RTE_MTANK_ALLOC_CHUNK = 1,
	/** Allocate extra memchunks if needed */
	RTE_MTANK_ALLOC_GROW = 2,
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Allocate up to requested number of objects from the memtank.
 * Note that depending on *alloc* behavior (flags) some new memory chunks
 * can be allocated from the underlying memory subsystem.
 *
 * @param t
 *   A pointer to the memtank instance.
 * @param obj
 *   An array of void * pointers (objects) that will be filled.
 * @param num
 *   Number of objects to allocate from the memtank.
 * @param flags
 *   Flags that control allocation behavior.
 * @return
 *   Number of allocated objects.
 */
__rte_experimental
uint32_t
rte_memtank_alloc(struct rte_memtank *t, void *obj[], uint32_t num,
		uint32_t flags);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Allocate up to requested number of objects from the memtank.
 * Note that this function bypasses *free* cache(s) and tries to allocate
 * objects straight from the memory chunks.
 * Note that depending on *alloc* behavior (flags) some new memory chunks
 * can be allocated from the underlying memory subsystem.
 *
 * @param t
 *   A pointer to the memtank instance.
 * @param obj
 *   An array of void * pointers (objects) that will be filled.
 * @param nb_obj
 *   Number of objects to allocate from the memtank.
 * @param flags
 *   Flags that control allocation behavior.
 * @return
 *   Number of allocated objects.
 */
__rte_experimental
uint32_t
rte_memtank_chunk_alloc(struct rte_memtank *t, void *obj[], uint32_t nb_obj,
		uint32_t flags);

/** free flags */
enum {
	/** Free unneeded chunk of memory */
	RTE_MTANK_FREE_SHRINK = 1,
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Free (put) provided objects back to the memtank.
 * Note that depending on *free* behavior (flags) some memory chunks can be
 * returned (freed) to the underlying memory subsystem.
 *
 * @param t
 *   A pointer to the memtank instance.
 * @param obj
 *   An array of object pointers to be freed.
 * @param num
 *   Number of objects to free.
 * @param flags
 *   Flags that control free behavior.
 */
__rte_experimental
void
rte_memtank_free(struct rte_memtank *t, void * const obj[],  uint32_t num,
		uint32_t flags);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Free (put) provided objects back to the memtank.
 * Note that this function bypasses *free* cache(s) and tries to put
 * objects straight to the memory chunks.
 * Note that depending on *free* behavior (flags) some memory chunks can be
 * returned (freed) to the underlying memory subsystem.
 *
 * @param t
 *   A pointer to the memtank instance.
 * @param obj
 *   An array of object pointers to be freed.
 * @param nb_obj
 *   Number of objects to allocate from the memtank.
 * @param flags
 *   Flags that control allocation behavior.
 */
__rte_experimental
void
rte_memtank_chunk_free(struct rte_memtank *t, void * const obj[],
		uint32_t nb_obj, uint32_t flags);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Check does number of objects in *free* cache is below memtank grow
 * threshold (min_free). If yes, then tries to allocate memory for new
 * objects from the underlying memory subsystem.
 *
 * @param t
 *   A pointer to the memtank instance.
 * @return
 *   Number of newly allocated memory chunks.
 */
__rte_experimental
int
rte_memtank_grow(struct rte_memtank *t);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Check does number of objects in *free* cache have reached memtank shrink
 * threshold (max_free). If yes, then tries to return excessive memory to
 * the underlying memory subsystem.
 *
 * @param t
 *   A pointer to the memtank instance.
 * @return
 *   Number of freed memory chunks.
 */
__rte_experimental
int
rte_memtank_shrink(struct rte_memtank *t);

/** dump flags */
enum {
	RTE_MTANK_DUMP_FREE_STAT = 1,
	RTE_MTANK_DUMP_CHUNK_STAT = 2,
	RTE_MTANK_DUMP_CHUNK = 4,
	/* first not used power of two */
	RTE_MTANK_DUMP_END = 8,

	/** dump all stats */
	RTE_MTANK_DUMP_STAT =
		(RTE_MTANK_DUMP_FREE_STAT | RTE_MTANK_DUMP_CHUNK_STAT),
	/** dump everything */
	RTE_MTANK_DUMP_ALL = RTE_MTANK_DUMP_END - 1,
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Dump information about the memtank to the file.
 * Note that depending of *flags* value it might cause some internal locks
 * grabbing, and might affect performance of others threads that
 * concurently use same memtank.
 *
 * @param f
 *   A pinter to the file.
 * @param t
 *   A pointer to the memtank instance.
 * @param flags
 *   Flags that control dump behavior.
 */
__rte_experimental
void
rte_memtank_dump(FILE *f, struct rte_memtank *t, uint32_t flags);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Check the consistency of the given memtank instance.
 * Dumps error messages to the RTE log subsystem, if some inconsitency
 * is detected.
 *
 * @param t
 *   A pointer to the memtank instance.
 * @param ct
 *   Value greater then zero, if some other threads do concurently use
 *   that memtank.
 * @return
 *   Zero on success, or negative value otherwise.
 */
__rte_experimental
int
rte_memtank_sanity_check(struct rte_memtank *t, int32_t ct);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_MEMTANK_H_ */

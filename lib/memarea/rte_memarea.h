/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 HiSilicon Limited
 */

#ifndef RTE_MEMAREA_H
#define RTE_MEMAREA_H

/**
 * @file
 * RTE Memarea.
 *
 * The memarea is an allocator of variable-size object which based on a memory
 * region. It has the following features:
 *
 * - The memory region can be initialized from the following memory sources:
 *   1. HEAP: e.g. invoke rte_malloc_socket.
 *   2. LIBC: e.g. invoke posix_memalign.
 *   3. Another memarea: it can be allocated from another memarea.
 *
 * - It provides refcnt feature which could be useful in multi-reader scenario.
 *
 * - It supports MT-safe as long as it's specified at creation time. If not
 *   specified, all the functions of the memarea API are lock-free, and assume
 *   to not be invoked in parallel on different logical cores to work on the
 *   same memarea.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <rte_compat.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RTE_MEMAREA_NAMESIZE	64

/**
 * Memarea memory source.
 */
enum rte_memarea_source {
	/** Memory source comes from rte memory. */
	RTE_MEMAREA_SOURCE_HEAP,
	/** Memory source comes from libc. */
	RTE_MEMAREA_SOURCE_LIBC,
	/** Memory source comes from another memarea. */
	RTE_MEMAREA_SOURCE_MEMAREA,
};

/**
 * Memarea memory management algorithm.
 */
enum rte_memarea_alg {
	/** The default management algorithm is a variant of the next fit
	 * algorithm. It uses a free-list to apply for memory and uses an
	 * element-list in ascending order of address to support merging
	 * upon free.
	 */
	RTE_MEMAREA_ALG_NEXTFIT,
};

struct rte_memarea;

/**
 * Memarea creation parameters.
 */
struct rte_memarea_param {
	char name[RTE_MEMAREA_NAMESIZE]; /**< Name of memarea. */
	enum rte_memarea_source source;  /**< Memory source of memarea. */
	enum rte_memarea_alg alg;        /**< Memory management algorithm. */
	size_t total_sz;                 /**< total size (bytes) of memarea. */
	/** Indicates whether the memarea API should be MT-safe. */
	uint32_t mt_safe : 1;
	union {
		/** Numa socket from which to apply for memarea's memory, this
		 * field is valid only when the source is set to be
		 * RTE_MEMAREA_SOURCE_HEAP.
		 */
		int numa_socket;
		/** Source memarea, this field is valid only when the source is
		 * set to be RTE_MEMAREA_SOURCE_MEMAREA.
		 */
		struct rte_memarea *src_memarea;
	};
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Create memarea.
 *
 * Create one new memarea.
 *
 * @param init
 *   The init parameter of memarea.
 *
 * @return
 *   Non-NULL on success. Otherwise NULL is returned.
 */
__rte_experimental
struct rte_memarea *rte_memarea_create(const struct rte_memarea_param *init);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Destroy memarea.
 *
 * Destroy the memarea.
 *
 * @param ma
 *   The pointer of memarea.
 */
__rte_experimental
void rte_memarea_destroy(struct rte_memarea *ma);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Allocate memory from memarea.
 *
 * Allocate one memory object from the memarea.
 *
 * @param ma
 *   The pointer of memarea.
 * @param size
 *   The memory size to be allocated.
 * @param cookie
 *   User-provided footprint which could used to debug memory leak.
 *
 * @return
 *   - NULL on error. Not enough memory, or invalid arguments (ma is NULL,
 *     size is 0).
 *   - Otherwise, the pointer to the allocated object.
 */
__rte_experimental
void *rte_memarea_alloc(struct rte_memarea *ma, size_t size, uint32_t cookie);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Free memory to memarea.
 *
 * Free one memory object to the memarea. If the object's refcnt is greater
 * than one, only the refcnt is decremented by one. Otherwise the object is
 * released.
 * @note The memory object must have been returned by a previous call to
 * rte_memarea_alloc(), if it is allocated from memarea-A, it must be freed to
 * the same memarea-A. The behaviour of rte_memarea_free() is undefined if the
 * memarea or pointer does not match these requirements.
 *
 * @param ma
 *   The pointer of memarea. If the ma is NULL, the function does nothing.
 * @param ptr
 *   The pointer of memory object which need be freed. If the pointer is NULL,
 *   the function does nothing.
 */
__rte_experimental
void rte_memarea_free(struct rte_memarea *ma, void *ptr);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Update memory's refcnt.
 *
 * Update one memory object's refcnt. When refcnt is updated to be zero, the
 * memory object is freed.
 *
 * @note The memory object must have been returned by a previous call to
 * rte_memarea_alloc(), if it is allocated from memarea-A, the refcnt update
 * must be operated to the same memarea-A. The behaviour of
 * rte_memarea_refcnt_update() is undefined if the memarea or pointer does not
 * match these requirements.
 *
 * @note If the memory object's refcnt updated to be lower than zero, an error
 * message will be printed, and the memory object will not freed to memrea.
 *
 * @param ma
 *   The pointer of memarea.
 * @param ptr
 *   The pointer of memory object which need be updated refcnt.
 * @param value
 *   The value which need be updated.
 */
__rte_experimental
void rte_memarea_refcnt_update(struct rte_memarea *ma, void *ptr, int32_t value);

#ifdef __cplusplus
}
#endif

#endif /* RTE_MEMAREA_H */

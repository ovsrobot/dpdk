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
 * - The allocated object aligned at RTE_CACHE_LINE_SIZE default.
 * - The memory region can be initialized from the following memory sources:
 *   1. HEAP: e.g. invoke rte_malloc_socket.
 *   2. LIBC: e.g. invoke posix_memalign.
 *   3. User provided: it can be from e.g. rte_extmem_xxx as long as it is
 *      available. The memory's start address must be aligned to
 *      RTE_CACHE_LINE_SIZE.
 *   4) User provided memarea: it can be from another memarea. So we can build
 *      the following memory management structure:
 *         \code{.unparsed}
 *                           -------------
 *                           | memarea-1 |
 *                           -------------
 *                                 |
 *                                 v
 *                  -------------------------------
 *                  |               |             |
 *                  v               v             v
 *            -------------   -------------   ----------
 *            | memarea-2 |   | memarea-3 |   | object |
 *            -------------   -------------   ----------
 *         \endcode
 *      As shown above, the memarea-2/3 both create from memarea-1's memory.
 * - It provides refcnt feature which could be useful in multi-reader scenario.
 * - It supports MT-safe as long as it's specified at creation time. If not
 *   specified, all the functions of the memarea API are lock-free, and assume
 *   to not be invoked in parallel on different logical cores to work on the
 *   same memarea.
 * - It provides backup memory mechanism, the memarea could use another memarea
 *   as a backup. It will attempts to allocate object from backup memarea when
 *   the current memarea failed to allocate.
 *   @note If the backup memarea is set improperly, loops may occur (e.g.
 *   memarea-1's backup is memarea-2, and memarea-2's backup is memarea-1) and
 *   the program will hangs, it is the responsibility of the application to
 *   ensure that the loops do not form.
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
	/** Memory source comes from user-provided memory. */
	RTE_MEMAREA_SOURCE_USER,
	/** Memory source comes from user-provided memarea. */
	RTE_MEMAREA_SOURCE_USER_MEMAREA,
};

/**
 * Memarea memory management algorithm.
 */
enum rte_memarea_alg {
	/* The default management algorithm is a variant of the next fit
	 * algorithm. It uses a free-list to apply for memory and uses an
	 * element-list in ascending order of address to support merging
	 * upon free.
	 */
	RTE_MEMAREA_ALG_DEFAULT,
};

struct rte_memarea;

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
		/** User provided address, this field is valid only when the
		 * source is set to be RTE_MEMAREA_SOURCE_USER.
		 * Note: the provided address must align at least
		 * RTE_CACHE_LINE_SIZE.
		 */
		void *user_addr;
		/** User provided memarea, this field is valid only when the
		 * source is set to be RTE_MEMAREA_SOURCE_USER_MEMAREA.
		 */
		struct rte_memarea *user_memarea;
	};
	/** Backup memarea, which is used to handle the scenario where the
	 * current memarea allocation failure.
	 */
	struct rte_memarea *bak_memarea;
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
 *   Non-NULL on success. Otherwise NULL is returned.
 */
__rte_experimental
void *rte_memarea_alloc(struct rte_memarea *ma, size_t size, uint32_t cookie);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Free memory to memarea.
 *
 * Free one memory object to the memarea.
 *
 * @param ma
 *   The pointer of memarea.
 * @param ptr
 *   The pointer of memory object which need be freed.
 */
__rte_experimental
void rte_memarea_free(struct rte_memarea *ma, void *ptr);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Update memory's refcnt.
 *
 * Update one memory object's refcnt.
 * When refcnt is updated to be zero, the memory object is freed.
 *
 * @param ma
 *   The pointer of memarea.
 * @param ptr
 *   The pointer of memory object which need be updated refcnt.
 * @param value
 *   The value which need be updated.
 */
__rte_experimental
void rte_memarea_update_refcnt(struct rte_memarea *ma, void *ptr, int16_t value);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Dump memarea.
 *
 * Dump one memarea.
 *
 * @param ma
 *   The pointer of memarea.
 * @param f
 *   The file to write the output to.
 * @param dump_all
 *   Indicate whether to dump the allocated and free memory objects information.
 *
 * @return
 *   0 on success. Otherwise negative value is returned.
 */
__rte_experimental
int rte_memarea_dump(struct rte_memarea *ma, FILE *f, bool dump_all);

#ifdef __cplusplus
}
#endif

#endif /* RTE_MEMAREA_H */

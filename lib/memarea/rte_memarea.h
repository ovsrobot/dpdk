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

#ifdef __cplusplus
}
#endif

#endif /* RTE_MEMAREA_H */

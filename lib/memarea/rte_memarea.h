/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 HiSilicon Limited
 */

#ifndef RTE_MEMAREA_H
#define RTE_MEMAREA_H

/**
 * @file
 * RTE Memarea.
 *
 * A memory area is an allocator of variable-size object. It is identified
 * by its name.
 *
 * The memarea is a collection of allocated objects that can be efficiently
 * alloc or free all at once, the main feature are as follows:
 *   a) It facilitate alloc and free of memory with low overhead.
 *   b) It's memory source could comes from:
 *      1) System API: malloc/memalign in C library.
 *      2) User provided address: it can be from the rte_malloc API series
 *         or extended memory as long as it is available. The address must be
 *         aligned to RTE_CACHE_LINE_SIZE.
 *      3) User provided memarea: it can be from another memarea. So we can
 *         build the following memory management structure:
 *         \code{.unparsed}
 *                           -------------
 *                           | memarea-1 |
 *                           -------------
 *                                 |
 *                                 v
 *                  ------------------------------
 *                  |               |            |
 *                  v               v            v
 *            -------------   -------------   -------
 *            | memarea-2 |   | memarea-3 |   | obj |
 *            -------------   -------------   -------
 *         \endcode
 *   c) The default alignment size is RTE_CACHE_LINE_SIZE.
 *   d) It provides refcnt feature which could be useful in some scenes.
 *   e) It supports MT-safe as long as it's specified at creation time. If not
 *      specified, all the functions of the memarea API are lock-free, and
 *      assume to not be invoked in parallel on different logical cores to work
 *      on the same memarea object.
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
	/** Memory source comes from system API (e.g. malloc). */
	RTE_MEMAREA_SOURCE_SYSTEM_API,
	/** Memory source comes from user-provided address. */
	RTE_MEMAREA_SOURCE_USER_ADDR,
	/** Memory source comes from user-provided memarea. */
	RTE_MEMAREA_SOURCE_USER_MEMAREA,
};

struct rte_memarea;

struct rte_memarea_param {
	char name[RTE_MEMAREA_NAMESIZE]; /**< Name of memarea. */
	enum rte_memarea_source source;  /**< Memory source of memarea. */
	size_t total_sz;                 /**< total size (bytes) of memarea. */
	/** Indicates whether the memarea API should be MT-safe. */
	uint32_t mt_safe : 1;
	union {
		/** User provided address, this field is valid only when the
		 * source is set to be RTE_MEMAREA_SOURCE_USER_ADDR.
		 * Note: the provided address must align at least
		 * RTE_CACHE_LINE_SIZE.
		 */
		void *user_addr;
		/** User provided memarea, this field is valid only when the
		 * source is set to be RTE_MEMAREA_SOURCE_USER_MEMAREA.
		 */
		struct rte_memarea *user_memarea;
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

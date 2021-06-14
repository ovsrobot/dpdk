/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA Corporation & Affiliates
 */

#ifndef RTE_PARRAY_H
#define RTE_PARRAY_H

#include <stddef.h>
#include <stdint.h>
#include <pthread.h>

#include <rte_compat.h>

/**
 * @file
 * Object containing a resizable array of pointers.
 *
 * The write operations (alloc/free) are protected by mutex.
 * The read operation (dereference) is considered as fast path
 * and is not directly protected.
 *
 * On resize, the array n-1 is kept to allow pending reads.
 * After 2 resizes, the array n-2 is freed.
 *
 * Iterating (rte_parray_find_next) is safe during alloc/free.
 *
 * Freeing must be synchronized with readers:
 * an element must not be accessed if it is being freed.
 *
 * @warning
 * Because of above limitations, this API is for internal use.
 */

#ifdef __cplusplus
extern "C" {
#endif

/** Main object representing a dynamic array of pointers. */
struct rte_parray {
	/** Array of pointer to dynamically allocated struct. */
	void **array;
	/** Old array before resize, freed on next resize. */
	void **old_array;
	/* Lock for alloc/free operations. */
	pthread_mutex_t mutex;
	/** Current size of the full array. */
	int32_t size;
	/** Number of allocated elements. */
	int32_t count;
	/** Last allocated element. */
	int32_t last;
};

/** Static initializer to assign. */
#define RTE_PARRAY_INITIALIZER {NULL, NULL, PTHREAD_MUTEX_INITIALIZER, 0, 0, -1}

/** Helper for access to the typed pointer of the element at index. */
#define RTE_PARRAY_P(type, obj, index) ((type *)(obj)->array[index])

/** Loop helper to iterate all elements. */
#define RTE_PARRAY_FOREACH(obj, index) for ( \
	index = rte_parray_find_next(obj, 0); \
	index > 0; \
	index = rte_parray_find_next(obj, index + 1))

/**
 * @warning
 * This internal API may change without prior notice.
 *
 * Get the next pointer in the array.
 *
 * @param obj
 *   Pointer to the main object.
 * @param index
 *   The initial index to start the research.
 *
 * @return
 *   Index of the next allocated element,
 *   -1 if there is none.
 *   rte_errno is set to EINVAL if parameters are NULL or negative.
 */
__rte_internal
int32_t rte_parray_find_next(struct rte_parray *obj, int32_t index);

/**
 * @warning
 * This internal API may change without prior notice.
 *
 * Allocate an element and insert it into the array.
 *
 * @param obj
 *   Pointer to the main object.
 * @param elem_size
 *   Number of bytes to allocate for the element.
 *   Do nothing if requesting 0.
 *
 * @return
 *   An index in the array, otherwise the negative rte_errno:
 *   - EINVAL if array is NULL
 *   - ENOMEM if out of space
 */
__rte_internal
int32_t rte_parray_alloc(struct rte_parray *obj, size_t elem_size);

/**
 * @warning
 * This internal API may change without prior notice.
 *
 * Free an element and remove it from the array.
 *
 * @param obj
 *   Pointer to the main object.
 * @param index
 *   Index of the element to be freed.
 *   Do nothing if not a valid element.
 *
 * rte_errno is set to EINVAL if a parameter is out of range.
 */
__rte_internal
void rte_parray_free(struct rte_parray *obj, int32_t index);

/**
 * @warning
 * This internal API may change without prior notice.
 *
 * Free all elements of an array.
 *
 * @param obj
 *   Pointer to the main object.
 */
__rte_internal
void rte_parray_free_all(struct rte_parray *obj);

#ifdef __cplusplus
}
#endif

#endif /* RTE_PARRAY_H */

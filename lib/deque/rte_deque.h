/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Arm Limited
 */

#ifndef _RTE_DEQUE_H_
#define _RTE_DEQUE_H_

/**
 * @file
 * RTE double ended queue (Deque)
 *
 * This fixed-size queue does not provide concurrent access by
 * multiple threads. If required, the application should use locks
 * to protect the deque from concurrent access.
 *
 * - Double ended queue
 * - Maximum size is fixed
 * - Store objects of any size
 * - Single/bulk/burst dequeue at tail or head
 * - Single/bulk/burst enqueue at head or tail
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_deque_core.h>
#include <rte_deque_pvt.h>
#include <rte_deque_zc.h>

/**
 * Calculate the memory size needed for a deque
 *
 * This function returns the number of bytes needed for a deque, given
 * the number of objects and the object size. This value is the sum of
 * the size of the structure rte_deque and the size of the memory needed
 * by the objects. The value is aligned to a cache line size.
 *
 * @param esize
 *   The size of deque object, in bytes. It must be a multiple of 4.
 * @param count
 *   The number of objects in the deque (must be a power of 2).
 * @return
 *   - The memory size needed for the deque on success.
 *   - -EINVAL if count is not a power of 2.
 */
__rte_experimental
ssize_t rte_deque_get_memsize_elem(unsigned int esize, unsigned int count);

/**
 * Initialize a deque structure.
 *
 * Initialize a deque structure in memory pointed by "d". The size of the
 * memory area must be large enough to store the deque structure and the
 * object table. It is advised to use rte_deque_get_memsize() to get the
 * appropriate size.
 *
 * The deque size is set to *count*, which must be a power of two.
 * The real usable deque size is *count-1* instead of *count* to
 * differentiate a full deque from an empty deque.
 *
 * @param d
 *   The pointer to the deque structure followed by the objects table.
 * @param name
 *   The name of the deque.
 * @param count
 *   The number of objects in the deque (must be a power of 2,
 *   unless RTE_DEQUE_F_EXACT_SZ is set in flags).
 * @param flags
 *   - RTE_DEQUE_F_EXACT_SZ: If this flag is set, the deque will hold
 *     exactly the requested number of objects, and the requested size
 *     will be rounded up to the next power of two, but the usable space
 *     will be exactly that requested. Worst case, if a power-of-2 size is
 *     requested, half the deque space will be wasted.
 *     Without this flag set, the deque size requested must be a power of 2,
 *     and the usable space will be that size - 1.
 * @return
 *   0 on success, or a negative value on error.
 */
__rte_experimental
int rte_deque_init(struct rte_deque *d, const char *name, unsigned int count,
		unsigned int flags);

/**
 * Create a new deque named *name* in memory.
 *
 * This function uses ``memzone_reserve()`` to allocate memory. Then it
 * calls rte_deque_init() to initialize an empty deque.
 *
 * The new deque size is set to *count*, which must be a power of two.
 * The real usable deque size is *count-1* instead of *count* to
 * differentiate a full deque from an empty deque.
 *
 * @param name
 *   The name of the deque.
 * @param esize
 *   The size of deque object, in bytes. It must be a multiple of 4.
 * @param count
 *   The size of the deque (must be a power of 2,
 *   unless RTE_DEQUE_F_EXACT_SZ is set in flags).
 * @param socket_id
 *   The *socket_id* argument is the socket identifier in case of
 *   NUMA. The value can be *SOCKET_ID_ANY* if there is no NUMA
 *   constraint for the reserved zone.
 * @param flags
 *   - RTE_DEQUE_F_EXACT_SZ: If this flag is set, the deque will hold exactly the
 *     requested number of entries, and the requested size will be rounded up
 *     to the next power of two, but the usable space will be exactly that
 *     requested. Worst case, if a power-of-2 size is requested, half the
 *     deque space will be wasted.
 *     Without this flag set, the deque size requested must be a power of 2,
 *     and the usable space will be that size - 1.
 * @return
 *   On success, the pointer to the new allocated deque. NULL on error with
 *    rte_errno set appropriately. Possible errno values include:
 *    - E_RTE_NO_CONFIG - function could not get pointer to rte_config structure
 *    - EINVAL - count provided is not a power of 2
 *    - ENOSPC - the maximum number of memzones has already been allocated
 *    - EEXIST - a memzone with the same name already exists
 *    - ENOMEM - no appropriate memory area found in which to create memzone
 */
__rte_experimental
struct rte_deque *rte_deque_create(const char *name, unsigned int esize,
				unsigned int count, int socket_id,
				unsigned int flags);

/**
 * De-allocate all memory used by the deque.
 *
 * @param d
 *   Deque to free.
 *   If NULL then, the function does nothing.
 */
__rte_experimental
void rte_deque_free(struct rte_deque *d);

/**
 * Dump the status of the deque to a file.
 *
 * @param f
 *   A pointer to a file for output
 * @param d
 *   A pointer to the deque structure.
 */
__rte_experimental
void rte_deque_dump(FILE *f, const struct rte_deque *d);

/**
 * Return the number of entries in a deque.
 *
 * @param d
 *   A pointer to the deque structure.
 * @return
 *   The number of entries in the deque.
 */
static inline unsigned int
rte_deque_count(const struct rte_deque *d)
{
	return (d->head - d->tail) & d->mask;
}

/**
 * Return the number of free entries in a deque.
 *
 * @param d
 *   A pointer to the deque structure.
 * @return
 *   The number of free entries in the deque.
 */
static inline unsigned int
rte_deque_free_count(const struct rte_deque *d)
{
	return d->capacity - rte_deque_count(d);
}

/**
 * Enqueue fixed number of objects on a deque.
 *
 * This function copies the objects at the head of the deque and
 * moves the head index.
 *
 * @param d
 *   A pointer to the deque structure.
 * @param obj_table
 *   A pointer to a table of objects.
 * @param esize
 *   The size of deque object, in bytes. It must be a multiple of 4.
 *   This must be the same value used while creating the deque. Otherwise
 *   the results are undefined.
 * @param n
 *   The number of objects to add in the deque from the obj_table.
 * @param free_space
 *   Returns the amount of space in the deque after the enqueue operation
 *   has finished.
 * @return
 *   The number of objects enqueued, either 0 or n
 */
__rte_experimental
static __rte_always_inline unsigned int
rte_deque_enqueue_bulk_elem(struct rte_deque *d,
			const void *obj_table,
			unsigned int esize,
			unsigned int n,
			unsigned int *free_space)
{
	*free_space = rte_deque_free_count(d);
	if (unlikely(n > *free_space))
		return 0;
	*free_space -= n;
	return __rte_deque_enqueue_at_head(d, obj_table, esize, n);
}

/**
 * Enqueue up to a maximum number of objects on a deque.
 *
 * This function copies the objects at the head of the deque and
 * moves the head index.
 *
 * @param d
 *   A pointer to the deque structure.
 * @param obj_table
 *   A pointer to a table of objects.
 * @param esize
 *   The size of deque object, in bytes. It must be a multiple of 4.
 *   This must be the same value used while creating the deque. Otherwise
 *   the results are undefined.
 * @param n
 *   The number of objects to add in the deque from the obj_table.
 * @param free_space
 *   Returns the amount of space in the deque after the enqueue operation
 *   has finished.
 * @return
 *   - n: Actual number of objects enqueued.
 */
__rte_experimental
static __rte_always_inline unsigned int
rte_deque_enqueue_burst_elem(struct rte_deque *d, const void *obj_table,
			unsigned int esize, unsigned int n,
			unsigned int *free_space)
{
	unsigned int avail_space = rte_deque_free_count(d);
	unsigned int to_be_enqueued = (n <= avail_space ? n : avail_space);
	*free_space = avail_space - n;
	return __rte_deque_enqueue_at_head(d, obj_table, esize, to_be_enqueued);
}

/**
 * Enqueue fixed number of objects on a deque at the tail.
 *
 * This function copies the objects at the tail of the deque and
 * moves the tail index (backwards).
 *
 * @param d
 *   A pointer to the deque structure.
 * @param obj_table
 *   A pointer to a table of objects.
 * @param esize
 *   The size of deque object, in bytes. It must be a multiple of 4.
 *   This must be the same value used while creating the deque. Otherwise
 *   the results are undefined.
 * @param n
 *   The number of objects to add in the deque from the obj_table.
 * @param free_space
 *   Returns the amount of space in the deque after the enqueue operation
 *   has finished.
 * @return
 *   The number of objects enqueued, either 0 or n
 */
__rte_experimental
static __rte_always_inline unsigned int
rte_deque_enqueue_at_tail_bulk_elem(struct rte_deque *d,
				 const void *obj_table, unsigned int esize,
				 unsigned int n, unsigned int *free_space)
{
	*free_space = rte_deque_free_count(d);
	if (unlikely(n > *free_space))
		return 0;
	*free_space -= n;
	return __rte_deque_enqueue_at_tail(d, obj_table, esize, n);
}

/**
 * Enqueue up to a maximum number of objects on a deque at the tail.
 *
 * This function copies the objects at the tail of the deque and
 * moves the tail index (backwards).
 *
 * @param d
 *   A pointer to the deque structure.
 * @param obj_table
 *   A pointer to a table of objects.
 * @param esize
 *   The size of deque object, in bytes. It must be a multiple of 4.
 *   This must be the same value used while creating the deque. Otherwise
 *   the results are undefined.
 * @param n
 *   The number of objects to add in the deque from the obj_table.
 * @param free_space
 *   Returns the amount of space in the deque after the enqueue operation
 *   has finished.
 * @return
 *   - n: Actual number of objects enqueued.
 */
__rte_experimental
static __rte_always_inline unsigned int
rte_deque_enqueue_at_tail_burst_elem(struct rte_deque *d,
				const void *obj_table, unsigned int esize,
				unsigned int n, unsigned int *free_space)
{
	unsigned int avail_space = rte_deque_free_count(d);
	unsigned int to_be_enqueued = (n <= avail_space ? n : avail_space);
	*free_space = avail_space - to_be_enqueued;
	return __rte_deque_enqueue_at_tail(d, obj_table, esize, to_be_enqueued);
}

/**
 * Dequeue a fixed number of objects from a deque.
 *
 * This function copies the objects from the tail of the deque and
 * moves the tail index.
 *
 * @param d
 *   A pointer to the deque structure.
 * @param obj_table
 *   A pointer to a table of objects that will be filled.
 * @param esize
 *   The size of deque object, in bytes. It must be a multiple of 4.
 *   This must be the same value used while creating the deque. Otherwise
 *   the results are undefined.
 * @param n
 *   The number of objects to dequeue from the deque to the obj_table.
 * @param available
 *   Returns the number of remaining deque entries after the dequeue
 *   has finished.
 * @return
 *   The number of objects dequeued, either 0 or n
 */
__rte_experimental
static __rte_always_inline unsigned int
rte_deque_dequeue_bulk_elem(struct rte_deque *d, void *obj_table,
			unsigned int esize, unsigned int n,
			unsigned int *available)
{
	*available = rte_deque_count(d);
	if (unlikely(n > *available))
		return 0;
	*available -= n;
	return __rte_deque_dequeue_at_tail(d, obj_table, esize, n);
}

/**
 * Dequeue up to a maximum number of objects from a deque.
 *
 * This function copies the objects from the tail of the deque and
 * moves the tail index.
 *
 * @param d
 *   A pointer to the deque structure.
 * @param obj_table
 *   A pointer to a table of objects that will be filled.
 * @param esize
 *   The size of deque object, in bytes. It must be a multiple of 4.
 *   This must be the same value used while creating the deque. Otherwise
 *   the results are undefined.
 * @param n
 *   The number of objects to dequeue from the deque to the obj_table.
 * @param available
 *   Returns the number of remaining deque entries after the dequeue
 *   has finished.
 * @return
 *   - Number of objects dequeued
 */
__rte_experimental
static __rte_always_inline unsigned int
rte_deque_dequeue_burst_elem(struct rte_deque *d, void *obj_table,
			unsigned int esize, unsigned int n,
			unsigned int *available)
{
	unsigned int count = rte_deque_count(d);
	unsigned int to_be_dequeued = (n <= count ? n : count);
	*available = count - to_be_dequeued;
	return __rte_deque_dequeue_at_tail(d, obj_table, esize, to_be_dequeued);
}

/**
 * Dequeue a fixed number of objects from a deque from the head.
 *
 * This function copies the objects from the head of the deque and
 * moves the head index (backwards).
 *
 * @param d
 *   A pointer to the deque structure.
 * @param obj_table
 *   A pointer to a table of objects that will be filled.
 * @param esize
 *   The size of deque object, in bytes. It must be a multiple of 4.
 *   This must be the same value used while creating the deque. Otherwise
 *   the results are undefined.
 * @param n
 *   The number of objects to dequeue from the deque to the obj_table.
 * @param available
 *   Returns the number of remaining deque entries after the dequeue
 *   has finished.
 * @return
 *   The number of objects dequeued, either 0 or n
 */
__rte_experimental
static __rte_always_inline unsigned int
rte_deque_dequeue_at_head_bulk_elem(struct rte_deque *d, void *obj_table,
			unsigned int esize, unsigned int n,
			unsigned int *available)
{
	*available = rte_deque_count(d);
	if (unlikely(n > *available))
		return 0;
	*available -= n;
	return __rte_deque_dequeue_at_head(d, obj_table, esize, n);
}

/**
 * Dequeue up to a maximum number of objects from a deque from the head.
 *
 * This function copies the objects from the head of the deque and
 * moves the head index (backwards).
 *
 * @param d
 *   A pointer to the deque structure.
 * @param obj_table
 *   A pointer to a table of objects that will be filled.
 * @param esize
 *   The size of deque object, in bytes. It must be a multiple of 4.
 *   This must be the same value used while creating the deque. Otherwise
 *   the results are undefined.
 * @param n
 *   The number of objects to dequeue from the deque to the obj_table.
 * @param available
 *   Returns the number of remaining deque entries after the dequeue
 *   has finished.
 * @return
 *   - Number of objects dequeued
 */
__rte_experimental
static __rte_always_inline unsigned int
rte_deque_dequeue_at_head_burst_elem(struct rte_deque *d, void *obj_table,
			unsigned int esize, unsigned int n,
			unsigned int *available)
{
	unsigned int count = rte_deque_count(d);
	unsigned int to_be_dequeued = (n <= count ? n : count);
	*available = count - to_be_dequeued;
	return __rte_deque_dequeue_at_head(d, obj_table, esize, to_be_dequeued);
}

/**
 * Flush a deque.
 *
 * This function flush all the objects in a deque
 *
 * @warning
 * Make sure the deque is not in use while calling this function.
 *
 * @param d
 *   A pointer to the deque structure.
 */
__rte_experimental
void rte_deque_reset(struct rte_deque *d);

/**
 * Test if a deque is full.
 *
 * @param d
 *   A pointer to the deque structure.
 * @return
 *   - 1: The deque is full.
 *   - 0: The deque is not full.
 */
static inline int
rte_deque_full(const struct rte_deque *d)
{
	return rte_deque_free_count(d) == 0;
}

/**
 * Test if a deque is empty.
 *
 * @param d
 *   A pointer to the deque structure.
 * @return
 *   - 1: The deque is empty.
 *   - 0: The deque is not empty.
 */
static inline int
rte_deque_empty(const struct rte_deque *d)
{
	return d->tail == d->head;
}

/**
 * Return the size of the deque.
 *
 * @param d
 *   A pointer to the deque structure.
 * @return
 *   The size of the data store used by the deque.
 *   NOTE: this is not the same as the usable space in the deque. To query that
 *   use ``rte_deque_get_capacity()``.
 */
static inline unsigned int
rte_deque_get_size(const struct rte_deque *d)
{
	return d->size;
}

/**
 * Return the number of objects which can be stored in the deque.
 *
 * @param d
 *   A pointer to the deque structure.
 * @return
 *   The usable size of the deque.
 */
static inline unsigned int
rte_deque_get_capacity(const struct rte_deque *d)
{
	return d->capacity;
}

#ifdef __cplusplus
}
#endif

#endif /* _RTE_DEQUE_H_ */

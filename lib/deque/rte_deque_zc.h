/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Arm Limited
 */
#ifndef _RTE_DEQUE_ZC_H_
#define _RTE_DEQUE_ZC_H_

/**
 * @file
 * This file should not be included directly, include rte_deque.h instead.
 *
 * Deque Zero Copy APIs
 * These APIs make it possible to split public enqueue/dequeue API
 * into 3 parts:
 * - enqueue/dequeue start
 * - copy data to/from the deque
 * - enqueue/dequeue finish
 * These APIs provide the ability to avoid copying of the data to temporary area.
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Deque zero-copy information structure.
 *
 * This structure contains the pointers and length of the space
 * reserved on the Deque storage.
 */
struct __rte_cache_aligned rte_deque_zc_data {
	/* Pointer to the first space in the deque */
	void *ptr1;
	/* Pointer to the second space in the deque if there is wrap-around.
	 * It contains valid value only if wrap-around happens.
	 */
	void *ptr2;
	/* Number of elements in the first pointer. If this is equal to
	 * the number of elements requested, then ptr2 is NULL.
	 * Otherwise, subtracting n1 from number of elements requested
	 * will give the number of elements available at ptr2.
	 */
	unsigned int n1;
};

static __rte_always_inline void
__rte_deque_get_elem_addr(struct rte_deque *d, uint32_t pos,
	uint32_t esize, uint32_t num, void **dst1, uint32_t *n1, void **dst2,
	bool low_to_high)
{
	uint32_t idx, scale, nr_idx;
	uint32_t *deque = (uint32_t *)&d[1];

	/* Normalize to uint32_t */
	scale = esize / sizeof(uint32_t);
	idx = pos & d->mask;
	nr_idx = idx * scale;

	*dst1 = deque + nr_idx;
	*n1 = num;

	if (low_to_high) {
		if (idx + num > d->size) {
			*n1 = d->size - idx;
			*dst2 = deque;
		} else
			*dst2 = NULL;
	} else {
		if ((int32_t)(idx - num) < 0) {
			*n1 = idx + 1;
			*dst2 = (void *)&deque[(-1 & d->mask) * scale];
		} else
			*dst2 = NULL;
	}
}

/**
 * Start to enqueue several objects on the deque.
 * Note that no actual objects are put in the deque by this function,
 * it just reserves space for the user on the deque.
 * User has to copy objects into the deque using the returned pointers.
 * User should call rte_deque_enqueue_zc_elem_finish to complete the
 * enqueue operation.
 *
 * @param d
 *   A pointer to the deque structure.
 * @param esize
 *   The size of deque element, in bytes. It must be a multiple of 4.
 * @param n
 *   The number of objects to add in the deque.
 * @param zcd
 *   Structure containing the pointers and length of the space
 *   reserved on the deque storage.
 * @param free_space
 *   Returns the amount of space in the deque after the reservation operation
 *   has finished.
 * @return
 *   The number of objects that can be enqueued, either 0 or n
 */
__rte_experimental
static __rte_always_inline unsigned int
rte_deque_enqueue_zc_bulk_elem_start(struct rte_deque *d, unsigned int esize,
	unsigned int n, struct rte_deque_zc_data *zcd, unsigned int *free_space)
{

	*free_space = __RTE_DEQUE_FREE_SPACE(d);
	if (unlikely(*free_space < n))
		return 0;
	__rte_deque_get_elem_addr(d, d->head, esize, n, &zcd->ptr1,
							&zcd->n1, &zcd->ptr2, true);

	*free_space -= n;
	return n;
}

/**
 * Complete enqueuing several pointers to objects on the deque.
 * Note that number of objects to enqueue should not exceed previous
 * enqueue_start return value.
 *
 * @param d
 *   A pointer to the deque structure.
 * @param n
 *   The number of pointers to objects to add to the deque.
 */
__rte_experimental
static __rte_always_inline void
rte_deque_enqueue_zc_elem_finish(struct rte_deque *d, unsigned int n)
{
	d->head = (d->head + n) & d->mask;
}

/**
 * Start to enqueue several objects on the deque.
 * Note that no actual objects are put in the queue by this function,
 * it just reserves space for the user on the deque.
 * User has to copy objects into the queue using the returned pointers.
 * User should call rte_deque_enqueue_zc_elem_finish to complete the
 * enqueue operation.
 *
 * @param d
 *   A pointer to the deque structure.
 * @param esize
 *   The size of deque element, in bytes. It must be a multiple of 4.
 * @param n
 *   The number of objects to add in the deque.
 * @param zcd
 *   Structure containing the pointers and length of the space
 *   reserved on the deque storage.
 * @param free_space
 *   Returns the amount of space in the deque after the reservation operation
 *   has finished.
 * @return
 *   The number of objects that can be enqueued, either 0 or n
 */
__rte_experimental
static __rte_always_inline unsigned int
rte_deque_enqueue_zc_burst_elem_start(struct rte_deque *d, unsigned int esize,
	unsigned int n, struct rte_deque_zc_data *zcd, unsigned int *free_space)
{
	*free_space = __RTE_DEQUE_FREE_SPACE(d);
	n = n > *free_space ? *free_space : n;
	return rte_deque_enqueue_zc_bulk_elem_start(d, esize, n, zcd, free_space);
}

/**
 * Start to enqueue several objects on the deque.
 * Note that no actual objects are put in the deque by this function,
 * it just reserves space for the user on the deque.
 * User has to copy objects into the deque using the returned pointers.
 * User should call rte_deque_enqueue_zc_elem_finish to complete the
 * enqueue operation.
 *
 * @param d
 *   A pointer to the deque structure.
 * @param esize
 *   The size of deque element, in bytes. It must be a multiple of 4.
 * @param n
 *   The number of objects to add in the deque.
 * @param zcd
 *   Structure containing the pointers and length of the space
 *   reserved on the deque storage.
 * @param free_space
 *   Returns the amount of space in the deque after the reservation operation
 *   has finished.
 * @return
 *   The number of objects that can be enqueued, either 0 or n
 */
__rte_experimental
static __rte_always_inline unsigned int
rte_deque_enqueue_zc_bulk_elem_tail_start(struct rte_deque *d, unsigned int esize,
	unsigned int n, struct rte_deque_zc_data *zcd, unsigned int *free_space)
{
	*free_space = __RTE_DEQUE_FREE_SPACE(d);
	if (unlikely(*free_space < n))
		return 0;
	__rte_deque_get_elem_addr(d, d->tail - 1, esize, n, &zcd->ptr1,
							  &zcd->n1, &zcd->ptr2, false);

	*free_space -= n;
	return n;
}

/**
 * Complete enqueuing several pointers to objects on the deque.
 * Note that number of objects to enqueue should not exceed previous
 * enqueue_start return value.
 *
 * @param d
 *   A pointer to the deque structure.
 * @param n
 *   The number of pointers to objects to add to the deque.
 */
__rte_experimental
static __rte_always_inline void
rte_deque_enqueue_zc_elem_tail_finish(struct rte_deque *d, unsigned int n)
{
	d->tail = (d->tail - n) & d->mask;
}

/**
 * Start to enqueue several objects on the deque.
 * Note that no actual objects are put in the queue by this function,
 * it just reserves space for the user on the deque.
 * User has to copy objects into the queue using the returned pointers.
 * User should call rte_deque_enqueue_zc_elem_finish to complete the
 * enqueue operation.
 *
 * @param d
 *   A pointer to the deque structure.
 * @param esize
 *   The size of deque element, in bytes. It must be a multiple of 4.
 * @param n
 *   The number of objects to add in the deque.@param r
 * @param zcd
 *   Structure containing the pointers and length of the space
 *   reserved on the deque storage.
 * @param free_space
 *   Returns the amount of space in the deque after the reservation operation
 *   has finished.
 * @return
 *   The number of objects that can be enqueued, either 0 or n
 */
__rte_experimental
static __rte_always_inline unsigned int
rte_deque_enqueue_zc_burst_elem_tail_start(struct rte_deque *d, unsigned int esize,
	unsigned int n, struct rte_deque_zc_data *zcd, unsigned int *free_space)
{
	*free_space = __RTE_DEQUE_FREE_SPACE(d);
	n = n > *free_space ? *free_space : n;
	return rte_deque_enqueue_zc_bulk_elem_tail_start(d, esize, n, zcd, free_space);
}

/**
 * Start to dequeue several objects from the deque.
 * Note that no actual objects are copied from the queue by this function.
 * User has to copy objects from the queue using the returned pointers.
 * User should call rte_deque_dequeue_zc_elem_finish to complete the
 * dequeue operation.
 *
 * @param d
 *   A pointer to the deque structure.
 * @param esize
 *   The size of deque element, in bytes. It must be a multiple of 4.
 * @param n
 *   The number of objects to remove from the deque.
 * @param zcd
 *   Structure containing the pointers and length of the space
 *   reserved on the deque storage.
 * @param available
 *   Returns the number of remaining deque entries after the dequeue has
 *   finished.
 * @return
 *   The number of objects that can be dequeued, either 0 or n.
 */
__rte_experimental
static __rte_always_inline unsigned int
rte_deque_dequeue_zc_bulk_elem_start(struct rte_deque *d, unsigned int esize,
	unsigned int n, struct rte_deque_zc_data *zcd, unsigned int *available)
{
	*available = __RTE_DEQUE_COUNT(d);
	if (unlikely(*available < n))
		return 0;
	__rte_deque_get_elem_addr(d, d->tail, esize, n, &zcd->ptr1,
							&zcd->n1, &zcd->ptr2, true);

	*available -= n;
	return n;
}

/**
 * Complete dequeuing several objects from the deque.
 * Note that number of objects to dequeued should not exceed previous
 * dequeue_start return value.
 *
 * @param d
 *   A pointer to the deque structure.
 * @param n
 *   The number of objects to remove from the deque.
 */
__rte_experimental
static __rte_always_inline void
rte_deque_dequeue_zc_elem_finish(struct rte_deque *d, unsigned int n)
{
	d->tail = (d->tail + n) & d->mask;
}

/**
 * Start to dequeue several objects from the deque.
 * Note that no actual objects are copied from the queue by this function.
 * User has to copy objects from the queue using the returned pointers.
 * User should call rte_deque_dequeue_zc_elem_finish to complete the
 * dequeue operation.
 *
 * @param d
 *   A pointer to the deque structure.
 * @param esize
 *   The size of deque element, in bytes. It must be a multiple of 4.
 * @param n
 *   The number of objects to remove from the deque.
 * @param zcd
 *   Structure containing the pointers and length of the space
 *   reserved on the deque storage.
 * @param available
 *   Returns the number of remaining deque entries after the dequeue has
 *   finished.
 * @return
 *   The number of objects that can be dequeued, either 0 or n.
 */
__rte_experimental
static __rte_always_inline unsigned int
rte_deque_dequeue_zc_burst_elem_start(struct rte_deque *d, unsigned int esize,
	unsigned int n, struct rte_deque_zc_data *zcd, unsigned int *available)
{
	*available = __RTE_DEQUE_COUNT(d);
	n = n > *available ? *available : n;
	return rte_deque_dequeue_zc_bulk_elem_start(d, esize, n, zcd, available);
}

/**
 * Start to dequeue several objects from the deque.
 * Note that no actual objects are copied from the queue by this function.
 * User has to copy objects from the queue using the returned pointers.
 * User should call rte_deque_dequeue_zc_elem_finish to complete the
 * dequeue operation.
 *
 * @param d
 *   A pointer to the deque structure.
 * @param esize
 *   The size of deque element, in bytes. It must be a multiple of 4.
 * @param n
 *   The number of objects to remove from the deque.
 * @param zcd
 *   Structure containing the pointers and length of the space
 *   reserved on the deque storage.
 * @param available
 *   Returns the number of remaining deque entries after the dequeue has
 *   finished.
 * @return
 *   The number of objects that can be dequeued, either 0 or n.
 */
__rte_experimental
static __rte_always_inline unsigned int
rte_deque_dequeue_zc_bulk_elem_head_start(struct rte_deque *d, unsigned int esize,
	unsigned int n, struct rte_deque_zc_data *zcd, unsigned int *available)
{
	*available = __RTE_DEQUE_COUNT(d);
	if (unlikely(*available < n))
		return 0;
	__rte_deque_get_elem_addr(d, d->head - 1, esize, n, &zcd->ptr1,
							&zcd->n1, &zcd->ptr2, false);

	*available -= n;
	return n;
}

/**
 * Complete dequeuing several objects from the deque.
 * Note that number of objects to dequeued should not exceed previous
 * dequeue_start return value.
 *
 * @param d
 *   A pointer to the deque structure.
 * @param n
 *   The number of objects to remove from the deque.
 */
__rte_experimental
static __rte_always_inline void
rte_deque_dequeue_zc_elem_head_finish(struct rte_deque *d, unsigned int n)
{
	d->head = (d->head - n) & d->mask;
}

/**
 * Start to dequeue several objects from the deque.
 * Note that no actual objects are copied from the queue by this function.
 * User has to copy objects from the queue using the returned pointers.
 * User should call rte_deque_dequeue_zc_elem_finish to complete the
 * dequeue operation.
 *
 * @param d
 *   A pointer to the deque structure.
 * @param esize
 *   The size of deque element, in bytes. It must be a multiple of 4.
 * @param n
 *   The number of objects to remove from the deque.
 * @param zcd
 *   Structure containing the pointers and length of the space
 *   reserved on the deque storage.
 * @param available
 *   Returns the number of remaining deque entries after the dequeue has
 *   finished.
 * @return
 *   The number of objects that can be dequeued, either 0 or n.
 */
__rte_experimental
static __rte_always_inline unsigned int
rte_deque_dequeue_zc_burst_elem_head_start(struct rte_deque *d, unsigned int esize,
	unsigned int n, struct rte_deque_zc_data *zcd, unsigned int *available)
{
	*available = __RTE_DEQUE_COUNT(d);
	n = n > *available ? *available : n;
	return rte_deque_dequeue_zc_bulk_elem_head_start(d, esize, n, zcd, available);
}

#ifdef __cplusplus
}
#endif

#endif /* _RTE_DEQUE_ZC_H_ */

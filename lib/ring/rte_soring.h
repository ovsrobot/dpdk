/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Huawei Technologies Co., Ltd
 */

#ifndef _RTE_SORING_H_
#define _RTE_SORING_H_

/**
 * @file
 * This file contains definition of RTE soring (Staged Ordered Ring) public API.
 * Brief description:
 * enqueue/dequeue works the same as for conventional rte_ring:
 * any rte_ring sync types can be used, etc.
 * Plus there could be multiple 'stages'.
 * For each stage there is an acquire (start) and release (finish) operation.
 * after some elems are 'acquired' - user  can safely assume that he has
 * exclusive possession of these elems till 'release' for them is done.
 * Note that right now user has to release exactly the same number of elems
 * he acquired before.
 * After 'release', elems can be 'acquired' by next stage and/or dequeued
 * (in case of last stage).
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_ring.h>

/* upper 2 bits are used for status */
#define RTE_SORING_ST_BIT       30

/* max possible number of elements in the soring */
#define RTE_SORING_ELEM_MAX	(RTE_BIT32(RTE_SORING_ST_BIT) - 1)

struct rte_soring_param {
	/** expected name of the ring */
	const char *name;
	/** number of elemnts in the ring */
	uint32_t elems;
	/** size of elements in the ring, must be a multiple of 4 */
	uint32_t esize;
	/**
	 * size of retcode for each elem, must be a multiple of 4.
	 * This parameter defines a size of supplementary and optional
	 * array of ret-codes associated with each object in the soring.
	 * While element size is configurable (see @esize parameter above),
	 * so user can specify it big enough to hold both object and its
	 * ret-code together, for performance reasons it might be plausible
	 * to access them as separate arrays.
	 * Common usage scenario when such separation helps:
	 * enqueue() - writes to objects array
	 * acquire() - reads from objects array
	 * release() - writes to ret-code array
	 * dequeue() - reads both objects and ret-code array
	 */
	uint32_t stsize;
	/** number of stages in the ring */
	uint32_t stages;
	/** sync type for producer */
	enum rte_ring_sync_type prod_synt;
	/** sync type for consumer */
	enum rte_ring_sync_type cons_synt;
};

struct rte_soring;

/**
 * Calculate the memory size needed for a soring
 *
 * This function returns the number of bytes needed for a ring, given
 * the expected parameters for it. This value is the sum of the size of
 * the internal metadata and the size of the memory needed by the
 * actual ring elements and theri rec-codes. The value is aligned to a cache
 * line size.
 *
 * @param prm
 *   Pointer to the structure that contains soring creation paramers.
 * @return
 *   - The memory size needed for the soring on success.
 *   - -EINVAL if provided paramer values are invalid.
 */
__rte_experimental
ssize_t
rte_soring_get_memsize(const struct rte_soring_param *prm);

/**
 * Initialize a soring structure.
 *
 * Initialize a soring structure in memory pointed by "r".
 * The size of the memory area must be large enough to store the soring
 * internal structures plus the objects and ret-code tables.
 * It is strongly advised to use rte_ring_get_memsize() to get the
 * appropriate size.
 *
 * @param r
 *   Pointer to the soring structure.
 * @param prm
 *   Pointer to the structure that contains soring creation paramers.
 * @return
 *   - 0 on success, or a negative error code.
 */
__rte_experimental
int
rte_soring_init(struct rte_soring *r,  const struct rte_soring_param *prm);

/**
 * Return the total number of filled entries in a ring.
 *
 * @param r
 *   A pointer to the soring structure.
 * @return
 *   The number of entries in the ring.
 */
__rte_experimental
unsigned int
rte_soring_count(const struct rte_soring *r);

/**
 * Enqueue several objects on the ring.
 *
 * @param r
 *   A pointer to the soring structure.
 * @param obj_table
 *   A pointer to an array of objects to enqueue.
 *   Size of objects to enqueue must be the same value as @esize parameter
 *   used while creating the ring. Otherwise the results are undefined.
 * @param objst
 *   A pointer to an array of status values for each object to enqueue.
 *   Note that if user not using object status values, then this parameter
 *   can be NULL.
 *   Size of elements in this array must be the same value as @stsize parameter
 *   used while creating the ring. If user created the soring with
 *   @stsize value equals zero, then @objst parameter should be NULL.
 *   Otherwise the results are undefined.
 * @param n
 *   The number of objects to add in the ring from the obj_table.
 * @param behavior
 *   Behavior type, one of:
 *   - RTE_RING_QUEUE_FIXED: enqueue either exactly @n objects or none.
 *   - RTE_RING_QUEUE_VARIABLE: enqueue up to @n objects.
 * @param free_space
 *   if non-NULL, returns the amount of space in the ring after the
 *   enqueue operation has finished.
 * @return
 *   - Actual number of objects enqueued.
 */
__rte_experimental
uint32_t
rte_soring_enqueue(struct rte_soring *r, const void *obj_table,
	const void *objst, uint32_t n, enum rte_ring_queue_behavior behavior,
	uint32_t *free_space);

/**
 * Dequeue several objects from the ring.
 *
 * @param r
 *   A pointer to the soring structure.
 * @param obj_table
 *   A pointer to an array of objects to dequeue.
 *   Size of objects to enqueue must be the same value as @esize parameter
 *   used while creating the ring. Otherwise the results are undefined.
 * @param objst
 *   A pointer to array of status values for each object to dequeue.
 *   Note that if user not using object status values, then this parameter
 *   can be NULL.
 *   Size of elements in this array must be the same value as @stsize parameter
 *   used while creating the ring. If user created the soring with
 *   @stsize value equals zero, then @objst parameter should be NULL.
 *   Otherwise the results are undefined.
 * @param num
 *   The number of objects to dequeue from the ring into the obj_table.
 * @param behavior
 *   Behavior type, one of:
 *   - RTE_RING_QUEUE_FIXED: dequeue either exactly @n objects or none.
 *   - RTE_RING_QUEUE_VARIABLE: dequeue up to @n objects.
 * @param available
 *   If non-NULL, returns the number of remaining ring entries after the
 *   dequeue has finished.
 * @return
 *   - Actual number of objects dequeued.
 */
__rte_experimental
uint32_t
rte_soring_dequeue(struct rte_soring *r, void *obj_table, void *objst,
	uint32_t num, enum rte_ring_queue_behavior behavior,
	uint32_t *available);

/**
 * Acquire several objects from the ring for given stage.
 *
 * @param r
 *   A pointer to the soring structure.
 * @param objs
 *   A pointer to an array of objects to acquire.
 *   Size of objects must be the same value as @esize parameter
 *   used while creating the ring. Otherwise the results are undefined.
 * @param objst
 *   A pointer to an array of status values for each for each acquired object.
 *   Note that if user not using object status values, then this parameter
 *   can be NULL.
 *   Size of elements in this array must be the same value as @stsize parameter
 *   used while creating the ring. If user created the soring with
 *   @stsize value equals zero, then @objst parameter should be NULL.
 *   Otherwise the results are undefined.
 * @param stage
 *   Stage to acquire objects for.
 * @param num
 *   The number of objects to acquire.
 * @param behavior
 *   Behavior type, one of:
 *   - RTE_RING_QUEUE_FIXED: acquire either exactly @n objects or none.
 *   - RTE_RING_QUEUE_VARIABLE: acquire up to @n objects.
 * @param ftoken
 *   Pointer to the opaque 'token' value used by release() op.
 *   User has to store this value somewhere, and later provide to the
 *   release().
 * @param available
 *   If non-NULL, returns the number of remaining ring entries for given stage
 *   after the acquire has finished.
 * @return
 *   - Actual number of objects acquired.
 */
__rte_experimental
uint32_t
rte_soring_acquire(struct rte_soring *r, void *objs, void *objst,
	uint32_t stage, uint32_t num, enum rte_ring_queue_behavior behavior,
	uint32_t *ftoken, uint32_t *available);

/**
 * Release several objects for given stage back to the ring.
 * Note that it means these objects become avaialble for next stage or
 * dequeue.
 *
 * @param r
 *   A pointer to the soring structure.
 * @param objs
 *   A pointer to an array of objects to relase.
 *   Note that unless user needs to overwrite ring objects this parameter
 *   can be NULL.
 *   Size of objects must be the same value as @esize parameter
 *   used while creating the ring. Otherwise the results are undefined.
 * @param objst
 *   A pointer to an array of status values for each object to release.
 *   Note that if user not using object status values, then this parameter
 *   can be NULL.
 *   Size of elements in this array must be the same value as @stsize parameter
 *   used while creating the ring. If user created the soring with
 *   @stsize value equals zero, then objst parameter should be NULL.
 *   Otherwise the results are undefined.
 * @param stage
 *   Current stage.
 * @param n
 *   The number of objects to release.
 *   Has to be the same value as returned by acquire() op.
 * @param ftoken
 *   Opaque 'token' value obtained from acquire() op.
 * @return
 *   - None.
 */
__rte_experimental
void
rte_soring_release(struct rte_soring *r, const void *objs,
	const void *objst, uint32_t stage, uint32_t n, uint32_t ftoken);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_SORING_H_ */

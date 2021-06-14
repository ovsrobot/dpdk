/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA Corporation & Affiliates
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_atomic.h>
#include <rte_errno.h>

#include "rte_parray.h"

#define PARRAY_DEFAULT_SIZE 32

int32_t
rte_parray_find_next(struct rte_parray *obj, int32_t index)
{
	if (obj == NULL || index < 0) {
		rte_errno = EINVAL;
		return -1;
	}

	pthread_mutex_lock(&obj->mutex);

	while (index < obj->size && obj->array[index] == NULL)
		index++;
	if (index >= obj->size)
		index = -1;

	pthread_mutex_unlock(&obj->mutex);

	rte_errno = 0;
	return index;
}

static int32_t
parray_find_next_free(const struct rte_parray *obj, int32_t index)
{
	while (index < obj->size && obj->array[index] != NULL)
		index++;
	if (index >= obj->size)
		return -1;
	return index;
}

static int
parray_resize(struct rte_parray *obj)
{
	void **new_array;
	int32_t new_size;
	int32_t index;

	if (unlikely(obj->size > INT32_MAX / 2))
		return -1;

	/* allocate a new array with bigger size */
	new_size = RTE_MAX(PARRAY_DEFAULT_SIZE, obj->size * 2);
	new_array = malloc(sizeof(void *) * new_size);
	if (new_array == NULL)
		return -1;

	/* free array of a previous resize */
	free(obj->old_array);
	/* save current array for freeing on next resize */
	obj->old_array = obj->array;

	/* copy current array in the new one */
	for (index = 0; index < obj->size; index++)
		new_array[index] = obj->old_array[index];
	/* initialize expanded part */
	memset(new_array + index, 0, sizeof(void *) * (new_size - index));

	/*
	 * Array readers have no guard/barrier/lock synchronization protection,
	 * that's why the ordering for array replacement is critical.
	 */
	/* new array must be initialized before replacing old array */
	rte_atomic_thread_fence(__ATOMIC_RELEASE);
	obj->array = new_array;
	/* array must be replaced before updating the size */
	rte_atomic_thread_fence(__ATOMIC_RELEASE);
	obj->size = new_size;

	return 0;
}

int32_t
rte_parray_alloc(struct rte_parray *obj, size_t elem_size)
{
	int32_t index;
	void *elem;

	if (obj == NULL) {
		rte_errno = EINVAL;
		return -rte_errno;
	}

	pthread_mutex_lock(&obj->mutex);

	if (obj->count == obj->size && parray_resize(obj) != 0) {
		rte_errno = ENOMEM;
		return -rte_errno;
	}

	elem = malloc(elem_size);
	if (elem == NULL) {
		rte_errno = ENOMEM;
		return -rte_errno;
	}

	index = parray_find_next_free(obj, obj->last + 1);
	if (index < 0)
		index = parray_find_next_free(obj, 0);

	obj->array[index] = elem;
	obj->count++;
	obj->last = index;

	pthread_mutex_unlock(&obj->mutex);

	rte_errno = 0;
	return index;
}

void
rte_parray_free(struct rte_parray *obj, int32_t index)
{
	if (obj == NULL || index < 0 || index > obj->last) {
		rte_errno = EINVAL;
		return;
	}

	pthread_mutex_lock(&obj->mutex);

	if (obj->array[index] != NULL) {
		free(obj->array[index]);
		obj->array[index] = NULL;
		obj->count--;
	}

	pthread_mutex_unlock(&obj->mutex);

	rte_errno = 0;
}

void
rte_parray_free_all(struct rte_parray *obj)
{
	int32_t index;
	int first_errno = 0;

	RTE_PARRAY_FOREACH(obj, index) {
		rte_parray_free(obj, index);
		if (rte_errno != 0 && first_errno == 0)
			first_errno = rte_errno;
	}
	rte_errno = first_errno;
}

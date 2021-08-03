/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 Mellanox Technologies, Ltd
 * Copyright(c) 2021 Microsoft Corporation
 */

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include <rte_common.h>
#include <rte_debug.h>
#include <rte_errno.h>
#include <rte_log.h>
#include <rte_thread.h>

struct eal_tls_key {
	pthread_key_t thread_index;
};

rte_thread_t
rte_thread_self(void)
{
	rte_thread_t thread_id;

	thread_id.opaque_id = (uintptr_t)pthread_self();

	return thread_id;
}

int
rte_thread_equal(rte_thread_t t1, rte_thread_t t2)
{
	return pthread_equal((pthread_t)t1.opaque_id, (pthread_t)t2.opaque_id);
}

int
rte_thread_set_affinity_by_id(rte_thread_t thread_id,
		const rte_cpuset_t *cpuset)
{
	return pthread_setaffinity_np((pthread_t)thread_id.opaque_id,
		sizeof(*cpuset), cpuset);
}

int
rte_thread_get_affinity_by_id(rte_thread_t thread_id,
		rte_cpuset_t *cpuset)
{
	return pthread_getaffinity_np((pthread_t)thread_id.opaque_id,
		sizeof(*cpuset), cpuset);
}

static int
thread_map_priority_to_os_value(enum rte_thread_priority eal_pri,
		int *os_pri, int *pol)
{
	/* Clear the output parameters */
	*os_pri = sched_get_priority_min(SCHED_OTHER) - 1;
	*pol = -1;

	switch (eal_pri) {
	case RTE_THREAD_PRIORITY_NORMAL:
		*pol = SCHED_OTHER;

		/*
		 * Choose the middle of the range to represent
		 * the priority 'normal'.
		 * On Linux, this should be 0, since both
		 * sched_get_priority_min/_max return 0 for SCHED_OTHER.
		 */
		*os_pri = (sched_get_priority_min(SCHED_OTHER) +
			sched_get_priority_max(SCHED_OTHER))/2;
		break;
	case RTE_THREAD_PRIORITY_REALTIME_CRITICAL:
		*pol = SCHED_RR;
		*os_pri = sched_get_priority_max(SCHED_RR);
		break;
	default:
		RTE_LOG(DEBUG, EAL, "The requested priority value is invalid.\n");
		return EINVAL;
	}
	return 0;
}

int
rte_thread_set_priority(rte_thread_t thread_id,
		enum rte_thread_priority priority)
{
	int ret;
	int policy;
	struct sched_param param;

	ret = thread_map_priority_to_os_value(priority, &param.sched_priority,
		&policy);
	if (ret != 0)
		return ret;

	return pthread_setschedparam((pthread_t)thread_id.opaque_id,
		policy, &param);
}

int
rte_thread_attr_init(rte_thread_attr_t *attr)
{
	RTE_VERIFY(attr != NULL);

	CPU_ZERO(&attr->cpuset);
	attr->priority = RTE_THREAD_PRIORITY_NORMAL;

	return 0;
}

int
rte_thread_attr_set_affinity(rte_thread_attr_t *thread_attr,
		rte_cpuset_t *cpuset)
{
	RTE_VERIFY(thread_attr != NULL);
	RTE_VERIFY(cpuset != NULL);

	thread_attr->cpuset = *cpuset;

	return 0;
}

int
rte_thread_attr_get_affinity(rte_thread_attr_t *thread_attr,
		rte_cpuset_t *cpuset)
{
	RTE_VERIFY(thread_attr != NULL);
	RTE_VERIFY(cpuset != NULL);

	*cpuset = thread_attr->cpuset;

	return 0;
}

int
rte_thread_attr_set_priority(rte_thread_attr_t *thread_attr,
		enum rte_thread_priority priority)
{
	RTE_VERIFY(thread_attr != NULL);

	thread_attr->priority = priority;
	return 0;
}

int
rte_thread_create(rte_thread_t *thread_id,
		const rte_thread_attr_t *thread_attr,
		rte_thread_func thread_func, void *args)
{
	int ret = 0;
	pthread_attr_t attr;
	pthread_attr_t *attrp = NULL;
	struct sched_param param = {
		.sched_priority = 0,
	};
	int policy = SCHED_OTHER;

	if (thread_attr != NULL) {
		ret = pthread_attr_init(&attr);
		if (ret != 0) {
			RTE_LOG(DEBUG, EAL, "pthread_attr_init failed\n");
			goto cleanup;
		}

		attrp = &attr;

		if (thread_attr->priority != RTE_THREAD_PRIORITY_UNDEFINED) {
			/*
			 * Set the inherit scheduler parameter to explicit,
			 * otherwise the priority attribute is ignored.
			 */
			ret = pthread_attr_setinheritsched(attrp,
					PTHREAD_EXPLICIT_SCHED);
			if (ret != 0) {
				RTE_LOG(DEBUG, EAL, "pthread_attr_setinheritsched failed\n");
				goto cleanup;
			}

			ret = thread_map_priority_to_os_value(
					thread_attr->priority,
					&param.sched_priority, &policy
					);
			if (ret != 0)
				goto cleanup;

			ret = pthread_attr_setschedpolicy(attrp, policy);
			if (ret != 0) {
				RTE_LOG(DEBUG, EAL, "pthread_attr_setschedpolicy failed\n");
				goto cleanup;
			}

			ret = pthread_attr_setschedparam(attrp, &param);
			if (ret != 0) {
				RTE_LOG(DEBUG, EAL, "pthread_attr_setschedparam failed\n");
				goto cleanup;
			}
		}

		if (CPU_COUNT(&thread_attr->cpuset) > 0) {
			ret = pthread_attr_setaffinity_np(attrp,
					sizeof(thread_attr->cpuset),
					&thread_attr->cpuset);
			if (ret != 0) {
				RTE_LOG(DEBUG, EAL, "pthread_attr_setaffinity_np failed\n");
				goto cleanup;
			}
		}
	}

	ret = pthread_create((pthread_t *)&thread_id->opaque_id, attrp,
		thread_func, args);
	if (ret != 0) {
		RTE_LOG(DEBUG, EAL, "pthread_create failed\n");
		goto cleanup;
	}

cleanup:
	if (attrp != NULL)
		pthread_attr_destroy(&attr);

	return ret;
}

int
rte_thread_join(rte_thread_t thread_id, unsigned long *value_ptr)
{
	int ret = 0;
	void *res = NULL;
	void **pres = NULL;

	if (value_ptr != NULL)
		pres = &res;

	ret = pthread_join((pthread_t)thread_id.opaque_id, pres);
	if (ret != 0) {
		RTE_LOG(DEBUG, EAL, "pthread_join failed\n");
		return ret;
	}

	if (pres != NULL)
		*value_ptr = *(unsigned long *)(*pres);

	return 0;
}

int
rte_thread_detach(rte_thread_t thread_id)
{
	return pthread_detach((pthread_t)thread_id.opaque_id);
}

int
rte_thread_mutex_init(rte_thread_mutex *mutex)
{
	int ret = 0;
	pthread_mutex_t *m = NULL;

	RTE_VERIFY(mutex != NULL);

	m = calloc(1, sizeof(*m));
	if (m == NULL) {
		RTE_LOG(DEBUG, EAL, "Unable to initialize mutex. Insufficient memory!\n");
		ret = ENOMEM;
		goto cleanup;
	}

	ret = pthread_mutex_init(m, NULL);
	if (ret != 0) {
		RTE_LOG(DEBUG, EAL, "Failed to init mutex. ret = %d\n", ret);
		goto cleanup;
	}

	mutex->mutex_id = m;
	m = NULL;

cleanup:
	free(m);
	return ret;
}

int
rte_thread_mutex_lock(rte_thread_mutex *mutex)
{
	RTE_VERIFY(mutex != NULL);

	return pthread_mutex_lock((pthread_mutex_t *)mutex->mutex_id);
}

int
rte_thread_mutex_unlock(rte_thread_mutex *mutex)
{
	RTE_VERIFY(mutex != NULL);

	return pthread_mutex_unlock((pthread_mutex_t *)mutex->mutex_id);
}

int
rte_thread_mutex_destroy(rte_thread_mutex *mutex)
{
	int ret = 0;
	RTE_VERIFY(mutex != NULL);

	ret = pthread_mutex_destroy((pthread_mutex_t *)mutex->mutex_id);
	if (ret != 0)
		RTE_LOG(DEBUG, EAL, "Unable to destroy mutex, ret = %d\n", ret);

	free(mutex->mutex_id);
	mutex->mutex_id = NULL;

	return ret;
}

int
rte_thread_barrier_init(rte_thread_barrier *barrier, int count)
{
	int ret = 0;
	pthread_barrier_t *pthread_barrier = NULL;

	RTE_VERIFY(barrier != NULL);
	RTE_VERIFY(count > 0);

	pthread_barrier = calloc(1, sizeof(*pthread_barrier));
	if (pthread_barrier == NULL) {
		RTE_LOG(DEBUG, EAL, "Unable to initialize barrier. Insufficient memory!\n");
		ret = ENOMEM;
		goto cleanup;
	}
	ret = pthread_barrier_init(pthread_barrier, NULL, count);
	if (ret != 0) {
		RTE_LOG(DEBUG, EAL, "Failed to init barrier, ret = %d\n", ret);
		goto cleanup;
	}

	barrier->barrier_id = pthread_barrier;
	pthread_barrier = NULL;

cleanup:
	free(pthread_barrier);
	return ret;
}

int
rte_thread_barrier_wait(rte_thread_barrier *barrier)
{
	int ret = 0;

	RTE_VERIFY(barrier != NULL);
	RTE_VERIFY(barrier->barrier_id != NULL);

	ret = pthread_barrier_wait(barrier->barrier_id);
	if (ret == PTHREAD_BARRIER_SERIAL_THREAD)
		ret = RTE_THREAD_BARRIER_SERIAL_THREAD;

	return ret;
}

int
rte_thread_barrier_destroy(rte_thread_barrier *barrier)
{
	int ret = 0;

	RTE_VERIFY(barrier != NULL);

	ret = pthread_barrier_destroy(barrier->barrier_id);
	if (ret != 0)
		RTE_LOG(DEBUG, EAL, "Failed to destroy barrier: %d\n", ret);

	free(barrier->barrier_id);
	barrier->barrier_id = NULL;

	return ret;
}

int
rte_thread_key_create(rte_thread_key *key, void (*destructor)(void *))
{
	int err;
	rte_thread_key k;

	k = malloc(sizeof(*k));
	if (k == NULL) {
		RTE_LOG(DEBUG, EAL, "Cannot allocate TLS key.\n");
		return EINVAL;
	}
	err = pthread_key_create(&(k->thread_index), destructor);
	if (err != 0) {
		RTE_LOG(DEBUG, EAL, "pthread_key_create failed: %s\n",
			 strerror(err));
		free(k);
		return err;
	}
	*key = k;
	return 0;
}

int
rte_thread_key_delete(rte_thread_key key)
{
	int err;

	if (key == NULL) {
		RTE_LOG(DEBUG, EAL, "Invalid TLS key.\n");
		return EINVAL;
	}
	err = pthread_key_delete(key->thread_index);
	if (err != 0) {
		RTE_LOG(DEBUG, EAL, "pthread_key_delete failed: %s\n",
			 strerror(err));
		free(key);
		return err;
	}
	free(key);
	return 0;
}

int
rte_thread_value_set(rte_thread_key key, const void *value)
{
	int err;

	if (key == NULL) {
		RTE_LOG(DEBUG, EAL, "Invalid TLS key.\n");
		return EINVAL;
	}
	err = pthread_setspecific(key->thread_index, value);
	if (err != 0) {
		RTE_LOG(DEBUG, EAL, "pthread_setspecific failed: %s\n",
			strerror(err));
		return err;
	}
	return 0;
}

void *
rte_thread_value_get(rte_thread_key key)
{
	if (key == NULL) {
		RTE_LOG(DEBUG, EAL, "Invalid TLS key.\n");
		rte_errno = EINVAL;
		return NULL;
	}
	return pthread_getspecific(key->thread_index);
}

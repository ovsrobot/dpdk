/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 Mellanox Technologies, Ltd
 * Copyright(c) 2021 Microsoft Corporation
 */

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include <rte_common.h>
#include <rte_errno.h>
#include <rte_log.h>
#include <rte_thread.h>

struct eal_tls_key {
	pthread_key_t thread_index;
};

rte_thread_t
rte_thread_self(void)
{
	return pthread_self();
}

int
rte_thread_equal(rte_thread_t t1, rte_thread_t t2)
{
	return pthread_equal(t1, t2);
}

int
rte_thread_set_affinity_by_id(rte_thread_t thread_id, size_t cpuset_size,
			const rte_cpuset_t *cpuset)
{
	return pthread_setaffinity_np(thread_id, cpuset_size, cpuset);
}

int rte_thread_get_affinity_by_id(rte_thread_t threadid, size_t cpuset_size,
		rte_cpuset_t *cpuset)
{
	return pthread_getaffinity_np(threadid, cpuset_size, cpuset);
}

int
rte_thread_set_priority(rte_thread_t thread_id,
		enum rte_thread_priority priority)
{
	int policy;
	struct sched_param param = {
		.sched_priority = 0,
	};


	if (priority == RTE_THREAD_PRIORITY_REALTIME_CRITICAL) {
		policy = SCHED_RR;
		param.sched_priority = priority;
	} else if (priority == RTE_THREAD_PRIORITY_NORMAL) {
		policy = SCHED_OTHER;
		param.sched_priority = priority;
	} else {
		RTE_LOG(DEBUG, EAL, "Invalid priority to set."
				    "Defaulting to priority 'normal'.\n");
		policy = SCHED_OTHER;
	}

	return pthread_setschedparam(thread_id, policy, &param);
}

int
rte_thread_attr_init(rte_thread_attr_t *attr)
{
	if (attr == NULL) {
		RTE_LOG(DEBUG, EAL, "Invalid thread attributes parameter\n");
		return EINVAL;
	}

	CPU_ZERO(&attr->cpuset);
	attr->priority = RTE_THREAD_PRIORITY_NORMAL;

	return 0;
}

int
rte_thread_attr_set_affinity(rte_thread_attr_t *thread_attr,
			     rte_cpuset_t *cpuset)
{
	if (thread_attr == NULL || cpuset == NULL) {
		RTE_LOG(DEBUG, EAL, "Invalid thread attributes parameter\n");
		return EINVAL;
	}
	thread_attr->cpuset = *cpuset;
	return 0;
}

int
rte_thread_attr_get_affinity(rte_thread_attr_t *thread_attr,
			     rte_cpuset_t *cpuset)
{
	if ((thread_attr == NULL) || (cpuset == NULL)) {
		RTE_LOG(DEBUG, EAL, "Invalid thread attributes parameter\n");
		return EINVAL;
	}

	*cpuset = thread_attr->cpuset;
	return 0;
}

int
rte_thread_attr_set_priority(rte_thread_attr_t *thread_attr,
			     enum rte_thread_priority priority)
{
	if (thread_attr == NULL) {
		RTE_LOG(DEBUG, EAL,
			"Unable to set priority attribute, invalid parameter\n");
		return EINVAL;
	}

	thread_attr->priority = priority;
	return 0;
}

int
rte_thread_create(rte_thread_t *thread_id,
		  const rte_thread_attr_t *thread_attr,
		  void *(*thread_func)(void *), void *args)
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

		/*
		 * In case a realtime scheduling policy is requested,
		 * the sched_priority parameter is set to the value stored in
		 * thread_attr. Otherwise, for the default scheduling policy
		 * (SCHED_OTHER) sched_priority needs to be initialized to 0.
		 */
		if (thread_attr->priority == RTE_THREAD_PRIORITY_REALTIME_CRITICAL) {
			policy = SCHED_RR;
			param.sched_priority = thread_attr->priority;
		}

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

		ret = pthread_attr_setaffinity_np(attrp,
						  sizeof(thread_attr->cpuset),
						  &thread_attr->cpuset);
		if (ret != 0) {
			RTE_LOG(DEBUG, EAL, "pthread_attr_setaffinity_np failed\n");
			goto cleanup;
		}
	}

	ret = pthread_create(thread_id, attrp, thread_func, args);
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
rte_thread_join(rte_thread_t thread_id, int *value_ptr)
{
	int ret = 0;
	void *res = NULL;
	void **pres = NULL;

	if (value_ptr != NULL)
		pres = &res;

	ret = pthread_join(thread_id, pres);
	if (ret != 0) {
		RTE_LOG(DEBUG, EAL, "pthread_join failed\n");
		return ret;
	}

	if (pres != NULL)
		*value_ptr = *(int *)(*pres);

	return 0;
}

int rte_thread_cancel(rte_thread_t thread_id)
{
	/*
	 * TODO: Behavior is different between POSIX and Windows threads.
	 * POSIX threads wait for a cancellation point.
	 * Current Windows emulation kills thread at any point.
	 */
	return pthread_cancel(thread_id);
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

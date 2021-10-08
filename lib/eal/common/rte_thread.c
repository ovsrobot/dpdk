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

static int
thread_map_os_priority_to_eal_priority(int policy, int os_pri,
		enum rte_thread_priority *eal_pri)
{
	switch (policy) {
	case SCHED_OTHER:
		if (os_pri == (sched_get_priority_min(SCHED_OTHER) +
				sched_get_priority_max(SCHED_OTHER))/2) {
			*eal_pri = RTE_THREAD_PRIORITY_NORMAL;
			return 0;
		}
		break;
	case SCHED_RR:
		if (os_pri == sched_get_priority_max(SCHED_RR)) {
			*eal_pri = RTE_THREAD_PRIORITY_REALTIME_CRITICAL;
			return 0;
		}
		break;
	default:
		RTE_LOG(DEBUG, EAL, "The OS priority value does not map to an EAL-defined priority.\n");
		return EINVAL;
	}

	return 0;
}

int
rte_thread_get_priority(rte_thread_t thread_id,
		enum rte_thread_priority *priority)
{
	int ret;
	int policy;
	struct sched_param param;

	ret = pthread_getschedparam(thread_id.opaque_id, &policy, &param);
	if (ret != 0) {
		RTE_LOG(DEBUG, EAL, "pthread_getschedparam failed\n");
		goto cleanup;
	}

	return thread_map_os_priority_to_eal_priority(policy,
			param.sched_priority, priority);

cleanup:
	return ret;
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

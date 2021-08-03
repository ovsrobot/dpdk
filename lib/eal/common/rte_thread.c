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

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 Mellanox Technologies, Ltd
 * Copyright (C) 2022 Microsoft Corporation
 */

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include <rte_cycles.h>
#include <rte_errno.h>
#include <rte_log.h>
#include <rte_thread.h>

struct eal_tls_key {
	pthread_key_t thread_index;
};

enum __rte_thread_wrapper_status {
	THREAD_WRAPPER_LAUNCHING, /* Yet to call thread_func function */
	THREAD_WRAPPER_RUNNING, /* Thread is running successfully */
	THREAD_WRAPPER_ERROR /* Thread thread_wrapper encountered an error */
};

struct thread_routine_ctx {
	rte_thread_func thread_func;
	const rte_thread_attr_t *thread_attr;
	int thread_wrapper_ret;
	enum __rte_thread_wrapper_status thread_wrapper_status;
	void *routine_args;
};

static int
thread_map_priority_to_os_value(enum rte_thread_priority eal_pri, int *os_pri,
	int *pol)
{
	/* Clear the output parameters. */
	*os_pri = sched_get_priority_min(SCHED_OTHER) - 1;
	*pol = -1;

	switch (eal_pri) {
	case RTE_THREAD_PRIORITY_NORMAL:
		*pol = SCHED_OTHER;

		/*
		 * Choose the middle of the range to represent the priority
		 * 'normal'.
		 * On Linux, this should be 0, since both
		 * sched_get_priority_min/_max return 0 for SCHED_OTHER.
		 */
		*os_pri = (sched_get_priority_min(SCHED_OTHER) +
			sched_get_priority_max(SCHED_OTHER)) / 2;
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
				sched_get_priority_max(SCHED_OTHER)) / 2) {
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

static void *
thread_func_wrapper(void *arg)
{
	struct thread_routine_ctx *ctx = (struct thread_routine_ctx *)arg;
	rte_thread_func thread_func = ctx->thread_func;
	void *thread_args = ctx->routine_args;

	if (ctx->thread_attr != NULL && CPU_COUNT(&ctx->thread_attr->cpuset) > 0) {
		ctx->thread_wrapper_ret = rte_thread_set_affinity(&ctx->thread_attr->cpuset);
		if (ctx->thread_wrapper_ret != 0) {
			RTE_LOG(DEBUG, EAL, "rte_thread_set_affinity failed\n");
			__atomic_store_n(&ctx->thread_wrapper_status,
				THREAD_WRAPPER_ERROR, __ATOMIC_RELEASE);
		}
	}
	__atomic_store_n(&ctx->thread_wrapper_status,
		THREAD_WRAPPER_RUNNING, __ATOMIC_RELEASE);

	free(arg);

	return (void *)(uintptr_t)thread_func(thread_args);
}

int
rte_thread_create(rte_thread_t *thread_id,
		const rte_thread_attr_t *thread_attr,
		rte_thread_func thread_func, void *args)
{
	int ret = 0;
	pthread_attr_t attr;
	pthread_attr_t *attrp = NULL;
	enum __rte_thread_wrapper_status thread_wrapper_status;
	struct thread_routine_ctx *ctx;
	struct sched_param param = {
		.sched_priority = 0,
	};
	int policy = SCHED_OTHER;

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		RTE_LOG(DEBUG, EAL, "Insufficient memory for thread context allocations\n");
		ret = ENOMEM;
		goto cleanup;
	}
	ctx->routine_args = args;
	ctx->thread_attr = thread_attr;
	ctx->thread_func = thread_func;
	ctx->thread_wrapper_ret = 0;
	ctx->thread_wrapper_status = THREAD_WRAPPER_LAUNCHING;

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


		if (thread_attr->priority ==
				RTE_THREAD_PRIORITY_REALTIME_CRITICAL) {
			ret = ENOTSUP;
			goto cleanup;
		}
		ret = thread_map_priority_to_os_value(thread_attr->priority,
				&param.sched_priority, &policy);
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

	ret = pthread_create((pthread_t *)&thread_id->opaque_id, attrp,
		thread_func_wrapper, ctx);
	if (ret != 0) {
		RTE_LOG(DEBUG, EAL, "pthread_create failed\n");
		goto cleanup;
	}

	/* Wait for the thread wrapper to initialize thread successfully */
	while ((thread_wrapper_status =
		__atomic_load_n(&ctx->thread_wrapper_status,
		__ATOMIC_ACQUIRE)) == THREAD_WRAPPER_LAUNCHING)
			sched_yield();

	/* Check if the control thread encountered an error */
	if (thread_wrapper_status == THREAD_WRAPPER_ERROR) {
		/* thread wrapper is exiting */
		pthread_join((pthread_t)thread_id->opaque_id, NULL);
		ret = ctx->thread_wrapper_ret;
		free(ctx);
	}
	ctx = NULL;

cleanup:
	free(ctx);
	if (attrp != NULL)
		pthread_attr_destroy(&attr);

	return ret;
}

int
rte_thread_join(rte_thread_t thread_id, uint32_t *value_ptr)
{
	int ret = 0;
	void *res = (void *)(uintptr_t)0;
	void **pres = NULL;

	if (value_ptr != NULL)
		pres = &res;

	ret = pthread_join((pthread_t)thread_id.opaque_id, pres);
	if (ret != 0) {
		RTE_LOG(DEBUG, EAL, "pthread_join failed\n");
		return ret;
	}

	if (value_ptr != NULL)
		*value_ptr = (uint32_t)(uintptr_t)res;

	return 0;
}

int
rte_thread_detach(rte_thread_t thread_id)
{
	return pthread_detach((pthread_t)thread_id.opaque_id);
}

int
rte_thread_equal(rte_thread_t t1, rte_thread_t t2)
{
	return pthread_equal((pthread_t)t1.opaque_id, (pthread_t)t2.opaque_id);
}

rte_thread_t
rte_thread_self(void)
{
	RTE_BUILD_BUG_ON(sizeof(pthread_t) > sizeof(uintptr_t));

	rte_thread_t thread_id;

	thread_id.opaque_id = (uintptr_t)pthread_self();

	return thread_id;
}

int
rte_thread_get_priority(rte_thread_t thread_id,
	enum rte_thread_priority *priority)
{
	struct sched_param param;
	int policy;
	int ret;

	ret = pthread_getschedparam((pthread_t)thread_id.opaque_id, &policy,
		&param);
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
	struct sched_param param;
	int policy;
	int ret;

	/* Realtime priority can cause crashes on non-Windows platforms. */
	if (priority == RTE_THREAD_PRIORITY_REALTIME_CRITICAL)
		return ENOTSUP;

	ret = thread_map_priority_to_os_value(priority, &param.sched_priority,
		&policy);
	if (ret != 0)
		return ret;

	return pthread_setschedparam((pthread_t)thread_id.opaque_id, policy,
		&param);
}

int
rte_thread_key_create(rte_thread_key *key, void (*destructor)(void *))
{
	int err;

	*key = malloc(sizeof(**key));
	if ((*key) == NULL) {
		RTE_LOG(DEBUG, EAL, "Cannot allocate TLS key.\n");
		rte_errno = ENOMEM;
		return -1;
	}
	err = pthread_key_create(&((*key)->thread_index), destructor);
	if (err) {
		RTE_LOG(DEBUG, EAL, "pthread_key_create failed: %s\n",
			strerror(err));
		free(*key);
		rte_errno = ENOEXEC;
		return -1;
	}
	return 0;
}

int
rte_thread_key_delete(rte_thread_key key)
{
	int err;

	if (!key) {
		RTE_LOG(DEBUG, EAL, "Invalid TLS key.\n");
		rte_errno = EINVAL;
		return -1;
	}
	err = pthread_key_delete(key->thread_index);
	if (err) {
		RTE_LOG(DEBUG, EAL, "pthread_key_delete failed: %s\n",
			strerror(err));
		free(key);
		rte_errno = ENOEXEC;
		return -1;
	}
	free(key);
	return 0;
}

int
rte_thread_value_set(rte_thread_key key, const void *value)
{
	int err;

	if (!key) {
		RTE_LOG(DEBUG, EAL, "Invalid TLS key.\n");
		rte_errno = EINVAL;
		return -1;
	}
	err = pthread_setspecific(key->thread_index, value);
	if (err) {
		RTE_LOG(DEBUG, EAL, "pthread_setspecific failed: %s\n",
			strerror(err));
		rte_errno = ENOEXEC;
		return -1;
	}
	return 0;
}

void *
rte_thread_value_get(rte_thread_key key)
{
	if (!key) {
		RTE_LOG(DEBUG, EAL, "Invalid TLS key.\n");
		rte_errno = EINVAL;
		return NULL;
	}
	return pthread_getspecific(key->thread_index);
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

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 Microsoft.
 */

#include <pthread.h>

#include <rte_thread.h>

#include "test.h"

#define THREADS_COUNT 20

#define TEST_THREADS_LOG(func) \
		printf("Error at line %d. %s failed!\n", __LINE__, func)

static void *
thread_loop_self(void *arg)
{
	rte_thread_t *id = arg;

	*id = rte_thread_self();

	return NULL;
}

static int
test_thread_self(void)
{
	rte_thread_t threads_ids[THREADS_COUNT];
	rte_thread_t self_ids[THREADS_COUNT] = {};
	size_t i;
	size_t j;
	int ret = 0;

	for (i = 0; i < THREADS_COUNT; ++i) {
		if (rte_thread_create(&threads_ids[i], NULL, thread_loop_self,
				&self_ids[i]) != 0) {
			printf("Error, Only %zu threads created.\n", i);
			break;
		}
	}

	for (j = 0; j < i; ++j) {
		ret = rte_thread_join(threads_ids[j], NULL);
		if (ret != 0) {
			TEST_THREADS_LOG("rte_thread_join()");
			return -1;
		}

		if (rte_thread_equal(threads_ids[j], self_ids[j]) == 0)
			ret = -1;
	}

	return ret;
}

struct thread_context {
	rte_thread_barrier *barrier;
	size_t *thread_count;
};

static void *
thread_loop_barrier(void *arg)
{

	struct thread_context *ctx = arg;

	(void)__atomic_add_fetch(ctx->thread_count, 1, __ATOMIC_RELAXED);

	if (rte_thread_barrier_wait(ctx->barrier) > 0)
		TEST_THREADS_LOG("rte_thread_barrier_wait()");

	return NULL;
}

static int
test_thread_barrier(void)
{
	rte_thread_t threads_ids[THREADS_COUNT];
	struct thread_context ctx[THREADS_COUNT] = {};
	rte_thread_barrier barrier;
	size_t count = 0;
	size_t i;
	size_t j;
	int ret = 0;

	ret = rte_thread_barrier_init(&barrier, THREADS_COUNT + 1);
	if (ret != 0) {
		TEST_THREADS_LOG("rte_thread_barrier_init()");
		return -1;
	}

	for (i = 0; i < THREADS_COUNT; ++i) {
		ctx[i].thread_count = &count;
		ctx[i].barrier = &barrier;
		if (rte_thread_create(&threads_ids[i], NULL,
				thread_loop_barrier, &ctx[i]) != 0) {
			printf("Error, Only %zu threads created.\n", i);
			ret = -1;
			goto error;
		}
	}

	ret = rte_thread_barrier_wait(ctx->barrier);
	if (ret > 0) {
		TEST_THREADS_LOG("rte_thread_barrier_wait()");
		ret = -1;
		goto error;
	}

	if (count != i) {
		ret = -1;
		printf("Error, expected thread count(%zu) to be equal "
			"to the number of threads that wait at the barrier(%zu)\n",
			count, i);
		goto error;
	}

error:
	for (j = 0; j < i; ++j) {
		ret = rte_thread_join(threads_ids[j], NULL);
		if (ret != 0) {
			TEST_THREADS_LOG("rte_thread_join()");
			ret = -1;
			break;
		}
	}

	ret = rte_thread_barrier_destroy(&barrier);
	if (ret != 0) {
		TEST_THREADS_LOG("rte_thread_barrier_destroy()");
		ret = -1;
	}

	return ret;
}

static size_t val;

static void *
thread_loop_mutex(void *arg)
{
	rte_thread_mutex *mutex = arg;

	rte_thread_mutex_lock(mutex);
	val++;
	rte_thread_mutex_unlock(mutex);

	return NULL;
}

static int
test_thread_mutex(void)
{
	rte_thread_t threads_ids[THREADS_COUNT];
	rte_thread_mutex mutex;
	size_t i;
	size_t j;
	int ret = 0;

	/*
	 * The value that each thread will increment while holding the mutex.
	 */
	val = 0;

	ret = rte_thread_mutex_init(&mutex);
	if (ret != 0) {
		TEST_THREADS_LOG("rte_thread_mutex_init()");
		return -1;
	}

	for (i = 0; i < THREADS_COUNT; ++i) {
		if (rte_thread_create(&threads_ids[i], NULL,
				thread_loop_mutex, &mutex) != 0) {
			printf("Error, created only %zu threads\n", i);
			ret = -1;
			goto error;
		}
	}

error:
	for (j = 0; j < i; ++j) {
		ret = rte_thread_join(threads_ids[j], NULL);
		if (ret != 0) {
			TEST_THREADS_LOG("rte_thread_join()");
			ret = -1;
		}
	}

	ret = rte_thread_mutex_destroy(&mutex);
	if (ret != 0) {
		TEST_THREADS_LOG("rte_thread_mutex_destroy()");
		ret = -1;
	}

	if (i != val) {
		printf("Unexpected value: %zu!. Expected %zu. "
			"Each thread should increment the value once.\n",
			val, i);
		ret = -1;
	}

	return ret;
}

struct thread_affinity_ctx {
	size_t idx;
	unsigned int result;
};

static void *
thread_loop_attributes_affinity(void *arg)
{
	struct thread_affinity_ctx *ctx = arg;
	rte_cpuset_t cpuset;
	size_t i;

	ctx->result = 0;

	CPU_ZERO(&cpuset);
	if (pthread_getaffinity_np(pthread_self(), sizeof(cpuset),
			&cpuset) != 0) {
		ctx->result = 1;
		TEST_THREADS_LOG("pthread_getaffinity_np()");
		return NULL;
	}

	if (!CPU_ISSET(ctx->idx, &cpuset)) {
		ctx->result = 1;
		printf("CPU %zu should be set for thread %zu\n",
			ctx->idx, ctx->idx);
		return NULL;
	}

	for (i = 0; i < CPU_SETSIZE; ++i) {
		if (i != ctx->idx && CPU_ISSET(i, &cpuset)) {
			ctx->result = 1;
			printf("CPU %zu should not be set for thread %zu\n",
				i, ctx->idx);
			return NULL;
		}
	}
	return NULL;
}

static int
test_thread_attributes_affinity(void)
{
	rte_thread_t threads_ids[THREADS_COUNT];
	struct thread_affinity_ctx ctx[THREADS_COUNT] = {};
	rte_thread_attr_t attr;
	rte_cpuset_t cpuset;
	size_t i;
	size_t j;
	int ret = 0;

	ret = rte_thread_attr_init(&attr);
	if (ret != 0) {
		TEST_THREADS_LOG("rte_thread_attr_init()");
		return -1;
	}

	for (i = 0; i < THREADS_COUNT; ++i) {
		CPU_ZERO(&cpuset);
		CPU_SET(i, &cpuset);

		ret = rte_thread_attr_set_affinity(&attr, &cpuset);
		if (ret != 0) {
			ret = -1;
			TEST_THREADS_LOG("rte_thread_attr_set_affinity()");
			goto error;
		}

		ctx[i].idx = i;
		if (rte_thread_create(&threads_ids[i], &attr,
				thread_loop_attributes_affinity,
				&ctx[i]) != 0) {
			printf("Error, created only %zu threads\n", i);
			ret = -1;
			goto error;
		}

	}

error:
	for (j = 0; j < i; ++j) {
		ret = rte_thread_join(threads_ids[j], NULL);
		if (ret != 0) {
			TEST_THREADS_LOG("rte_thread_join()");
			ret = -1;
			break;
		}

		if (ctx[j].result != 0)
			ret = -1;
	}

	return ret;
}

static void *
thread_loop_return(void *arg)
{
	RTE_SET_USED(arg);
	return NULL;
}

static int
test_thread_attributes_priority(void)
{
	rte_thread_t threads_ids[THREADS_COUNT];
	rte_thread_attr_t attr;
	size_t i;
	size_t j;
	int ret = 0;
	int policy;
	struct sched_param param;

	ret = rte_thread_attr_init(&attr);
	if (ret != 0) {
		TEST_THREADS_LOG("rte_thread_attr_init()");
		return -1;
	}

	ret = rte_thread_attr_set_priority(&attr, RTE_THREAD_PRIORITY_NORMAL);
	if (ret != 0) {
		TEST_THREADS_LOG("rte_thread_attr_set_priority()");
		return -1;
	}

	for (i = 0; i < THREADS_COUNT; ++i) {
		if (rte_thread_create(&threads_ids[i], &attr,
				thread_loop_return, NULL) != 0) {
			printf("Error, created only %zu threads\n", i);
			ret = -1;
			goto error;
		}

		ret = pthread_getschedparam(
				(pthread_t)threads_ids[i].opaque_id,
				&policy, &param);
		if (ret != 0) {
			ret = -1;
			TEST_THREADS_LOG("pthread_getschedparam()");
			goto error;
		}

		if (policy != SCHED_OTHER || param.sched_priority != 0) {
			ret = -1;
			printf("Unexpected priority: %d or policy: %d\n",
					param.sched_priority, SCHED_OTHER);
			goto error;
		}

	}

error:
	for (j = 0; j < i; ++j) {
		ret = rte_thread_join(threads_ids[j], NULL);
		if (ret != 0) {
			TEST_THREADS_LOG("rte_thread_join()");
			ret = -1;
			break;
		}
	}

	return ret;
}

static int
test_thread_detach(void)
{
	rte_thread_t threads_ids[THREADS_COUNT];
	size_t i;
	size_t j;
	int ret = 0;

	for (i = 0; i < THREADS_COUNT; ++i) {
		if (rte_thread_create(&threads_ids[i], NULL,
				thread_loop_return, NULL) != 0) {
			printf("Error, Only %zu threads created.\n", i);
			goto error;
		}
	}

error:
	for (j = 0; j < i; ++j) {
		ret = rte_thread_detach(threads_ids[j]);
		if (ret != 0) {
			TEST_THREADS_LOG("rte_thread_detach()");
			return -1;
		}
	}

	return ret;
}

static struct unit_test_suite threads_test_suite = {
	.suite_name = "threads autotest",
	.setup = NULL,
	.teardown = NULL,
	.unit_test_cases = {
			TEST_CASE(test_thread_self),
			TEST_CASE(test_thread_barrier),
			TEST_CASE(test_thread_mutex),
			TEST_CASE(test_thread_attributes_affinity),
			TEST_CASE(test_thread_attributes_priority),
			TEST_CASE(test_thread_detach),
			TEST_CASES_END()
	}
};

static int
test_threads(void)
{
	return unit_test_suite_runner(&threads_test_suite);
}

REGISTER_TEST_COMMAND(threads_autotest, test_threads);

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 Microsoft.
 */

#include <rte_thread.h>
#include <rte_debug.h>

#include "test.h"

#define THREADS_COUNT 20

RTE_LOG_REGISTER(threads_logtype_test, test.threads, INFO);

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
	int ret;
	int i;

	for (i = 0; i < THREADS_COUNT; ++i) {
		ret = rte_thread_create(&threads_ids[i], NULL, thread_loop_self,
				&self_ids[i]);
		RTE_TEST_ASSERT(ret == 0, "Failed to create threads!");
	}

	for (i = 0; i < THREADS_COUNT; ++i) {
		RTE_TEST_ASSERT(rte_thread_join(threads_ids[i], NULL) == 0, "Failed to join thread!");
		RTE_TEST_ASSERT_EQUAL(threads_ids[i].opaque_id,
				self_ids[i].opaque_id, "Unexpected thread id!");
	}

	return 0;
}

struct thread_context {
	rte_thread_barrier *barrier;
	int barrier_result;
};

static void *
thread_loop_barrier(void *arg)
{
	struct thread_context *ctx = arg;

	ctx->barrier_result = rte_thread_barrier_wait(ctx->barrier);
	if (ctx->barrier_result > 0)
		rte_log(RTE_LOG_DEBUG, threads_logtype_test, "Failed to wait at barrier!");

	return NULL;
}

static int
test_thread_barrier(void)
{
	rte_thread_t thread_id;
	struct thread_context ctx;
	rte_thread_barrier barrier;
	int ret = 0;
	int result = 0;

	ret = rte_thread_barrier_init(&barrier, 2);
	RTE_TEST_ASSERT(ret == 0, "Failed to initialize barrier!");

	ctx.barrier = &barrier;
	ret = rte_thread_create(&thread_id, NULL, thread_loop_barrier, &ctx);
	RTE_TEST_ASSERT(ret == 0, "Failed to create thread!");

	result = rte_thread_barrier_wait(&barrier);
	RTE_TEST_ASSERT(result <= 0, "Failed to wait at the barrier!");

	ret = rte_thread_join(thread_id, NULL);
	RTE_TEST_ASSERT(ret == 0, "Failed to join threads!");

	ret = rte_thread_barrier_destroy(&barrier);
	RTE_TEST_ASSERT(ret == 0, "Failed to destroy barrier!");

	RTE_TEST_ASSERT(ctx.barrier_result <= 0, "Child thread failed to wait at the barrier!");
	RTE_TEST_ASSERT_NOT_EQUAL(ctx.barrier_result, result, "Threads were not blocked at the barrier!");

	return 0;
}

RTE_STATIC_MUTEX(static_mutex);

struct mutex_loop_args {
	rte_thread_barrier *barrier;
	rte_thread_mutex *mutex;
	unsigned long result_A;
	unsigned long result_B;
};

static void *
thread_loop_mutex_B(void *arg)
{
	struct mutex_loop_args *args = arg;

	if (rte_thread_mutex_try_lock(args->mutex) == 0) {
		rte_thread_barrier_wait(args->barrier);
		rte_thread_mutex_unlock(args->mutex);
		args->result_B = 1;
	} else {
		rte_thread_barrier_wait(args->barrier);
		args->result_B = 2;
	}

	return NULL;
}

static void *
thread_loop_mutex_A(void *arg)
{
	struct mutex_loop_args *args = arg;

	if (rte_thread_mutex_try_lock(args->mutex) != 0) {
		rte_thread_barrier_wait(args->barrier);
		args->result_A = 2;
	} else {
		rte_thread_barrier_wait(args->barrier);
		rte_thread_mutex_unlock(args->mutex);
		args->result_A = 1;
	}

	return NULL;
}

static int
test_thread_mutex(rte_thread_mutex *pmutex)
{
	rte_thread_t thread_A;
	rte_thread_t thread_B;
	rte_thread_mutex mutex;
	rte_thread_barrier barrier;
	struct mutex_loop_args args;
	int ret = 0;

	/* If mutex is not statically initialized */
	if (pmutex == NULL) {
		ret = rte_thread_mutex_init(&mutex);
		RTE_TEST_ASSERT(ret == 0, "Failed to initialize mutex!");
	} else
		mutex = *pmutex;

	ret = rte_thread_barrier_init(&barrier, 2);
	RTE_TEST_ASSERT(ret == 0, "Failed to initialize barrier!");

	args.mutex = &mutex;
	args.barrier = &barrier;

	ret = rte_thread_create(&thread_A, NULL, thread_loop_mutex_A, &args);
	RTE_TEST_ASSERT(ret == 0, "Failed to create thread!");

	ret = rte_thread_create(&thread_B, NULL, thread_loop_mutex_B, &args);
	RTE_TEST_ASSERT(ret == 0, "Failed to create thread!");

	ret = rte_thread_join(thread_A, NULL);
	RTE_TEST_ASSERT(ret == 0, "Failed to join thread!");

	ret = rte_thread_join(thread_B, NULL);
	RTE_TEST_ASSERT(ret == 0, "Failed to join thread!");

	RTE_TEST_ASSERT(args.result_A != args.result_B, "Mutex failed to be acquired or was acquired by both threads!");

	/* Destroy if dynamically initialized */
	if (pmutex == NULL) {
		ret = rte_thread_mutex_destroy(&mutex);
		RTE_TEST_ASSERT(ret == 0, "Failed to destroy mutex!");
	}

	ret = rte_thread_barrier_destroy(&barrier);
	RTE_TEST_ASSERT(ret == 0, "Failed to destroy barrier!");

	return ret;
}

static int
test_thread_mutex_static(void)
{
	return test_thread_mutex(&static_mutex);
}

static int
test_thread_mutex_dynamic(void)
{
	return test_thread_mutex(NULL);
}

struct thread_affinity_ctx {
	rte_cpuset_t *cpuset;
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
	if (rte_thread_get_affinity_by_id(rte_thread_self(), &cpuset) != 0) {
		ctx->result = 1;
		rte_log(RTE_LOG_DEBUG, threads_logtype_test, "Failed to get thread affinity!");
		return NULL;
	}

	/*
	 * Check that the thread is not running on CPUs which were not
	 * specified in the affinity mask. Note that the CPU mask
	 * retrieved above can be different than the original mask specified
	 * with rte_thread_attr_set_affinity(), since some CPUs may not be
	 * available on the system.
	 */
	for (i = 0; i < CPU_SETSIZE; ++i) {
		if (!CPU_ISSET(i, ctx->cpuset) && CPU_ISSET(i, &cpuset)) {
			ctx->result = 1;
			rte_log(RTE_LOG_DEBUG, threads_logtype_test, "CPU %zu should not be set for this thread!\n",
					i);
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
	int ret = 0;

	ret = rte_thread_attr_init(&attr);
	RTE_TEST_ASSERT(ret == 0, "Failed to initialize thread attributes!");

	CPU_ZERO(&cpuset);
	ret = rte_thread_get_affinity_by_id(rte_thread_self(), &cpuset);
	RTE_TEST_ASSERT(ret == 0, "Failed to get main thread affinity!");

	ret = rte_thread_attr_set_affinity(&attr, &cpuset);
	RTE_TEST_ASSERT(ret == 0, "Failed to set thread attributes!");

	for (i = 0; i < THREADS_COUNT; ++i) {
		ctx[i].cpuset = &cpuset;
		ret = rte_thread_create(&threads_ids[i], &attr,
				thread_loop_attributes_affinity, &ctx[i]);
		RTE_TEST_ASSERT(ret == 0, "Failed to create threads!");
	}

	for (i = 0; i < THREADS_COUNT; ++i) {
		ret = rte_thread_join(threads_ids[i], NULL);
		RTE_TEST_ASSERT(ret == 0, "Failed to join threads!");

		RTE_TEST_ASSERT_EQUAL(ctx[i].result, 0, "Unexpected thread affinity!");
	}

	return ret;
}

static void *
thread_loop_priority(void *arg)
{
	int ret;
	enum rte_thread_priority priority;
	int *result = arg;

	*result = 1;
	ret = rte_thread_get_priority(rte_thread_self(), &priority);
	if (ret != 0 || priority != RTE_THREAD_PRIORITY_NORMAL)
		*result = 2;

	return NULL;
}

static int
test_thread_attributes_priority(void)
{
	rte_thread_t threads_ids[THREADS_COUNT];
	rte_thread_attr_t attr;
	size_t i;
	int ret = 0;
	int results[THREADS_COUNT] = {};

	ret = rte_thread_attr_init(&attr);
	RTE_TEST_ASSERT(ret == 0, "Failed to initialize  thread attributes!");

	ret = rte_thread_attr_set_priority(&attr, RTE_THREAD_PRIORITY_NORMAL);
	RTE_TEST_ASSERT(ret == 0, "Failed to set thread priority!");

	for (i = 0; i < THREADS_COUNT; ++i) {
		ret = rte_thread_create(&threads_ids[i], &attr,
				thread_loop_priority, &results[i]);
		RTE_TEST_ASSERT(ret == 0, "Failed to create threads!");
	}

	for (i = 0; i < THREADS_COUNT; ++i) {
		ret = rte_thread_join(threads_ids[i], NULL);
		RTE_TEST_ASSERT(ret == 0, "Failed to join threads!");

		RTE_TEST_ASSERT_EQUAL(results[i], 1, "Unexpected priority value!");
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
test_thread_detach(void)
{
	rte_thread_t threads_ids[THREADS_COUNT];
	size_t i;
	int ret = 0;

	for (i = 0; i < THREADS_COUNT; ++i) {
		ret = rte_thread_create(&threads_ids[i], NULL,
				thread_loop_return, NULL);
		RTE_TEST_ASSERT(ret == 0, "Failed to create threads!");
	}

	for (i = 0; i < THREADS_COUNT; ++i) {
		ret = rte_thread_detach(threads_ids[i]);
		RTE_TEST_ASSERT(ret == 0, "Failed to detach thread!");
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
			TEST_CASE(test_thread_mutex_static),
			TEST_CASE(test_thread_mutex_dynamic),
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

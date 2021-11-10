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

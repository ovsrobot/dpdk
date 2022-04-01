/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022 Microsoft.
 */

#include <string.h>
#include <pthread.h>

#include <rte_thread.h>
#include <rte_debug.h>

#include "test.h"

RTE_LOG_REGISTER(threads_logtype_test, test.threads, INFO);

static void *
thread_main(void *arg)
{
	(void)arg;
	return NULL;
}

static int
test_thread_affinity(void)
{
	pthread_t id;
	rte_thread_t thread_id;

	RTE_TEST_ASSERT(pthread_create(&id, NULL, thread_main, NULL) == 0,
		"Failed to create thread");
	thread_id.opaque_id = id;

	rte_cpuset_t cpuset0;
	RTE_TEST_ASSERT(rte_thread_get_affinity_by_id(thread_id, &cpuset0) == 0,
		"Failed to get thread affinity");

	rte_cpuset_t cpuset1;
	RTE_TEST_ASSERT(rte_thread_get_affinity_by_id(thread_id, &cpuset1) == 0,
		"Failed to get thread affinity");
	RTE_TEST_ASSERT(0 == memcmp(&cpuset0, &cpuset1, sizeof(rte_cpuset_t)),
		"Affinity should be stable");

	RTE_TEST_ASSERT(rte_thread_set_affinity_by_id(thread_id, &cpuset1) == 0,
		"Failed to set thread affinity");
	RTE_TEST_ASSERT(rte_thread_get_affinity_by_id(thread_id, &cpuset0) == 0,
		"Failed to get thread affinity");
	RTE_TEST_ASSERT(0 == memcmp(&cpuset0, &cpuset1, sizeof(rte_cpuset_t)),
		"Affinity should be stable");

	size_t i;
	for (i = 1; i < CPU_SETSIZE; i++)
		if (CPU_ISSET(i, &cpuset0)) {
			CPU_ZERO(&cpuset0);
			CPU_SET(i, &cpuset0);

			break;
		}
	RTE_TEST_ASSERT(rte_thread_set_affinity_by_id(thread_id, &cpuset0) == 0,
		"Failed to set thread affinity");
	RTE_TEST_ASSERT(rte_thread_get_affinity_by_id(thread_id, &cpuset1) == 0,
		"Failed to get thread affinity");
	RTE_TEST_ASSERT(0 == memcmp(&cpuset0, &cpuset1, sizeof(rte_cpuset_t)),
		"Affinity should be stable");

	return 0;
}

static struct unit_test_suite threads_test_suite = {
	.suite_name = "threads autotest",
	.setup = NULL,
	.teardown = NULL,
	.unit_test_cases = {
		TEST_CASE(test_thread_affinity),
		TEST_CASES_END()
	}
};

static int
test_threads(void)
{
	return unit_test_suite_runner(&threads_test_suite);
}

REGISTER_TEST_COMMAND(threads_autotest, test_threads);

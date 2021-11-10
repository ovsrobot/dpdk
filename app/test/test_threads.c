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

static struct unit_test_suite threads_test_suite = {
	.suite_name = "threads autotest",
	.setup = NULL,
	.teardown = NULL,
	.unit_test_cases = {
			TEST_CASE(test_thread_self),
			TEST_CASES_END()
	}
};

static int
test_threads(void)
{
	return unit_test_suite_runner(&threads_test_suite);
}

REGISTER_TEST_COMMAND(threads_autotest, test_threads);

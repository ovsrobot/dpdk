/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA Corporation & Affiliates
 */

#include <stdbool.h>
#include <sys/resource.h>

#include <rte_parray.h>
#include <rte_lcore.h>
#include <rte_errno.h>
#include <rte_log.h>

#include "test.h"

RTE_LOG_REGISTER(test_parray_log, test.parray, INFO);
#define LOG(level, ...) \
	rte_log(RTE_LOG_ ## level, test_parray_log, RTE_FMT("parray test: " \
		RTE_FMT_HEAD(__VA_ARGS__,) "\n", RTE_FMT_TAIL(__VA_ARGS__,)))

static bool stop;

static struct rte_parray array = RTE_PARRAY_INITIALIZER;
typedef int elem_t; /* array of int pointers */

static elem_t trash;

static long
get_context_switches(void)
{
	struct rusage thread_info;
	long context_switches;

	getrusage(RUSAGE_THREAD, &thread_info);
	context_switches = thread_info.ru_nivcsw;
	LOG(DEBUG, "%ld involuntary context switches on lcore %u",
			context_switches, rte_lcore_id());

	return context_switches;
}

static int
reader(void *userdata __rte_unused)
{
	LOG(DEBUG, "%s on lcore %u", __func__, rte_lcore_id());
	while (!stop) {
		int32_t index;

		RTE_PARRAY_FOREACH(&array, index)
			trash = *RTE_PARRAY_P(elem_t, &array, index);
	}
	return 0;
}

static int
test_parray(void)
{
	int iter;
	int32_t index;
	long context_switches;

	stop = false;
	rte_eal_mp_remote_launch(reader, NULL, SKIP_MAIN);
	LOG(DEBUG, "writer on lcore %u", rte_lcore_id());

	rte_parray_find_next(NULL, 0);
	TEST_ASSERT_FAIL(rte_errno, "find from NULL did not fail");
	rte_parray_find_next(&array, -1);
	TEST_ASSERT_FAIL(rte_errno, "find from -1 did not fail");
	rte_parray_find_next(&array, 0);
	TEST_ASSERT_SUCCESS(rte_errno, "find from empty failed");

	rte_parray_free(NULL, 0);
	TEST_ASSERT_FAIL(rte_errno, "free in NULL did not fail");
	rte_parray_free(&array, 0);
	TEST_ASSERT_FAIL(rte_errno, "free out of range did not fail");

	rte_parray_alloc(NULL, 0);
	TEST_ASSERT_FAIL(rte_errno, "alloc in NULL did not fail");
	for (iter = 0; iter < 127; iter++) {
		index = rte_parray_alloc(&array, sizeof(elem_t));
		TEST_ASSERT_SUCCESS(rte_errno, "alloc returned an error");
		TEST_ASSERT(index >= 0, "alloc returned a negative index");
		TEST_ASSERT_EQUAL(index, iter, "alloc returned wrong index");
	}

	rte_parray_free(&array, 0);
	TEST_ASSERT_SUCCESS(rte_errno, "free returned an error");
	rte_parray_free(&array, 0);
	TEST_ASSERT_SUCCESS(rte_errno, "double free returned an error");

	/* alloc should increase index if possible */
	index = rte_parray_alloc(&array, sizeof(elem_t));
	TEST_ASSERT_SUCCESS(rte_errno, "alloc after free returned an error");
	TEST_ASSERT_EQUAL(index, 127, "alloc after free returned wrong index");
	/* size should be 128, almost full, forcing next element to be 0 */
	index = rte_parray_alloc(&array, sizeof(elem_t));
	TEST_ASSERT_SUCCESS(rte_errno, "alloc freed 0 returned an error");
	TEST_ASSERT_EQUAL(index, 0, "alloc freed 0 returned wrong index");

	/* try more race with readers */
	context_switches = get_context_switches();
	for (iter = 0; iter < 99; iter++) {
		for (index = 0; index < 9999; index++) {
			rte_parray_alloc(&array, sizeof(elem_t));
			TEST_ASSERT_SUCCESS(rte_errno, "alloc returned an error");
		}
		if (get_context_switches() > context_switches + 9)
			break;
	}

	stop = true;
	rte_eal_mp_wait_lcore();

	rte_parray_free_all(&array);
	TEST_ASSERT_SUCCESS(rte_errno, "free all returned an error");

	return TEST_SUCCESS;
}

REGISTER_TEST_COMMAND(parray_autotest, test_parray);

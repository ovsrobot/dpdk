/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Arm Limited
 */

#include "test.h"

#include <assert.h>
#include <inttypes.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_deque.h>
#include <rte_errno.h>
#include <rte_malloc.h>
#include <rte_tailq.h>

static int
test_deque_get_memsize(void)
{
	const ssize_t RTE_DEQUE_SZ = sizeof(struct rte_deque);
	/* (1) Should return EINVAL when the supplied size of deque is not a
	 * power of 2.
	 */
	TEST_ASSERT_EQUAL(rte_deque_get_memsize_elem(4, 9), -EINVAL,
					  "Get memsize function failed.");

	/* (2) Should return EINVAL when the supplied size of deque is not a
	 * multiple of 4.
	 */
	TEST_ASSERT_EQUAL(rte_deque_get_memsize_elem(5, 8), -EINVAL,
					  "Get memsize function failed.");

	/* (3) Requested size of the deque should be less than or equal to
	 * RTE_DEQUEUE_SZ_MASK
	 */
	TEST_ASSERT_EQUAL(rte_deque_get_memsize_elem(4, RTE_DEQUE_SZ_MASK), -EINVAL,
					  "Get memsize function failed.");

	/* (4) A deque of count 1, where the element size is 0, should not allocate
	 * any more memory than necessary to hold the dequeu structure.
	 */
	TEST_ASSERT_EQUAL(rte_deque_get_memsize_elem(0, 1), RTE_DEQUE_SZ,
					  "Get memsize function failed.");

	/* (5) Make sure the function is calculating the size correctly.
	 * size of deque: 128. Size for two elements each of size esize: 8
	 * total: 128 + 8 = 132
	 * Cache align'd size = 192.
	 */
	const ssize_t calculated_sz = RTE_ALIGN(RTE_DEQUE_SZ + 8, RTE_CACHE_LINE_SIZE);
	TEST_ASSERT_EQUAL(rte_deque_get_memsize_elem(4, 2), calculated_sz,
					  "Get memsize function failed.");
	return 0;
}

/* Define a Test macro that will allow us to correctly free all the rte_deque
 * objects that were created as a part of the test in case of a failure.
 */

#define TEST_DEQUE_MEMSAFE(exp, msg, stmt) do { \
	if (!(exp)) { \
		printf("error at %s:%d\tcondition " #exp " failed. Msg: %s\n",	\
			__func__, __LINE__, msg); \
		stmt; \
	 } \
} while (0)

static int
test_deque_init(void)
{
	{
	/* (1) Make sure init fails when the flags are not correctly passed in. */
	struct rte_deque deque;

	/* Calling init with undefined flags should fail. */
	TEST_ASSERT_EQUAL(rte_deque_init(&deque, "Deque", 10, 0x8),
					  -EINVAL, "Init failed.");

	/* Calling init with a count that is not a power of 2
	 * And also not the setting the RTE_DEQUE_F_EXACT_SZ
	 * flag should fail.
	 */
	TEST_ASSERT_EQUAL(rte_deque_init(&deque, "Deque", 10, 0),
					  -EINVAL, "Init failed.");

	/* Calling init with a count that is not a power of 2
	 * Should succeed only if the RTE_DEQUE_F_EXACT_SZ flag is set.
	 */
	TEST_ASSERT_EQUAL(rte_deque_init(&deque, "Deque", 10, RTE_DEQUE_F_EXACT_SZ),
					  0, "Init failed.");
	}

	{
	/* Make sure all the fields are being correctly set when creating a
	 * Deque of a size that is not a power of 2.
	 */
	struct rte_deque deque;
	static const char NAME[] = "Deque";

	/* Calling init with a count that is not a power of 2
	 * But with RTE_DEQUE_F_EXACT_SZ should succeed.
	 */
	TEST_ASSERT_EQUAL(rte_deque_init(&deque, NAME, 10, RTE_DEQUE_F_EXACT_SZ),
					  0, "Init failed.");

	TEST_ASSERT_BUFFERS_ARE_EQUAL(deque.name, NAME, sizeof(NAME), "Init failed.");
	TEST_ASSERT_EQUAL(deque.flags, RTE_DEQUE_F_EXACT_SZ, "Init failed.");
	TEST_ASSERT_EQUAL(deque.size, 16, "Init failed.");
	TEST_ASSERT_EQUAL(deque.mask, 15, "Init failed.");
	TEST_ASSERT_EQUAL(deque.capacity, 10, "Init failed.");
	}

	{
	/* Make sure all the fields are being correctly set when creating a
	 * Deque of a size that is a power of 2.
	 */
	struct rte_deque deque;
	static const char NAME[] = "Deque";

	/* Calling init with a count that is not a power of 2
	 * But with RTE_DEQUE_F_EXACT_SZ should succeed.
	 */
	TEST_ASSERT_EQUAL(rte_deque_init(&deque, NAME, 16, 0), 0, "Init failed.");

	TEST_ASSERT_EQUAL(deque.size, 16, "Init failed.");
	TEST_ASSERT_EQUAL(deque.mask, 15, "Init failed.");
	TEST_ASSERT_EQUAL(deque.capacity, 15, "Init failed.");
	}
	return 0;
}

static int
test_deque_create(void)
{
	struct rte_deque *deque;
	const char *NAME = "Deque";
	deque = rte_deque_create(NAME, 4, 16, 0, 0);

	/* Make sure the deque creation is successful. */
	TEST_DEQUE_MEMSAFE(deque != NULL, "Deque creation failed.", goto fail);
	TEST_DEQUE_MEMSAFE(deque->memzone != NULL, "Deque creation failed.", goto fail);
	return 0;
fail:
	rte_free(deque);
	return -1;
}

#undef TEST_DEQUE_MEMSAFE

static struct unit_test_suite deque_helper_functions_testsuite = {
	.suite_name = "Deque library helper functions test suite",
	.unit_test_cases = {
		TEST_CASE(test_deque_get_memsize),
		TEST_CASE(test_deque_init),
		TEST_CASE(test_deque_create),
		TEST_CASES_END(), /**< NULL terminate unit test array */
	},
};

static int
deque_helper_functions_autotest_fn(void)
{
	return unit_test_suite_runner(&deque_helper_functions_testsuite);
}

REGISTER_FAST_TEST(deque_helper_functions_autotest, true, true,
		deque_helper_functions_autotest_fn);

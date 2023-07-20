/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 HiSilicon Limited
 */

#ifdef RTE_EXEC_ENV_WINDOWS

#include <stdio.h>

#include "test.h"

static int
test_memarea(void)
{
	printf("memarea not supported on Windows, skipping test\n");
	return TEST_SKIPPED;
}

#else

#include <stdio.h>
#include <string.h>

#include <rte_errno.h>
#include <rte_memory.h>
#include <rte_memarea.h>

#include "test.h"

#define MEMAREA_TEST_DEFAULT_SIZE	0x1000

static void
test_memarea_init_param(struct rte_memarea_param *init)
{
	memset(init, 0, sizeof(struct rte_memarea_param));
	sprintf(init->name, "%s", "autotest");
	init->source = RTE_MEMAREA_SOURCE_LIBC;
	init->total_sz = MEMAREA_TEST_DEFAULT_SIZE;
	init->mt_safe = 1;
}

static int
test_memarea_create_bad_param(void)
{
	struct rte_memarea_param init;
	struct rte_memarea *ma;

	/* test for NULL */
	rte_errno = 0;
	ma = rte_memarea_create(NULL);
	TEST_ASSERT(ma == NULL, "Memarea creation expect fail");
	TEST_ASSERT(rte_errno == EINVAL, "Expected EINVAL");

	/* test for invalid name */
	rte_errno = 0;
	memset(&init, 0, sizeof(init));
	ma = rte_memarea_create(&init);
	TEST_ASSERT(ma == NULL, "Memarea creation expect fail");
	TEST_ASSERT(rte_errno == EINVAL, "Expected EINVAL");
	rte_errno = 0;
	memset(&init.name, 1, sizeof(init.name));
	ma = rte_memarea_create(&init);
	TEST_ASSERT(ma == NULL, "Memarea creation expect fail");
	TEST_ASSERT(rte_errno == EINVAL, "Expected EINVAL");

	/* test for invalid source */
	rte_errno = 0;
	test_memarea_init_param(&init);
	init.source = RTE_MEMAREA_SOURCE_MEMAREA + 1;
	ma = rte_memarea_create(&init);
	TEST_ASSERT(ma == NULL, "Memarea creation expect fail");
	TEST_ASSERT(rte_errno == EINVAL, "Expected EINVAL");

	/* test for total_sz */
	rte_errno = 0;
	test_memarea_init_param(&init);
	init.total_sz = 0;
	ma = rte_memarea_create(&init);
	TEST_ASSERT(ma == NULL, "Memarea creation expect fail");
	TEST_ASSERT(rte_errno == EINVAL, "Expected EINVAL");

	/* test for memarea NULL */
	rte_errno = 0;
	test_memarea_init_param(&init);
	init.source = RTE_MEMAREA_SOURCE_MEMAREA;
	ma = rte_memarea_create(&init);
	TEST_ASSERT(ma == NULL, "Memarea creation expect fail");
	TEST_ASSERT(rte_errno == EINVAL, "Expected EINVAL");

	/* test for algorithm invalid */
	rte_errno = 0;
	test_memarea_init_param(&init);
	init.alg = RTE_MEMAREA_ALGORITHM_NEXTFIT + 1;
	ma = rte_memarea_create(&init);
	TEST_ASSERT(ma == NULL, "Memarea creation expect fail");
	TEST_ASSERT(rte_errno == EINVAL, "Expected EINVAL");

	/* test for reserved field */
	rte_errno = 0;
	test_memarea_init_param(&init);
	init.reserved_bits = 1;
	ma = rte_memarea_create(&init);
	TEST_ASSERT(ma == NULL, "Memarea creation expect fail");
	TEST_ASSERT(rte_errno == EINVAL, "Expected EINVAL");
	rte_errno = 0;
	test_memarea_init_param(&init);
	init.reserved_64s[0] = 1;
	ma = rte_memarea_create(&init);
	TEST_ASSERT(ma == NULL, "Memarea creation expect fail");
	TEST_ASSERT(rte_errno == EINVAL, "Expected EINVAL");
	rte_errno = 0;
	test_memarea_init_param(&init);
	init.reserved_64s[1] = 1;
	ma = rte_memarea_create(&init);
	TEST_ASSERT(ma == NULL, "Memarea creation expect fail");
	TEST_ASSERT(rte_errno == EINVAL, "Expected EINVAL");

	return TEST_SUCCESS;
}

static int
test_memarea_create_destroy(void)
{
	struct rte_memarea *ma;
	struct rte_memarea_param init;

	rte_errno = 0;

	/* test for create with HEAP */
	test_memarea_init_param(&init);
	init.source = RTE_MEMAREA_SOURCE_HEAP;
	init.heap.socket_id = SOCKET_ID_ANY;
	ma = rte_memarea_create(&init);
	TEST_ASSERT(ma != NULL, "Memarea creation failed");
	rte_memarea_destroy(ma);

	/* test for create with LIBC */
	test_memarea_init_param(&init);
	init.source = RTE_MEMAREA_SOURCE_LIBC;
	ma = rte_memarea_create(&init);
	TEST_ASSERT(ma != NULL, "Memarea creation failed");
	rte_memarea_destroy(ma);

	return TEST_SUCCESS;
}

static struct unit_test_suite memarea_test_suite  = {
	.suite_name = "Memarea Unit Test Suite",
	.setup = NULL,
	.teardown = NULL,
	.unit_test_cases = {
		TEST_CASE(test_memarea_create_bad_param),
		TEST_CASE(test_memarea_create_destroy),

		TEST_CASES_END() /**< NULL terminate unit test array */
	}
};

static int
test_memarea(void)
{
	return unit_test_suite_runner(&memarea_test_suite);
}

#endif /* RTE_EXEC_ENV_WINDOWS */

REGISTER_TEST_COMMAND(memarea_autotest, test_memarea);

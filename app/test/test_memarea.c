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

static void
test_memarea_fill_region(void *ptr, size_t size)
{
	memset(ptr, 0xff, size);
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
	struct rte_memarea *ma, *src_ma;
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

	/* test for create with another memarea */
	test_memarea_init_param(&init);
	init.source = RTE_MEMAREA_SOURCE_LIBC;
	src_ma = rte_memarea_create(&init);
	TEST_ASSERT(src_ma != NULL, "Memarea creation failed");
	test_memarea_init_param(&init);
	init.source = RTE_MEMAREA_SOURCE_MEMAREA;
	init.total_sz = init.total_sz >> 1;
	init.ma.src = src_ma;
	ma = rte_memarea_create(&init);
	TEST_ASSERT(ma != NULL, "Memarea creation failed");
	rte_memarea_destroy(ma);
	rte_memarea_destroy(src_ma);

	TEST_ASSERT(rte_errno == 0, "Expected ZERO");

	return TEST_SUCCESS;
}

static int
test_memarea_alloc_bad_param(void)
{
	struct rte_memarea_param init;
	struct rte_memarea *ma;
	size_t size;
	void *ptr;

	test_memarea_init_param(&init);
	init.source = RTE_MEMAREA_SOURCE_LIBC;
	init.total_sz = MEMAREA_TEST_DEFAULT_SIZE;
	ma = rte_memarea_create(&init);
	TEST_ASSERT(ma != NULL, "Memarea creation failed");

	/* test for invalid ma */
	rte_errno = 0;
	ptr = rte_memarea_alloc(NULL, 1);
	TEST_ASSERT(ptr == NULL, "Memarea allocation expect fail");
	TEST_ASSERT(rte_errno == EINVAL, "Expected EINVAL");

	/* test for invalid size (size = 0) */
	rte_errno = 0;
	ptr = rte_memarea_alloc(ma, 0);
	TEST_ASSERT(ptr == NULL, "Memarea allocation expect fail");
	TEST_ASSERT(rte_errno == EINVAL, "Expected EINVAL");

	/* test for invalid size (size rewind) */
	rte_errno = 0;
	memset(&size, 0xff, sizeof(size));
	ptr = rte_memarea_alloc(ma, size);
	TEST_ASSERT(ptr == NULL, "Memarea allocation expect fail");
	TEST_ASSERT(rte_errno == EINVAL, "Expected EINVAL");

	rte_memarea_destroy(ma);

	return TEST_SUCCESS;
}

static int
test_memarea_free_bad_param(void)
{
	struct rte_memarea_param init;
	struct rte_memarea *ma;
	void *ptr;

	test_memarea_init_param(&init);
	init.source = RTE_MEMAREA_SOURCE_LIBC;
	init.total_sz = MEMAREA_TEST_DEFAULT_SIZE;
	ma = rte_memarea_create(&init);
	TEST_ASSERT(ma != NULL, "Memarea creation failed");
	ptr = rte_memarea_alloc(ma, 1);
	TEST_ASSERT(ptr != NULL, "Memarea allocation failed");
	test_memarea_fill_region(ptr, 1);

	/* test for invalid ma */
	rte_errno = 0;
	rte_memarea_free(NULL, ptr);
	TEST_ASSERT(rte_errno == EINVAL, "Expected EINVAL");

	/* test for invalid ptr */
	rte_errno = 0;
	rte_memarea_free(ma, NULL);
	TEST_ASSERT(rte_errno == EINVAL, "Expected EINVAL");

	rte_memarea_destroy(ma);

	return TEST_SUCCESS;
}

static int
test_memarea_alloc_fail(void)
{
	struct rte_memarea_param init;
	struct rte_memarea *ma;
	void *ptr[2];

	test_memarea_init_param(&init);
	init.source = RTE_MEMAREA_SOURCE_LIBC;
	init.total_sz = MEMAREA_TEST_DEFAULT_SIZE;
	ma = rte_memarea_create(&init);
	TEST_ASSERT(ma != NULL, "Memarea creation failed");

	/* test alloc fail with big size */
	rte_errno = 0;
	ptr[0] = rte_memarea_alloc(ma, MEMAREA_TEST_DEFAULT_SIZE);
	TEST_ASSERT(ptr[0] == NULL, "Memarea allocation expect fail");
	TEST_ASSERT(rte_errno == ENOMEM, "Expected ENOMEM");

	/* test alloc fail because no memory */
	ptr[0] = rte_memarea_alloc(ma, MEMAREA_TEST_DEFAULT_SIZE >> 1);
	TEST_ASSERT(ptr[0] != NULL, "Memarea allocation failed");
	test_memarea_fill_region(ptr[0], MEMAREA_TEST_DEFAULT_SIZE >> 1);
	rte_errno = 0;
	ptr[1] = rte_memarea_alloc(ma, MEMAREA_TEST_DEFAULT_SIZE >> 1);
	TEST_ASSERT(ptr[1] == NULL, "Memarea allocation expect fail");
	TEST_ASSERT(rte_errno == ENOMEM, "Expected ENOMEM");
	rte_memarea_free(ma, ptr[0]);

	/* test alloc fail when second fail */
	ptr[0] = rte_memarea_alloc(ma, MEMAREA_TEST_DEFAULT_SIZE >> 1);
	TEST_ASSERT(ptr[0] != NULL, "Memarea allocation failed");
	test_memarea_fill_region(ptr[0], MEMAREA_TEST_DEFAULT_SIZE >> 1);
	rte_errno = 0;
	ptr[1] = rte_memarea_alloc(ma, MEMAREA_TEST_DEFAULT_SIZE >> 1);
	TEST_ASSERT(ptr[1] == NULL, "Memarea allocation expect fail");
	TEST_ASSERT(rte_errno == ENOMEM, "Expected ENOMEM");
	rte_memarea_free(ma, ptr[0]);
	ptr[1] = rte_memarea_alloc(ma, MEMAREA_TEST_DEFAULT_SIZE >> 1);
	TEST_ASSERT(ptr[1] != NULL, "Memarea allocation failed");
	test_memarea_fill_region(ptr[1], MEMAREA_TEST_DEFAULT_SIZE >> 1);
	rte_memarea_free(ma, ptr[1]);

	rte_memarea_destroy(ma);

	return TEST_SUCCESS;
}

static int
test_memarea_free_fail(void)
{
	struct rte_memarea_param init;
	struct rte_memarea *ma;
	void *ptr;

	test_memarea_init_param(&init);
	init.source = RTE_MEMAREA_SOURCE_LIBC;
	init.total_sz = MEMAREA_TEST_DEFAULT_SIZE;
	ma = rte_memarea_create(&init);
	TEST_ASSERT(ma != NULL, "Memarea creation failed");

	/* test repeat free */
	rte_errno = 0;
	ptr = rte_memarea_alloc(ma, MEMAREA_TEST_DEFAULT_SIZE >> 1);
	TEST_ASSERT(ptr != NULL, "Memarea allocation failed");
	test_memarea_fill_region(ptr, MEMAREA_TEST_DEFAULT_SIZE >> 1);
	rte_memarea_free(ma, ptr);
	TEST_ASSERT(rte_errno == 0, "Expected Zero");
	rte_memarea_free(ma, ptr);
	TEST_ASSERT(rte_errno == EFAULT, "Expected EFAULT");

	rte_memarea_destroy(ma);

	return TEST_SUCCESS;
}

static int
test_memarea_alloc_free(void)
{
#define ALLOC_MAX_NUM	8
	struct rte_memarea_param init;
	void *ptr[ALLOC_MAX_NUM];
	struct rte_memarea *ma;
	int i;

	test_memarea_init_param(&init);
	init.source = RTE_MEMAREA_SOURCE_LIBC;
	init.total_sz = MEMAREA_TEST_DEFAULT_SIZE;
	ma = rte_memarea_create(&init);
	TEST_ASSERT(ma != NULL, "Memarea creation failed");
	memset(ptr, 0, sizeof(ptr));

	rte_errno = 0;

	/* test random alloc and free */
	for (i = 0; i < ALLOC_MAX_NUM; i++) {
		ptr[i] = rte_memarea_alloc(ma, 1);
		TEST_ASSERT(ptr[i] != NULL, "Memarea allocation failed");
		test_memarea_fill_region(ptr[i], 1);
	}

	/* test merge left */
	rte_memarea_free(ma, ptr[0]);
	rte_memarea_free(ma, ptr[1]);

	/* test merge right */
	rte_memarea_free(ma, ptr[7]);
	rte_memarea_free(ma, ptr[6]);

	/* test merge left and right */
	rte_memarea_free(ma, ptr[3]);
	rte_memarea_free(ma, ptr[2]);

	/* test merge remains */
	rte_memarea_free(ma, ptr[4]);
	rte_memarea_free(ma, ptr[5]);

	TEST_ASSERT(rte_errno == 0, "Expected Zero");

	fprintf(stderr, "There should have no allocated object.\n");
	rte_memarea_dump(ma, stderr, true);

	rte_memarea_destroy(ma);

	return TEST_SUCCESS;
}

static int
test_memarea_dump(void)
{
	struct rte_memarea_param init;
	uint32_t alloced_num = 0;
	struct rte_memarea *ma;
	void *ptr;
	int ret;

	test_memarea_init_param(&init);
	init.source = RTE_MEMAREA_SOURCE_LIBC;
	init.total_sz = MEMAREA_TEST_DEFAULT_SIZE;
	ma = rte_memarea_create(&init);
	TEST_ASSERT(ma != NULL, "Memarea creation failed");

	/* test for invalid parameters */
	rte_errno = 0;
	ret = rte_memarea_dump(NULL, stderr, false);
	TEST_ASSERT(ret == -1, "Expected -1");
	TEST_ASSERT(rte_errno == EINVAL, "Expected EINVAL");
	rte_errno = 0;
	ret = rte_memarea_dump(ma, NULL, false);
	TEST_ASSERT(ret == -1, "Expected -1");
	TEST_ASSERT(rte_errno == EINVAL, "Expected EINVAL");

	/* test for dump */
	ptr = rte_memarea_alloc(ma, 1);
	TEST_ASSERT(ptr != NULL, "Memarea allocation failed");
	alloced_num++;
	ptr = rte_memarea_alloc(ma, 1);
	TEST_ASSERT(ptr != NULL, "Memarea allocation failed");
	alloced_num++;
	ptr = rte_memarea_alloc(ma, 1);
	TEST_ASSERT(ptr != NULL, "Memarea allocation failed");
	alloced_num++;
	ptr = rte_memarea_alloc(ma, MEMAREA_TEST_DEFAULT_SIZE);
	TEST_ASSERT(ptr == NULL, "Memarea allocation expect fail");
	ptr = rte_memarea_alloc(ma, MEMAREA_TEST_DEFAULT_SIZE);
	TEST_ASSERT(ptr == NULL, "Memarea allocation expect fail");
	fprintf(stderr, "There should have %u allocated object.\n", alloced_num);
	ret = rte_memarea_dump(ma, stderr, true);
	TEST_ASSERT(ret == 0, "Memarea dump failed");

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
		TEST_CASE(test_memarea_alloc_bad_param),
		TEST_CASE(test_memarea_free_bad_param),
		TEST_CASE(test_memarea_alloc_fail),
		TEST_CASE(test_memarea_free_fail),
		TEST_CASE(test_memarea_alloc_free),
		TEST_CASE(test_memarea_dump),

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

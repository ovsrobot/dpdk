/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 HiSilicon Limited
 */

#include <stdio.h>
#include <string.h>

#include "test.h"

#ifdef RTE_EXEC_ENV_WINDOWS
static int
test_memarea(void)
{
	printf("memarea not supported on Windows, skipping test\n");
	return TEST_SKIPPED;
}

#else

#include <rte_memory.h>
#include <rte_memarea.h>

#define MEMAREA_TEST_DEFAULT_SIZE	0x1000

#define MEMAREA_TEST_API_RUN(test_func) \
	do { \
		int ret = test_func(); \
		if (ret < 0) { \
			printf("%s Failed\n", #test_func); \
			fails++; \
		} else { \
			printf("%s Passed\n", #test_func); \
		} \
	} while (0)

static int fails;

static void
test_memarea_prepare(void)
{
	fails = 0;
}

static int
test_memarea_retcode(void)
{
	return fails > 0 ? -1 : 0;
}

static void
test_memarea_init_param(struct rte_memarea_param *init)
{
	memset(init, 0, sizeof(struct rte_memarea_param));
	sprintf(init->name, "%s", "test-memarea");
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
	int i;

	/* test for NULL */
	ma = rte_memarea_create(NULL);
	RTE_TEST_ASSERT(ma == NULL, "Expected NULL");

	/* test for invalid name */
	memset(&init, 0, sizeof(init));
	ma = rte_memarea_create(&init);
	RTE_TEST_ASSERT(ma == NULL, "Expected NULL");
	memset(&init.name, 1, sizeof(init.name));
	ma = rte_memarea_create(&init);
	RTE_TEST_ASSERT(ma == NULL, "Expected NULL");

	/* test for invalid source */
	test_memarea_init_param(&init);
	init.source = RTE_MEMAREA_SOURCE_MEMAREA + 1;
	ma = rte_memarea_create(&init);
	RTE_TEST_ASSERT(ma == NULL, "Expected NULL");

	/* test for total_sz */
	test_memarea_init_param(&init);
	init.total_sz = 0;
	ma = rte_memarea_create(&init);
	RTE_TEST_ASSERT(ma == NULL, "Expected NULL");

	/* test for user memory address NULL */
	test_memarea_init_param(&init);
	init.source = RTE_MEMAREA_SOURCE_USER;
	ma = rte_memarea_create(&init);
	RTE_TEST_ASSERT(ma == NULL, "Expected NULL");

	/* test for user memory address align invalid */
	test_memarea_init_param(&init);
	init.source = RTE_MEMAREA_SOURCE_USER;
	for (i = 1; i < RTE_CACHE_LINE_SIZE; i++) {
		init.user_addr = (void *)((uintptr_t)i);
		ma = rte_memarea_create(&init);
		RTE_TEST_ASSERT(ma == NULL, "Expected NULL");
	}

	/* test for memarea NULL */
	test_memarea_init_param(&init);
	init.source = RTE_MEMAREA_SOURCE_MEMAREA;
	ma = rte_memarea_create(&init);
	RTE_TEST_ASSERT(ma == NULL, "Expected NULL");

	/* test for alg invalid */
	test_memarea_init_param(&init);
	init.alg = RTE_MEMAREA_ALG_NEXTFIT + 1;
	ma = rte_memarea_create(&init);
	RTE_TEST_ASSERT(ma == NULL, "Expected NULL");

	return 0;
}

static int
test_memarea_create_destroy(void)
{
	uint8_t user_buffer[MEMAREA_TEST_DEFAULT_SIZE + RTE_CACHE_LINE_SIZE];
	struct rte_memarea *ma, *src_ma;
	struct rte_memarea_param init;

	/* test for create with HEAP */
	test_memarea_init_param(&init);
	init.source = RTE_MEMAREA_SOURCE_HEAP;
	init.numa_socket = SOCKET_ID_ANY;
	ma = rte_memarea_create(&init);
	RTE_TEST_ASSERT(ma != NULL, "Expected Non-NULL");
	rte_memarea_destroy(ma);

	/* test for create with LIBC */
	test_memarea_init_param(&init);
	init.source = RTE_MEMAREA_SOURCE_LIBC;
	ma = rte_memarea_create(&init);
	RTE_TEST_ASSERT(ma != NULL, "Expected Non-NULL");
	rte_memarea_destroy(ma);

	/* test for create with user memory */
	test_memarea_init_param(&init);
	init.source = RTE_MEMAREA_SOURCE_USER;
	init.user_addr = (void *)(((uintptr_t)user_buffer + RTE_CACHE_LINE_SIZE) &
				  ~(RTE_CACHE_LINE_SIZE - 1));
	ma = rte_memarea_create(&init);
	RTE_TEST_ASSERT(ma != NULL, "Expected Non-NULL");
	rte_memarea_destroy(ma);

	/* test for create with another memarea */
	test_memarea_init_param(&init);
	init.source = RTE_MEMAREA_SOURCE_LIBC;
	src_ma = rte_memarea_create(&init);
	RTE_TEST_ASSERT(src_ma != NULL, "Expected Non-NULL");
	test_memarea_init_param(&init);
	init.source = RTE_MEMAREA_SOURCE_MEMAREA;
	init.total_sz = init.total_sz >> 1;
	init.src_memarea = src_ma;
	ma = rte_memarea_create(&init);
	RTE_TEST_ASSERT(ma != NULL, "Expected Non-NULL");
	rte_memarea_destroy(ma);
	rte_memarea_destroy(src_ma);

	return 0;
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
	RTE_TEST_ASSERT(ma != NULL, "Expected Non-NULL");

	/* test alloc fail with big size */
	ptr[0] = rte_memarea_alloc(ma, MEMAREA_TEST_DEFAULT_SIZE, 0);
	RTE_TEST_ASSERT(ptr[0] == NULL, "Expected NULL");

	/* test alloc fail because no memory */
	ptr[0] = rte_memarea_alloc(ma, MEMAREA_TEST_DEFAULT_SIZE - RTE_CACHE_LINE_SIZE, 0);
	RTE_TEST_ASSERT(ptr[0] != NULL, "Expected Non-NULL");
	ptr[1] = rte_memarea_alloc(ma, 1, 0);
	RTE_TEST_ASSERT(ptr[1] == NULL, "Expected NULL");
	rte_memarea_free(ma, ptr[0]);

	/* test alloc fail when second fail */
	ptr[0] = rte_memarea_alloc(ma, MEMAREA_TEST_DEFAULT_SIZE >> 1, 0);
	RTE_TEST_ASSERT(ptr[0] != NULL, "Expected Non-NULL");
	test_memarea_fill_region(ptr[0], MEMAREA_TEST_DEFAULT_SIZE >> 1);
	ptr[1] = rte_memarea_alloc(ma, MEMAREA_TEST_DEFAULT_SIZE >> 1, 0);
	RTE_TEST_ASSERT(ptr[1] == NULL, "Expected NULL");
	rte_memarea_free(ma, ptr[0]);
	ptr[1] = rte_memarea_alloc(ma, MEMAREA_TEST_DEFAULT_SIZE >> 1, 0);
	RTE_TEST_ASSERT(ptr[1] != NULL, "Expected Non-NULL");
	test_memarea_fill_region(ptr[1], MEMAREA_TEST_DEFAULT_SIZE >> 1);
	rte_memarea_free(ma, ptr[1]);

	rte_memarea_destroy(ma);

	return 0;
}

static int
test_memarea_free_fail(void)
{
	struct rte_memarea_param init;
	struct rte_memarea *ma;
	void *ptr;

	/* prepare env */
	test_memarea_init_param(&init);
	init.source = RTE_MEMAREA_SOURCE_LIBC;
	init.total_sz = MEMAREA_TEST_DEFAULT_SIZE;
	ma = rte_memarea_create(&init);
	RTE_TEST_ASSERT(ma != NULL, "Expected Non-NULL");

	/* test invalid parameters with update-refcnt */
	rte_memarea_update_refcnt(NULL, (void *)(uintptr_t)1, 0);
	rte_memarea_update_refcnt(ma, NULL, 0);
	rte_memarea_update_refcnt(NULL, NULL, 0);

	/* test free with refcnt fail */
	ptr = rte_memarea_alloc(ma, MEMAREA_TEST_DEFAULT_SIZE >> 1, 0);
	RTE_TEST_ASSERT(ptr != NULL, "Expected Non-NULL");
	test_memarea_fill_region(ptr, MEMAREA_TEST_DEFAULT_SIZE >> 1);
	rte_memarea_free(ma, ptr);
	rte_memarea_free(ma, ptr);

	/* test update refcnt with fail */
	ptr = rte_memarea_alloc(ma, MEMAREA_TEST_DEFAULT_SIZE >> 1, 0);
	RTE_TEST_ASSERT(ptr != NULL, "Expected Non-NULL");
	test_memarea_fill_region(ptr, MEMAREA_TEST_DEFAULT_SIZE >> 1);
	rte_memarea_update_refcnt(ma, ptr, -2);
	ptr = rte_memarea_alloc(ma, MEMAREA_TEST_DEFAULT_SIZE >> 1, 0);
	RTE_TEST_ASSERT(ptr == NULL, "Expected NULL");

	rte_memarea_destroy(ma);

	return 0;
}

static int
test_memarea_alloc_free(void)
{
#define ALLOC_MAX_NUM	8
	struct rte_memarea_param init;
	struct rte_memarea *ma;
	void *ptr[ALLOC_MAX_NUM];
	int i;

	/* prepare env */
	test_memarea_init_param(&init);
	init.source = RTE_MEMAREA_SOURCE_LIBC;
	init.total_sz = MEMAREA_TEST_DEFAULT_SIZE;
	ma = rte_memarea_create(&init);
	RTE_TEST_ASSERT(ma != NULL, "Expected Non-NULL");
	memset(ptr, 0, sizeof(ptr));

	/* test random alloc and free */
	for (i = 0; i < ALLOC_MAX_NUM; i++)
		ptr[i] = rte_memarea_alloc(ma, 1, 0);

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

	/* test free NULL */
	rte_memarea_free(ma, NULL);

	rte_memarea_destroy(ma);

	return 0;
}

static int
test_memarea_dump(void)
{
	struct rte_memarea_param init;
	struct rte_memarea *ma;
	int ret;

	/* prepare env */
	test_memarea_init_param(&init);
	init.source = RTE_MEMAREA_SOURCE_LIBC;
	init.total_sz = MEMAREA_TEST_DEFAULT_SIZE;
	ma = rte_memarea_create(&init);
	RTE_TEST_ASSERT(ma != NULL, "Expected Non-NULL");

	/* test for invalid parameters */
	ret = rte_memarea_dump(NULL, stderr, false);
	RTE_TEST_ASSERT(ret == -EINVAL, "Expected EINVAL");
	ret = rte_memarea_dump(ma, NULL, false);
	RTE_TEST_ASSERT(ret == -EINVAL, "Expected EINVAL");

	/* test for dump */
	(void)rte_memarea_alloc(ma, 1, 0);
	(void)rte_memarea_alloc(ma, 1, 0);
	(void)rte_memarea_alloc(ma, 1, 0);
	ret = rte_memarea_dump(ma, stderr, true);
	RTE_TEST_ASSERT(ret == 0, "Expected ZERO");

	rte_memarea_destroy(ma);

	return 0;
}

static int
test_memarea(void)
{
	test_memarea_prepare();

	MEMAREA_TEST_API_RUN(test_memarea_create_bad_param);
	MEMAREA_TEST_API_RUN(test_memarea_create_destroy);
	MEMAREA_TEST_API_RUN(test_memarea_alloc_fail);
	MEMAREA_TEST_API_RUN(test_memarea_free_fail);
	MEMAREA_TEST_API_RUN(test_memarea_alloc_free);
	MEMAREA_TEST_API_RUN(test_memarea_dump);

	return test_memarea_retcode();
}

#endif /* !RTE_EXEC_ENV_WINDOWS */

REGISTER_TEST_COMMAND(memarea_autotest, test_memarea);

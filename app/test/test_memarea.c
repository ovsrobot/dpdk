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
		if (ret < 0) \
			printf("%s Failed\n", #test_func); \
		else \
			printf("%s Passed\n", #test_func); \
	} while (0)

static void
test_memarea_init_def_param(struct rte_memarea_param *init)
{
	memset(init, 0, sizeof(struct rte_memarea_param));
	sprintf(init->name, "%s", "test-memarea");
	init->source = RTE_MEMAREA_SOURCE_SYSTEM_API;
	init->total_sz = MEMAREA_TEST_DEFAULT_SIZE;
	init->mt_safe = 1;
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
	test_memarea_init_def_param(&init);
	init.source = RTE_MEMAREA_SOURCE_USER_MEMAREA + 1;
	ma = rte_memarea_create(&init);
	RTE_TEST_ASSERT(ma == NULL, "Expected NULL");

	/* test for total_sz */
	test_memarea_init_def_param(&init);
	init.total_sz = 0;
	ma = rte_memarea_create(&init);
	RTE_TEST_ASSERT(ma == NULL, "Expected NULL");

	/* test for user address NULL */
	test_memarea_init_def_param(&init);
	init.source = RTE_MEMAREA_SOURCE_USER_ADDR;
	ma = rte_memarea_create(&init);
	RTE_TEST_ASSERT(ma == NULL, "Expected NULL");

	/* test for user address align invalid */
	test_memarea_init_def_param(&init);
	init.source = RTE_MEMAREA_SOURCE_USER_ADDR;
	for (i = 1; i < RTE_CACHE_LINE_SIZE; i++) {
		init.user_addr = (void *)((uintptr_t)i);
		ma = rte_memarea_create(&init);
		RTE_TEST_ASSERT(ma == NULL, "Expected NULL");
	}

	/* test for user memarea NULL */
	test_memarea_init_def_param(&init);
	init.source = RTE_MEMAREA_SOURCE_USER_MEMAREA;
	ma = rte_memarea_create(&init);
	RTE_TEST_ASSERT(ma == NULL, "Expected NULL");

	/* test for alg invalid */
	test_memarea_init_def_param(&init);
	init.alg = RTE_MEMAREA_ALG_DEFAULT + 1;
	ma = rte_memarea_create(&init);
	RTE_TEST_ASSERT(ma == NULL, "Expected NULL");

	return 0;
}

static int
test_memarea_create_destroy(void)
{
	uint8_t user_buffer[MEMAREA_TEST_DEFAULT_SIZE + RTE_CACHE_LINE_SIZE];
	struct rte_memarea_param init;
	struct rte_memarea *ma;

	/* test for create with RTE memory */
	test_memarea_init_def_param(&init);
	init.source = RTE_MEMAREA_SOURCE_RTE_MEMORY;
	init.numa_socket = SOCKET_ID_ANY;
	ma = rte_memarea_create(&init);
	RTE_TEST_ASSERT(ma != NULL, "Expected Non-NULL");
	rte_memarea_destroy(ma);

	/* test for create with system API */
	test_memarea_init_def_param(&init);
	init.source = RTE_MEMAREA_SOURCE_SYSTEM_API;
	ma = rte_memarea_create(&init);
	RTE_TEST_ASSERT(ma != NULL, "Expected Non-NULL");
	rte_memarea_destroy(ma);

	/* test for create with user-address */
	test_memarea_init_def_param(&init);
	init.source = RTE_MEMAREA_SOURCE_USER_ADDR;
	init.user_addr = (void *)(((uintptr_t)user_buffer + RTE_CACHE_LINE_SIZE) &
				  ~(RTE_CACHE_LINE_SIZE - 1));
	ma = rte_memarea_create(&init);
	RTE_TEST_ASSERT(ma != NULL, "Expected Non-NULL");
	rte_memarea_destroy(ma);

	return 0;
}

static int
test_memarea(void)
{
	MEMAREA_TEST_API_RUN(test_memarea_create_bad_param);
	MEMAREA_TEST_API_RUN(test_memarea_create_destroy);
	return 0;
}

#endif /* !RTE_EXEC_ENV_WINDOWS */

REGISTER_TEST_COMMAND(memarea_autotest, test_memarea);

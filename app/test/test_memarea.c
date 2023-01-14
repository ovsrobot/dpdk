/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 HiSilicon Limited
 */

#include <stdio.h>
#include <string.h>

#include "test.h"

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

static int
test_memarea_create_bad_param(void)
{
	struct rte_memarea_param init;
	struct rte_memarea *ma;

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

	/* test for memarea NULL */
	test_memarea_init_param(&init);
	init.source = RTE_MEMAREA_SOURCE_MEMAREA;
	ma = rte_memarea_create(&init);
	RTE_TEST_ASSERT(ma == NULL, "Expected NULL");

	/* test for algorithm invalid */
	test_memarea_init_param(&init);
	init.alg = RTE_MEMAREA_ALGORITHM_NEXTFIT + 1;
	ma = rte_memarea_create(&init);
	RTE_TEST_ASSERT(ma == NULL, "Expected NULL");

	return 0;
}

static int
test_memarea_create_destroy(void)
{
	struct rte_memarea_param init;
	struct rte_memarea *ma;

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

	return 0;
}

static int
test_memarea(void)
{
	test_memarea_prepare();

	MEMAREA_TEST_API_RUN(test_memarea_create_bad_param);
	MEMAREA_TEST_API_RUN(test_memarea_create_destroy);

	return test_memarea_retcode();
}

REGISTER_TEST_COMMAND(memarea_autotest, test_memarea);

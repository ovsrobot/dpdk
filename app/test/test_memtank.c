/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Intel Corporation
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include <rte_memory.h>
#include <rte_memtank.h>
#include <rte_errno.h>
#include "test.h"

/* TEST SUITE */

static int
memtank_test_setup(void)
{
	return 0;
}

static void
memtank_test_teardown(void)
{
}



static void *
test_alloc(size_t sz, void *p)
{
	RTE_SET_USED(p);
	return malloc(sz);
}

static void
test_free(void *buf, void *p)
{
	RTE_SET_USED(p);
	return free(buf);
}

static int
test_memtank_create_invalid(void)
{
	struct rte_memtank_prm prm;
	struct rte_memtank *mt;

	memset(&prm, 0, sizeof(prm));

	rte_errno = 0;
	mt = rte_memtank_create(&prm);
	RTE_TEST_ASSERT_EQUAL(mt, NULL, "memtank create");
	RTE_TEST_ASSERT_EQUAL(rte_errno, EINVAL, "errno EINVAL");

	prm.alloc = test_alloc;
	rte_errno = 0;
	mt = rte_memtank_create(&prm);
	RTE_TEST_ASSERT_EQUAL(mt, NULL, "memtank create");
	RTE_TEST_ASSERT_EQUAL(rte_errno, EINVAL, "errno EINVAL");

	prm.free = test_free;
	rte_errno = 0;
	mt = rte_memtank_create(&prm);
	RTE_TEST_ASSERT_EQUAL(mt, NULL, "memtank create");
	RTE_TEST_ASSERT_EQUAL(rte_errno, EINVAL, "errno EINVAL");

	prm.obj_align = 2;
	rte_errno = 0;
	mt = rte_memtank_create(&prm);
	RTE_TEST_ASSERT_EQUAL(mt, NULL, "memtank create");
	RTE_TEST_ASSERT_EQUAL(rte_errno, EINVAL, "errno EINVAL");

	prm.min_free = 2;
	rte_errno = 0;
	mt = rte_memtank_create(&prm);
	RTE_TEST_ASSERT_EQUAL(mt, NULL, "memtank create");
	RTE_TEST_ASSERT_EQUAL(rte_errno, EINVAL, "errno EINVAL");

	prm.max_free = 2;
	rte_errno = 0;
	mt = rte_memtank_create(&prm);
	RTE_TEST_ASSERT_EQUAL(mt, NULL, "memtank create");
	RTE_TEST_ASSERT_EQUAL(rte_errno, EINVAL, "errno EINVAL");

	prm.max_obj = 2;
	rte_errno = 0;
	mt = rte_memtank_create(&prm);
	RTE_TEST_ASSERT_EQUAL(mt, NULL, "memtank create");
	RTE_TEST_ASSERT_EQUAL(rte_errno, EINVAL, "errno EINVAL");

	prm.nb_obj_chunk = 2;
	rte_errno = 0;
	mt = rte_memtank_create(&prm);
	RTE_TEST_ASSERT_NOT_EQUAL(mt, NULL, "memtank create");

	rte_memtank_destroy(mt);
	return TEST_SUCCESS;
}


static int
test_memtank_alloc(void)
{
	struct rte_memtank_prm prm;
	struct rte_memtank *mt;

	memset(&prm, 0, sizeof(prm));
	prm.alloc = test_alloc;
	prm.free = test_free;
	prm.obj_align = 2;
	prm.nb_obj_chunk = 2;
	prm.min_free = 2;
	prm.max_free = 2;
	prm.max_obj = 10;

	mt = rte_memtank_create(&prm);
	RTE_TEST_ASSERT_NOT_EQUAL(mt, NULL, "memtank create");

	void *obj[3] = { NULL };
	uint32_t rc;

	/* min_obj is 0 so this is expected to fail */
	rc = rte_memtank_alloc(mt, obj, 1, RTE_MTANK_ALLOC_CHUNK);
	RTE_TEST_ASSERT_EQUAL(rc, 0, "memtank alloc chunk 0 (%u)", rc);

	rc = rte_memtank_alloc(mt, obj, 1, RTE_MTANK_ALLOC_GROW);
	RTE_TEST_ASSERT_EQUAL(rc, 1, "memtank alloc 1 (%u)", rc);
	RTE_TEST_ASSERT_NOT_EQUAL(obj[0], NULL, "alloc obj");

	rc = rte_memtank_alloc(mt, obj, 3, RTE_MTANK_ALLOC_CHUNK);
	RTE_TEST_ASSERT_EQUAL(rc, 3, "memtank alloc 3 (%u)", rc);

	/* will fail - out of free objs */
	rc = rte_memtank_alloc(mt, obj, 1, RTE_MTANK_ALLOC_CHUNK);
	RTE_TEST_ASSERT_EQUAL(rc, 0, "memtank alloc chunk 0 (%u)", rc);

	rte_memtank_destroy(mt);
	return TEST_SUCCESS;
}

static struct unit_test_suite memtank_testsuite = {
	.suite_name = "memtank library test suite",
	.setup = memtank_test_setup,
	.teardown = memtank_test_teardown,
	.unit_test_cases = {
		TEST_CASE(test_memtank_alloc),
		TEST_CASE(test_memtank_create_invalid),
		TEST_CASES_END(), /**< NULL terminate unit test array */
	},
};

static int
test_memtank(void)
{
	return unit_test_suite_runner(&memtank_testsuite);
}

REGISTER_FAST_TEST(memtank_autotest, NOHUGE_OK, ASAN_OK, test_memtank);

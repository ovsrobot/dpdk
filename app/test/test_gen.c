/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Intel Corporation
 */

#include <rte_common.h>
#include <rte_gen.h>
#include <rte_mbuf.h>

#include "test.h"

static struct rte_mempool *mp;

static int
testsuite_setup(void)
{
	if (!mp) {
		mp = rte_pktmbuf_pool_create("test_gen_mp", 8192, 256, 0, 2048,
						SOCKET_ID_ANY);
	}
	return mp ? TEST_SUCCESS : TEST_FAILED;
}

static void
testsuite_teardown(void)
{
	rte_mempool_free(mp);
}

static int
test_gen_create(void)
{
	struct rte_gen *gen = rte_gen_create(mp);
	TEST_ASSERT_FAIL(gen, "Expected valid pointer after create()");

	rte_gen_destroy(gen);
	return 0;
}

static struct unit_test_suite gen_suite  = {
	.suite_name = "gen: packet generator unit test suite",
	.setup = testsuite_setup,
	.teardown = testsuite_teardown,
	.unit_test_cases = {
		TEST_CASE_ST(NULL, NULL, test_gen_create),
		TEST_CASES_END() /**< NULL terminate unit test array */
	}
};

static int
test_gen_suite(void)
{
	return unit_test_suite_runner(&gen_suite);
}

REGISTER_TEST_COMMAND(gen_autotest, test_gen_suite);

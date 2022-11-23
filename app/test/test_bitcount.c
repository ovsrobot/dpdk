/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2022 Microsoft Corporation
 */

#include <string.h>

#include <rte_bitcount.h>
#include <rte_debug.h>

#include "test.h"

RTE_LOG_REGISTER(bitcount_logtype_test, test.bitcount, INFO);

static int
test_clz(void)
{
	unsigned int v = 1;
	RTE_TEST_ASSERT(rte_clz(v) == sizeof(v) * CHAR_BIT - 1,
	    "Unexpected count.");

	return 0;
}

static int
test_clzl(void)
{
	unsigned long v = 1;
	RTE_TEST_ASSERT(rte_clzl(v) == sizeof(v) * CHAR_BIT - 1,
	    "Unexpected count.");

	return 0;
}

static int
test_clzll(void)
{
	unsigned long long v = 1;
	RTE_TEST_ASSERT(rte_clzll(v) == sizeof(v) * CHAR_BIT - 1,
	    "Unexpected count.");

	return 0;
}

static int
test_ctz(void)
{
	unsigned int v = 2;
	RTE_TEST_ASSERT(rte_ctz(v) == 1, "Unexpected count.");

	return 0;
}

static int
test_ctzl(void)
{
	unsigned long v = 2;
	RTE_TEST_ASSERT(rte_ctzl(v) == 1, "Unexpected count.");

	return 0;
}

static int
test_ctzll(void)
{
	unsigned long long v = 2;
	RTE_TEST_ASSERT(rte_ctzll(v) == 1, "Unexpected count.");

	return 0;
}

static struct unit_test_suite bitcount_test_suite = {
	.suite_name = "bitcount autotest",
	.setup = NULL,
	.teardown = NULL,
	.unit_test_cases = {
		TEST_CASE(test_clz),
		TEST_CASE(test_clzl),
		TEST_CASE(test_clzll),
		TEST_CASE(test_ctz),
		TEST_CASE(test_ctzl),
		TEST_CASE(test_ctzll),
		TEST_CASES_END()
	}
};

static int
test_bitcount(void)
{
	return unit_test_suite_runner(&bitcount_test_suite);
}

REGISTER_TEST_COMMAND(bitcount_autotest, test_bitcount);

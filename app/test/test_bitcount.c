/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2022 Microsoft Corporation
 */

#include <string.h>

#include <rte_bitops.h>
#include <rte_debug.h>

#include "test.h"

RTE_LOG_REGISTER(bitcount_logtype_test, test.bitcount, INFO);

static int
test_clz32(void)
{
	uint32_t v = 1;
	RTE_TEST_ASSERT(rte_clz32(v) == sizeof(v) * CHAR_BIT - 1,
	    "Unexpected count.");

	return 0;
}

static int
test_clz64(void)
{
	uint64_t v = 1;
	RTE_TEST_ASSERT(rte_clz64(v) == sizeof(v) * CHAR_BIT - 1,
	    "Unexpected count.");

	return 0;
}

static int
test_ctz32(void)
{
	uint32_t v = 2;
	RTE_TEST_ASSERT(rte_ctz32(v) == 1, "Unexpected count.");

	return 0;
}

static int
test_ctz64(void)
{
	uint64_t v = 2;
	RTE_TEST_ASSERT(rte_ctz64(v) == 1, "Unexpected count.");

	return 0;
}

static struct unit_test_suite bitcount_test_suite = {
	.suite_name = "bitcount autotest",
	.setup = NULL,
	.teardown = NULL,
	.unit_test_cases = {
		TEST_CASE(test_clz32),
		TEST_CASE(test_clz64),
		TEST_CASE(test_ctz32),
		TEST_CASE(test_ctz64),
		TEST_CASES_END()
	}
};

static int
test_bitcount(void)
{
	return unit_test_suite_runner(&bitcount_test_suite);
}

REGISTER_TEST_COMMAND(bitcount_autotest, test_bitcount);

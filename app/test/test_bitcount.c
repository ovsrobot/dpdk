/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2022 Microsoft Corporation
 */

#include <string.h>
#include <stdio.h>

#include <rte_bitops.h>
#include <rte_debug.h>

#include "test.h"

RTE_LOG_REGISTER(bitcount_logtype_test, test.bitcount, INFO);

static int
test_clz32(void)
{
	size_t leading;
	uint32_t v = 0xffffffff;

	for (leading = 0; v; leading++) {
		RTE_TEST_ASSERT(rte_clz32(v) == leading,
		    "Unexpected count.");
		v >>= 1;
	}

	return 0;
}

static int
test_clz64(void)
{
	size_t leading;
	uint64_t v = 0xffffffffffffffff;

	for (leading = 0; v; leading++) {
		RTE_TEST_ASSERT(rte_clz64(v) == leading,
		    "Unexpected count.");
		v >>= 1;
	}

	return 0;
}

static int
test_ctz32(void)
{
	size_t trailing;
	uint32_t v = 1;

	for (trailing = 0; v; trailing++) {
		RTE_TEST_ASSERT(rte_ctz32(v) == trailing,
		    "Unexpected count.");
		v <<= 1;
	}

	return 0;
}

static int
test_ctz64(void)
{
	size_t trailing;
	uint64_t v = 1;

	for (trailing = 0; v; trailing++) {
		RTE_TEST_ASSERT(rte_ctz64(v) == trailing,
		    "Unexpected count.");
		v <<= 1;
	}

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

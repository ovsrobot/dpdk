/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Marvell International Ltd.
 */

#include <rte_pmu.h>

#include "test.h"

static int
test_pmu_read(void)
{
	int tries = 10, event = -1;
	uint64_t val = 0;

	if (rte_pmu_init() < 0)
		return TEST_FAILED;

	while (tries--)
		val += rte_pmu_read(event);

	rte_pmu_fini();

	return val ? TEST_SUCCESS : TEST_FAILED;
}

static struct unit_test_suite pmu_tests = {
	.suite_name = "pmu autotest",
	.setup = NULL,
	.teardown = NULL,
	.unit_test_cases = {
		TEST_CASE(test_pmu_read),
		TEST_CASES_END()
	}
};

static int
test_pmu(void)
{
	return unit_test_suite_runner(&pmu_tests);
}

REGISTER_TEST_COMMAND(pmu_autotest, test_pmu);

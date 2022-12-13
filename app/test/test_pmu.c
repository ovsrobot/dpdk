/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell International Ltd.
 */

#include <rte_pmu.h>

#include "test.h"

static int
test_pmu_read(void)
{
	uint64_t val = 0;
	int tries = 10;
	int event = -1;

#if defined(RTE_ARCH_ARM64)
	event = rte_pmu_add_event("cpu_cycles");
#elif defined(RTE_ARCH_X86_64)
	event = rte_pmu_add_event("cpu-cycles");
#endif

	while (tries--)
		val += rte_pmu_read(event);

	if (val == 0)
		return TEST_FAILED;

	return TEST_SUCCESS;
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

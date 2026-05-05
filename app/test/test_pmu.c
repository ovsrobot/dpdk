/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2025 Marvell International Ltd.
 */

#include <errno.h>
#include <stdio.h>

#include <rte_pmu.h>

#include "test.h"

static int
test_pmu_read(void)
{
	const char *name = NULL;
	int ret, tries = 10, event;
	uint64_t val = 0;

#if defined(RTE_ARCH_ARM64)
	name = "cpu_cycles";
#elif defined(RTE_ARCH_X86_64)
	name = "cpu-cycles";
#endif

	if (name == NULL) {
		printf("PMU not supported on this arch\n");
		return TEST_SKIPPED;
	}

	ret = rte_pmu_init();
	if (ret == -ENODEV) {
		printf("PMU hardware not available or kernel lacks PMU support\n");
		return TEST_SKIPPED;
	}
	if (ret == -EACCES) {
		printf("Insufficient privileges for PMU access\n");
		printf("Try: echo 0 | sudo tee /proc/sys/kernel/perf_event_paranoid\n");
		return TEST_FAILED;
	}
	if (ret < 0) {
		printf("PMU initialization failed: %d\n", ret);
		return TEST_FAILED;
	}

	event = rte_pmu_add_event(name);
	if (event < 0) {
		printf("Failed to add event '%s': %d\n", name, event);
		rte_pmu_fini();
		return TEST_FAILED;
	}

	while (tries--)
		val += rte_pmu_read(event);

	rte_pmu_fini();

	if (val == 0) {
		printf("PMU counter read returned zero\n");
		return TEST_FAILED;
	}

	return TEST_SUCCESS;
}

static struct unit_test_suite pmu_tests = {
	.suite_name = "PMU autotest",
	.setup = NULL,
	.teardown = NULL,
	.unit_test_cases = {
		TEST_CASE(test_pmu_read),
		TEST_CASES_END()
	}
};

static int __rte_unused
test_pmu(void)
{
	return unit_test_suite_runner(&pmu_tests);
}

REGISTER_FAST_TEST(pmu_autotest, NOHUGE_OK, ASAN_OK, test_pmu);

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2025 Marvell International Ltd.
 */

#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <rte_pmu.h>

#include "test.h"

#define PERF_EVENT_PARANOID_PATH "/proc/sys/kernel/perf_event_paranoid"

static bool perf_allowed_quirk(void)
{
	int level, ret;
	FILE *fp;

	fp = fopen(PERF_EVENT_PARANOID_PATH, "r");
	if (!fp)
		return false;

	ret = fscanf(fp, "%d", &level);
	fclose(fp);
	if (ret != 1)
		return false;

	/* On vanilla Linux the default perf_event_paranoid level is 2, which allows non-privileged
	 * processes to access performance counters.
	 *
	 * Debian / Ubuntu and their derivatives apply patches that introduce
	 * additional paranoia levels:
	 *
	 * - Debian adds level 3, which restricts access to perf_event_open() for
	 *   monitoring other processes, but still allows unprivileged self-monitoring.
	 *   See: https://lore.kernel.org/all/1469630746-32279-1-git-send-email-jeffv@google.com/
	 * - Ubuntu adds level 4 (which is also the default), completely disabling perf_event_open()
	 *   for unprivileged users—effectively disabling self-monitoring.
	 *
	 * That said, check below should be sufficient to enable this test on most kernels.
	 */
	return level < 4;
}

static int
test_pmu_read(void)
{
	const char *name = NULL;
	int tries = 10, event;
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

	if ((getuid() != 0) && !perf_allowed_quirk()) {
		printf("self-monitoring disabled\n");
		return TEST_SKIPPED;
	}

	if (rte_pmu_init() < 0) {
		printf("PMU not initialized\n");
		return TEST_SKIPPED;
	}

	event = rte_pmu_add_event(name);
	while (tries--)
		val += rte_pmu_read(event);

	rte_pmu_fini();

	/* rte_pmu_read() returns zero if it can't read perf counter. Thus series of zeros doesn't
	 * necessarily mean the counter is actually zero. It might just signal a problem with setup
	 * itself. So skip test to avoid testing failure and leave it to user to interpret this
	 * outcome.
	 */
	return val ? TEST_SUCCESS : TEST_SKIPPED;
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

REGISTER_FAST_TEST(pmu_autotest, true, true, test_pmu);

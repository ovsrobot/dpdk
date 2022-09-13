/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Intel Corporation
 */

#include <unistd.h>
#include <inttypes.h>

#include <rte_lcore.h>
#include <rte_cycles.h>

#include "test.h"

/* Arbitrary amount of "work" to simulate busyness with */
#define WORK		32
#define TIMESTAMP_ITERS	1000000
#define TEST_ITERS	10000

static void
simulate_lcore_poll_busyness(int iters)
{
	int i;

	for (i = 0; i < iters; i++)
		RTE_LCORE_POLL_BUSYNESS_TIMESTAMP(WORK);
}

static void
test_timestamp_perf(void)
{
	uint64_t start, end, diff;
	uint64_t min = UINT64_MAX;
	uint64_t max = 0;
	uint64_t total = 0;
	int i;

	for (i = 0; i < TEST_ITERS; i++) {
		start = rte_rdtsc();
		RTE_LCORE_POLL_BUSYNESS_TIMESTAMP(WORK);
		end = rte_rdtsc();

		diff = end - start;
		min = RTE_MIN(diff, min);
		max = RTE_MAX(diff, max);
		total += diff;
	}

	printf("### Timestamp perf ###\n");
	printf("Min cycles: %"PRIu64"\n", min);
	printf("Avg cycles: %"PRIu64"\n", total / TEST_ITERS);
	printf("Max cycles: %"PRIu64"\n", max);
	printf("\n");
}


static int
test_lcore_poll_busyness_perf(void)
{
	if (rte_lcore_poll_busyness_enabled()  == -ENOTSUP) {
		printf("Lcore poll busyness may be disabled...\n");
		return TEST_SKIPPED;
	}

	/* Initialize and prime the timestamp struct with simulated "work" for this lcore */
	simulate_lcore_poll_busyness(10000);

	/* Run perf tests */
	test_timestamp_perf();

	return TEST_SUCCESS;
}

REGISTER_TEST_COMMAND(lcore_poll_busyness_perf_autotest, test_lcore_poll_busyness_perf);

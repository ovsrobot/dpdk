/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Ericsson AB
 */

/*
 * A minimal fastmem workload intended for use with perf record /
 * perf report. Runs a tight alloc/free loop for a fixed duration
 * so that sampling profilers can attribute cycles to individual
 * functions and instructions within the fastmem hot path.
 *
 * Usage:
 *   perf record -g -- dpdk-test --no-huge --no-pci -m 8192 \
 *       -l 0 <<< fastmem_profile_autotest
 *   perf report
 */

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_memory.h>

#include <rte_fastmem.h>

#include "test.h"

/* Duration of each sub-test in TSC cycles (~3 seconds at 3 GHz). */
#define PROFILE_DURATION_CYCLES (3ULL * rte_get_tsc_hz())

/* Allocation size for the profiling workload. */
#define PROFILE_SIZE 256u

/*
 * Sub-test 1: tight alloc+free, exercises only the per-lcore
 * cache (no bin interaction after warmup).
 */
static int
profile_cache_hit(void)
{
	uint64_t deadline;
	uint64_t ops = 0;

	deadline = rte_rdtsc() + PROFILE_DURATION_CYCLES;

	while (rte_rdtsc() < deadline) {
		void *p = rte_fastmem_alloc(PROFILE_SIZE, 0, 0);

		if (p == NULL)
			return -1;
		rte_fastmem_free(p);
		ops++;
	}

	printf("  cache_hit: %" PRIu64 " ops\n", ops);
	return 0;
}

/*
 * Sub-test 2: alloc N then free N, where N exceeds the cache
 * capacity. This forces repeated cache refills and drains,
 * exercising the bin lock and slab free-list traversal.
 */
#define PROFILE_BATCH 256u

static int
profile_cache_miss(void)
{
	void *ptrs[PROFILE_BATCH];
	uint64_t deadline;
	uint64_t ops = 0;
	unsigned int i;

	deadline = rte_rdtsc() + PROFILE_DURATION_CYCLES;

	while (rte_rdtsc() < deadline) {
		for (i = 0; i < PROFILE_BATCH; i++) {
			ptrs[i] = rte_fastmem_alloc(PROFILE_SIZE, 0, 0);
			if (ptrs[i] == NULL)
				return -1;
		}
		for (i = 0; i < PROFILE_BATCH; i++)
			rte_fastmem_free(ptrs[i]);
		ops += PROFILE_BATCH;
	}

	printf("  cache_miss: %" PRIu64 " ops\n", ops);
	return 0;
}

static int
test_fastmem_profile_cache_hit(void)
{
	int rc;

	rc = rte_fastmem_init();
	if (rc < 0) {
		printf("rte_fastmem_init() failed: %d\n", rc);
		return -1;
	}

	rc = rte_fastmem_reserve(128 * 1024 * 1024, SOCKET_ID_ANY);
	if (rc < 0) {
		printf("rte_fastmem_reserve() failed: %d\n", rc);
		rte_fastmem_deinit();
		return -1;
	}

	printf("fastmem profile: cache-hit workload (size=%u, ~%u s)\n",
		PROFILE_SIZE, 3);

	if (profile_cache_hit() < 0) {
		rte_fastmem_deinit();
		return -1;
	}

	rte_fastmem_deinit();
	return 0;
}

static int
test_fastmem_profile_cache_miss(void)
{
	int rc;

	rc = rte_fastmem_init();
	if (rc < 0) {
		printf("rte_fastmem_init() failed: %d\n", rc);
		return -1;
	}

	rc = rte_fastmem_reserve(128 * 1024 * 1024, SOCKET_ID_ANY);
	if (rc < 0) {
		printf("rte_fastmem_reserve() failed: %d\n", rc);
		rte_fastmem_deinit();
		return -1;
	}

	printf("fastmem profile: cache-miss workload (size=%u, ~%u s)\n",
		PROFILE_SIZE, 3);

	if (profile_cache_miss() < 0) {
		rte_fastmem_deinit();
		return -1;
	}

	rte_fastmem_deinit();
	return 0;
}

REGISTER_PERF_TEST(fastmem_profile_cache_hit_autotest,
		test_fastmem_profile_cache_hit);
REGISTER_PERF_TEST(fastmem_profile_cache_miss_autotest,
		test_fastmem_profile_cache_miss);

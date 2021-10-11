/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA Corporation & Affiliates
 */

#include <inttypes.h>
#include <string.h>
#include <rte_cycles.h>
#include <rte_errno.h>
#include <rte_malloc.h>
#include <rte_memzone.h>

#include "test.h"

typedef void * (alloc_t)(const char *name, size_t size, unsigned int align);
typedef void (free_t)(void *addr);

static const uint64_t KB = 1 << 10;
static const uint64_t GB = 1 << 30;

static double
tsc_to_us(uint64_t tsc, size_t runs)
{
	return (double)tsc / rte_get_tsc_hz() * US_PER_S / runs;
}

static int
test_memset_perf(double *us_per_gb)
{
	static const size_t RUNS = 20;

	void *ptr;
	size_t i;
	uint64_t tsc;

	puts("Performance: memset");

	ptr = rte_malloc(NULL, GB, 0);
	if (ptr == NULL) {
		printf("rte_malloc(size=%"PRIx64") failed\n", GB);
		return -1;
	}

	tsc = rte_rdtsc_precise();
	for (i = 0; i < RUNS; i++)
		memset(ptr, 0, GB);
	tsc = rte_rdtsc_precise() - tsc;

	*us_per_gb = tsc_to_us(tsc, RUNS);
	printf("Result: %f.3 GiB/s <=> %.2f us/MiB\n",
			US_PER_S / *us_per_gb, *us_per_gb / KB);

	rte_free(ptr);
	putchar('\n');
	return 0;
}

static int
test_alloc_perf(const char *name, alloc_t *alloc_fn, free_t free_fn,
		size_t max_runs, double memset_gb_us)
{
	static const size_t SIZES[] = {
			1 << 6, 1 << 7, 1 << 10, 1 << 12, 1 << 16, 1 << 20,
			1 << 21, 1 << 22, 1 << 24, 1 << 30 };

	size_t i, j;
	void **ptrs;

	printf("Performance: %s\n", name);

	ptrs = calloc(max_runs, sizeof(ptrs[0]));
	if (ptrs == NULL) {
		puts("Cannot allocate memory for pointers");
		return -1;
	}

	printf("%12s%8s%12s%12s%12s%12s\n",
			"Size (B)", "Runs", "Alloc (us)", "Free (us)",
			"Total (us)", "memset (us)");
	for (i = 0; i < RTE_DIM(SIZES); i++) {
		size_t size = SIZES[i];
		size_t runs_done;
		uint64_t tsc_start, tsc_alloc, tsc_free;
		double alloc_time, free_time, memset_time;

		tsc_start = rte_rdtsc_precise();
		for (j = 0; j < max_runs; j++) {
			ptrs[j] = alloc_fn(NULL, size, 0);
			if (ptrs[j] == NULL)
				break;
		}
		tsc_alloc = rte_rdtsc_precise() - tsc_start;

		if (j == 0) {
			printf("%12zu Interrupted: out of memory.\n", size);
			break;
		}
		runs_done = j;

		tsc_start = rte_rdtsc_precise();
		for (j = 0; j < runs_done && ptrs[j] != NULL; j++)
			free_fn(ptrs[j]);
		tsc_free = rte_rdtsc_precise() - tsc_start;

		alloc_time = tsc_to_us(tsc_alloc, runs_done);
		free_time = tsc_to_us(tsc_free, runs_done);
		memset_time = memset_gb_us * size / GB;
		printf("%12zu%8zu%12.2f%12.2f%12.2f%12.2f\n",
				size, runs_done, alloc_time, free_time,
				alloc_time + free_time, memset_time);

		memset(ptrs, 0, max_runs * sizeof(ptrs[0]));
	}

	free(ptrs);
	putchar('\n');
	return 0;
}

static void *
memzone_alloc(const char *name __rte_unused, size_t size, unsigned int align)
{
	const struct rte_memzone *mz;
	char gen_name[RTE_MEMZONE_NAMESIZE];

	snprintf(gen_name, sizeof(gen_name), "test-mz-%"PRIx64, rte_rdtsc());
	mz = rte_memzone_reserve_aligned(gen_name, size, SOCKET_ID_ANY,
			RTE_MEMZONE_1GB | RTE_MEMZONE_SIZE_HINT_ONLY, align);
	return (void *)(uintptr_t)mz;
}

static void
memzone_free(void *addr)
{
	rte_memzone_free((struct rte_memzone *)addr);
}

static int
test_malloc_perf(void)
{
	static const size_t MAX_RUNS = 10000;

	double memset_gb_us;

	if (test_memset_perf(&memset_gb_us) < 0)
		return -1;

	if (test_alloc_perf("rte_malloc", rte_malloc, rte_free,
			MAX_RUNS, memset_gb_us) < 0)
		return -1;
	if (test_alloc_perf("rte_zmalloc", rte_zmalloc, rte_free,
			MAX_RUNS, memset_gb_us) < 0)
		return -1;

	if (test_alloc_perf("rte_memzone_reserve", memzone_alloc, memzone_free,
			RTE_MAX_MEMZONE - 1, memset_gb_us) < 0)
		return -1;

	return 0;
}

REGISTER_TEST_COMMAND(malloc_perf_autotest, test_malloc_perf);

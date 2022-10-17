/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA Corporation & Affiliates
 */

#include <inttypes.h>
#include <string.h>
#include <rte_cycles.h>
#include <rte_errno.h>
#include <rte_malloc.h>
#include <rte_memarea.h>
#include <rte_memzone.h>

#include "test.h"

#define TEST_LOG(level, ...) RTE_LOG(level, USER1, __VA_ARGS__)

typedef void * (alloc_t)(const char *name, size_t size, unsigned int align);
typedef void (free_t)(void *addr);
typedef void * (memset_t)(void *addr, int value, size_t size);

static const uint64_t KB = 1 << 10;
static const uint64_t GB = 1 << 30;

static struct rte_memarea *ma_perftest_handle;

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

	TEST_LOG(INFO, "Reference: memset\n");

	ptr = rte_malloc(NULL, GB, 0);
	if (ptr == NULL) {
		TEST_LOG(ERR, "rte_malloc(size=%"PRIx64") failed\n", GB);
		return -1;
	}

	tsc = rte_rdtsc_precise();
	for (i = 0; i < RUNS; i++)
		memset(ptr, 0, GB);
	tsc = rte_rdtsc_precise() - tsc;

	*us_per_gb = tsc_to_us(tsc, RUNS);
	TEST_LOG(INFO, "Result: %f.3 GiB/s <=> %.2f us/MiB\n",
			US_PER_S / *us_per_gb, *us_per_gb / KB);

	rte_free(ptr);
	TEST_LOG(INFO, "\n");
	return 0;
}

static int
test_alloc_perf(const char *name, alloc_t *alloc_fn, free_t *free_fn,
		memset_t *memset_fn, double memset_gb_us, size_t max_runs)
{
	static const size_t SIZES[] = {
			1 << 6, 1 << 7, 1 << 10, 1 << 12, 1 << 16, 1 << 20,
			1 << 21, 1 << 22, 1 << 24, 1 << 30 };

	size_t i, j;
	void **ptrs;

	TEST_LOG(INFO, "Performance: %s\n", name);

	ptrs = calloc(max_runs, sizeof(ptrs[0]));
	if (ptrs == NULL) {
		TEST_LOG(ERR, "Cannot allocate memory for pointers");
		return -1;
	}

	TEST_LOG(INFO, "%12s%8s%12s%12s%12s%17s\n", "Size (B)", "Runs",
			"Alloc (us)", "Free (us)", "Total (us)",
			memset_fn != NULL ? "memset (us)" : "est.memset (us)");
	for (i = 0; i < RTE_DIM(SIZES); i++) {
		size_t size = SIZES[i];
		size_t runs_done;
		uint64_t tsc_start, tsc_alloc, tsc_memset = 0, tsc_free;
		double alloc_time, free_time, memset_time;

		tsc_start = rte_rdtsc_precise();
		for (j = 0; j < max_runs; j++) {
			ptrs[j] = alloc_fn(NULL, size, 0);
			if (ptrs[j] == NULL)
				break;
		}
		tsc_alloc = rte_rdtsc_precise() - tsc_start;

		if (j == 0) {
			TEST_LOG(INFO, "%12zu Interrupted: out of memory.\n",
					size);
			break;
		}
		runs_done = j;

		if (memset_fn != NULL) {
			tsc_start = rte_rdtsc_precise();
			for (j = 0; j < runs_done && ptrs[j] != NULL; j++)
				memset_fn(ptrs[j], 0, size);
			tsc_memset = rte_rdtsc_precise() - tsc_start;
		}

		tsc_start = rte_rdtsc_precise();
		for (j = 0; j < runs_done && ptrs[j] != NULL; j++)
			free_fn(ptrs[j]);
		tsc_free = rte_rdtsc_precise() - tsc_start;

		alloc_time = tsc_to_us(tsc_alloc, runs_done);
		free_time = tsc_to_us(tsc_free, runs_done);
		memset_time = memset_fn != NULL ?
				tsc_to_us(tsc_memset, runs_done) :
				memset_gb_us * size / GB;
		TEST_LOG(INFO, "%12zu%8zu%12.2f%12.2f%12.2f%17.2f\n",
				size, runs_done, alloc_time, free_time,
				alloc_time + free_time, memset_time);

		memset(ptrs, 0, max_runs * sizeof(ptrs[0]));
	}

	free(ptrs);
	TEST_LOG(INFO, "\n");
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

static const char *
memarea_perftest_source_name(enum rte_memarea_source source)
{
	if (source == RTE_MEMAREA_SOURCE_HEAP)
		return "heap";
	else if (source == RTE_MEMAREA_SOURCE_LIBC)
		return "libc";
	else
		return "unknown";
}

static int
memarea_perftest_pre_env(enum rte_memarea_source source)
{
	struct rte_memarea_param init;

	memset(&init, 0, sizeof(init));
	snprintf(init.name, sizeof(init.name), "perftest");
	init.source = source;
	init.alg = RTE_MEMAREA_ALG_NEXTFIT;
	init.total_sz = GB;
	init.mt_safe = 1;
	init.numa_socket = SOCKET_ID_ANY;

	ma_perftest_handle = rte_memarea_create(&init);
	if (ma_perftest_handle == NULL) {
		fprintf(stderr, "memarea create failed, skip memarea source: %s perftest!\n",
			memarea_perftest_source_name(source));
		return -1;
	}
	return 0;
}

static void
memarea_perftest_clear_env(void)
{
	rte_memarea_destroy(ma_perftest_handle);
	ma_perftest_handle = NULL;
}

static void *
memarea_perftest_alloc(const char *name, size_t size, unsigned int align)
{
	RTE_SET_USED(name);
	RTE_SET_USED(align);
	return rte_memarea_alloc(ma_perftest_handle, size, 0);
}

static void
memarea_perftest_free(void *addr)
{
	rte_memarea_free(ma_perftest_handle, addr);
}

static int
memarea_perftest(enum rte_memarea_source source, double memset_gb_us, size_t max_runs)
{
	char test_name[64] = { 0 };

	if (memarea_perftest_pre_env(source) < 0)
		return 0;

	snprintf(test_name, sizeof(test_name), "rte_memarea.%s",
		 memarea_perftest_source_name(source));
	if (test_alloc_perf(test_name, memarea_perftest_alloc, memarea_perftest_free,
			memset, memset_gb_us, max_runs) < 0) {
		memarea_perftest_clear_env();
		return -1;
	}

	memarea_perftest_clear_env();
	return 0;
}

static int
test_malloc_perf(void)
{
	static const size_t MAX_RUNS = 10000;

	double memset_us_gb = 0;

	if (test_memset_perf(&memset_us_gb) < 0)
		return -1;

	if (test_alloc_perf("rte_malloc", rte_malloc, rte_free, memset,
			memset_us_gb, MAX_RUNS) < 0)
		return -1;
	if (test_alloc_perf("rte_zmalloc", rte_zmalloc, rte_free, memset,
			memset_us_gb, MAX_RUNS) < 0)
		return -1;

	if (test_alloc_perf("rte_memzone_reserve", memzone_alloc, memzone_free,
			NULL, memset_us_gb, RTE_MAX_MEMZONE - 1) < 0)
		return -1;

	if (memarea_perftest(RTE_MEMAREA_SOURCE_HEAP, memset_us_gb, MAX_RUNS) < 0)
		return -1;
	if (memarea_perftest(RTE_MEMAREA_SOURCE_LIBC, memset_us_gb, MAX_RUNS) < 0)
		return -1;

	return 0;
}

REGISTER_TEST_COMMAND(malloc_perf_autotest, test_malloc_perf);

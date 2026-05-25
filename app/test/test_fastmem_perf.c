/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Ericsson AB
 */

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_stdatomic.h>

#include <rte_fastmem.h>

#include "test.h"

#define TEST_LOG(...) printf(__VA_ARGS__)

static const size_t SIZES[] = { 8, 64, 256, 1024, 4096 };
#define N_SIZES RTE_DIM(SIZES)

/* Number of ops for warmup and measurement. */
#define WARMUP_OPS 20000u
#define MEASURE_OPS 2000000u

/* Buffer for scenarios that allocate N then free N. */
#define BATCH_N 256

/*
 * Allocator vtable: a thin adapter exposing alloc / free /
 * per-allocator setup/teardown. Each scenario calls these
 * indirectly so the same timing loop serves all allocators.
 */
struct allocator {
	const char *name;
	int (*setup)(size_t size, unsigned int n_max);
	void (*teardown)(void);
	void *(*alloc)(void);
	void (*free_obj)(void *ptr);
	int (*alloc_bulk)(void **ptrs, unsigned int n);
	void (*free_bulk)(void **ptrs, unsigned int n);
};

/* Fastmem adapter -------------------------------------------------- */

static size_t fastmem_size;

static int
fastmem_setup(size_t size, unsigned int n_max __rte_unused)
{
	fastmem_size = size;
	return 0;
}

static void
fastmem_teardown(void)
{
	rte_fastmem_cache_flush();
}

static void * __rte_noinline
fastmem_alloc(void)
{
	return rte_fastmem_alloc(fastmem_size, 0, 0);
}

static void __rte_noinline
fastmem_free(void *ptr)
{
	rte_fastmem_free(ptr);
}

/* Mempool adapter -------------------------------------------------- */

static struct rte_mempool *mempool_pool;

static int
mempool_setup(size_t size, unsigned int n_max)
{
	char name[RTE_MEMPOOL_NAMESIZE];
	unsigned int cache_size;

	/*
	 * Pool size must accommodate the full batch burst plus
	 * per-lcore cache capacity. Use mempool's default cache
	 * size so we're measuring its standard hot path.
	 */
	cache_size = RTE_MEMPOOL_CACHE_MAX_SIZE;

	snprintf(name, sizeof(name), "fmperf_mp_%zu", size);
	mempool_pool = rte_mempool_create(name, n_max + cache_size * 2,
			size, cache_size, 0, NULL, NULL, NULL, NULL,
			SOCKET_ID_ANY, 0);
	if (mempool_pool == NULL) {
		TEST_LOG("mempool_create(%zu) failed\n", size);
		return -1;
	}

	return 0;
}

static void
mempool_teardown(void)
{
	rte_mempool_free(mempool_pool);
	mempool_pool = NULL;
}

static void * __rte_noinline
mempool_alloc_one(void)
{
	void *obj = NULL;

	if (rte_mempool_get(mempool_pool, &obj) < 0)
		return NULL;
	return obj;
}

static void __rte_noinline
mempool_free_one(void *ptr)
{
	rte_mempool_put(mempool_pool, ptr);
}

/* rte_malloc adapter ----------------------------------------------- */

static size_t malloc_size;

static int
malloc_setup(size_t size, unsigned int n_max __rte_unused)
{
	malloc_size = size;
	return 0;
}

static void
malloc_teardown(void)
{
}

static void * __rte_noinline
malloc_alloc(void)
{
	return rte_malloc(NULL, malloc_size, 0);
}

static void __rte_noinline
malloc_free(void *ptr)
{
	rte_free(ptr);
}

/* libc (glibc) malloc adapter -------------------------------------- */

static size_t libc_size;

static int
libc_setup(size_t size, unsigned int n_max __rte_unused)
{
	/*
	 * Round up to cache-line alignment to match the other
	 * allocators' default alignment guarantees and keep the
	 * comparison honest. aligned_alloc() requires size to be
	 * a multiple of the alignment.
	 */
	libc_size = RTE_ALIGN_CEIL(size, RTE_CACHE_LINE_SIZE);
	return 0;
}

static void
libc_teardown(void)
{
}

static void * __rte_noinline
libc_alloc(void)
{
	return aligned_alloc(RTE_CACHE_LINE_SIZE, libc_size);
}

static void __rte_noinline
libc_free(void *ptr)
{
	free(ptr);
}

/* Bulk adapters ---------------------------------------------------- */

static int __rte_noinline
fastmem_alloc_bulk(void **ptrs, unsigned int n)
{
	return rte_fastmem_alloc_bulk(ptrs, n, fastmem_size, 0, 0);
}

static void __rte_noinline
fastmem_free_bulk(void **ptrs, unsigned int n)
{
	rte_fastmem_free_bulk(ptrs, n);
}

static int __rte_noinline
mempool_alloc_bulk(void **ptrs, unsigned int n)
{
	return rte_mempool_get_bulk(mempool_pool, ptrs, n);
}

static void __rte_noinline
mempool_free_bulk(void **ptrs, unsigned int n)
{
	rte_mempool_put_bulk(mempool_pool, ptrs, n);
}

static int __rte_noinline
generic_alloc_bulk(void **ptrs, unsigned int n, void *(*alloc_fn)(void))
{
	unsigned int i;

	for (i = 0; i < n; i++) {
		ptrs[i] = alloc_fn();
		if (ptrs[i] == NULL)
			return -1;
	}
	return 0;
}

static int __rte_noinline
malloc_alloc_bulk(void **ptrs, unsigned int n)
{
	return generic_alloc_bulk(ptrs, n, malloc_alloc);
}

static void __rte_noinline
malloc_free_bulk(void **ptrs, unsigned int n)
{
	unsigned int i;

	for (i = 0; i < n; i++)
		malloc_free(ptrs[i]);
}

static int __rte_noinline
libc_alloc_bulk(void **ptrs, unsigned int n)
{
	return generic_alloc_bulk(ptrs, n, libc_alloc);
}

static void __rte_noinline
libc_free_bulk(void **ptrs, unsigned int n)
{
	unsigned int i;

	for (i = 0; i < n; i++)
		libc_free(ptrs[i]);
}

/* Adapter table ---------------------------------------------------- */

static const struct allocator allocators[] = {
	{ "fastmem",    fastmem_setup, fastmem_teardown, fastmem_alloc,     fastmem_free,     fastmem_alloc_bulk, fastmem_free_bulk },
	{ "mempool",    mempool_setup, mempool_teardown, mempool_alloc_one, mempool_free_one, mempool_alloc_bulk, mempool_free_bulk },
	{ "rte_malloc", malloc_setup,  malloc_teardown,  malloc_alloc,      malloc_free,      malloc_alloc_bulk,  malloc_free_bulk },
	{ "libc",       libc_setup,    libc_teardown,    libc_alloc,        libc_free,        libc_alloc_bulk,    libc_free_bulk },
};
#define N_ALLOCATORS RTE_DIM(allocators)

/*
 * Scenario 1: tight alloc+free loop. A single object is cycled
 * repeatedly. The LIFO path keeps the same pointer hot, giving
 * a best-case measurement.
 */
static double
run_tight(const struct allocator *alloc, size_t size)
{
	void *p;
	uint64_t tsc;
	unsigned int i;

	if (alloc->setup(size, 1) < 0)
		return -1.0;

	/* Warmup. */
	for (i = 0; i < WARMUP_OPS; i++) {
		p = alloc->alloc();
		if (p == NULL)
			goto err;
		alloc->free_obj(p);
	}

	tsc = rte_rdtsc_precise();
	for (i = 0; i < MEASURE_OPS; i++) {
		p = alloc->alloc();
		if (p == NULL)
			goto err;
		alloc->free_obj(p);
	}
	tsc = rte_rdtsc_precise() - tsc;

	alloc->teardown();

	return (double)tsc / MEASURE_OPS;
err:
	alloc->teardown();
	return -1.0;
}

/*
 * Scenario 2: allocate N, free N (FIFO free order). Exercises
 * cache refill and drain paths when N exceeds cache capacity.
 */
static void
run_batch(const struct allocator *alloc, size_t size,
		double *cycles_alloc, double *cycles_free)
{
	void *ptrs[BATCH_N];
	uint64_t tsc_alloc = 0, tsc_free = 0;
	unsigned int iter, i;
	unsigned int iters;

	*cycles_alloc = -1.0;
	*cycles_free = -1.0;

	if (alloc->setup(size, BATCH_N) < 0)
		return;

	/* Pick iteration count so total ops ~= MEASURE_OPS. */
	iters = MEASURE_OPS / BATCH_N;

	/* Warmup. */
	for (iter = 0; iter < WARMUP_OPS / BATCH_N; iter++) {
		for (i = 0; i < BATCH_N; i++) {
			ptrs[i] = alloc->alloc();
			if (ptrs[i] == NULL)
				goto err;
		}
		for (i = 0; i < BATCH_N; i++)
			alloc->free_obj(ptrs[i]);
	}

	for (iter = 0; iter < iters; iter++) {
		uint64_t t0;

		t0 = rte_rdtsc_precise();
		for (i = 0; i < BATCH_N; i++) {
			ptrs[i] = alloc->alloc();
			if (ptrs[i] == NULL)
				goto err;
		}
		tsc_alloc += rte_rdtsc_precise() - t0;

		t0 = rte_rdtsc_precise();
		for (i = 0; i < BATCH_N; i++)
			alloc->free_obj(ptrs[i]);
		tsc_free += rte_rdtsc_precise() - t0;
	}

	alloc->teardown();

	*cycles_alloc = (double)tsc_alloc / (iters * BATCH_N);
	*cycles_free = (double)tsc_free / (iters * BATCH_N);
	return;
err:
	alloc->teardown();
}

/*
 * Scenario 3: allocate N, free N in reverse order.
 */
static void
run_batch_reverse(const struct allocator *alloc, size_t size,
		double *cycles_alloc, double *cycles_free)
{
	void *ptrs[BATCH_N];
	uint64_t tsc_alloc = 0, tsc_free = 0;
	unsigned int iter, i;
	unsigned int iters;

	*cycles_alloc = -1.0;
	*cycles_free = -1.0;

	if (alloc->setup(size, BATCH_N) < 0)
		return;

	iters = MEASURE_OPS / BATCH_N;

	for (iter = 0; iter < WARMUP_OPS / BATCH_N; iter++) {
		for (i = 0; i < BATCH_N; i++) {
			ptrs[i] = alloc->alloc();
			if (ptrs[i] == NULL)
				goto err;
		}
		for (i = BATCH_N; i > 0; i--)
			alloc->free_obj(ptrs[i - 1]);
	}

	for (iter = 0; iter < iters; iter++) {
		uint64_t t0;

		t0 = rte_rdtsc_precise();
		for (i = 0; i < BATCH_N; i++) {
			ptrs[i] = alloc->alloc();
			if (ptrs[i] == NULL)
				goto err;
		}
		tsc_alloc += rte_rdtsc_precise() - t0;

		t0 = rte_rdtsc_precise();
		for (i = BATCH_N; i > 0; i--)
			alloc->free_obj(ptrs[i - 1]);
		tsc_free += rte_rdtsc_precise() - t0;
	}

	alloc->teardown();

	*cycles_alloc = (double)tsc_alloc / (iters * BATCH_N);
	*cycles_free = (double)tsc_free / (iters * BATCH_N);
	return;
err:
	alloc->teardown();
}

/*
 * Scenario 4: multi-lcore alloc/work/free with a dummy-work
 * baseline. Each worker runs a tight alloc → touch → free loop
 * on its own lcore. A second run with the same dummy work but
 * no allocator traffic establishes a baseline; the per-op
 * allocator cost is reported as (alloc_run - baseline_run).
 *
 * Fixed size class and a fixed amount of dummy work per op —
 * this scenario sweeps lcore count rather than size.
 */
#define MULTI_SIZE 256u
#define MULTI_WORK_BYTES 64u
#define MULTI_WORK_PASSES 8u   /* RMW passes over the work region. */
#define MULTI_OPS 200000u
#define MULTI_WARMUP 2000u
#define MAX_MULTI_LCORES 32u

/*
 * Per-worker volatile sink. Each worker writes to its own
 * slot, preventing dead-code elimination of touch_buffer() and
 * avoiding cross-lcore cache-line sharing on the hot path.
 * Padded to cache-line stride to prevent false sharing between
 * neighboring workers' slots.
 */
struct worker_sink {
	volatile uint64_t value;
} __rte_cache_aligned;

static struct worker_sink worker_sinks[RTE_MAX_LCORE];

/*
 * Out-of-line dummy workload: run MULTI_WORK_PASSES
 * read-modify-write passes over the first 'bytes' of the
 * buffer. Each pass reads what the previous pass wrote, so the
 * compiler cannot unroll or parallelize across passes — the
 * work scales linearly with MULTI_WORK_PASSES. Returns an
 * accumulator so the caller can feed it into a volatile sink;
 * without that, the compiler could elide the whole function.
 *
 * __rte_noinline so it looks identical to the compiler in both
 * the baseline (pre-allocated scratch buffer) and alloc-path
 * runs, making the cycle-delta subtraction valid.
 *
 * The purpose of this being tunably expensive is to keep
 * worker-per-iteration cost high relative to the allocator's
 * critical section, so that even serialized allocators like
 * rte_malloc spend most of their time outside the lock and the
 * measured per-op allocator cost reflects its own work rather
 * than its contention queue.
 */
static uint64_t __rte_noinline
touch_buffer(void *buf, size_t bytes)
{
	uint64_t *p = buf;
	size_t n = bytes / sizeof(uint64_t);
	uint64_t acc = 0;
	unsigned int pass;
	size_t i;

	/* Prime the buffer with a known pattern. */
	for (i = 0; i < n; i++)
		p[i] = i * 0x9E3779B97F4A7C15ULL;

	/*
	 * Dependent RMW passes: each pass reads p[i] written by
	 * the previous pass, mixes the pass index in, and writes
	 * back. The XOR into acc keeps the chain live.
	 */
	for (pass = 0; pass < MULTI_WORK_PASSES; pass++) {
		for (i = 0; i < n; i++) {
			uint64_t v = p[i];

			v = v * 0xC2B2AE3D27D4EB4FULL + pass;
			v ^= v >> 33;
			p[i] = v;
			acc ^= v;
		}
	}

	return acc;
}

struct worker_args {
	const struct allocator *alloc;
	void *scratch;            /* baseline only; NULL => alloc path */
	unsigned int iters;
	unsigned int warmup;
	unsigned int bulk_n;      /* 0 = single-object, >0 = bulk */
	RTE_ATOMIC(bool) start_flag; /* barrier at worker entry */
	uint64_t cycles;          /* out */
	unsigned int ops;         /* out */
	int err;                  /* out */
};

static int
worker_run(void *arg)
{
	struct worker_args *wa = arg;
	unsigned int lcore = rte_lcore_id();
	uint64_t acc = 0;
	uint64_t t0;
	unsigned int i;

	wa->err = 0;
	wa->ops = 0;
	wa->cycles = 0;

	/* Wait for start flag (spin-barrier set by main). */
	while (!rte_atomic_load_explicit(&wa->start_flag,
			rte_memory_order_acquire))
		rte_pause();

	/* Warmup. */
	for (i = 0; i < wa->warmup; i++) {
		void *p;

		if (wa->scratch != NULL)
			p = wa->scratch;
		else {
			p = wa->alloc->alloc();
			if (p == NULL) {
				wa->err = -1;
				return -1;
			}
		}
		acc ^= touch_buffer(p, MULTI_WORK_BYTES);
		if (wa->scratch == NULL)
			wa->alloc->free_obj(p);
	}

	/* Measured loop. */
	t0 = rte_rdtsc_precise();
	for (i = 0; i < wa->iters; i++) {
		void *p;

		if (wa->scratch != NULL)
			p = wa->scratch;
		else {
			p = wa->alloc->alloc();
			if (p == NULL) {
				wa->err = -1;
				break;
			}
		}
		acc ^= touch_buffer(p, MULTI_WORK_BYTES);
		if (wa->scratch == NULL)
			wa->alloc->free_obj(p);
	}
	wa->cycles = rte_rdtsc_precise() - t0;
	wa->ops = i;

	/* Publish accumulator to defeat dead-code elimination. */
	worker_sinks[lcore].value ^= acc;

	return 0;
}

static int
worker_run_bulk(void *arg)
{
	struct worker_args *wa = arg;
	unsigned int lcore = rte_lcore_id();
	void *ptrs[BATCH_N];
	uint64_t acc = 0;
	uint64_t t0;
	unsigned int i, j;
	unsigned int bulk_n = wa->bulk_n;

	wa->err = 0;
	wa->ops = 0;
	wa->cycles = 0;

	while (!rte_atomic_load_explicit(&wa->start_flag,
			rte_memory_order_acquire))
		rte_pause();

	/* Warmup. */
	for (i = 0; i < wa->warmup; i++) {
		if (wa->alloc->alloc_bulk(ptrs, bulk_n) < 0) {
			wa->err = -1;
			return -1;
		}
		for (j = 0; j < bulk_n; j++)
			acc ^= touch_buffer(ptrs[j], MULTI_WORK_BYTES);
		wa->alloc->free_bulk(ptrs, bulk_n);
	}

	t0 = rte_rdtsc_precise();
	for (i = 0; i < wa->iters; i++) {
		if (wa->alloc->alloc_bulk(ptrs, bulk_n) < 0) {
			wa->err = -1;
			break;
		}
		for (j = 0; j < bulk_n; j++)
			acc ^= touch_buffer(ptrs[j], MULTI_WORK_BYTES);
		wa->alloc->free_bulk(ptrs, bulk_n);
	}
	wa->cycles = rte_rdtsc_precise() - t0;
	wa->ops = i * bulk_n;

	worker_sinks[lcore].value ^= acc;

	return 0;
}

/*
 * Launch workers on the first 'n_workers' worker lcores, run
 * either the baseline (scratch != NULL) or the alloc path
 * (scratch == NULL), and return the mean per-op cycle cost
 * averaged across participating workers.
 *
 * On any worker error, returns -1.0.
 */
static double
run_multi_workers(const struct allocator *alloc, unsigned int n_workers,
		void *const *scratches, unsigned int bulk_n)
{
	struct worker_args wargs[RTE_MAX_LCORE];
	unsigned int worker_lcores[MAX_MULTI_LCORES];
	unsigned int n = 0;
	unsigned int lcore_id;
	unsigned int i;
	lcore_function_t *fn = bulk_n > 0 ? worker_run_bulk : worker_run;

	/* Collect the first n_workers worker lcores. */
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (n >= n_workers)
			break;
		worker_lcores[n++] = lcore_id;
	}
	if (n < n_workers)
		return -1.0;

	/* Prepare per-worker args. */
	for (i = 0; i < n_workers; i++) {
		struct worker_args *wa = &wargs[worker_lcores[i]];

		wa->alloc = alloc;
		wa->scratch = scratches != NULL ? scratches[i] : NULL;
		wa->iters = MULTI_OPS;
		wa->warmup = MULTI_WARMUP;
		wa->bulk_n = bulk_n;
		rte_atomic_store_explicit(&wa->start_flag, false,
				rte_memory_order_relaxed);
	}

	/* Launch workers. They spin on start_flag until released. */
	for (i = 0; i < n_workers; i++)
		rte_eal_remote_launch(fn, &wargs[worker_lcores[i]],
				worker_lcores[i]);

	/* Release all workers roughly simultaneously. */
	for (i = 0; i < n_workers; i++)
		rte_atomic_store_explicit(
			&wargs[worker_lcores[i]].start_flag, true,
			rte_memory_order_release);

	/* Wait for completion. */
	for (i = 0; i < n_workers; i++)
		rte_eal_wait_lcore(worker_lcores[i]);

	/* Aggregate: mean cycles per op across workers. */
	{
		double sum_cycles_per_op = 0.0;
		unsigned int n_ok = 0;

		for (i = 0; i < n_workers; i++) {
			struct worker_args *wa = &wargs[worker_lcores[i]];

			if (wa->err != 0 || wa->ops == 0)
				return -1.0;
			sum_cycles_per_op +=
				(double)wa->cycles / (double)wa->ops;
			n_ok++;
		}
		return sum_cycles_per_op / n_ok;
	}
}

/*
 * One sub-run of Scenario 4: given an allocator and a worker
 * count, return (baseline, alloc_path) mean cycles per op.
 */
static void
run_multi_lcore(const struct allocator *alloc, unsigned int n_workers,
		unsigned int bulk_n, double *baseline, double *alloc_path)
{
	void *scratches[MAX_MULTI_LCORES] = {0};
	unsigned int n_alloced = 0;
	unsigned int i;

	*baseline = -1.0;
	*alloc_path = -1.0;

	if (alloc->setup(MULTI_SIZE, n_workers * 64) < 0)
		return;

	/* Baseline: pre-allocate one scratch per worker. */
	for (i = 0; i < n_workers; i++) {
		scratches[i] = alloc->alloc();
		if (scratches[i] == NULL)
			goto err;
		n_alloced++;
	}

	*baseline = run_multi_workers(alloc, n_workers, scratches, 0);

	for (i = 0; i < n_alloced; i++)
		alloc->free_obj(scratches[i]);
	n_alloced = 0;

	/* Alloc path: workers alloc+free each iter. */
	*alloc_path = run_multi_workers(alloc, n_workers, NULL, bulk_n);

	alloc->teardown();
	return;
err:
	for (i = 0; i < n_alloced; i++)
		alloc->free_obj(scratches[i]);
	alloc->teardown();
}

/* Reporting -------------------------------------------------------- */

static void
print_header(const char *title)
{
	size_t i;

	TEST_LOG("\n=== %s ===\n", title);
	TEST_LOG("%-12s", "allocator");
	for (i = 0; i < N_SIZES; i++)
		TEST_LOG(" %10zu B", SIZES[i]);
	TEST_LOG("\n");
}

static void
print_row(const char *name, const double *values)
{
	size_t i;

	TEST_LOG("%-12s", name);
	for (i = 0; i < N_SIZES; i++) {
		if (values[i] < 0)
			TEST_LOG(" %12s", "--");
		else
			TEST_LOG(" %12.1f", values[i]);
	}
	TEST_LOG("\n");
}

static void
print_multi_header(const char *title, const unsigned int *lcore_counts,
		unsigned int n_counts)
{
	unsigned int i;

	TEST_LOG("\n=== %s ===\n", title);
	TEST_LOG("%-12s", "allocator");
	for (i = 0; i < n_counts; i++)
		TEST_LOG(" %8u lcore%c", lcore_counts[i],
				lcore_counts[i] == 1 ? ' ' : 's');
	TEST_LOG("\n");
}

static void
print_multi_row(const char *name, const double *values, unsigned int n_counts)
{
	unsigned int i;

	TEST_LOG("%-12s", name);
	for (i = 0; i < n_counts; i++) {
		if (values[i] < 0)
			TEST_LOG(" %14s", "--");
		else
			TEST_LOG(" %14.1f", values[i]);
	}
	TEST_LOG("\n");
}

/* Driver ----------------------------------------------------------- */

static int
test_fastmem_perf(void)
{
	size_t i;
	size_t a;
	int rc;

	rc = rte_fastmem_init();
	if (rc < 0) {
		TEST_LOG("rte_fastmem_init() failed: %d\n", rc);
		return -1;
	}

	rc = rte_fastmem_reserve(128 * 1024 * 1024, SOCKET_ID_ANY);
	if (rc < 0) {
		TEST_LOG("rte_fastmem_reserve() failed: %d\n", rc);
		rte_fastmem_deinit();
		return -1;
	}

	TEST_LOG("\nfastmem performance — single-lcore, fixed-size\n");
	TEST_LOG("All numbers are TSC cycles.\n");

	/* Scenario 1: tight alloc+free. */
	print_header("Scenario 1: Single-object hot path — cycles per (alloc + free)");
	for (a = 0; a < N_ALLOCATORS; a++) {
		double vals[N_SIZES];

		for (i = 0; i < N_SIZES; i++)
			vals[i] = run_tight(&allocators[a], SIZES[i]);
		print_row(allocators[a].name, vals);
	}

	/* Scenario 2: batched, FIFO free. */
	print_header("Scenario 2: Batch alloc, FIFO free — cycles per alloc");
	for (a = 0; a < N_ALLOCATORS; a++) {
		double vals_alloc[N_SIZES], vals_free[N_SIZES];

		for (i = 0; i < N_SIZES; i++)
			run_batch(&allocators[a], SIZES[i],
				&vals_alloc[i], &vals_free[i]);
		print_row(allocators[a].name, vals_alloc);
	}
	print_header("Scenario 2: Batch alloc, FIFO free — cycles per free");
	for (a = 0; a < N_ALLOCATORS; a++) {
		double vals_alloc[N_SIZES], vals_free[N_SIZES];

		for (i = 0; i < N_SIZES; i++)
			run_batch(&allocators[a], SIZES[i],
				&vals_alloc[i], &vals_free[i]);
		print_row(allocators[a].name, vals_free);
	}

	/* Scenario 3: batched, reverse free. */
	print_header("Scenario 3: Batch alloc, LIFO free — cycles per alloc");
	for (a = 0; a < N_ALLOCATORS; a++) {
		double vals_alloc[N_SIZES], vals_free[N_SIZES];

		for (i = 0; i < N_SIZES; i++)
			run_batch_reverse(&allocators[a], SIZES[i],
				&vals_alloc[i], &vals_free[i]);
		print_row(allocators[a].name, vals_alloc);
	}
	print_header("Scenario 3: Batch alloc, LIFO free — cycles per free");
	for (a = 0; a < N_ALLOCATORS; a++) {
		double vals_alloc[N_SIZES], vals_free[N_SIZES];

		for (i = 0; i < N_SIZES; i++)
			run_batch_reverse(&allocators[a], SIZES[i],
				&vals_alloc[i], &vals_free[i]);
		print_row(allocators[a].name, vals_free);
	}

	/* Scenario 4: multi-lcore alloc/work/free with baseline. */
	{
		unsigned int max_workers = rte_lcore_count() - 1;
		unsigned int lcore_counts[8];
		unsigned int n_counts = 0;
		unsigned int w;
		double base_vals[N_ALLOCATORS][8];
		double alloc_vals[N_ALLOCATORS][8];
		double delta_vals[N_ALLOCATORS][8];

		if (max_workers > MAX_MULTI_LCORES)
			max_workers = MAX_MULTI_LCORES;

		/* Sweep lcore counts: 1, 2, 4, 8, ... up to max_workers. */
		for (w = 1; w <= max_workers && n_counts < RTE_DIM(lcore_counts); w *= 2)
			lcore_counts[n_counts++] = w;
		/* Ensure max_workers is the final column if not power of two. */
		if (n_counts > 0 && lcore_counts[n_counts - 1] != max_workers &&
				n_counts < RTE_DIM(lcore_counts) && max_workers >= 1)
			lcore_counts[n_counts++] = max_workers;

		if (n_counts == 0) {
			TEST_LOG("\nScenario 4 (Multi-lcore contention) skipped: no worker lcores available.\n");
		} else {
			TEST_LOG("\nScenario 4 parameters: size=%u B\n",
				MULTI_SIZE);

			for (a = 0; a < N_ALLOCATORS; a++) {
				unsigned int c;

				for (c = 0; c < n_counts; c++)
					run_multi_lcore(&allocators[a], lcore_counts[c],
							0, &base_vals[a][c],
							&alloc_vals[a][c]);
				for (c = 0; c < n_counts; c++) {
					if (base_vals[a][c] < 0 || alloc_vals[a][c] < 0)
						delta_vals[a][c] = -1.0;
					else
						delta_vals[a][c] = alloc_vals[a][c] -
							base_vals[a][c];
				}
			}

			TEST_LOG("Baseline (domain logic only): %.1f cycles/op\n",
					base_vals[0][0]);

			print_multi_header("Scenario 4: Multi-lcore contention — allocator overhead (cycles/op)",
					lcore_counts, n_counts);
			for (a = 0; a < N_ALLOCATORS; a++)
				print_multi_row(allocators[a].name,
						delta_vals[a], n_counts);
		}
	}

	/* Scenario 5: multi-lcore bulk alloc/work/free. */
	{
		unsigned int max_workers = rte_lcore_count() - 1;
		unsigned int lcore_counts[8];
		unsigned int n_counts = 0;
		unsigned int w;
		double base_vals[N_ALLOCATORS][8];
		double alloc_vals[N_ALLOCATORS][8];
		double delta_vals[N_ALLOCATORS][8];
		unsigned int bulk_n = 8;

		if (max_workers > MAX_MULTI_LCORES)
			max_workers = MAX_MULTI_LCORES;

		for (w = 1; w <= max_workers && n_counts < RTE_DIM(lcore_counts); w *= 2)
			lcore_counts[n_counts++] = w;
		if (n_counts > 0 && lcore_counts[n_counts - 1] != max_workers &&
				n_counts < RTE_DIM(lcore_counts) && max_workers >= 1)
			lcore_counts[n_counts++] = max_workers;

		if (n_counts == 0) {
			TEST_LOG("\nScenario 5 (Multi-lcore bulk contention) skipped: no worker lcores available.\n");
		} else {
			TEST_LOG("\nScenario 5 parameters: size=%u B, "
				"bulk=%u\n",
				MULTI_SIZE, bulk_n);

			for (size_t a = 0; a < N_ALLOCATORS; a++) {
				unsigned int c;

				for (c = 0; c < n_counts; c++)
					run_multi_lcore(&allocators[a],
							lcore_counts[c], bulk_n,
							&base_vals[a][c],
							&alloc_vals[a][c]);
				for (c = 0; c < n_counts; c++) {
					if (base_vals[a][c] < 0 || alloc_vals[a][c] < 0)
						delta_vals[a][c] = -1.0;
					else
						delta_vals[a][c] = alloc_vals[a][c] -
							base_vals[a][c];
				}
			}

			TEST_LOG("Baseline (domain logic only): %.1f cycles/op\n",
					base_vals[0][0]);

			print_multi_header("Scenario 5: Multi-lcore bulk contention — allocator overhead (cycles/op)",
					lcore_counts, n_counts);
			for (size_t a = 0; a < N_ALLOCATORS; a++)
				print_multi_row(allocators[a].name,
						delta_vals[a], n_counts);
		}
	}

	TEST_LOG("\n");
	rte_fastmem_deinit();
	return 0;
}

REGISTER_PERF_TEST(fastmem_perf_autotest, test_fastmem_perf);

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Ericsson AB
 */

#include <errno.h>
#include <inttypes.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_common.h>
#include <rte_errno.h>
#include <rte_lcore.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_thread.h>

#include <rte_fastmem.h>

#include "test.h"

#define FASTMEM_MEMZONE_SIZE (128U << 20)

/*
 * Count memzones whose names begin with the fastmem prefix.
 * Used to verify that rte_fastmem_reserve() really did reserve
 * backing memzones.
 */
static int fastmem_memzone_count;

static void
count_fastmem_memzones_walk(const struct rte_memzone *mz, void *arg)
{
	RTE_SET_USED(arg);

	if (strncmp(mz->name, "fastmem_", strlen("fastmem_")) == 0)
		fastmem_memzone_count++;
}

static unsigned int
count_fastmem_memzones(void)
{
	fastmem_memzone_count = 0;
	rte_memzone_walk(count_fastmem_memzones_walk, NULL);
	return fastmem_memzone_count;
}

static int
test_init_deinit(void)
{
	int rc;

	rc = rte_fastmem_init();
	TEST_ASSERT_EQUAL(rc, 0, "rte_fastmem_init() failed: %d", rc);

	rte_fastmem_deinit();

	/* A subsequent init/deinit cycle must succeed. */
	rc = rte_fastmem_init();
	TEST_ASSERT_EQUAL(rc, 0, "second rte_fastmem_init() failed: %d", rc);

	rte_fastmem_deinit();

	return TEST_SUCCESS;
}

static int
test_init_is_not_idempotent(void)
{
	int rc;

	rc = rte_fastmem_init();
	TEST_ASSERT_EQUAL(rc, 0, "rte_fastmem_init() failed: %d", rc);

	rc = rte_fastmem_init();
	TEST_ASSERT_EQUAL(rc, -EBUSY,
		"expected -EBUSY on re-init, got %d", rc);

	rte_fastmem_deinit();

	return TEST_SUCCESS;
}

static int
test_deinit_without_init(void)
{
	/* Must be a no-op, not a crash. */
	rte_fastmem_deinit();

	return TEST_SUCCESS;
}

static int
test_max_size(void)
{
	size_t max;

	max = rte_fastmem_max_size();
	TEST_ASSERT(max >= (1U << 20),
		"max_size=%zu below required 1 MiB minimum", max);

	return TEST_SUCCESS;
}

static int
test_reserve_small(void)
{
	int socket_id;
	unsigned int before, after;
	int rc;

	socket_id = rte_socket_id_by_idx(0);
	TEST_ASSERT(socket_id >= 0, "no available sockets");

	before = count_fastmem_memzones();

	/*
	 * A small reserve request (1 byte) must result in exactly
	 * one memzone reservation: the internal rounding is to
	 * memzone granularity.
	 */
	rc = rte_fastmem_reserve(1, socket_id);
	TEST_ASSERT_EQUAL(rc, 0, "rte_fastmem_reserve() failed: %d", rc);

	after = count_fastmem_memzones();
	TEST_ASSERT_EQUAL(after - before, 1,
		"expected 1 new memzone, got %u", after - before);

	rte_fastmem_deinit();

	/* After deinit the memzones must be released. */
	TEST_ASSERT_EQUAL(count_fastmem_memzones(), 0,
		"%u fastmem memzones leaked after deinit",
		count_fastmem_memzones());

	return TEST_SUCCESS;
}

static int
test_reserve_multiple_memzones(void)
{
	int socket_id;
	unsigned int before, after;
	size_t reserve_size;
	int rc;

	socket_id = rte_socket_id_by_idx(0);
	TEST_ASSERT(socket_id >= 0, "no available sockets");

	before = count_fastmem_memzones();

	/*
	 * Request just over one memzone's worth; this must force
	 * a second memzone to be reserved.
	 */
	reserve_size = FASTMEM_MEMZONE_SIZE + 1;
	rc = rte_fastmem_reserve(reserve_size, socket_id);
	TEST_ASSERT_EQUAL(rc, 0, "rte_fastmem_reserve(%zu) failed: %d",
		reserve_size, rc);

	after = count_fastmem_memzones();
	TEST_ASSERT_EQUAL(after - before, 2,
		"expected 2 new memzones for %zu-byte reserve, got %u",
		reserve_size, after - before);

	return TEST_SUCCESS;
}

static int
test_reserve_cumulative(void)
{
	int socket_id;
	unsigned int after_first, after_second;
	int rc;

	socket_id = rte_socket_id_by_idx(0);
	TEST_ASSERT(socket_id >= 0, "no available sockets");

	rc = rte_fastmem_reserve(FASTMEM_MEMZONE_SIZE, socket_id);
	TEST_ASSERT_EQUAL(rc, 0, "first reserve failed: %d", rc);

	after_first = count_fastmem_memzones();

	/*
	 * A second call requesting the same amount that's already
	 * reserved must not trigger any new memzone reservation.
	 */
	rc = rte_fastmem_reserve(FASTMEM_MEMZONE_SIZE, socket_id);
	TEST_ASSERT_EQUAL(rc, 0, "second reserve failed: %d", rc);

	after_second = count_fastmem_memzones();
	TEST_ASSERT_EQUAL(after_first, after_second,
		"reserve of already-reserved amount added memzones (%u -> %u)",
		after_first, after_second);

	return TEST_SUCCESS;
}

static int
test_reserve_invalid_socket(void)
{
	int rc;

	rc = rte_fastmem_reserve(1, RTE_MAX_NUMA_NODES);
	TEST_ASSERT_EQUAL(rc, -EINVAL,
		"expected -EINVAL for out-of-range socket, got %d", rc);

	rc = rte_fastmem_reserve(1, -2);
	TEST_ASSERT_EQUAL(rc, -EINVAL,
		"expected -EINVAL for negative socket, got %d", rc);

	return TEST_SUCCESS;
}

static int
test_reserve_without_init(void)
{
	int rc;

	rc = rte_fastmem_reserve(1, SOCKET_ID_ANY);
	TEST_ASSERT(rc < 0,
		"expected failure without init, got %d", rc);

	return TEST_SUCCESS;
}

static int
test_reserve_any_socket(void)
{
	unsigned int before, after;
	int rc;

	before = count_fastmem_memzones();

	/*
	 * SOCKET_ID_ANY should succeed on any system with at least
	 * one configured socket. The allocator picks the caller's
	 * socket first and falls back to other sockets if needed.
	 */
	rc = rte_fastmem_reserve(1, SOCKET_ID_ANY);
	TEST_ASSERT_EQUAL(rc, 0,
		"rte_fastmem_reserve(SOCKET_ID_ANY) failed: %d", rc);

	after = count_fastmem_memzones();
	TEST_ASSERT_EQUAL(after - before, 1,
		"expected 1 new memzone, got %u", after - before);

	return TEST_SUCCESS;
}

/*
 * Stage 2 tests: allocation and free.
 */

static int
test_alloc_too_big(void)
{
	void *p;
	rte_errno = 0;
	p = rte_fastmem_alloc(rte_fastmem_max_size() + 1, 0, 0);
	TEST_ASSERT_NULL(p, "alloc above max_size returned non-NULL");
	TEST_ASSERT_EQUAL(rte_errno, E2BIG,
		"expected rte_errno=E2BIG, got %d", rte_errno);

	return TEST_SUCCESS;
}

static int
test_alloc_invalid_align(void)
{
	void *p;
	rte_errno = 0;
	p = rte_fastmem_alloc(16, 3, 0); /* 3 is not a power of 2 */
	TEST_ASSERT_NULL(p, "alloc with align=3 returned non-NULL");
	TEST_ASSERT_EQUAL(rte_errno, EINVAL,
		"expected rte_errno=EINVAL, got %d", rte_errno);

	return TEST_SUCCESS;
}

static int
test_alloc_free_small(void)
{
	void *p;
	p = rte_fastmem_alloc(8, 0, 0);
	TEST_ASSERT_NOT_NULL(p, "alloc(8) failed: rte_errno=%d", rte_errno);

	/* Writing into the object must not crash. */
	memset(p, 0xa5, 8);

	rte_fastmem_free(p);

	return TEST_SUCCESS;
}

static int
test_alloc_free_various_sizes(void)
{
	static const size_t sizes[] = {
		1, 8, 16, 17, 63, 64, 128, 1024, 4096,
		64 * 1024, 256 * 1024, 1024 * 1024,
	};
	void *ptrs[RTE_DIM(sizes)];
	unsigned int i;
	for (i = 0; i < RTE_DIM(sizes); i++) {
		ptrs[i] = rte_fastmem_alloc(sizes[i], 0, 0);
		TEST_ASSERT_NOT_NULL(ptrs[i],
			"alloc(%zu) failed: rte_errno=%d",
			sizes[i], rte_errno);
		memset(ptrs[i], 0x5a, sizes[i]);
	}

	for (i = 0; i < RTE_DIM(sizes); i++)
		rte_fastmem_free(ptrs[i]);

	return TEST_SUCCESS;
}

static int
test_alloc_alignment(void)
{
	static const size_t aligns[] = {
		8, 16, 64, 256, 4096, 65536,
	};
	unsigned int i;
	for (i = 0; i < RTE_DIM(aligns); i++) {
		void *p = rte_fastmem_alloc(1, aligns[i], 0);

		TEST_ASSERT_NOT_NULL(p,
			"alloc(1, align=%zu) failed: rte_errno=%d",
			aligns[i], rte_errno);
		TEST_ASSERT((uintptr_t)p % aligns[i] == 0,
			"pointer %p not aligned on %zu",
			p, aligns[i]);
		rte_fastmem_free(p);
	}

	/* Default (align=0) gives at least RTE_CACHE_LINE_SIZE. */
	{
		void *p = rte_fastmem_alloc(1, 0, 0);

		TEST_ASSERT_NOT_NULL(p,
			"alloc(1, align=0) failed: rte_errno=%d", rte_errno);
		TEST_ASSERT((uintptr_t)p % RTE_CACHE_LINE_SIZE == 0,
			"default-align pointer %p not cache-line aligned",
			p);
		rte_fastmem_free(p);
	}

	return TEST_SUCCESS;
}

static int
test_alloc_zero_flag(void)
{
	uint8_t *p;
	unsigned int i;
	bool all_zero = true;

	/*
	 * Dirty a slab first by allocating without F_ZERO, writing
	 * a non-zero pattern, and freeing. A subsequent F_ZERO
	 * allocation on the same slab must return zeroed memory.
	 */
	p = rte_fastmem_alloc(128, 0, 0);
	TEST_ASSERT_NOT_NULL(p, "priming alloc failed");
	memset(p, 0xff, 128);
	rte_fastmem_free(p);

	p = rte_fastmem_alloc(128, 0, RTE_FASTMEM_F_ZERO);
	TEST_ASSERT_NOT_NULL(p, "F_ZERO alloc failed");
	for (i = 0; i < 128; i++) {
		if (p[i] != 0) {
			all_zero = false;
			break;
		}
	}
	TEST_ASSERT(all_zero, "F_ZERO returned non-zero byte at offset %u", i);

	rte_fastmem_free(p);

	return TEST_SUCCESS;
}

static int
test_alloc_reuse(void)
{
	void *first, *second;
	first = rte_fastmem_alloc(64, 0, 0);
	TEST_ASSERT_NOT_NULL(first, "first alloc failed");
	rte_fastmem_free(first);

	second = rte_fastmem_alloc(64, 0, 0);
	TEST_ASSERT_NOT_NULL(second, "second alloc failed");

	/*
	 * The slab's free list is LIFO, so the most recently freed
	 * object is at the head of the list. A subsequent alloc in
	 * the same class returns it.
	 */
	TEST_ASSERT_EQUAL(first, second,
		"free + alloc did not reuse: first=%p second=%p",
		first, second);

	rte_fastmem_free(second);

	return TEST_SUCCESS;
}

static int
test_alloc_many_in_class(void)
{
	/*
	 * Allocate more objects in one class than fit in a single
	 * slab, forcing the bin to pull a second block. This
	 * exercises the partial->full transition and the cross-slab
	 * allocation path.
	 */
	enum { CLASS_SIZE = 8, COUNT = 300000 };
	void **ptrs;
	unsigned int i;

	ptrs = calloc(COUNT, sizeof(*ptrs));
	TEST_ASSERT_NOT_NULL(ptrs, "calloc for test ptrs failed");

	for (i = 0; i < COUNT; i++) {
		ptrs[i] = rte_fastmem_alloc(CLASS_SIZE, 0, 0);
		TEST_ASSERT_NOT_NULL(ptrs[i],
			"alloc[%u] failed: rte_errno=%d",
			i, rte_errno);
	}

	for (i = 0; i < COUNT; i++)
		rte_fastmem_free(ptrs[i]);

	free(ptrs);

	return TEST_SUCCESS;
}

static int
test_alloc_socket(void)
{
	void *p;
	int socket_id;
	socket_id = rte_socket_id_by_idx(0);
	TEST_ASSERT(socket_id >= 0, "no available sockets");

	p = rte_fastmem_alloc_socket(64, 0, 0, socket_id);
	TEST_ASSERT_NOT_NULL(p,
		"alloc_socket(%d) failed: rte_errno=%d",
		socket_id, rte_errno);

	rte_fastmem_free(p);

	return TEST_SUCCESS;
}

static int
test_alloc_block_repurposing(void)
{
	void *small, *large;

	/*
	 * Allocate and free a small object, forcing a block to be
	 * assigned to the small class and then returned to the
	 * free-block pool. A subsequent allocation in a different
	 * class must be able to reuse that block.
	 */
	small = rte_fastmem_alloc(8, 0, 0);
	TEST_ASSERT_NOT_NULL(small, "small alloc failed");
	rte_fastmem_free(small);

	large = rte_fastmem_alloc(256 * 1024, 0, 0);
	TEST_ASSERT_NOT_NULL(large, "large alloc failed");
	rte_fastmem_free(large);

	return TEST_SUCCESS;
}

static int
test_alloc_block_repurposing_no_growth(void)
{
	struct rte_fastmem_stats stats;
	void *small, *large;
	uint64_t after_small;
	int rc;

	/*
	 * Stronger version of test_alloc_block_repurposing: assert
	 * that the cross-class allocation does not grow the
	 * backing memory (bytes_backing stays flat). Because the
	 * free-block pool is shared across size classes — not
	 * partitioned per class — the block freed from the small
	 * class must serve the large allocation without triggering
	 * a new memzone reservation.
	 */
	rc = rte_fastmem_stats(&stats);
	TEST_ASSERT_EQUAL(rc, 0, "rte_fastmem_stats() failed: %d", rc);
	TEST_ASSERT_EQUAL(stats.bytes_backing, (uint64_t)0,
		"unexpected pre-alloc bytes_backing: %" PRIu64,
		stats.bytes_backing);

	small = rte_fastmem_alloc(8, 0, 0);
	TEST_ASSERT_NOT_NULL(small, "small alloc failed");

	rc = rte_fastmem_stats(&stats);
	TEST_ASSERT_EQUAL(rc, 0, "rte_fastmem_stats() failed: %d", rc);
	TEST_ASSERT(stats.bytes_backing > 0,
		"bytes_backing did not grow on first alloc");
	after_small = stats.bytes_backing;

	rte_fastmem_free(small);
	rte_fastmem_cache_flush();

	large = rte_fastmem_alloc(256 * 1024, 0, 0);
	TEST_ASSERT_NOT_NULL(large,
		"large alloc failed: rte_errno=%d", rte_errno);

	rc = rte_fastmem_stats(&stats);
	TEST_ASSERT_EQUAL(rc, 0, "rte_fastmem_stats() failed: %d", rc);
	TEST_ASSERT_EQUAL(stats.bytes_backing, after_small,
		"cross-class alloc grew backing memory from %" PRIu64
		" to %" PRIu64,
		after_small, stats.bytes_backing);

	rte_fastmem_free(large);

	return TEST_SUCCESS;
}

static int
test_free_null(void)
{
	/* Must be a no-op, not a crash. */
	rte_fastmem_free(NULL);

	return TEST_SUCCESS;
}

static int
test_alloc_content_integrity(void)
{
	/*
	 * Allocate a batch of objects, fill each with a distinct
	 * byte pattern, then verify none of the patterns overlap.
	 * This catches header overwrites (slab header corrupted by
	 * object access) and slot-overlap bugs (two pointers pointing
	 * at overlapping slots).
	 */
	enum { N = 256, SIZE = 128 };
	uint8_t *ptrs[N];
	unsigned int i, j;
	for (i = 0; i < N; i++) {
		ptrs[i] = rte_fastmem_alloc(SIZE, 0, 0);
		TEST_ASSERT_NOT_NULL(ptrs[i], "alloc[%u] failed", i);
		memset(ptrs[i], (int)i, SIZE);
	}

	for (i = 0; i < N; i++)
		for (j = 0; j < SIZE; j++)
			TEST_ASSERT_EQUAL(ptrs[i][j], (uint8_t)i,
				"corruption at ptrs[%u][%u]: got 0x%x, want 0x%x",
				i, j, ptrs[i][j], (uint8_t)i);

	for (i = 0; i < N; i++)
		rte_fastmem_free(ptrs[i]);

	return TEST_SUCCESS;
}

static int
test_alloc_align_too_big(void)
{
	void *p;
	/*
	 * A small size with an alignment larger than the maximum
	 * size class cannot be served. The class selected must be
	 * large enough for the alignment, but no such class exists.
	 */
	rte_errno = 0;
	p = rte_fastmem_alloc(1, rte_fastmem_max_size() * 2, 0);
	TEST_ASSERT_NULL(p,
		"alloc with align>max_size returned non-NULL");
	TEST_ASSERT_EQUAL(rte_errno, E2BIG,
		"expected rte_errno=E2BIG, got %d", rte_errno);

	return TEST_SUCCESS;
}

static int
test_alloc_align_one(void)
{
	void *p;
	/* align=1 is a valid power of 2 and must be accepted. */
	p = rte_fastmem_alloc(8, 1, 0);
	TEST_ASSERT_NOT_NULL(p, "alloc(8, 1) failed: rte_errno=%d",
		rte_errno);
	rte_fastmem_free(p);

	return TEST_SUCCESS;
}

static int
test_alloc_socket_numa_placement(void)
{
	void *p;
	int socket_id;
	struct rte_memseg *ms;
	socket_id = rte_socket_id_by_idx(0);
	TEST_ASSERT(socket_id >= 0, "no available sockets");

	p = rte_fastmem_alloc_socket(64, 0, 0, socket_id);
	TEST_ASSERT_NOT_NULL(p,
		"alloc_socket(%d) failed: rte_errno=%d",
		socket_id, rte_errno);

	/*
	 * Walk the memory to find the memseg for this pointer and
	 * verify its socket. Skip the check if lookup fails (e.g.,
	 * --no-huge mode may not populate memsegs for fastmem's
	 * allocations in a way that rte_mem_virt2memseg can find).
	 */
	ms = rte_mem_virt2memseg(p, NULL);
	if (ms != NULL) {
		TEST_ASSERT_EQUAL(ms->socket_id, socket_id,
			"alloc on socket %d landed on socket %d",
			socket_id, ms->socket_id);
	}

	rte_fastmem_free(p);

	return TEST_SUCCESS;
}

/*
 * Allocate from a socket different from the calling lcore's socket,
 * triggering a cross-socket cache allocation. Then deinit to exercise
 * the teardown path where a cache's backing memory lives on a
 * different socket than the one it serves.
 */
static int
test_alloc_cross_socket_deinit(void)
{
	int local_sid, remote_sid;
	unsigned int i, n_sockets;
	void *p;

	local_sid = (int)rte_socket_id();
	if (local_sid < 0 || (unsigned int)local_sid >= RTE_MAX_NUMA_NODES)
		local_sid = rte_socket_id_by_idx(0);

	n_sockets = rte_socket_count();
	if (n_sockets < 2)
		return TEST_SKIPPED;

	/* Find a socket different from the local one. */
	remote_sid = -1;
	for (i = 0; i < n_sockets; i++) {
		int sid = rte_socket_id_by_idx(i);
		if (sid >= 0 && sid != local_sid) {
			remote_sid = sid;
			break;
		}
	}
	if (remote_sid < 0)
		return TEST_SKIPPED;

	p = rte_fastmem_alloc_socket(64, 0, 0, remote_sid);
	TEST_ASSERT_NOT_NULL(p,
		"cross-socket alloc(socket %d) failed: rte_errno=%d",
		remote_sid, rte_errno);

	rte_fastmem_free(p);

	/* Teardown and re-init to exercise the deinit path with
	 * cross-socket caches.
	 */
	rte_fastmem_deinit();

	TEST_ASSERT_EQUAL(rte_fastmem_init(), 0,
		"re-init after cross-socket deinit failed");

	return TEST_SUCCESS;
}

/*
 * Stage 3 tests: per-lcore caches.
 */

static int
test_cache_flush(void)
{
	void *p;
	/*
	 * Alloc and free one object, leaving it in the cache. Then
	 * flush and verify that a subsequent alloc may or may not
	 * return the same pointer (not asserting same/different —
	 * just checking that flush does not crash and a follow-up
	 * alloc still works).
	 */
	p = rte_fastmem_alloc(64, 0, 0);
	TEST_ASSERT_NOT_NULL(p, "first alloc failed");
	rte_fastmem_free(p);

	rte_fastmem_cache_flush();

	/* Flush again — must be idempotent. */
	rte_fastmem_cache_flush();

	p = rte_fastmem_alloc(64, 0, 0);
	TEST_ASSERT_NOT_NULL(p, "post-flush alloc failed");
	rte_fastmem_free(p);

	return TEST_SUCCESS;
}

static int
test_cache_flush_without_init(void)
{
	/* Must be a no-op, not a crash. */
	rte_fastmem_cache_flush();

	return TEST_SUCCESS;
}

static int
test_cache_exceeds_capacity(void)
{
	/*
	 * Free more objects at a single size class than the cache
	 * capacity (64 for classes <= 4 KiB). This forces the
	 * cache-drain slow path and verifies no corruption.
	 */
	enum { COUNT = 200, SIZE = 64 };
	void *ptrs[COUNT];
	unsigned int i;

	for (i = 0; i < COUNT; i++) {
		ptrs[i] = rte_fastmem_alloc(SIZE, 0, 0);
		TEST_ASSERT_NOT_NULL(ptrs[i],
			"alloc[%u] failed: rte_errno=%d", i, rte_errno);
	}

	for (i = 0; i < COUNT; i++)
		rte_fastmem_free(ptrs[i]);

	/* Re-alloc the same count should still work. */
	for (i = 0; i < COUNT; i++) {
		ptrs[i] = rte_fastmem_alloc(SIZE, 0, 0);
		TEST_ASSERT_NOT_NULL(ptrs[i],
			"re-alloc[%u] failed: rte_errno=%d", i, rte_errno);
	}

	for (i = 0; i < COUNT; i++)
		rte_fastmem_free(ptrs[i]);

	return TEST_SUCCESS;
}

struct non_eal_args {
	int ok;
	char pad[64];
};

static uint32_t
non_eal_thread_main(void *arg)
{
	struct non_eal_args *args = arg;
	uint8_t *p;

	p = rte_fastmem_alloc(128, 0, 0);
	if (p == NULL)
		return 1;

	memset(p, 0x7e, 128);

	rte_fastmem_free(p);

	args->ok = 1;
	return 0;
}

static int
test_non_eal_thread(void)
{
	rte_thread_t thread_id;
	struct non_eal_args args = { 0 };
	int rc;

	rc = rte_thread_create(&thread_id, NULL, non_eal_thread_main, &args);
	TEST_ASSERT_EQUAL(rc, 0, "rte_thread_create() failed: %d", rc);

	rc = rte_thread_join(thread_id, NULL);
	TEST_ASSERT_EQUAL(rc, 0, "rte_thread_join() failed: %d", rc);

	TEST_ASSERT_EQUAL(args.ok, 1,
		"non-EAL thread did not complete alloc/free successfully");

	return TEST_SUCCESS;
}

static int
test_cache_flush_returns_memory(void)
{
	/*
	 * When an entire slab's worth of objects is freed, the
	 * slab's block is returned to the free-block pool and can
	 * be reassigned to another size class. Verify the cache
	 * does not permanently hold objects that prevent this.
	 *
	 * Allocate enough objects in one class to force multiple
	 * slabs, free them all, then flush the cache. After the
	 * flush, all cached objects are drained to their bins and
	 * empty slabs are returned to the block pool.
	 */
	enum { N = 200, SIZE = 64 };
	void *ptrs[N];
	unsigned int i;

	for (i = 0; i < N; i++) {
		ptrs[i] = rte_fastmem_alloc(SIZE, 0, 0);
		TEST_ASSERT_NOT_NULL(ptrs[i], "alloc[%u] failed", i);
	}
	for (i = 0; i < N; i++)
		rte_fastmem_free(ptrs[i]);

	rte_fastmem_cache_flush();

	/*
	 * An allocation in a completely different class should
	 * succeed now, having access to any blocks freed by the
	 * flush.
	 */
	{
		void *other = rte_fastmem_alloc(65536, 0, 0);

		TEST_ASSERT_NOT_NULL(other,
			"post-flush cross-class alloc failed");
		rte_fastmem_free(other);
	}

	return TEST_SUCCESS;
}

static int
test_alloc_bulk_basic(void)
{
	enum { N = 32 };
	void *ptrs[N];
	int rc;

	rc = rte_fastmem_alloc_bulk(ptrs, N, 64, 0, 0);
	TEST_ASSERT_EQUAL(rc, 0, "alloc_bulk failed: %d", rc);

	/* Verify all pointers are non-NULL and distinct. */
	for (unsigned int i = 0; i < N; i++) {
		TEST_ASSERT_NOT_NULL(ptrs[i], "ptrs[%u] is NULL", i);
		for (unsigned int j = 0; j < i; j++)
			TEST_ASSERT(ptrs[i] != ptrs[j],
				"ptrs[%u] == ptrs[%u]", i, j);
	}

	rte_fastmem_free_bulk(ptrs, N);

	return TEST_SUCCESS;
}

static int
test_alloc_bulk_zero_flag(void)
{
	enum { N = 8, SIZE = 128 };
	void *ptrs[N];
	int rc;

	rc = rte_fastmem_alloc_bulk(ptrs, N, SIZE, 0, RTE_FASTMEM_F_ZERO);
	TEST_ASSERT_EQUAL(rc, 0, "alloc_bulk failed: %d", rc);

	for (unsigned int i = 0; i < N; i++) {
		uint8_t *p = ptrs[i];

		for (unsigned int b = 0; b < SIZE; b++)
			TEST_ASSERT_EQUAL(p[b], 0,
				"ptrs[%u][%u] != 0", i, b);
	}

	rte_fastmem_free_bulk(ptrs, N);

	return TEST_SUCCESS;
}

static int
test_alloc_bulk_exceeds_cache(void)
{
	/* Allocate more than cache capacity (64) in one bulk call. */
	enum { N = 128 };
	void *ptrs[N];
	int rc;

	rc = rte_fastmem_alloc_bulk(ptrs, N, 64, 0, 0);
	TEST_ASSERT_EQUAL(rc, 0, "alloc_bulk(%u) failed: %d", N, rc);

	rte_fastmem_free_bulk(ptrs, N);

	return TEST_SUCCESS;
}

static int
test_alloc_bulk_socket(void)
{
	enum { N = 16 };
	void *ptrs[N];
	int socket_id;
	int rc;

	socket_id = rte_socket_id_by_idx(0);
	TEST_ASSERT(socket_id >= 0, "no sockets");

	rc = rte_fastmem_alloc_bulk_socket(ptrs, N, 64, 0, 0, socket_id);
	TEST_ASSERT_EQUAL(rc, 0, "alloc_bulk_socket failed: %d", rc);

	rte_fastmem_free_bulk(ptrs, N);

	/* SOCKET_ID_ANY */
	rc = rte_fastmem_alloc_bulk_socket(ptrs, N, 64, 0, 0, SOCKET_ID_ANY);
	TEST_ASSERT_EQUAL(rc, 0, "alloc_bulk_socket(ANY) failed: %d", rc);

	rte_fastmem_free_bulk(ptrs, N);

	return TEST_SUCCESS;
}

static int
test_free_bulk(void)
{
	enum { N = 64 };
	void *ptrs[N];
	/* Allocate individually, free in bulk. */
	for (unsigned int i = 0; i < N; i++) {
		ptrs[i] = rte_fastmem_alloc(64, 0, 0);
		TEST_ASSERT_NOT_NULL(ptrs[i], "alloc[%u] failed", i);
	}

	rte_fastmem_free_bulk(ptrs, N);

	/* Verify memory is reusable. */
	for (unsigned int i = 0; i < N; i++) {
		ptrs[i] = rte_fastmem_alloc(64, 0, 0);
		TEST_ASSERT_NOT_NULL(ptrs[i], "re-alloc[%u] failed", i);
	}

	rte_fastmem_free_bulk(ptrs, N);

	return TEST_SUCCESS;
}

static int
test_classes(void)
{
	size_t sizes[32];
	unsigned int n;

	n = rte_fastmem_classes(NULL);
	TEST_ASSERT_EQUAL(n, 18u, "expected 18 classes, got %u", n);

	n = rte_fastmem_classes(sizes);
	TEST_ASSERT_EQUAL(n, 18u, "expected 18 classes, got %u", n);
	TEST_ASSERT_EQUAL(sizes[0], (size_t)8, "class 0 != 8");
	TEST_ASSERT_EQUAL(sizes[n - 1], (size_t)(1 << 20),
		"last class != 1 MiB");

	for (unsigned int i = 0; i < n; i++) {
		TEST_ASSERT(sizes[i] != 0 && (sizes[i] & (sizes[i] - 1)) == 0,
			"class %u size %zu not power of 2", i, sizes[i]);
		if (i > 0)
			TEST_ASSERT(sizes[i] > sizes[i - 1],
				"classes not ascending at %u", i);
	}

	return TEST_SUCCESS;
}

static int
test_stats_class(void)
{
	enum { N = 10 };
	struct rte_fastmem_class_stats cs;
	void *ptrs[N];
	int rc;

	for (unsigned int i = 0; i < N; i++) {
		ptrs[i] = rte_fastmem_alloc(64, 0, 0);
		TEST_ASSERT_NOT_NULL(ptrs[i], "alloc[%u] failed", i);
	}

	rc = rte_fastmem_stats_class(64, &cs);
	TEST_ASSERT_EQUAL(rc, 0, "stats_class failed: %d", rc);
	TEST_ASSERT_EQUAL(cs.class_size, (size_t)64, "wrong class_size");
	TEST_ASSERT(cs.alloc_cache_hits + cs.alloc_cache_misses == N,
		"alloc count != N: hits=%" PRIu64 " misses=%" PRIu64,
		cs.alloc_cache_hits, cs.alloc_cache_misses);
	TEST_ASSERT_EQUAL(cs.in_use, (uint64_t)N, "in_use != N");

	for (unsigned int i = 0; i < N; i++)
		rte_fastmem_free(ptrs[i]);

	rc = rte_fastmem_stats_class(64, &cs);
	TEST_ASSERT_EQUAL(rc, 0, "stats_class after free failed: %d", rc);
	TEST_ASSERT_EQUAL(cs.in_use, (uint64_t)0, "in_use != 0 after free");

	/* Invalid class size. */
	rc = rte_fastmem_stats_class(13, &cs);
	TEST_ASSERT_EQUAL(rc, -EINVAL, "expected -EINVAL for bad size");

	return TEST_SUCCESS;
}

static int
test_stats_lcore(void)
{
	struct rte_fastmem_lcore_stats ls;
	void *ptr;
	int rc;

	ptr = rte_fastmem_alloc(128, 0, 0);
	TEST_ASSERT_NOT_NULL(ptr, "alloc failed");

	rc = rte_fastmem_stats_lcore(rte_lcore_id(), &ls);
	TEST_ASSERT_EQUAL(rc, 0, "stats_lcore failed: %d", rc);
	TEST_ASSERT(ls.alloc_cache_hits + ls.alloc_cache_misses > 0,
		"no alloc activity on this lcore");

	rte_fastmem_free(ptr);

	rc = rte_fastmem_stats_lcore(rte_lcore_id(), &ls);
	TEST_ASSERT_EQUAL(rc, 0, "stats_lcore after free failed: %d", rc);
	TEST_ASSERT(ls.free_cache_hits + ls.free_cache_misses > 0,
		"no free activity on this lcore");

	/* Invalid lcore. */
	rc = rte_fastmem_stats_lcore(RTE_MAX_LCORE, &ls);
	TEST_ASSERT_EQUAL(rc, -EINVAL, "expected -EINVAL for bad lcore");

	return TEST_SUCCESS;
}

static int
test_stats_lcore_class(void)
{
	struct rte_fastmem_lcore_class_stats lcs;
	void *ptr;
	int rc;

	ptr = rte_fastmem_alloc(256, 0, 0);
	TEST_ASSERT_NOT_NULL(ptr, "alloc failed");

	rc = rte_fastmem_stats_lcore_class(rte_lcore_id(), 256, &lcs);
	TEST_ASSERT_EQUAL(rc, 0, "stats_lcore_class failed: %d", rc);
	TEST_ASSERT_EQUAL(lcs.class_size, (size_t)256, "wrong class_size");
	TEST_ASSERT(lcs.alloc_cache_hits + lcs.alloc_cache_misses > 0,
		"no alloc activity");

	rte_fastmem_free(ptr);
	return TEST_SUCCESS;
}

static int
test_stats_reset(void)
{
	struct rte_fastmem_stats gs;
	void *ptr;
	int rc;

	ptr = rte_fastmem_alloc(64, 0, 0);
	TEST_ASSERT_NOT_NULL(ptr, "alloc failed");
	rte_fastmem_free(ptr);

	rte_fastmem_stats_reset();

	rc = rte_fastmem_stats(&gs);
	TEST_ASSERT_EQUAL(rc, 0, "stats failed: %d", rc);
	TEST_ASSERT_EQUAL(gs.alloc_total, (uint64_t)0,
		"alloc_total not zero after reset");
	TEST_ASSERT_EQUAL(gs.free_total, (uint64_t)0,
		"free_total not zero after reset");

	return TEST_SUCCESS;
}


#define MIXED_LONG_LIVED_COUNT 25
#define MIXED_SHORT_LIVED_ITERS 1000
#define MIXED_MIN_LCORES 3

static const size_t mixed_long_sizes[] = { 64, 256, 4096 };
static const size_t mixed_short_sizes[] = { 8, 16, 32, 64, 128, 256, 512, 1024 };

struct mixed_worker_args {
	uint32_t seed;
	int result;
};

static uint32_t
xorshift32(uint32_t *state)
{
	uint32_t x = *state;

	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	*state = x;
	return x;
}

static int
mixed_worker(void *arg)
{
	struct mixed_worker_args *args = arg;
	uint32_t seed = args->seed;
	void *long_lived[MIXED_LONG_LIVED_COUNT];
	size_t long_sizes[MIXED_LONG_LIVED_COUNT];
	unsigned int i;

	/* Allocate long-lived objects of mixed sizes. */
	for (i = 0; i < MIXED_LONG_LIVED_COUNT; i++) {
		long_sizes[i] = mixed_long_sizes[i % RTE_DIM(mixed_long_sizes)];
		long_lived[i] = rte_fastmem_alloc(long_sizes[i], 0, 0);
		if (long_lived[i] == NULL) {
			args->result = TEST_FAILED;
			return -1;
		}
		memset(long_lived[i], (int)(i + 1), long_sizes[i]);
	}

	/* Rapidly cycle short-lived objects. */
	for (i = 0; i < MIXED_SHORT_LIVED_ITERS; i++) {
		size_t sz = mixed_short_sizes[xorshift32(&seed) %
					      RTE_DIM(mixed_short_sizes)];
		uint8_t pattern = (uint8_t)(i & 0xff);
		uint8_t *p;

		p = rte_fastmem_alloc(sz, 0, 0);
		if (p == NULL) {
			args->result = TEST_FAILED;
			return -1;
		}
		memset(p, pattern, sz);

		/* Verify before freeing. */
		for (size_t j = 0; j < sz; j++) {
			if (p[j] != pattern) {
				args->result = TEST_FAILED;
				return -1;
			}
		}
		rte_fastmem_free(p);
	}

	/* Verify long-lived objects are still intact. */
	for (i = 0; i < MIXED_LONG_LIVED_COUNT; i++) {
		uint8_t *bytes = long_lived[i];
		uint8_t expected = (uint8_t)(i + 1);

		for (size_t j = 0; j < long_sizes[i]; j++) {
			if (bytes[j] != expected) {
				args->result = TEST_FAILED;
				return -1;
			}
		}
		rte_fastmem_free(long_lived[i]);
	}

	args->result = TEST_SUCCESS;
	return 0;
}

static int
test_mixed_lifetimes_multi_lcore(void)
{
	struct mixed_worker_args args[RTE_MAX_LCORE];
	unsigned int lcore_id;
	unsigned int count = 0;
	struct rte_fastmem_stats stats;
	int rc;

	RTE_LCORE_FOREACH_WORKER(lcore_id)
		count++;

	if (count < MIXED_MIN_LCORES) {
		printf("Not enough worker lcores (%u < %u), skipping\n",
		       count, MIXED_MIN_LCORES);
		return TEST_SKIPPED;
	}

	/* Launch workers with distinct seeds. */
	uint32_t seed = 0xdeadbeef;

	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		args[lcore_id].seed = seed;
		args[lcore_id].result = TEST_FAILED;
		seed += 0x12345678;
		rte_eal_remote_launch(mixed_worker, &args[lcore_id], lcore_id);
	}

	rte_eal_mp_wait_lcore();

	/* Check all workers succeeded. */
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		TEST_ASSERT_EQUAL(args[lcore_id].result, TEST_SUCCESS,
			"worker on lcore %u failed", lcore_id);
	}

	/* Verify no memory leak. */
	rc = rte_fastmem_stats(&stats);
	TEST_ASSERT_EQUAL(rc, 0, "stats failed: %d", rc);
	TEST_ASSERT_EQUAL(stats.bytes_in_use, (uint64_t)0,
		"bytes_in_use not zero after test: %" PRIu64,
		stats.bytes_in_use);

	return TEST_SUCCESS;
}


/*
 * Memory limit tests.
 *
 * FASTMEM_MEMZONE_SIZE is 128 MiB. We use a limit of 128 MiB
 * (one memzone) for most tests, and large objects (256 KiB) to
 * exhaust slabs quickly.
 */

#define LIMIT_ONE_MZ ((size_t)128 << 20)
#define LIMIT_OBJ_SIZE ((size_t)256 * 1024)

static int
test_memory_limit_basic(void)
{
	int rc;

	rc = rte_fastmem_set_limit(SOCKET_ID_ANY, LIMIT_ONE_MZ);
	TEST_ASSERT_EQUAL(rc, 0, "set_memory_limit failed: %d", rc);

	const size_t got = rte_fastmem_get_limit(0);
	TEST_ASSERT_EQUAL(got, LIMIT_ONE_MZ,
		"get_memory_limit mismatch: %zu", got);

	rc = rte_fastmem_reserve(LIMIT_ONE_MZ, SOCKET_ID_ANY);
	TEST_ASSERT_EQUAL(rc, 0, "first reserve failed: %d", rc);

	rc = rte_fastmem_reserve(LIMIT_ONE_MZ + 1, SOCKET_ID_ANY);
	TEST_ASSERT(rc < 0, "second reserve should have failed");

	return TEST_SUCCESS;
}

static int
test_memory_limit_alloc_exhaustion(void)
{
	const unsigned int max_ptrs = 1024;
	void *ptrs[max_ptrs];
	unsigned int count = 0;
	rte_fastmem_set_limit(SOCKET_ID_ANY, LIMIT_ONE_MZ);

	for (count = 0; count < max_ptrs; count++) {
		ptrs[count] = rte_fastmem_alloc(LIMIT_OBJ_SIZE, 0, 0);
		if (ptrs[count] == NULL)
			break;
	}

	TEST_ASSERT(count > 0, "should have allocated at least one");
	TEST_ASSERT(count < max_ptrs, "should have hit the limit");
	TEST_ASSERT_EQUAL(rte_errno, ENOMEM, "expected ENOMEM, got %d", rte_errno);

	rte_fastmem_free(ptrs[count - 1]);
	void *p = rte_fastmem_alloc(LIMIT_OBJ_SIZE, 0, 0);
	TEST_ASSERT_NOT_NULL(p, "alloc after free should succeed");
	rte_fastmem_free(p);

	for (unsigned int i = 0; i < count - 1; i++)
		rte_fastmem_free(ptrs[i]);

	return TEST_SUCCESS;
}

static int
test_memory_limit_zero_blocks_growth(void)
{
	int rc;

	rte_fastmem_set_limit(SOCKET_ID_ANY, 0);

	rc = rte_fastmem_reserve(1, SOCKET_ID_ANY);
	TEST_ASSERT(rc < 0, "reserve with limit=0 should fail");

	void *p = rte_fastmem_alloc(64, 0, 0);
	TEST_ASSERT_NULL(p, "alloc with limit=0 should fail");

	return TEST_SUCCESS;
}

static int
test_memory_limit_below_current(void)
{
	int rc;

	rc = rte_fastmem_reserve(LIMIT_ONE_MZ, SOCKET_ID_ANY);
	TEST_ASSERT_EQUAL(rc, 0, "reserve failed: %d", rc);

	rte_fastmem_set_limit(SOCKET_ID_ANY, 1);

	void *p = rte_fastmem_alloc(64, 0, 0);
	TEST_ASSERT_NOT_NULL(p, "alloc from existing backing should work");
	rte_fastmem_free(p);

	rc = rte_fastmem_reserve(LIMIT_ONE_MZ * 2, SOCKET_ID_ANY);
	TEST_ASSERT(rc < 0, "growth beyond limit should fail");

	return TEST_SUCCESS;
}

static int
test_memory_limit_socket_id_any(void)
{
	rte_fastmem_set_limit(SOCKET_ID_ANY, 42);

	for (unsigned int i = 0; i < rte_socket_count(); i++) {
		const int sid = rte_socket_id_by_idx(i);
		const size_t lim = rte_fastmem_get_limit(sid);

		TEST_ASSERT_EQUAL(lim, (size_t)42,
			"socket %d limit mismatch: %zu", sid, lim);
	}

	return TEST_SUCCESS;
}

static int
test_memory_limit_unlimited(void)
{
	int rc;

	rte_fastmem_set_limit(SOCKET_ID_ANY, 0);
	rte_fastmem_set_limit(SOCKET_ID_ANY, SIZE_MAX);

	rc = rte_fastmem_reserve(LIMIT_ONE_MZ, SOCKET_ID_ANY);
	TEST_ASSERT_EQUAL(rc, 0, "reserve after reset failed: %d", rc);

	return TEST_SUCCESS;
}

static int
test_memory_limit_alloc_integrity_under_oom(void)
{
	const unsigned int n = 128;
	const size_t obj_size = 1024;
	uint8_t *ptrs[n];
	const unsigned int extra_max = 1024;
	void *extra[extra_max];
	unsigned int n_extra = 0;
	unsigned int i;
	rte_fastmem_set_limit(SOCKET_ID_ANY, LIMIT_ONE_MZ);

	for (i = 0; i < n; i++) {
		ptrs[i] = rte_fastmem_alloc(obj_size, 0, 0);
		TEST_ASSERT_NOT_NULL(ptrs[i], "alloc[%u] failed", i);
		memset(ptrs[i], (int)(i & 0xff), obj_size);
	}

	/* Exhaust remaining backing with large objects. */
	for (n_extra = 0; n_extra < extra_max; n_extra++) {
		extra[n_extra] = rte_fastmem_alloc(LIMIT_OBJ_SIZE, 0, 0);
		if (extra[n_extra] == NULL)
			break;
	}

	/* Verify original objects are intact. */
	for (i = 0; i < n; i++) {
		const uint8_t expected = (uint8_t)(i & 0xff);
		for (unsigned int j = 0; j < obj_size; j++)
			TEST_ASSERT_EQUAL(ptrs[i][j], expected,
				"corruption at [%u][%u]", i, j);
	}

	for (i = 0; i < n; i++)
		rte_fastmem_free(ptrs[i]);
	for (i = 0; i < n_extra; i++)
		rte_fastmem_free(extra[i]);

	return TEST_SUCCESS;
}

static int
test_memory_limit_bulk_alloc_oom(void)
{
	const unsigned int bulk_n = 64;
	const unsigned int drain_max = 512;
	void *ptrs[bulk_n];
	void *drain[drain_max];
	unsigned int drained = 0;
	int rc;

	rte_fastmem_set_limit(SOCKET_ID_ANY, LIMIT_ONE_MZ);

	for (drained = 0; drained < drain_max; drained++) {
		drain[drained] = rte_fastmem_alloc(LIMIT_OBJ_SIZE, 0, 0);
		if (drain[drained] == NULL)
			break;
	}

	/* Free a few — enough for some but not bulk_n objects. */
	const unsigned int freed = RTE_MIN(drained, 4u);
	for (unsigned int i = 0; i < freed; i++)
		rte_fastmem_free(drain[--drained]);

	rc = rte_fastmem_alloc_bulk(ptrs, bulk_n, LIMIT_OBJ_SIZE, 0, 0);
	TEST_ASSERT(rc < 0, "bulk alloc should fail");

	for (unsigned int i = 0; i < drained; i++)
		rte_fastmem_free(drain[i]);

	return TEST_SUCCESS;
}

static int
test_memory_limit_recovery_after_free(void)
{
	const unsigned int max_ptrs = 512;
	void *ptrs[max_ptrs];
	unsigned int count = 0;
	rte_fastmem_set_limit(SOCKET_ID_ANY, LIMIT_ONE_MZ);

	for (count = 0; count < max_ptrs; count++) {
		ptrs[count] = rte_fastmem_alloc(LIMIT_OBJ_SIZE, 0, 0);
		if (ptrs[count] == NULL)
			break;
	}
	TEST_ASSERT(count > 0 && count < max_ptrs,
		"expected partial fill, got %u", count);

	const unsigned int half = count / 2;
	for (unsigned int i = 0; i < half; i++)
		rte_fastmem_free(ptrs[i]);

	for (unsigned int i = 0; i < half; i++) {
		ptrs[i] = rte_fastmem_alloc(LIMIT_OBJ_SIZE, 0, 0);
		TEST_ASSERT_NOT_NULL(ptrs[i], "recovery alloc[%u] failed", i);
	}

	for (unsigned int i = 0; i < count; i++)
		rte_fastmem_free(ptrs[i]);

	return TEST_SUCCESS;
}

struct limit_worker_args {
	unsigned int alloc_count;
	int result;
};

static int
limit_worker(void *arg)
{
	struct limit_worker_args *args = arg;
	const unsigned int max_ptrs = 128;
	void *ptrs[max_ptrs];
	unsigned int i;

	args->alloc_count = 0;

	for (i = 0; i < max_ptrs; i++) {
		ptrs[i] = rte_fastmem_alloc(LIMIT_OBJ_SIZE, 0, 0);
		if (ptrs[i] == NULL)
			break;
		memset(ptrs[i], 0xab, LIMIT_OBJ_SIZE);
		args->alloc_count++;
	}

	for (unsigned int j = 0; j < args->alloc_count; j++) {
		uint8_t *bytes = ptrs[j];
		for (size_t k = 0; k < LIMIT_OBJ_SIZE; k++) {
			if (bytes[k] != 0xab) {
				args->result = TEST_FAILED;
				return -1;
			}
		}
		rte_fastmem_free(ptrs[j]);
	}

	args->result = TEST_SUCCESS;
	return 0;
}

static int
test_memory_limit_multi_lcore_oom(void)
{
	struct limit_worker_args args[RTE_MAX_LCORE];
	unsigned int lcore_id;
	unsigned int worker_count = 0;
	RTE_LCORE_FOREACH_WORKER(lcore_id)
		worker_count++;

	if (worker_count < 2) {
		printf("Not enough workers (%u < 2), skipping\n", worker_count);
		return TEST_SKIPPED;
	}

	rte_fastmem_set_limit(SOCKET_ID_ANY, LIMIT_ONE_MZ);

	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		args[lcore_id].result = TEST_FAILED;
		rte_eal_remote_launch(limit_worker, &args[lcore_id], lcore_id);
	}

	rte_eal_mp_wait_lcore();

	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		TEST_ASSERT_EQUAL(args[lcore_id].result, TEST_SUCCESS,
			"worker on lcore %u failed", lcore_id);
	}

	struct rte_fastmem_stats stats;
	rte_fastmem_stats(&stats);
	TEST_ASSERT_EQUAL(stats.bytes_in_use, (uint64_t)0,
		"bytes_in_use not zero: %" PRIu64, stats.bytes_in_use);

	return TEST_SUCCESS;
}

static int
fastmem_setup(void)
{
	return rte_fastmem_init();
}

static void
fastmem_teardown(void)
{
	rte_fastmem_deinit();
}

static struct unit_test_suite fastmem_lifecycle_testsuite = {
	.suite_name = "fastmem lifecycle tests",
	.setup = NULL,
	.teardown = NULL,
	.unit_test_cases = {
		TEST_CASE(test_init_deinit),
		TEST_CASE(test_init_is_not_idempotent),
		TEST_CASE(test_deinit_without_init),
		TEST_CASE(test_max_size),
		TEST_CASE(test_reserve_without_init),
		TEST_CASE(test_cache_flush_without_init),
		TEST_CASE(test_classes),
		TEST_CASES_END()
	}
};

static struct unit_test_suite fastmem_functional_testsuite = {
	.suite_name = "fastmem functional tests",
	.setup = NULL,
	.teardown = NULL,
	.unit_test_cases = {
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_reserve_small),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_reserve_multiple_memzones),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_reserve_cumulative),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_reserve_invalid_socket),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_reserve_any_socket),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_alloc_too_big),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_alloc_invalid_align),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_alloc_free_small),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_alloc_free_various_sizes),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_alloc_alignment),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_alloc_zero_flag),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_alloc_reuse),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_alloc_many_in_class),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_alloc_socket),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_alloc_block_repurposing),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_alloc_block_repurposing_no_growth),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_free_null),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_alloc_content_integrity),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_alloc_align_too_big),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_alloc_align_one),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_alloc_socket_numa_placement),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_alloc_cross_socket_deinit),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_cache_flush),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_cache_exceeds_capacity),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_non_eal_thread),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_cache_flush_returns_memory),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_alloc_bulk_basic),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_alloc_bulk_zero_flag),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_alloc_bulk_exceeds_cache),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_alloc_bulk_socket),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_free_bulk),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_stats_class),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_stats_lcore),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_stats_lcore_class),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_stats_reset),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_mixed_lifetimes_multi_lcore),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_memory_limit_basic),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_memory_limit_alloc_exhaustion),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_memory_limit_zero_blocks_growth),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_memory_limit_below_current),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_memory_limit_socket_id_any),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_memory_limit_unlimited),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_memory_limit_alloc_integrity_under_oom),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_memory_limit_bulk_alloc_oom),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_memory_limit_recovery_after_free),
		TEST_CASE_ST(fastmem_setup, fastmem_teardown,
			test_memory_limit_multi_lcore_oom),
		TEST_CASES_END()
	}
};

static int
test_fastmem(void)
{
	int rc;

	rc = unit_test_suite_runner(&fastmem_lifecycle_testsuite);
	if (rc != 0)
		return rc;

	return unit_test_suite_runner(&fastmem_functional_testsuite);
}

REGISTER_FAST_TEST(fastmem_autotest, NOHUGE_SKIP, ASAN_OK, test_fastmem);

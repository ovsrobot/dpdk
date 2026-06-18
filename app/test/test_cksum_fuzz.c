/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Apple Inc.
 */

#include <stdio.h>
#include <string.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_hexdump.h>
#include <rte_cksum.h>
#include <rte_malloc.h>
#include <rte_random.h>

#include "test.h"

/*
 * Fuzz test for __rte_raw_cksum optimization.
 * Compares the optimized implementation against the original reference
 * implementation across random data of various lengths.
 */

#define DEFAULT_ITERATIONS 1000
#define MAX_TEST_LEN 65536  /* 64K to match GRO frame sizes */

/*
 * Original (reference) implementation of __rte_raw_cksum from DPDK v23.11.
 * This is retained here for comparison testing against the optimized version.
 */
static inline uint32_t
__rte_raw_cksum_reference(const void *buf, size_t len, uint32_t sum)
{
	const void *end;

	for (end = RTE_PTR_ADD(buf, RTE_ALIGN_FLOOR(len, sizeof(uint16_t)));
	     buf != end; buf = RTE_PTR_ADD(buf, sizeof(uint16_t))) {
		uint16_t v;

		memcpy(&v, buf, sizeof(uint16_t));
		sum += v;
	}

	/* if length is odd, keeping it byte order independent */
	if (unlikely(len % 2)) {
		uint16_t left = 0;

		memcpy(&left, end, 1);
		sum += left;
	}

	return sum;
}

static void
init_random_buffer(uint8_t *buf, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		buf[i] = (uint8_t)rte_rand();
}

static inline uint32_t
get_initial_sum(bool random_initial_sum)
{
	return random_initial_sum ? (rte_rand() & 0xFFFFFFFF) : 0;
}

/*
 * Test a single buffer length with specific alignment and initial sum
 */
static int
test_cksum_fuzz_length_aligned(size_t len, bool aligned, uint32_t initial_sum)
{
	uint8_t *data;
	uint8_t *buf;
	size_t alloc_size;
	uint32_t sum_ref, sum_opt;

	if (len == 0 && !aligned) {
		/* Skip unaligned test for zero length - nothing to test */
		return TEST_SUCCESS;
	}

	/* Allocate exact size for aligned, +1 for unaligned offset */
	alloc_size = aligned ? len : len + 1;
	if (alloc_size == 0)
		alloc_size = 1;  /* rte_malloc doesn't like 0 */

	data = rte_malloc(NULL, alloc_size, 64);
	if (data == NULL) {
		printf("Failed to allocate %zu bytes\n", alloc_size);
		return TEST_FAILED;
	}

	buf = aligned ? data : (data + 1);

	init_random_buffer(buf, len);

	sum_ref = __rte_raw_cksum_reference(buf, len, initial_sum);
	sum_opt = __rte_raw_cksum(buf, len, initial_sum);

	if (sum_ref != sum_opt) {
		printf("MISMATCH at len=%zu aligned='%s' initial_sum=0x%08x ref=0x%08x opt=0x%08x\n",
		       len, aligned ? "aligned" : "unaligned",
		       initial_sum, sum_ref, sum_opt);
		rte_hexdump(stdout, "failing buffer", buf, len);
		rte_free(data);
		return TEST_FAILED;
	}

	rte_free(data);
	return TEST_SUCCESS;
}

/*
 * Test a length with both alignments
 */
static int
test_cksum_fuzz_length(size_t len, uint32_t initial_sum)
{
	int rc;

	/* Test aligned */
	rc = test_cksum_fuzz_length_aligned(len, true, initial_sum);
	if (rc != TEST_SUCCESS)
		return rc;

	/* Test unaligned */
	rc = test_cksum_fuzz_length_aligned(len, false, initial_sum);

	return rc;
}

/*
 * Test specific edge case lengths
 */
static int
test_cksum_fuzz_edge_cases(void)
{
	/* Edge case lengths that might trigger bugs */
	static const size_t edge_lengths[] = {
		0, 1, 2, 3, 4, 5, 6, 7, 8,
		15, 16, 17,
		31, 32, 33,
		63, 64, 65,
		127, 128, 129,
		255, 256, 257,
		511, 512, 513,
		1023, 1024, 1025,
		1500, 1501,  /* MTU boundaries */
		2047, 2048, 2049,
		4095, 4096, 4097,
		8191, 8192, 8193,
		16383, 16384, 16385,
		32767, 32768, 32769,
		65534, 65535, 65536  /* 64K GRO boundaries */
	};
	unsigned int i;
	int rc;

	printf("Testing edge case lengths...\n");

	for (i = 0; i < RTE_DIM(edge_lengths); i++) {
		/* Test with zero initial sum */
		rc = test_cksum_fuzz_length(edge_lengths[i], 0);
		if (rc != TEST_SUCCESS)
			return rc;

		/* Test with random initial sum */
		rc = test_cksum_fuzz_length(edge_lengths[i], get_initial_sum(true));
		if (rc != TEST_SUCCESS)
			return rc;
	}

	return TEST_SUCCESS;
}

/*
 * Test random lengths with optional random initial sums
 */
static int
test_cksum_fuzz_random(unsigned int iterations, bool random_initial_sum)
{
	unsigned int i;
	int rc;

	printf("Testing random lengths (0-%d)%s...\n", MAX_TEST_LEN,
	       random_initial_sum ? " with random initial sums" : "");

	for (i = 0; i < iterations; i++) {
		size_t len = rte_rand() % (MAX_TEST_LEN + 1);

		rc = test_cksum_fuzz_length(len, get_initial_sum(random_initial_sum));
		if (rc != TEST_SUCCESS) {
			printf("Failed at len=%zu\n", len);
			return rc;
		}
	}

	return TEST_SUCCESS;
}

static int
test_cksum_fuzz(void)
{
	int rc;
	unsigned int iterations = DEFAULT_ITERATIONS;
	printf("### __rte_raw_cksum optimization fuzz test ###\n");
	printf("Iterations per test: %u\n\n", iterations);

	/* Test edge cases */
	rc = test_cksum_fuzz_edge_cases();
	if (rc != TEST_SUCCESS) {
		printf("Edge case test FAILED\n");
		return rc;
	}
	printf("Edge case test PASSED\n\n");

	/* Test random lengths with zero initial sum */
	rc = test_cksum_fuzz_random(iterations, false);
	if (rc != TEST_SUCCESS) {
		printf("Random length test FAILED\n");
		return rc;
	}
	printf("Random length test PASSED\n\n");

	/* Test random lengths with random initial sums */
	rc = test_cksum_fuzz_random(iterations, true);
	if (rc != TEST_SUCCESS) {
		printf("Random initial sum test FAILED\n");
		return rc;
	}
	printf("Random initial sum test PASSED\n\n");

	printf("All fuzz tests PASSED!\n");
	return TEST_SUCCESS;
}

REGISTER_FAST_TEST(cksum_fuzz_autotest, true, true, test_cksum_fuzz);

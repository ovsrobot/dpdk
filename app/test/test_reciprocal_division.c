/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Cavium, Inc
 */

#include "test.h"

#include <stdio.h>
#include <inttypes.h>

#include <rte_common.h>
#include <rte_random.h>
#include <rte_reciprocal.h>

#define MAX_ITERATIONS	(1ULL << 20)
#define DIVISORS_RANDOM 64

static int
test_u32_divide(uint32_t a, uint32_t d, struct rte_reciprocal r)
{
	uint32_t expected = a / d;
	uint32_t result = rte_reciprocal_divide(a, r);

	TEST_ASSERT_EQUAL(expected, result,
			  "%"PRIu32"/%"PRIu32" expected %"PRIu32" got %"PRIu32,
			  a, d, expected, result);
	return 0;
}

static int
test_reciprocal_u32(void)
{
	const uint32_t edge_div_u32[] = {
		1, 2, 3, 7, 0x7fffffff, 0x80000000, 0xfffffffe, UINT32_MAX,
	};
	unsigned int n_div = RTE_DIM(edge_div_u32) + DIVISORS_RANDOM;

	for (unsigned int di = 0; di < n_div; di++) {
		uint32_t d;
		if (di < RTE_DIM(edge_div_u32))
			d = edge_div_u32[di]; /* Make sure and test the edge cases */
		else
			d = rte_rand_max(UINT32_MAX - 1) + 1;

		struct rte_reciprocal r = rte_reciprocal_value(d);
		uint32_t qmax = UINT32_MAX / d;   /* largest q with q*d <= UINT32_MAX */
		if (d != 1)
			qmax++;

		for (unsigned int k = 0; k < MAX_ITERATIONS; k++) {
			uint32_t q = rte_rand_max(qmax);
			uint32_t val = q * d;           /* fits in u32 */

			/* Check around the value.
			 * Under and overflow of 32 bit value are fine here.
			 */
			if (test_u32_divide(val - 1, d, r) < 0 ||
			    test_u32_divide(val, d, r) < 0 ||
			    test_u32_divide(val + 1, d, r) < 0)
				return -1;
		}
	}
	return TEST_SUCCESS;
}

static int
test_u64_divide(uint64_t a, uint64_t d, const struct rte_reciprocal_u64 *r)
{
	uint64_t expected = a / d;
	uint64_t result = rte_reciprocal_divide_u64(a, r);

	TEST_ASSERT_EQUAL(expected, result,
			  "%"PRIu64"/%"PRIu64" expected %"PRIu64" got %"PRIu64,
			  a, d, expected, result);
	return 0;
}


static int
test_reciprocal_u64(void)
{
	const uint64_t edge_div_u64[] = {
		1, 2, 3, 7, 0x7fffffff, 0x80000000, 0xfffffffe, UINT64_MAX,
	};
	unsigned int n_div = RTE_DIM(edge_div_u64) + DIVISORS_RANDOM;

	for (unsigned int di = 0; di < n_div; di++) {
		uint64_t d;
		if (di < RTE_DIM(edge_div_u64))
			d = edge_div_u64[di];
		else
			d = rte_rand_max(UINT64_MAX - 1) + 1;

		struct rte_reciprocal_u64 r = rte_reciprocal_value_u64(d);
		uint64_t qmax = UINT64_MAX / d;   /* largest q with q*d <= UINT64_MAX */
		if (d != 1)
			++qmax;

		for (unsigned int k = 0; k < MAX_ITERATIONS; k++) {
			uint64_t q = rte_rand_max(qmax);
			uint64_t val = q * d;

			if (test_u64_divide(val - 1, d, &r) < 0 ||
			    test_u64_divide(val, d, &r) < 0 ||
			    test_u64_divide(val + 1, d, &r) < 0)
				return -1;

		}
	}
	return TEST_SUCCESS;
}

static int
test_reciprocal_u64_small(void)
{
	/* 64-bit division with a 32-bit-range divisor */
	uint64_t divisor_u64 = (rte_rand() >> 32) | 1;
	struct rte_reciprocal_u64 reci_u64 = rte_reciprocal_value_u64(divisor_u64);

	for (unsigned int i = 0; i < MAX_ITERATIONS; i++) {
		uint64_t dividend_u64 = rte_rand();
		uint64_t nresult_u64 = dividend_u64 / divisor_u64;
		uint64_t rresult_u64 = rte_reciprocal_divide_u64(dividend_u64, &reci_u64);

		TEST_ASSERT_EQUAL(nresult_u64, rresult_u64,
			"%"PRIu64"/%"PRIu64" = expected %"PRIu64" got %"PRIu64,
			dividend_u64, divisor_u64, nresult_u64, rresult_u64);
	}

	return TEST_SUCCESS;
}

static int
test_reciprocal_pow2(void)
{
	for (unsigned int i = 0; i < 32; i++) {
		uint64_t divisor_u64 = 1ULL << i;
		struct rte_reciprocal_u64 reci_u64 = rte_reciprocal_value_u64(divisor_u64);
		struct rte_reciprocal reci_u32 = rte_reciprocal_value((uint32_t)divisor_u64);

		for (unsigned int j = 0; j < MAX_ITERATIONS >> 4; j++) {
			uint64_t dividend_u64 = rte_rand();
			uint64_t nresult_u64 = dividend_u64 / divisor_u64;
			uint64_t rresult_u64 = rte_reciprocal_divide_u64(dividend_u64,
					&reci_u64);

			TEST_ASSERT_EQUAL(nresult_u64, rresult_u64,
				"u64 %"PRIu64"/%"PRIu64" = expected %"PRIu64" got %"PRIu64,
				dividend_u64, divisor_u64,
				nresult_u64, rresult_u64);

			uint32_t nresult_u32 = (dividend_u64 >> 32) / divisor_u64;
			uint32_t rresult_u32 = rte_reciprocal_divide(
					(dividend_u64 >> 32), reci_u32);

			TEST_ASSERT_EQUAL(nresult_u32, rresult_u32,
				"u32 %"PRIu64"/%"PRIu64" = expected %"PRIu32" got %"PRIu32,
				dividend_u64 >> 32, divisor_u64,
				nresult_u32, rresult_u32);
		}
	}

	for (unsigned int i = 32; i < 64; i++) {
		uint64_t divisor_u64 = 1ULL << i;
		struct rte_reciprocal_u64 reci_u64 = rte_reciprocal_value_u64(divisor_u64);

		for (unsigned int j = 0; j < MAX_ITERATIONS >> 4; j++) {
			uint64_t dividend_u64 = rte_rand();
			uint64_t nresult_u64 = dividend_u64 / divisor_u64;
			uint64_t rresult_u64 = rte_reciprocal_divide_u64(dividend_u64,
					&reci_u64);

			TEST_ASSERT_EQUAL(nresult_u64, rresult_u64,
				"u64 %"PRIu64"/%"PRIu64" = expected %"PRIu64" got %"PRIu64,
				dividend_u64, divisor_u64,
				nresult_u64, rresult_u64);
		}
	}

	return TEST_SUCCESS;
}

static struct unit_test_suite reciprocal_tests = {
	.suite_name = "reciprocal division autotest",
	.setup = NULL,
	.teardown = NULL,
	.unit_test_cases = {
		TEST_CASE(test_reciprocal_u32),
		TEST_CASE(test_reciprocal_u64),
		TEST_CASE(test_reciprocal_u64_small),
		TEST_CASE(test_reciprocal_pow2),
		TEST_CASES_END()
	}
};

static int
test_reciprocal(void)
{
	return unit_test_suite_runner(&reciprocal_tests);
}

REGISTER_FAST_TEST(reciprocal_division_autotest, NOHUGE_OK, ASAN_OK, test_reciprocal);

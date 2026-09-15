/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Stephen Hemminger
 */

#include <inttypes.h>
#include <stdbool.h>
#include <string.h>

#include <rte_common.h>
#include <rte_random.h>

#include "test.h"

/* Larger than the chunk size rte_random_bytes() splits requests into,
 * and not a multiple of it, so the loop is exercised.
 */
#define BIG_LEN (3 * 256 + 7)

/* Fill pattern, any byte left untouched by the call is visible. */
#define FILL_BYTE 0xa5

static bool
all_equal(const uint8_t *buf, size_t len, uint8_t val)
{
	size_t i;

	for (i = 0; i < len; i++)
		if (buf[i] != val)
			return false;

	return true;
}

static int
test_random_bytes_zero(void)
{
	uint8_t buf[8];

	memset(buf, FILL_BYTE, sizeof(buf));

	TEST_ASSERT(rte_random_bytes(buf, 0) == 0,
		    "zero length request failed");
	TEST_ASSERT(all_equal(buf, sizeof(buf), FILL_BYTE),
		    "zero length request wrote to the buffer");

	return TEST_SUCCESS;
}

static int
test_random_bytes_small(void)
{
	uint8_t buf[32];
	unsigned int i;

	/* A single byte is worth checking on its own, it is the
	 * smallest request that must still be filled.
	 */
	for (i = 1; i <= sizeof(buf); i++) {
		memset(buf, FILL_BYTE, sizeof(buf));

		TEST_ASSERT(rte_random_bytes(buf, i) == 0,
			    "request of %u bytes failed", i);
		TEST_ASSERT(all_equal(buf + i, sizeof(buf) - i, FILL_BYTE),
			    "request of %u bytes wrote past the end", i);
	}

	return TEST_SUCCESS;
}

static int
test_random_bytes_large(void)
{
	uint8_t buf[BIG_LEN + 8];

	memset(buf, FILL_BYTE, sizeof(buf));

	/* Must be split internally and still filled completely. */
	TEST_ASSERT(rte_random_bytes(buf, BIG_LEN) == 0,
		    "request of %d bytes failed", BIG_LEN);
	TEST_ASSERT(all_equal(buf + BIG_LEN, sizeof(buf) - BIG_LEN, FILL_BYTE),
		    "request of %d bytes wrote past the end", BIG_LEN);
	TEST_ASSERT(!all_equal(buf, BIG_LEN, 0),
		    "request of %d bytes returned all zero", BIG_LEN);
	TEST_ASSERT(!all_equal(buf, BIG_LEN, FILL_BYTE),
		    "request of %d bytes left the buffer untouched", BIG_LEN);

	return TEST_SUCCESS;
}

static int
test_random_bytes_distinct(void)
{
	uint8_t a[64], b[64];

	TEST_ASSERT(rte_random_bytes(a, sizeof(a)) == 0, "first call failed");
	TEST_ASSERT(rte_random_bytes(b, sizeof(b)) == 0, "second call failed");

	/* The chance of a false failure here is 2^-512. */
	TEST_ASSERT(memcmp(a, b, sizeof(a)) != 0,
		    "two calls returned the same bytes");

	return TEST_SUCCESS;
}

static int
test_rand(void)
{
	unsigned int i;
	uint64_t any_set = 0;
	uint64_t always_set = UINT64_MAX;

	/* Every bit position should be both set and clear at some
	 * point, which catches a generator that is stuck or that only
	 * ever fills part of the word.
	 */
	for (i = 0; i < 100; i++) {
		uint64_t v = rte_rand();

		any_set |= v;
		always_set &= v;
	}

	TEST_ASSERT(any_set == UINT64_MAX,
		    "some bits were never set: %#" PRIx64, any_set);
	TEST_ASSERT(always_set == 0,
		    "some bits were always set: %#" PRIx64, always_set);

	return TEST_SUCCESS;
}

static int
test_rand32(void)
{
	unsigned int i;
	uint32_t any_set = 0;
	uint32_t always_set = UINT32_MAX;

	/* Every bit position should be both set and clear at some
	 * point, which catches a generator that is stuck or that only
	 * ever fills part of the word.
	 */
	for (i = 0; i < 100; i++) {
		uint32_t v = rte_rand32();

		any_set |= v;
		always_set &= v;
	}

	TEST_ASSERT(any_set == UINT32_MAX,
		    "some bits were never set: %#x", any_set);
	TEST_ASSERT(always_set == 0,
		    "some bits were always set: %#x", always_set);

	return TEST_SUCCESS;
}

/* Bounds worth covering: the power of two case is handled by masking,
 * everything else goes through the rejection loop.
 */
static const uint64_t rand_max_bounds[] = {
	2, 3, 17, 64, 1000, 1ULL << 32, (1ULL << 63) + 1, UINT64_MAX,
};

static int
test_rand_max(void)
{
	unsigned int i, j;

	/* A bound of one leaves only a single legal value. */
	for (i = 0; i < 100; i++)
		TEST_ASSERT(rte_rand_max(1) == 0,
			    "upper bound of 1 returned a non-zero value");

	for (i = 0; i < RTE_DIM(rand_max_bounds); i++) {
		uint64_t bound = rand_max_bounds[i];

		for (j = 0; j < 10000; j++) {
			uint64_t v = rte_rand_max(bound);

			TEST_ASSERT(v < bound,
				    "value %" PRIu64 " is not less than the upper bound %" PRIu64,
				    v, bound);
		}
	}

	return TEST_SUCCESS;
}

static int
test_rand_max_spread(void)
{
	unsigned int i;
	bool seen[3] = { false, false, false };

	/* With a small bound every value has to show up quickly. The
	 * chance of missing one in 100 draws is 3 * (2/3)^100.
	 */
	for (i = 0; i < 100; i++)
		seen[rte_rand_max(RTE_DIM(seen))] = true;

	for (i = 0; i < RTE_DIM(seen); i++)
		TEST_ASSERT(seen[i], "value %u was never generated", i);

	return TEST_SUCCESS;
}

static int
test_drand(void)
{
	unsigned int i;
	bool low = false, high = false;

	for (i = 0; i < 100; i++) {
		double v = rte_drand();

		TEST_ASSERT(v >= 0.0 && v < 1.0,
			    "value %f is outside of [0.0, 1.0)", v);

		if (v < 0.5)
			low = true;
		else
			high = true;
	}

	/* Both halves of the interval have to be used, which catches a
	 * generator stuck on a constant. Missing one has a probability
	 * of 2^-100.
	 */
	TEST_ASSERT(low, "no value below 0.5 was generated");
	TEST_ASSERT(high, "no value of 0.5 or above was generated");

	return TEST_SUCCESS;
}

/* Record a sequence that uses every generator function, so that a
 * function left out of the shared state would show up here.
 */
static void
record_sequence(uint64_t seed, uint64_t *out, unsigned int n)
{
	unsigned int i;

	rte_srand(seed);

	for (i = 0; i < n; i += 4) {
		out[i] = rte_rand();
		out[i + 1] = rte_rand32();
		out[i + 2] = rte_rand_max(1000);
		out[i + 3] = (uint64_t)(rte_drand() * (1ULL << 53));
	}
}

static int
test_srand_repeatable(void)
{
	uint64_t first[16], second[16];

	record_sequence(42, first, RTE_DIM(first));
	record_sequence(42, second, RTE_DIM(second));

	TEST_ASSERT(memcmp(first, second, sizeof(first)) == 0,
		    "same seed produced a different sequence");

	record_sequence(43, second, RTE_DIM(second));

	TEST_ASSERT(memcmp(first, second, sizeof(first)) != 0,
		    "different seed produced the same sequence");

	return TEST_SUCCESS;
}

static struct unit_test_suite random_test_suite = {
	.suite_name = "random autotest",
	.setup = NULL,
	.teardown = NULL,
	.unit_test_cases = {
		TEST_CASE(test_random_bytes_zero),
		TEST_CASE(test_random_bytes_small),
		TEST_CASE(test_random_bytes_large),
		TEST_CASE(test_random_bytes_distinct),
		TEST_CASE(test_rand),
		TEST_CASE(test_rand32),
		TEST_CASE(test_rand_max),
		TEST_CASE(test_rand_max_spread),
		TEST_CASE(test_drand),
		TEST_CASE(test_srand_repeatable),
		TEST_CASES_END()
	}
};

static int
test_random(void)
{
	return unit_test_suite_runner(&random_test_suite);
}

REGISTER_FAST_TEST(random_autotest, NOHUGE_OK, ASAN_OK, test_random);

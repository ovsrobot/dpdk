/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Ericsson AB
 */

#include <errno.h>
#include <string.h>
#include <unistd.h>
#ifndef RTE_EXEC_ENV_WINDOWS
#include <sys/random.h>
#endif

#include <rte_bitops.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_lcore_var.h>
#include <rte_random.h>

#include <eal_export.h>
#include <rte_os_shim.h>
#include "eal_private.h"

struct __rte_cache_aligned rte_rand_state {
	uint64_t z1;
	uint64_t z2;
	uint64_t z3;
	uint64_t z4;
	uint64_t z5;
};

static RTE_LCORE_VAR_HANDLE(struct rte_rand_state, rand_state);

/* instance to be shared by all unregistered non-EAL threads */
static struct rte_rand_state unregistered_rand_state;

/* SplitMix64, used to expand the seed into the generator state.
 * It has a full 64 bit period and good avalanche, so all the bits
 * of the seed affect every word of the resulting state.
 *
 * See "Fast Splittable Pseudorandom Number Generators" by Steele,
 * Lea and Flood, https://doi.org/10.1145/2714064.2660195
 */
static uint64_t
__rte_rand_splitmix64(uint64_t *state)
{
	uint64_t z;

	z = (*state += 0x9E3779B97F4A7C15ULL);
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
	z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;

	return z ^ (z >> 31);
}

static uint64_t
__rte_rand_lfsr258_gen_seed(uint64_t *state, uint64_t min_value)
{
	/* LFSR258 degenerates unless each word exceeds its threshold.
	 * All thresholds are powers of two, so a bitwise or is enough
	 * and keeps the remaining bits untouched.
	 */
	return __rte_rand_splitmix64(state) | min_value;
}

static void
__rte_srand_lfsr258(uint64_t seed, struct rte_rand_state *state)
{
	uint64_t mix_state = seed;

	state->z1 = __rte_rand_lfsr258_gen_seed(&mix_state, 2UL);
	state->z2 = __rte_rand_lfsr258_gen_seed(&mix_state, 512UL);
	state->z3 = __rte_rand_lfsr258_gen_seed(&mix_state, 4096UL);
	state->z4 = __rte_rand_lfsr258_gen_seed(&mix_state, 131072UL);
	state->z5 = __rte_rand_lfsr258_gen_seed(&mix_state, 8388608UL);
}

RTE_EXPORT_SYMBOL(rte_srand)
void
rte_srand(uint64_t seed)
{
	unsigned int lcore_id;
	uint64_t mix_state;

	/* Mix in the lcore id so that each lcore gets an unrelated
	 * sequence. Adding it to the seed would leave neighbouring
	 * lcores with nearly identical generator state.
	 */
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		struct rte_rand_state *lcore_state =
			RTE_LCORE_VAR_LCORE(lcore_id, rand_state);

		mix_state = seed + lcore_id;
		__rte_srand_lfsr258(__rte_rand_splitmix64(&mix_state),
				    lcore_state);
	}

	mix_state = seed + lcore_id;
	__rte_srand_lfsr258(__rte_rand_splitmix64(&mix_state),
			    &unregistered_rand_state);
}

static __rte_always_inline uint64_t
__rte_rand_lfsr258_comp(uint64_t z, uint64_t a, uint64_t b, uint64_t c,
			uint64_t d)
{
	return ((z & c) << d) ^ (((z << a) ^ z) >> b);
}

/* Based on L’Ecuyer, P.: Tables of maximally equidistributed combined
 * LFSR generators.
 */

static __rte_always_inline uint64_t
__rte_rand_lfsr258(struct rte_rand_state *state)
{
	state->z1 = __rte_rand_lfsr258_comp(state->z1, 1UL, 53UL,
					    18446744073709551614UL, 10UL);
	state->z2 = __rte_rand_lfsr258_comp(state->z2, 24UL, 50UL,
					    18446744073709551104UL, 5UL);
	state->z3 = __rte_rand_lfsr258_comp(state->z3, 3UL, 23UL,
					    18446744073709547520UL, 29UL);
	state->z4 = __rte_rand_lfsr258_comp(state->z4, 5UL, 24UL,
					    18446744073709420544UL, 23UL);
	state->z5 = __rte_rand_lfsr258_comp(state->z5, 3UL, 33UL,
					    18446744073701163008UL, 8UL);

	return state->z1 ^ state->z2 ^ state->z3 ^ state->z4 ^ state->z5;
}

static __rte_always_inline
struct rte_rand_state *__rte_rand_get_state(void)
{
	unsigned int idx;

	idx = rte_lcore_id();

	if (unlikely(idx == LCORE_ID_ANY)) {
		/* Make sure rte_*rand() was called after rte_eal_init(). */
		RTE_ASSERT(rand_state != NULL);
		return &unregistered_rand_state;
	}

	return RTE_LCORE_VAR(rand_state);
}

RTE_EXPORT_SYMBOL(rte_rand)
uint64_t
rte_rand(void)
{
	struct rte_rand_state *state;

	state = __rte_rand_get_state();

	return __rte_rand_lfsr258(state);
}

RTE_EXPORT_SYMBOL(rte_rand32)
uint32_t
rte_rand32(void)
{
	/* Use the high bits, they are the ones that stay good if the
	 * underlying generator is ever changed.
	 */
	return (uint32_t)(rte_rand() >> 32);
}

RTE_EXPORT_SYMBOL(rte_rand_max)
uint64_t
rte_rand_max(uint64_t upper_bound)
{
	struct rte_rand_state *state;
	uint8_t ones;
	uint8_t leading_zeros;
	uint64_t mask = ~((uint64_t)0);
	uint64_t res;

	if (unlikely(upper_bound < 2))
		return 0;

	state = __rte_rand_get_state();

	ones = rte_popcount64(upper_bound);

	/* Handle power-of-2 upper_bound as a special case, since it
	 * has no bias issues.
	 */
	if (unlikely(ones == 1))
		return __rte_rand_lfsr258(state) & (upper_bound - 1);

	/* The approach to avoiding bias is to create a mask that
	 * stretches beyond the request value range, and up to the
	 * next power-of-2. In case the masked generated random value
	 * is equal to or greater than the upper bound, just discard
	 * the value and generate a new one.
	 */

	leading_zeros = rte_clz64(upper_bound);
	mask >>= leading_zeros;

	do {
		res = __rte_rand_lfsr258(state) & mask;
	} while (unlikely(res >= upper_bound));

	return res;
}

RTE_EXPORT_SYMBOL(rte_drand)
double
rte_drand(void)
{
	static const uint64_t denom = (uint64_t)1 << 53;
	uint64_t rand64 = rte_rand();

	/*
	 * The double mantissa only has 53 bits, so we uniformly mask off the
	 * high 11 bits and then floating-point divide by 2^53 to achieve a
	 * result in [0, 1).
	 *
	 * We are not allowed to emit 1.0, so denom must be one greater than
	 * the possible range of the preceding step.
	 */

	rand64 &= denom - 1;
	return (double)rand64 / denom;
}

/* Requests of at most this size are guaranteed to return in full
 * once the random source has been initialized. Larger requests are
 * split so that callers do not have to care about the limit.
 */
#define RANDOM_BYTES_CHUNK 256

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_random_bytes, 26.11)
int
rte_random_bytes(void *buf, size_t len)
{
	uint8_t *ptr = buf;

	while (len > 0) {
		size_t chunk = RTE_MIN(len, (size_t)RANDOM_BYTES_CHUNK);
		ssize_t ret;

		ret = getrandom(ptr, chunk, 0);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}

		/* Should not happen, a bounded request either blocks
		 * until it can be satisfied in full or fails.
		 */
		if (ret == 0)
			return -EIO;

		ptr += ret;
		len -= ret;
	}

	return 0;
}

static uint64_t
__rte_random_initial_seed(void)
{
	int ge_rc;
	uint64_t ge_seed;

	ge_rc = getentropy(&ge_seed, sizeof(ge_seed));

	if (ge_rc == 0)
		return ge_seed;

	/* fallback: seed using rdtsc */
	EAL_LOG(ERR, "getentropy() failed (%s), seeding PRNG from TSC: seed has low entropy",
		strerror(errno));
	return rte_get_tsc_cycles();
}

void
eal_rand_init(void)
{
	uint64_t seed;

	RTE_LCORE_VAR_ALLOC(rand_state);

	seed = __rte_random_initial_seed();

	rte_srand(seed);
}

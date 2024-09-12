/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Ericsson AB
 */

#include <stdio.h>

#include <rte_cycles.h>
#include <rte_lcore_var.h>
#include <rte_per_lcore.h>
#include <rte_random.h>

#include "test.h"

struct lcore_state {
	uint64_t a;
	uint64_t b;
	uint64_t sum;
};

static void
init(struct lcore_state *state)
{
	state->a = rte_rand();
	state->b = rte_rand();
	state->sum = 0;
}

static __rte_always_inline void
update(struct lcore_state *state)
{
	state->sum += state->a * state->b;
}

static RTE_DEFINE_PER_LCORE(struct lcore_state, tls_lcore_state);

static void
tls_init(void)
{
	init(&RTE_PER_LCORE(tls_lcore_state));
}

static __rte_noinline void
tls_update(void)
{
	update(&RTE_PER_LCORE(tls_lcore_state));
}

struct __rte_cache_aligned lcore_state_aligned {
	uint64_t a;
	uint64_t b;
	uint64_t sum;
};

static struct lcore_state_aligned sarray_lcore_state[RTE_MAX_LCORE];

static void
sarray_init(void)
{
	struct lcore_state *state =
		(struct lcore_state *)&sarray_lcore_state[rte_lcore_id()];

	init(state);
}

static __rte_noinline void
sarray_update(void)
{
	struct lcore_state *state =
		(struct lcore_state *)&sarray_lcore_state[rte_lcore_id()];

	update(state);
}

RTE_LCORE_VAR_HANDLE(struct lcore_state, lvar_lcore_state);

static void
lvar_init(void)
{
	RTE_LCORE_VAR_ALLOC(lvar_lcore_state);

	struct lcore_state *state = RTE_LCORE_VAR_VALUE(lvar_lcore_state);

	init(state);
}

static __rte_noinline void
lvar_update(void)
{
	struct lcore_state *state = RTE_LCORE_VAR_VALUE(lvar_lcore_state);

	update(state);
}

#define ITERATIONS UINT64_C(10000000)

static double
benchmark_access_method(void (*init_fun)(void), void (*update_fun)(void))
{
	uint64_t i;
	uint64_t start;
	uint64_t end;
	double latency;

	init_fun();

	start = rte_get_timer_cycles();

	for (i = 0; i < ITERATIONS; i++)
		update_fun();

	end = rte_get_timer_cycles();

	latency = ((end - start) / (double)rte_get_timer_hz()) / ITERATIONS;

	return latency;
}

static int
test_lcore_var_access(void)
{
	/* Note: the potential performance benefit of lcore variables
	 * compared thread-local storage or the use of statically
	 * sized, lcore id-indexed arrays are not shorter latencies in
	 * a scenario with low cache pressure, but rather fewer cache
	 * misses in a real-world scenario, with extensive cache
	 * usage. These tests just tries to assure that the lcore
	 * variable overhead is not significantly greater other
	 * alternatives, when the per-lcore data is in L1.
	 */
	double tls_latency;
	double sarray_latency;
	double lvar_latency;

	tls_latency = benchmark_access_method(tls_init, tls_update);
	sarray_latency = benchmark_access_method(sarray_init, sarray_update);
	lvar_latency = benchmark_access_method(lvar_init, lvar_update);

	printf("Latencies [ns/update]\n");
	printf("Thread-local storage  Static array  Lcore variables\n");
	printf("%20.1f %13.1f %16.1f\n", tls_latency * 1e9,
	       sarray_latency * 1e9, lvar_latency * 1e9);

	return TEST_SUCCESS;
}

static struct unit_test_suite lcore_var_testsuite = {
	.suite_name = "lcore variable perf autotest",
	.unit_test_cases = {
		TEST_CASE(test_lcore_var_access),
		TEST_CASES_END()
	},
};

static int
test_lcore_var_perf(void)
{
	return unit_test_suite_runner(&lcore_var_testsuite);
}

REGISTER_PERF_TEST(lcore_var_perf_autotest, test_lcore_var_perf);

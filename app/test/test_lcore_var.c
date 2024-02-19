/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Ericsson AB
 */

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <rte_launch.h>
#include <rte_lcore_var.h>
#include <rte_random.h>

#include "test.h"

#define MIN_LCORES 2

RTE_LCORE_VAR_HANDLE(int, test_int);
RTE_LCORE_VAR_HANDLE(char, test_char);
RTE_LCORE_VAR_HANDLE(long, test_long_sized);
RTE_LCORE_VAR_HANDLE(short, test_short);
RTE_LCORE_VAR_HANDLE(long, test_long_sized_aligned);

struct int_checker_state {
	int old_value;
	int new_value;
	bool success;
};

static bool
rand_bool(void)
{
	return rte_rand() & 1;
}

static void
rand_blk(void *blk, size_t size)
{
	size_t i;

	for (i = 0; i < size; i++)
		((unsigned char *)blk)[i] = (unsigned char)rte_rand();
}

static bool
is_ptr_aligned(const void *ptr, size_t align)
{
	return ptr != NULL ? (uintptr_t)ptr % align == 0 : false;
}

static int
check_int(void *arg)
{
	struct int_checker_state *state = arg;

	int *ptr = RTE_LCORE_VAR_PTR(test_int);

	bool naturally_aligned = is_ptr_aligned(ptr, sizeof(int));

	bool equal;

	if (rand_bool())
		equal = RTE_LCORE_VAR_GET(test_int) == state->old_value;
	else
		equal = *(RTE_LCORE_VAR_PTR(test_int)) == state->old_value;

	state->success = equal && naturally_aligned;

	if (rand_bool())
		RTE_LCORE_VAR_SET(test_int, state->new_value);
	else
		*ptr = state->new_value;

	return 0;
}

RTE_LCORE_VAR_INIT(test_int);
RTE_LCORE_VAR_INIT(test_char);
RTE_LCORE_VAR_INIT_SIZE(test_long_sized, 32);
RTE_LCORE_VAR_INIT(test_short);
RTE_LCORE_VAR_INIT_SIZE_ALIGN(test_long_sized_aligned, sizeof(long),
			      RTE_CACHE_LINE_SIZE);

static int
test_int_lvar(void)
{
	unsigned int lcore_id;

	struct int_checker_state states[RTE_MAX_LCORE] = {};

	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		struct int_checker_state *state = &states[lcore_id];

		state->old_value = (int)rte_rand();
		state->new_value = (int)rte_rand();

		RTE_LCORE_VAR_LCORE_SET(lcore_id, test_int, state->old_value);
	}

	RTE_LCORE_FOREACH_WORKER(lcore_id)
		rte_eal_remote_launch(check_int, &states[lcore_id], lcore_id);

	rte_eal_mp_wait_lcore();

	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		struct int_checker_state *state = &states[lcore_id];

		TEST_ASSERT(state->success, "Unexpected value "
			    "encountered on lcore %d", lcore_id);

		TEST_ASSERT_EQUAL(state->new_value,
				  RTE_LCORE_VAR_LCORE_GET(lcore_id, test_int),
				  "Lcore %d failed to update int", lcore_id);
	}

	/* take the opportunity to test the foreach macro */
	int *v;
	lcore_id = 0;
	RTE_LCORE_VAR_FOREACH_VALUE(v, test_int) {
		TEST_ASSERT_EQUAL(states[lcore_id].new_value, *v,
				  "Unexpected value on lcore %d during "
				  "iteration", lcore_id);
		lcore_id++;
	}

	return TEST_SUCCESS;
}

static int
test_sized_alignment(void)
{
	long *v;

	RTE_LCORE_VAR_FOREACH_VALUE(v, test_long_sized) {
		TEST_ASSERT(is_ptr_aligned(v, alignof(long)),
			    "Type-derived alignment failed");
	}

	RTE_LCORE_VAR_FOREACH_VALUE(v, test_long_sized_aligned) {
		TEST_ASSERT(is_ptr_aligned(v, RTE_CACHE_LINE_SIZE),
			    "Explicit alignment failed");
	}

	return TEST_SUCCESS;
}

/* private, larger, struct */
#define TEST_STRUCT_DATA_SIZE 1234

struct test_struct {
	uint8_t data[TEST_STRUCT_DATA_SIZE];
};

static RTE_LCORE_VAR_HANDLE(char, before_struct);
static RTE_LCORE_VAR_HANDLE(struct test_struct, test_struct);
static RTE_LCORE_VAR_HANDLE(char, after_struct);

struct struct_checker_state {
	struct test_struct old_value;
	struct test_struct new_value;
	bool success;
};

static int check_struct(void *arg)
{
	struct struct_checker_state *state = arg;

	struct test_struct *lcore_struct = RTE_LCORE_VAR_PTR(test_struct);

	bool properly_aligned =
		is_ptr_aligned(test_struct, alignof(struct test_struct));

	bool equal = memcmp(lcore_struct->data, state->old_value.data,
			    TEST_STRUCT_DATA_SIZE) == 0;

	state->success = equal && properly_aligned;

	memcpy(lcore_struct->data, state->new_value.data,
	       TEST_STRUCT_DATA_SIZE);

	return 0;
}

static int
test_struct_lvar(void)
{
	unsigned int lcore_id;

	RTE_LCORE_VAR_ALLOC(before_struct);
	RTE_LCORE_VAR_ALLOC(test_struct);
	RTE_LCORE_VAR_ALLOC(after_struct);

	struct struct_checker_state states[RTE_MAX_LCORE];

	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		struct struct_checker_state *state = &states[lcore_id];

		rand_blk(state->old_value.data, TEST_STRUCT_DATA_SIZE);
		rand_blk(state->new_value.data, TEST_STRUCT_DATA_SIZE);

		memcpy(RTE_LCORE_VAR_LCORE_PTR(lcore_id, test_struct)->data,
		       state->old_value.data, TEST_STRUCT_DATA_SIZE);
	}

	RTE_LCORE_FOREACH_WORKER(lcore_id)
		rte_eal_remote_launch(check_struct, &states[lcore_id],
				      lcore_id);

	rte_eal_mp_wait_lcore();

	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		struct struct_checker_state *state = &states[lcore_id];
		struct test_struct *lstruct =
			RTE_LCORE_VAR_LCORE_PTR(lcore_id, test_struct);

		TEST_ASSERT(state->success, "Unexpected value encountered on "
			    "lcore %d", lcore_id);

		bool equal = memcmp(lstruct->data, state->new_value.data,
				    TEST_STRUCT_DATA_SIZE) == 0;

		TEST_ASSERT(equal, "Lcore %d failed to update struct",
			    lcore_id);
	}

	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		char before = RTE_LCORE_VAR_LCORE_GET(lcore_id, before_struct);
		char after = RTE_LCORE_VAR_LCORE_GET(lcore_id, after_struct);

		TEST_ASSERT_EQUAL(before, 0, "Lcore variable before test "
				  "struct was modified on lcore %d", lcore_id);
		TEST_ASSERT_EQUAL(after, 0, "Lcore variable after test "
				  "struct was modified on lcore %d", lcore_id);
	}

	return TEST_SUCCESS;
}

#define TEST_ARRAY_SIZE 99

typedef uint16_t test_array_t[TEST_ARRAY_SIZE];

static void test_array_init_rand(test_array_t a)
{
	size_t i;
	for (i = 0; i < TEST_ARRAY_SIZE; i++)
		a[i] = (uint16_t)rte_rand();
}

static bool test_array_equal(test_array_t a, test_array_t b)
{
	size_t i;
	for (i = 0; i < TEST_ARRAY_SIZE; i++) {
		if (a[i] != b[i])
			return false;
	}
	return true;
}

static void test_array_copy(test_array_t dst, const test_array_t src)
{
	size_t i;
	for (i = 0; i < TEST_ARRAY_SIZE; i++)
		dst[i] = src[i];
}

static RTE_LCORE_VAR_HANDLE(char, before_array);
static RTE_LCORE_VAR_HANDLE(test_array_t, test_array);
static RTE_LCORE_VAR_HANDLE(char, after_array);

struct array_checker_state
{
	test_array_t old_value;
	test_array_t new_value;
	bool success;
};

static int check_array(void *arg)
{
	struct array_checker_state *state = arg;

	test_array_t *lcore_array = RTE_LCORE_VAR_PTR(test_array);

	bool properly_aligned =
		is_ptr_aligned(lcore_array, alignof(test_array_t));

	bool equal = test_array_equal(*lcore_array, state->old_value);

	state->success = equal && properly_aligned;

	test_array_copy(*lcore_array, state->new_value);

	return 0;
}

static int
test_array_lvar(void)
{
	unsigned int lcore_id;

	RTE_LCORE_VAR_ALLOC(before_array);
	RTE_LCORE_VAR_ALLOC(test_array);
	RTE_LCORE_VAR_ALLOC(after_array);

	struct array_checker_state states[RTE_MAX_LCORE];

	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		struct array_checker_state *state = &states[lcore_id];

		test_array_init_rand(state->new_value);
		test_array_init_rand(state->old_value);

		test_array_copy(RTE_LCORE_VAR_LCORE_GET(lcore_id, test_array),
				state->old_value);
	}

	RTE_LCORE_FOREACH_WORKER(lcore_id)
		rte_eal_remote_launch(check_array, &states[lcore_id],
				      lcore_id);

	rte_eal_mp_wait_lcore();

	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		struct array_checker_state *state = &states[lcore_id];
		test_array_t *larray =
			RTE_LCORE_VAR_LCORE_PTR(lcore_id, test_array);

		TEST_ASSERT(state->success, "Unexpected value encountered on "
			    "lcore %d", lcore_id);

		bool equal = test_array_equal(*larray, state->new_value);

		TEST_ASSERT(equal, "Lcore %d failed to update array",
			    lcore_id);
	}

	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		char before = RTE_LCORE_VAR_LCORE_GET(lcore_id, before_array);
		char after = RTE_LCORE_VAR_LCORE_GET(lcore_id, after_array);

		TEST_ASSERT_EQUAL(before, 0, "Lcore variable before test "
				  "array was modified on lcore %d", lcore_id);
		TEST_ASSERT_EQUAL(after, 0, "Lcore variable after test "
				  "array was modified on lcore %d", lcore_id);
	}

	return TEST_SUCCESS;
}

#define MANY_LVARS (RTE_MAX_LCORE_VAR / 2)

static int
test_many_lvars(void)
{
	void **handlers = malloc(sizeof(void *) * MANY_LVARS);
	int i;

	TEST_ASSERT(handlers != NULL, "Unable to allocate memory");

	for (i = 0; i < MANY_LVARS; i++) {
		void *handle = rte_lcore_var_alloc(1, 1);

		uint8_t *b = __RTE_LCORE_VAR_LCORE_PTR(rte_lcore_id(), handle);

		*b = (uint8_t)i;

		handlers[i] = handle;
	}

	for (i = 0; i < MANY_LVARS; i++) {
		unsigned int lcore_id;

		RTE_LCORE_FOREACH_WORKER(lcore_id) {
			uint8_t *b = __RTE_LCORE_VAR_LCORE_PTR(rte_lcore_id(),
							       handlers[i]);
			TEST_ASSERT_EQUAL((uint8_t)i, *b,
					  "Unexpected lcore variable value.");
		}
	}

	free(handlers);

	return TEST_SUCCESS;
}

static struct unit_test_suite lcore_var_testsuite = {
	.suite_name = "lcore variable autotest",
	.unit_test_cases = {
		TEST_CASE(test_int_lvar),
		TEST_CASE(test_sized_alignment),
		TEST_CASE(test_struct_lvar),
		TEST_CASE(test_array_lvar),
		TEST_CASE(test_many_lvars),
		TEST_CASES_END()
	},
};

static int test_lcore_var(void)
{
	if (rte_lcore_count() < MIN_LCORES) {
		printf("Not enough cores for lcore_var_autotest; expecting at "
		       "least %d.\n", MIN_LCORES);
		return TEST_SKIPPED;
	}

	return unit_test_suite_runner(&lcore_var_testsuite);
}

REGISTER_FAST_TEST(lcore_var_autotest, true, false, test_lcore_var);

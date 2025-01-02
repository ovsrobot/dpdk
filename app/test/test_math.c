/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2025 Microsoft Corporation
 */

#include <rte_math.h>
#include <rte_debug.h>

#include "test.h"

/* Check condition and return if true. */
#define TEST_MATH_RETURN_IF_ERROR(X) \
do { \
	if (X) { \
		return -1; \
	} \
} while (0)

RTE_LOG_REGISTER(math_logtype_test, test.math, INFO);

static int
verify_add_overflow_u8(uint8_t a, uint8_t b,
		uint8_t expected_res, uint8_t expected_overflow)
{
	uint8_t res;
	uint8_t overflow = __rte_add_overflow_u8(a, b, &res);
	RTE_TEST_ASSERT_EQUAL(res, expected_res,
			"ERROR: __rte_add_overflow_u8(0x%x, 0x%x) returned result 0x%x,"
			" but 0x%x was expected.", a, b, res, expected_res);
	RTE_TEST_ASSERT_EQUAL(overflow, expected_overflow,
			"ERROR: __rte_add_overflow_u8(0x%x, 0x%x) returned overflow 0x%x,"
			" but 0x%x was expected.", a, b, overflow, expected_overflow);

	return 0;
}

static int
verify_add_overflow_u16(uint16_t a, uint16_t b,
		uint16_t expected_res, uint16_t expected_overflow)
{
	uint16_t res;
	uint8_t overflow = __rte_add_overflow_u16(a, b, &res);
	RTE_TEST_ASSERT_EQUAL(res, expected_res,
			"ERROR: __rte_add_overflow_u16(0x%x, 0x%x) returned result 0x%x,"
			" but 0x%x was expected.", a, b, res, expected_res);
	RTE_TEST_ASSERT_EQUAL(overflow, expected_overflow,
			"ERROR: __rte_add_overflow_u16(0x%x, 0x%x) returned overflow 0x%x,"
			" but 0x%x was expected.", a, b, overflow, expected_overflow);

	return 0;
}

static int
verify_add_overflow_u32(uint32_t a, uint32_t b,
		uint32_t expected_res, uint32_t expected_overflow)
{
	uint32_t res;
	uint8_t overflow = __rte_add_overflow_u32(a, b, &res);
	RTE_TEST_ASSERT_EQUAL(res, expected_res,
			"ERROR: __rte_add_overflow_u32(0x%x, 0x%x) returned result 0x%x,"
			" but 0x%x was expected.", a, b, res, expected_res);
	RTE_TEST_ASSERT_EQUAL(overflow, expected_overflow,
			"ERROR: __rte_add_overflow_u32(0x%x, 0x%x) returned overflow 0x%x,"
			" but 0x%x was expected.", a, b, overflow, expected_overflow);

	return 0;
}

static int
test_add_overflow_u8(void)
{
	TEST_MATH_RETURN_IF_ERROR(verify_add_overflow_u8(0, 0, 0, 0));
	TEST_MATH_RETURN_IF_ERROR(verify_add_overflow_u8(0, 1, 1, 0));
	TEST_MATH_RETURN_IF_ERROR(verify_add_overflow_u8(0, 0xFF, 0xFF, 0));
	TEST_MATH_RETURN_IF_ERROR(verify_add_overflow_u8(1, 0xFF, 0, 1));
	TEST_MATH_RETURN_IF_ERROR(verify_add_overflow_u8(2, 0xFF, 1, 1));
	TEST_MATH_RETURN_IF_ERROR(verify_add_overflow_u8(4, 0xFE, 2, 1));

	return 0;
}

static int
test_add_overflow_u16(void)
{
	TEST_MATH_RETURN_IF_ERROR(verify_add_overflow_u16(0, 0, 0, 0));
	TEST_MATH_RETURN_IF_ERROR(verify_add_overflow_u16(0, 1, 1, 0));
	TEST_MATH_RETURN_IF_ERROR(verify_add_overflow_u16(0, 0xFFFF, 0xFFFF, 0));
	TEST_MATH_RETURN_IF_ERROR(verify_add_overflow_u16(1, 0xFFFF, 0, 1));
	TEST_MATH_RETURN_IF_ERROR(verify_add_overflow_u16(2, 0xFFFF, 1, 1));
	TEST_MATH_RETURN_IF_ERROR(verify_add_overflow_u16(4, 0xFFFE, 2, 1));

	return 0;
}

static int
test_add_overflow_u32(void)
{
	TEST_MATH_RETURN_IF_ERROR(verify_add_overflow_u32(0, 0, 0, 0));
	TEST_MATH_RETURN_IF_ERROR(verify_add_overflow_u32(0, 1, 1, 0));
	TEST_MATH_RETURN_IF_ERROR(verify_add_overflow_u32(0, 0xFFFFFFFF, 0xFFFFFFFF, 0));
	TEST_MATH_RETURN_IF_ERROR(verify_add_overflow_u32(1, 0xFFFFFFFF, 0, 1));
	TEST_MATH_RETURN_IF_ERROR(verify_add_overflow_u32(2, 0xFFFFFFFF, 1, 1));
	TEST_MATH_RETURN_IF_ERROR(verify_add_overflow_u32(4, 0xFFFFFFFE, 2, 1));

	return 0;
}

static struct unit_test_suite math_test_suite = {
	.suite_name = "math autotest",
	.setup = NULL,
	.teardown = NULL,
	.unit_test_cases = {
		TEST_CASE(test_add_overflow_u8),
		TEST_CASE(test_add_overflow_u16),
		TEST_CASE(test_add_overflow_u32),
		TEST_CASES_END()
	}
};

static int
test_math(void)
{
	return unit_test_suite_runner(&math_test_suite);
}

REGISTER_FAST_TEST(math_autotest, true, true, test_math);

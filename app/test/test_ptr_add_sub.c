/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Apple Inc.
 */

#include <stdint.h>

#include <rte_common.h>

#include "test.h"

/* Test constants */
#define TEST_INITVAL 0x1000
#define TEST_INCREMENT 100
#define TEST_RETVAL ((void *)(TEST_INITVAL + TEST_INCREMENT))

/* Buffer size for pointer tests */
#define TEST_BUFFER_SIZE (TEST_INCREMENT + 256)

/* Test RTE_INT_PTR_ADD/SUB with integer types and NULL */
static int
test_int_ptr_add_sub(void)
{
	/* Test NULL + offset (primary use case for RTE_INT_PTR_*) */
	uintptr_t uptr_result = RTE_INT_PTR_ADD((uintptr_t)NULL, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(uptr_result, (uintptr_t)TEST_INCREMENT,
		"RTE_INT_PTR_ADD failed for NULL");

	uptr_result = RTE_INT_PTR_SUB((uintptr_t)NULL, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(uptr_result, (uintptr_t)(-TEST_INCREMENT),
		"RTE_INT_PTR_SUB failed for NULL");

	/* Test with various integer types that could represent pointers */
	unsigned long long ull = TEST_INITVAL;
	unsigned long long ull_result = RTE_INT_PTR_ADD(ull, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(ull_result, (unsigned long long)(TEST_INITVAL + TEST_INCREMENT),
		"RTE_INT_PTR_ADD failed for unsigned long long");
	ull_result = RTE_INT_PTR_SUB(ull_result, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(ull_result, ull,
		"RTE_INT_PTR_SUB round-trip failed for unsigned long long");

	long long ll = TEST_INITVAL;
	long long ll_result = RTE_INT_PTR_ADD(ll, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(ll_result, (long long)(TEST_INITVAL + TEST_INCREMENT),
		"RTE_INT_PTR_ADD failed for long long");
	ll_result = RTE_INT_PTR_SUB(ll_result, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(ll_result, ll,
		"RTE_INT_PTR_SUB round-trip failed for long long");

	unsigned long ul = TEST_INITVAL;
	unsigned long ul_result = RTE_INT_PTR_ADD(ul, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(ul_result, (unsigned long)(TEST_INITVAL + TEST_INCREMENT),
		"RTE_INT_PTR_ADD failed for unsigned long");
	ul_result = RTE_INT_PTR_SUB(ul_result, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(ul_result, ul,
		"RTE_INT_PTR_SUB round-trip failed for unsigned long");

	long l = TEST_INITVAL;
	long l_result = RTE_INT_PTR_ADD(l, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(l_result, (long)(TEST_INITVAL + TEST_INCREMENT),
		"RTE_INT_PTR_ADD failed for long");
	l_result = RTE_INT_PTR_SUB(l_result, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(l_result, l,
		"RTE_INT_PTR_SUB round-trip failed for long");

	unsigned int ui = TEST_INITVAL;
	unsigned int ui_result = RTE_INT_PTR_ADD(ui, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(ui_result, (unsigned int)(TEST_INITVAL + TEST_INCREMENT),
		"RTE_INT_PTR_ADD failed for unsigned int");
	ui_result = RTE_INT_PTR_SUB(ui_result, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(ui_result, ui,
		"RTE_INT_PTR_SUB round-trip failed for unsigned int");

	int i = TEST_INITVAL;
	int i_result = RTE_INT_PTR_ADD(i, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(i_result, (int)(TEST_INITVAL + TEST_INCREMENT),
		"RTE_INT_PTR_ADD failed for int");
	i_result = RTE_INT_PTR_SUB(i_result, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(i_result, i,
		"RTE_INT_PTR_SUB round-trip failed for int");

	uint64_t u64 = TEST_INITVAL;
	uint64_t u64_result = RTE_INT_PTR_ADD(u64, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(u64_result, (uint64_t)(TEST_INITVAL + TEST_INCREMENT),
		"RTE_INT_PTR_ADD failed for uint64_t");
	u64_result = RTE_INT_PTR_SUB(u64_result, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(u64_result, u64,
		"RTE_INT_PTR_SUB round-trip failed for uint64_t");

	uint32_t u32 = TEST_INITVAL;
	uint32_t u32_result = RTE_INT_PTR_ADD(u32, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(u32_result, (uint32_t)(TEST_INITVAL + TEST_INCREMENT),
		"RTE_INT_PTR_ADD failed for uint32_t");
	u32_result = RTE_INT_PTR_SUB(u32_result, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(u32_result, u32,
		"RTE_INT_PTR_SUB round-trip failed for uint32_t");

	uintptr_t uptr = TEST_INITVAL;
	uptr_result = RTE_INT_PTR_ADD(uptr, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(uptr_result, (uintptr_t)(TEST_INITVAL + TEST_INCREMENT),
		"RTE_INT_PTR_ADD failed for uintptr_t");
	uptr_result = RTE_INT_PTR_SUB(uptr, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(uptr_result, uptr - TEST_INCREMENT,
		"RTE_INT_PTR_SUB failed for uintptr_t");

	size_t sz = TEST_INITVAL;
	size_t sz_result = RTE_INT_PTR_ADD(sz, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(sz_result, (size_t)(TEST_INITVAL + TEST_INCREMENT),
		"RTE_INT_PTR_ADD failed for size_t");
	sz_result = RTE_INT_PTR_SUB(sz_result, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(sz_result, sz,
		"RTE_INT_PTR_SUB round-trip failed for size_t");

	return 0;
}

/* Test RTE_PTR_ADD/SUB with pointer types and type preservation */
static int
test_ptr_add_sub(void)
{
	char buffer[TEST_BUFFER_SIZE];

	/* Test void* */
	void *vp = buffer;
	void *result = RTE_PTR_ADD(vp, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(result, (void *)(buffer + TEST_INCREMENT),
		"RTE_PTR_ADD failed for void*");
	result = RTE_PTR_SUB(result, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(result, vp,
		"RTE_PTR_SUB round-trip failed for void*");

	/* Test const void* - verifies const preservation */
	const void *cvp = buffer;
	const void *cvp_result = RTE_PTR_ADD(cvp, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(cvp_result, (const void *)(buffer + TEST_INCREMENT),
		"RTE_PTR_ADD failed for const void*");
	cvp_result = RTE_PTR_SUB(cvp_result, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(cvp_result, cvp,
		"RTE_PTR_SUB round-trip failed for const void*");

	/* Test char* - verifies type preservation */
	char *cp = buffer;
	char *cp_result = RTE_PTR_ADD(cp, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(cp_result, buffer + TEST_INCREMENT,
		"RTE_PTR_ADD failed for char*");
	cp_result = RTE_PTR_SUB(cp_result, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(cp_result, cp,
		"RTE_PTR_SUB round-trip failed for char*");

	/* Test const char* - verifies type and const preservation */
	const char *ccp = buffer;
	const char *ccp_result = RTE_PTR_ADD(ccp, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(ccp_result, buffer + TEST_INCREMENT,
		"RTE_PTR_ADD failed for const char*");
	ccp_result = RTE_PTR_SUB(ccp_result, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(ccp_result, ccp,
		"RTE_PTR_SUB round-trip failed for const char*");

	/* Test uint32_t* - verifies typed pointer preservation */
	uint32_t *u32p = (uint32_t *)buffer;
	uint32_t *u32p_result = RTE_PTR_ADD(u32p, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(u32p_result, (uint32_t *)(buffer + TEST_INCREMENT),
		"RTE_PTR_ADD failed for uint32_t*");
	u32p_result = RTE_PTR_SUB(u32p_result, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(u32p_result, u32p,
		"RTE_PTR_SUB round-trip failed for uint32_t*");

	/* Test const uint32_t* - verifies typed pointer and const preservation */
	const uint32_t *cu32p = (const uint32_t *)buffer;
	const uint32_t *cu32p_result = RTE_PTR_ADD(cu32p, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(cu32p_result, (const uint32_t *)(buffer + TEST_INCREMENT),
		"RTE_PTR_ADD failed for const uint32_t*");
	cu32p_result = RTE_PTR_SUB(cu32p_result, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(cu32p_result, cu32p,
		"RTE_PTR_SUB round-trip failed for const uint32_t*");

	return 0;
}

static struct unit_test_suite ptr_add_sub_test_suite = {
	.suite_name = "ptr add/sub autotest",
	.setup = NULL,
	.teardown = NULL,
	.unit_test_cases = {
		TEST_CASE(test_int_ptr_add_sub),
		TEST_CASE(test_ptr_add_sub),
		TEST_CASES_END()
	}
};

/* Main test function that runs all subtests */
static int
test_ptr_add_sub_suite(void)
{
	return unit_test_suite_runner(&ptr_add_sub_test_suite);
}

REGISTER_FAST_TEST(ptr_add_sub_autotest, NOHUGE_OK, ASAN_OK, test_ptr_add_sub_suite);

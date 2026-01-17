/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Apple Inc.
 */

#include <stdint.h>

#include <rte_common.h>

#include "test.h"

/* Test constants for 32-bit and 64-bit integer types */
#define TEST_INITVAL 0x1000
#define TEST_INCREMENT 100
#define TEST_RETVAL ((void *)(TEST_INITVAL + TEST_INCREMENT))

/* Buffer size for pointer tests */
#define TEST_BUFFER_SIZE (TEST_INCREMENT + 256)

/* Test 32-bit and 64-bit integer types */
static int
test_ptr_add_sub_integer_types(void)
{
	void *result;

	unsigned long long ull = TEST_INITVAL;
	result = RTE_PTR_ADD(ull, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(result, TEST_RETVAL,
		"RTE_PTR_ADD failed for unsigned long long");
	result = RTE_PTR_SUB(result, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(result, (void *)(uintptr_t)ull,
		"RTE_PTR_SUB round-trip failed for unsigned long long");

	long long ll = TEST_INITVAL;
	result = RTE_PTR_ADD(ll, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(result, TEST_RETVAL,
		"RTE_PTR_ADD failed for long long");
	result = RTE_PTR_SUB(result, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(result, (void *)(uintptr_t)ll,
		"RTE_PTR_SUB round-trip failed for long long");

	unsigned long ul = TEST_INITVAL;
	result = RTE_PTR_ADD(ul, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(result, TEST_RETVAL,
		"RTE_PTR_ADD failed for unsigned long");
	result = RTE_PTR_SUB(result, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(result, (void *)(uintptr_t)ul,
		"RTE_PTR_SUB round-trip failed for unsigned long");

	long l = TEST_INITVAL;
	result = RTE_PTR_ADD(l, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(result, TEST_RETVAL,
		"RTE_PTR_ADD failed for long");
	result = RTE_PTR_SUB(result, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(result, (void *)(uintptr_t)l,
		"RTE_PTR_SUB round-trip failed for long");

	unsigned int ui = TEST_INITVAL;
	result = RTE_PTR_ADD(ui, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(result, TEST_RETVAL,
		"RTE_PTR_ADD failed for unsigned int");
	result = RTE_PTR_SUB(result, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(result, (void *)(uintptr_t)ui,
		"RTE_PTR_SUB round-trip failed for unsigned int");

	int i = TEST_INITVAL;
	result = RTE_PTR_ADD(i, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(result, TEST_RETVAL,
		"RTE_PTR_ADD failed for int");
	result = RTE_PTR_SUB(result, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(result, (void *)(uintptr_t)i,
		"RTE_PTR_SUB round-trip failed for int");

	uint64_t u64 = TEST_INITVAL;
	result = RTE_PTR_ADD(u64, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(result, TEST_RETVAL,
		"RTE_PTR_ADD failed for uint64_t");
	result = RTE_PTR_SUB(result, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(result, (void *)(uintptr_t)u64,
		"RTE_PTR_SUB round-trip failed for uint64_t");

	uint32_t u32 = TEST_INITVAL;
	result = RTE_PTR_ADD(u32, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(result, TEST_RETVAL,
		"RTE_PTR_ADD failed for uint32_t");
	result = RTE_PTR_SUB(result, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(result, (void *)(uintptr_t)u32,
		"RTE_PTR_SUB round-trip failed for uint32_t");

	uintptr_t uptr = TEST_INITVAL;
	result = RTE_PTR_ADD(uptr, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(result, TEST_RETVAL,
		"RTE_PTR_ADD failed for uintptr_t");
	result = RTE_PTR_SUB(result, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(result, (void *)uptr,
		"RTE_PTR_SUB round-trip failed for uintptr_t");

	size_t sz = TEST_INITVAL;
	result = RTE_PTR_ADD(sz, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(result, TEST_RETVAL,
		"RTE_PTR_ADD failed for size_t");
	result = RTE_PTR_SUB(result, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(result, (void *)sz,
		"RTE_PTR_SUB round-trip failed for size_t");

	return 0;
}

/* Test pointer types including const correctness */
static int
test_ptr_add_sub_pointer_types(void)
{
	char buffer[TEST_BUFFER_SIZE];
	void *result;

	/* Test void* and const void* */
	void *vp = buffer;
	result = RTE_PTR_ADD(vp, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(result, (void *)(buffer + TEST_INCREMENT),
		"RTE_PTR_ADD failed for void*");
	result = RTE_PTR_SUB(result, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(result, vp,
		"RTE_PTR_SUB round-trip failed for void*");

	const void *cvp = buffer;
	result = RTE_PTR_ADD(cvp, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(result, (void *)(buffer + TEST_INCREMENT),
		"RTE_PTR_ADD failed for const void*");
	result = RTE_PTR_SUB(result, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(result, (const void *)cvp,
		"RTE_PTR_SUB round-trip failed for const void*");

	/* Test char* and const char* */
	char *cp = buffer;
	result = RTE_PTR_ADD(cp, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(result, (void *)(buffer + TEST_INCREMENT),
		"RTE_PTR_ADD failed for char*");
	result = RTE_PTR_SUB(result, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(result, (void *)cp,
		"RTE_PTR_SUB round-trip failed for char*");

	const char *ccp = buffer;
	result = RTE_PTR_ADD(ccp, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(result, (void *)(buffer + TEST_INCREMENT),
		"RTE_PTR_ADD failed for const char*");
	result = RTE_PTR_SUB(result, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(result, (const void *)ccp,
		"RTE_PTR_SUB round-trip failed for const char*");

	/* Test uint32_t* and const uint32_t* */
	uint32_t *u32p = (uint32_t *)buffer;
	result = RTE_PTR_ADD(u32p, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(result, (void *)(buffer + TEST_INCREMENT),
		"RTE_PTR_ADD failed for uint32_t*");
	result = RTE_PTR_SUB(result, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(result, (void *)u32p,
		"RTE_PTR_SUB round-trip failed for uint32_t*");

	const uint32_t *cu32p = (const uint32_t *)buffer;
	result = RTE_PTR_ADD(cu32p, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(result, (void *)(buffer + TEST_INCREMENT),
		"RTE_PTR_ADD failed for const uint32_t*");
	result = RTE_PTR_SUB(result, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(result, (const void *)cu32p,
		"RTE_PTR_SUB round-trip failed for const uint32_t*");

	/* Verify assigning to const pointer works (adding const is safe) */
	const void *result_const = RTE_PTR_ADD(cvp, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(result_const, (const void *)(buffer + TEST_INCREMENT),
		"RTE_PTR_ADD failed when assigning to const void*");
	result_const = RTE_PTR_SUB(result_const, TEST_INCREMENT);
	TEST_ASSERT_EQUAL(result_const, cvp,
		"RTE_PTR_SUB round-trip failed when assigning to const void*");

	return 0;
}

/* Main test function that runs all subtests */
static int
test_ptr_add_sub(void)
{
	int ret;

	ret = test_ptr_add_sub_integer_types();
	if (ret != 0)
		return ret;

	ret = test_ptr_add_sub_pointer_types();
	if (ret != 0)
		return ret;

	return 0;
}

REGISTER_FAST_TEST(ptr_add_sub_autotest, NOHUGE_OK, ASAN_OK, test_ptr_add_sub);

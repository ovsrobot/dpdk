/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Apple Inc.
 */

#include "test.h"
#include <stdint.h>
#include <stdbool.h>

#include <rte_common.h>

/* Test all C11 standard integer types */
static int
test_ptr_add_sub_integer_types(void)
{
	unsigned long long ull = 0x1000;
	TEST_ASSERT_EQUAL((uintptr_t)RTE_PTR_ADD(ull, 100), 0x1064,
		"RTE_PTR_ADD failed for unsigned long long");
	TEST_ASSERT_EQUAL((uintptr_t)RTE_PTR_SUB(ull, 100), 0x1000 - 100,
		"RTE_PTR_SUB failed for unsigned long long");

	long long ll = 0x1000;
	TEST_ASSERT_EQUAL((uintptr_t)RTE_PTR_ADD(ll, 100), 0x1064,
		"RTE_PTR_ADD failed for long long");

	unsigned long ul = 0x1000;
	TEST_ASSERT_EQUAL((uintptr_t)RTE_PTR_ADD(ul, 100), 0x1064,
		"RTE_PTR_ADD failed for unsigned long");

	long l = 0x1000;
	TEST_ASSERT_EQUAL((uintptr_t)RTE_PTR_ADD(l, 100), 0x1064,
		"RTE_PTR_ADD failed for long");

	unsigned int ui = 0x1000;
	TEST_ASSERT_EQUAL((uintptr_t)RTE_PTR_ADD(ui, 100), 0x1064,
		"RTE_PTR_ADD failed for unsigned int");

	int i = 0x1000;
	TEST_ASSERT_EQUAL((uintptr_t)RTE_PTR_ADD(i, 100), 0x1064,
		"RTE_PTR_ADD failed for int");

	unsigned short us = 0x1000;
	TEST_ASSERT_EQUAL((uintptr_t)RTE_PTR_ADD(us, 100), 0x1064,
		"RTE_PTR_ADD failed for unsigned short");

	short s = 0x1000;
	TEST_ASSERT_EQUAL((uintptr_t)RTE_PTR_ADD(s, 100), 0x1064,
		"RTE_PTR_ADD failed for short");

	unsigned char uc = 100;
	TEST_ASSERT_EQUAL((uintptr_t)RTE_PTR_ADD(uc, 50), 150,
		"RTE_PTR_ADD failed for unsigned char");

	signed char sc = 100;
	TEST_ASSERT_EQUAL((uintptr_t)RTE_PTR_ADD(sc, 50), 150,
		"RTE_PTR_ADD failed for signed char");

	char c = 100;
	TEST_ASSERT_EQUAL((uintptr_t)RTE_PTR_ADD(c, 50), 150,
		"RTE_PTR_ADD failed for char");

	_Bool b = 1;
	TEST_ASSERT_EQUAL((uintptr_t)RTE_PTR_ADD(b, 99), 100,
		"RTE_PTR_ADD failed for _Bool");

	bool b2 = true;
	TEST_ASSERT_EQUAL((uintptr_t)RTE_PTR_ADD(b2, 99), 100,
		"RTE_PTR_ADD failed for bool");

	return 0;
}

/* Test pointer types including const correctness */
static int
test_ptr_add_sub_pointer_types(void)
{
	char buffer[256];
	void *result;

	/* Test void* and const void* */
	void *vp = buffer;
	result = RTE_PTR_ADD(vp, 100);
	TEST_ASSERT_EQUAL(result, (void *)(buffer + 100),
		"RTE_PTR_ADD failed for void*");
	result = RTE_PTR_SUB(vp, 50);
	TEST_ASSERT_EQUAL(result, (void *)(buffer - 50),
		"RTE_PTR_SUB failed for void*");

	const void *cvp = buffer;
	result = RTE_PTR_ADD(cvp, 100);
	TEST_ASSERT_EQUAL(result, (void *)(buffer + 100),
		"RTE_PTR_ADD failed for const void*");
	result = RTE_PTR_SUB(cvp, 50);
	TEST_ASSERT_EQUAL(result, (void *)(buffer - 50),
		"RTE_PTR_SUB failed for const void*");

	/* Test char* and const char* */
	char *cp = buffer;
	result = RTE_PTR_ADD(cp, 100);
	TEST_ASSERT_EQUAL(result, (void *)(buffer + 100),
		"RTE_PTR_ADD failed for char*");
	result = RTE_PTR_SUB(cp, 50);
	TEST_ASSERT_EQUAL(result, (void *)(buffer - 50),
		"RTE_PTR_SUB failed for char*");

	const char *ccp = buffer;
	result = RTE_PTR_ADD(ccp, 100);
	TEST_ASSERT_EQUAL(result, (void *)(buffer + 100),
		"RTE_PTR_ADD failed for const char*");
	result = RTE_PTR_SUB(ccp, 50);
	TEST_ASSERT_EQUAL(result, (void *)(buffer - 50),
		"RTE_PTR_SUB failed for const char*");

	/* Test uint32_t* and const uint32_t* */
	uint32_t *u32p = (uint32_t *)buffer;
	result = RTE_PTR_ADD(u32p, 100);
	TEST_ASSERT_EQUAL(result, (void *)(buffer + 100),
		"RTE_PTR_ADD failed for uint32_t*");
	result = RTE_PTR_SUB(u32p, 50);
	TEST_ASSERT_EQUAL(result, (void *)(buffer - 50),
		"RTE_PTR_SUB failed for uint32_t*");

	const uint32_t *cu32p = (const uint32_t *)buffer;
	result = RTE_PTR_ADD(cu32p, 100);
	TEST_ASSERT_EQUAL(result, (void *)(buffer + 100),
		"RTE_PTR_ADD failed for const uint32_t*");
	result = RTE_PTR_SUB(cu32p, 50);
	TEST_ASSERT_EQUAL(result, (void *)(buffer - 50),
		"RTE_PTR_SUB failed for const uint32_t*");

	/* Verify assigning to const pointer works (adding const is safe) */
	const void *result_const = RTE_PTR_ADD(cvp, 100);
	TEST_ASSERT_EQUAL(result_const, (const void *)(buffer + 100),
		"RTE_PTR_ADD failed when assigning to const void*");

	return 0;
}

/* Test that typedefs resolve to native types correctly */
static int
test_ptr_add_sub_typedefs(void)
{
	uint64_t u64 = 0x1000;
	TEST_ASSERT_EQUAL((uintptr_t)RTE_PTR_ADD(u64, 100), 0x1064,
		"RTE_PTR_ADD failed for uint64_t");

	uint32_t u32 = 0x1000;
	TEST_ASSERT_EQUAL((uintptr_t)RTE_PTR_ADD(u32, 100), 0x1064,
		"RTE_PTR_ADD failed for uint32_t");

	uint16_t u16 = 0x1000;
	TEST_ASSERT_EQUAL((uintptr_t)RTE_PTR_ADD(u16, 100), 0x1064,
		"RTE_PTR_ADD failed for uint16_t");

	uint8_t u8 = 100;
	TEST_ASSERT_EQUAL((uintptr_t)RTE_PTR_ADD(u8, 50), 150,
		"RTE_PTR_ADD failed for uint8_t");

	uintptr_t uptr = 0x1000;
	TEST_ASSERT_EQUAL((uintptr_t)RTE_PTR_ADD(uptr, 100), 0x1064,
		"RTE_PTR_ADD failed for uintptr_t");

	size_t sz = 0x1000;
	TEST_ASSERT_EQUAL((uintptr_t)RTE_PTR_ADD(sz, 100), 0x1064,
		"RTE_PTR_ADD failed for size_t");

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

	ret = test_ptr_add_sub_typedefs();
	if (ret != 0)
		return ret;

	return 0;
}

REGISTER_FAST_TEST(ptr_add_sub_autotest, true, true, test_ptr_add_sub);

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>

#include <rte_debug.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_random.h>
#include <rte_string_fns.h>

#include "test.h"

#define LOG(...) do {\
	fprintf(stderr, "%s() ln %d: ", __func__, __LINE__); \
	fprintf(stderr, __VA_ARGS__); \
} while(0)

#define DATA_BYTE 'a'

static int
test_rte_strsplit(void)
{
	int i;
	do {
		/* =======================================================
		 * split a mac address correct number of splits requested
		 * =======================================================*/
		char test_string[] = "54:65:76:87:98:90";
		char *splits[6];

		LOG("Source string: '%s', to split on ':'\n", test_string);
		if (rte_strsplit(test_string, sizeof(test_string),
				splits, 6, ':') != 6) {
			LOG("Error splitting mac address\n");
			return -1;
		}
		for (i = 0; i < 6; i++)
			LOG("Token %d = %s\n", i + 1, splits[i]);
	} while (0);


	do {
		/* =======================================================
		 * split on spaces smaller number of splits requested
		 * =======================================================*/
		char test_string[] = "54 65 76 87 98 90";
		char *splits[6];

		LOG("Source string: '%s', to split on ' '\n", test_string);
		if (rte_strsplit(test_string, sizeof(test_string),
				splits, 3, ' ') != 3) {
			LOG("Error splitting mac address for max 2 splits\n");
			return -1;
		}
		for (i = 0; i < 3; i++)
			LOG("Token %d = %s\n", i + 1, splits[i]);
	} while (0);

	do {
		/* =======================================================
		 * split on commas - more splits than commas requested
		 * =======================================================*/
		char test_string[] = "a,b,c,d";
		char *splits[6];

		LOG("Source string: '%s', to split on ','\n", test_string);
		if (rte_strsplit(test_string, sizeof(test_string),
				splits, 6, ',') != 4) {
			LOG("Error splitting %s on ','\n", test_string);
			return -1;
		}
		for (i = 0; i < 4; i++)
			LOG("Token %d = %s\n", i + 1, splits[i]);
	} while(0);

	do {
		/* =======================================================
		 * Try splitting on non-existent character.
		 * =======================================================*/
		char test_string[] = "a,b,c,d";
		char *splits[6];

		LOG("Source string: '%s', to split on ' '\n", test_string);
		if (rte_strsplit(test_string, sizeof(test_string),
				splits, 6, ' ') != 1) {
			LOG("Error splitting %s on ' '\n", test_string);
			return -1;
		}
		LOG("String not split\n");
	} while(0);

	do {
		/* =======================================================
		 * Invalid / edge case parameter checks
		 * =======================================================*/
		char test_string[] = "a,b,c,d";
		char *splits[6];

		if (rte_strsplit(NULL, 0, splits, 6, ',') >= 0
				|| errno != EINVAL){
			LOG("Error: rte_strsplit accepted NULL string parameter\n");
			return -1;
		}

		if (rte_strsplit(test_string, sizeof(test_string), NULL, 0, ',') >= 0
				|| errno != EINVAL){
			LOG("Error: rte_strsplit accepted NULL array parameter\n");
			return -1;
		}

		errno = 0;
		if (rte_strsplit(test_string, 0, splits, 6, ',') != 0 || errno != 0) {
			LOG("Error: rte_strsplit did not accept 0 length string\n");
			return -1;
		}

		if (rte_strsplit(test_string, sizeof(test_string), splits, 0, ',') != 0
				|| errno != 0) {
			LOG("Error: rte_strsplit did not accept 0 length array\n");
			return -1;
		}

		LOG("Parameter test cases passed\n");
	} while(0);

	LOG("%s - PASSED\n", __func__);
	return 0;
}

static int
test_rte_strlcat(void)
{
	/* only run actual unit tests if we have system-provided strlcat */
#if defined(__BSD_VISIBLE) || defined(RTE_USE_LIBBSD)
#define BUF_LEN 32
	const char dst[BUF_LEN] = "Test string";
	const char src[] = " appended";
	char bsd_dst[BUF_LEN];
	char rte_dst[BUF_LEN];
	size_t i, bsd_ret, rte_ret;

	LOG("dst = '%s', strlen(dst) = %zu\n", dst, strlen(dst));
	LOG("src = '%s', strlen(src) = %zu\n", src, strlen(src));
	LOG("---\n");

	for (i = 0; i < BUF_LEN; i++) {
		/* initialize destination buffers */
		memcpy(bsd_dst, dst, BUF_LEN);
		memcpy(rte_dst, dst, BUF_LEN);
		/* compare implementations */
		bsd_ret = strlcat(bsd_dst, src, i);
		rte_ret = rte_strlcat(rte_dst, src, i);
		if (bsd_ret != rte_ret) {
			LOG("Incorrect retval for buf length = %zu\n", i);
			LOG("BSD: '%zu', rte: '%zu'\n", bsd_ret, rte_ret);
			return -1;
		}
		if (memcmp(bsd_dst, rte_dst, BUF_LEN) != 0) {
			LOG("Resulting buffers don't match\n");
			LOG("BSD: '%s', rte: '%s'\n", bsd_dst, rte_dst);
			return -1;
		}
		LOG("buffer size = %zu: dst = '%s', ret = %zu\n",
			i, rte_dst, rte_ret);
	}
	LOG("Checked %zu combinations\n", i);
#undef BUF_LEN
#endif /* defined(__BSD_VISIBLE) || defined(RTE_USE_LIBBSD) */

	return 0;
}

static int
test_rte_str_skip_leading_spaces(void)
{
	static const char empty[] = "";
	static const char nowhitespace[] = "Thereisreallynowhitespace";
	static const char somewhitespaces[] = " \f\n\r\t\vThere are some whitespaces";
	const char *p;

	LOG("Checking '%s'\n", empty);
	p = rte_str_skip_leading_spaces(empty);
	if (p != empty) {
		LOG("Returned address '%s' does not match expected result\n", p);
		return -1;
	}
	LOG("Got expected '%s'\n", p);
	LOG("Checking '%s'\n", nowhitespace);
	p = rte_str_skip_leading_spaces(nowhitespace);
	if (p != nowhitespace) {
		LOG("Returned address '%s' does not match expected result\n", p);
		return -1;
	}
	LOG("Got expected '%s'\n", p);
	LOG("Checking '%s'\n", somewhitespaces);
	p = rte_str_skip_leading_spaces(somewhitespaces);
	if (p != strchr(somewhitespaces, 'T')) {
		LOG("Returned address '%s' does not match expected result\n", p);
		return -1;
	}
	LOG("Got expected '%s'\n", p);

	return 0;
}

/*
 * This test does a variation of what OpenBSD regression suite does to test explicit bzero.
 * One thread creates a buffer then zeros it but does not touch after that.
 * Other thread checks that buffer has been cleared.
 * A broken implementation would get optimized away.
 */
#define TEST_DATA_SIZE	123
static int
run_memzero_explicit(void *arg)
{
	uint8_t *data = arg;

	for (unsigned int i = 0; i < TEST_DATA_SIZE; i++)
		data[i] = rte_rand_max(256);

	rte_memzero_explicit(data, TEST_DATA_SIZE);
	return 0;
}

static unsigned int
get_worker_lcore(void)
{
	unsigned int lcore_id = rte_get_next_lcore(-1, 1, 0);

	/* avoid checkers (like Coverity) false positives */
	RTE_VERIFY(lcore_id < RTE_MAX_LCORE);

	return lcore_id;
}

static int
test_rte_memzero_explicit(void)
{
	if (rte_lcore_count() < 2) {
		printf("Need multiple cores to run memzero explicit test.\n");
		return TEST_SKIPPED;
	}

	uint8_t test_data[TEST_DATA_SIZE] = { 1 };
	unsigned int worker_lcore_id = get_worker_lcore();
	int rc = rte_eal_remote_launch(run_memzero_explicit, test_data, worker_lcore_id);
	TEST_ASSERT(rc == 0, "Worker thread launch failed");

	rte_eal_mp_wait_lcore();

	for (unsigned int i = 0; i < TEST_DATA_SIZE; i++)
		TEST_ASSERT(test_data[i] == 0, "rte_memset_explicit did not zero");

	return TEST_SUCCESS;
}

static struct unit_test_suite test_suite = {
	.suite_name = "String functions tests",
	.unit_test_cases = {
		TEST_CASE(test_rte_strsplit),
		TEST_CASE(test_rte_strlcat),
		TEST_CASE(test_rte_str_skip_leading_spaces),
		TEST_CASE(test_rte_memzero_explicit),
		TEST_CASES_END()
	}
};

static int
test_string_fns(void)
{
	return unit_test_suite_runner(&test_suite);
}

REGISTER_FAST_TEST(string_autotest, true, true, test_string_fns);

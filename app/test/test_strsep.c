/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2025 Microsoft Corporation
 */

#include <string.h>
#include <rte_os_shim.h>

#include "test.h"

static int
test_strsep_helper(const char *str, const char *delim,
		   const char * const expected_tokens[], size_t expected_tokens_count)
{
	char *s = str != NULL ? strdup(str) : NULL;
	const char *token;
	for (size_t i = 0; i < expected_tokens_count; i++) {
		token = strsep(&s, delim);
		if (token == NULL) {
			printf("Expected token '%s', got NULL\n", expected_tokens[i]);
			free(s);
			return TEST_FAILED;
		}
		if (strcmp(expected_tokens[i], token) != 0) {
			printf("Expected '%s', got '%s'\n", expected_tokens[i], token);
			free(s);
			return TEST_FAILED;
		}
	}
	/* Check that there are no more tokens left */
	token = strsep(&s, delim);
	if (token != NULL) {
		printf("Expected NULL, got '%s'\n", token);
		free(s);
		return TEST_FAILED;
	}
	free(s);
	return TEST_SUCCESS;
}

static int
test_strsep_single_delimiter(void)
{
	const char *str = "hello,world";
	const char *delim = ",";
	static const char * const expected_tokens[] = { "hello", "world" };
	const size_t expected_tokens_count = RTE_DIM(expected_tokens);
	return test_strsep_helper(str, delim, expected_tokens, expected_tokens_count);
}

static int
test_strsep_multiple_delimiters(void)
{
	const char *str = "hello,world;this:is;a:test";
	const char *delim = ",;:";
	static const char * const expected_tokens[] = {"hello", "world", "this", "is", "a", "test"};
	const size_t expected_tokens_count = RTE_DIM(expected_tokens);
	return test_strsep_helper(str, delim, expected_tokens, expected_tokens_count);
}

static int
test_strsep_string_with_no_delimiters(void)
{
	const char *str = "helloworld";
	const char *delim = ",";
	static const char * const expected_tokens[] = {"helloworld"};
	const size_t expected_tokens_count = RTE_DIM(expected_tokens);
	return test_strsep_helper(str, delim, expected_tokens, expected_tokens_count);
}

static int
test_strsep_empty_string(void)
{
	const char *str = "";
	const char *delim = ",";
	static const char * const expected_tokens[] = {""};
	const size_t expected_tokens_count = RTE_DIM(expected_tokens);
	return test_strsep_helper(str, delim, expected_tokens, expected_tokens_count);
}

static int
test_strsep_null(void)
{
	const char *str = NULL;
	const char *delim = ",";
	static const char * const expected_tokens[] = {""};
	const size_t expected_tokens_count = 0;
	return test_strsep_helper(str, delim, expected_tokens, expected_tokens_count);
}

static struct unit_test_suite test_suite = {
	.suite_name = "Strsep test suite",
	.unit_test_cases = {
		TEST_CASE(test_strsep_single_delimiter),
		TEST_CASE(test_strsep_multiple_delimiters),
		TEST_CASE(test_strsep_string_with_no_delimiters),
		TEST_CASE(test_strsep_empty_string),
		TEST_CASE(test_strsep_null),
		TEST_CASES_END()
	}
};

static int
test_strsep(void)
{
	return unit_test_suite_runner(&test_suite);
}

REGISTER_FAST_TEST(strsep_autotest, true, true, test_strsep);

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020 Samsung Electronics Co., Ltd All Rights Reserved
 */

#include <rte_log.h>
#include <rte_ethdev.h>

#include <rte_test.h>
#include "test.h"


static int32_t
test_link_status_up_default(void)
{
	int ret = 0;
	struct rte_eth_link link_status = {
		.link_speed = ETH_SPEED_NUM_2_5G,
		.link_status = ETH_LINK_UP,
		.link_autoneg = ETH_LINK_AUTONEG,
		.link_duplex = ETH_LINK_FULL_DUPLEX
	};
	char text[128];
	ret = rte_eth_link_strf(text, 128, NULL, &link_status);
	RTE_TEST_ASSERT(ret > 0, "Failed to format default string\n");
	printf("Default link up #1: %s\n", text);
	TEST_ASSERT_BUFFERS_ARE_EQUAL("Link up at 2.5 Gbit/s FDX Autoneg\n",
		text, strlen(text), "Invalid default link status string");

	link_status.link_duplex = ETH_LINK_HALF_DUPLEX;
	link_status.link_autoneg = ETH_LINK_FIXED;
	link_status.link_speed = ETH_SPEED_NUM_10M,
	ret = rte_eth_link_strf(text, 128, NULL, &link_status);
	printf("Default link up #2: %s\n", text);
	RTE_TEST_ASSERT(ret > 0, "Failed to format default string\n");
	TEST_ASSERT_BUFFERS_ARE_EQUAL("Link up at 10 Mbit/s HDX Fixed\n",
		text, strlen(text), "Invalid default link status "
		"string with HDX");

	link_status.link_speed = ETH_SPEED_NUM_UNKNOWN,
	ret = rte_eth_link_strf(text, 128, NULL, &link_status);
	printf("Default link up #3: %s\n", text);
	RTE_TEST_ASSERT(ret > 0, "Failed to format default string\n");
	TEST_ASSERT_BUFFERS_ARE_EQUAL("Link up at Unknown speed HDX Fixed\n",
		text, strlen(text), "Invalid default link status "
		"string with HDX");
	return TEST_SUCCESS;
}

static int32_t
test_link_status_down_default(void)
{
	int ret = 0;
	struct rte_eth_link link_status = {
		.link_speed = ETH_SPEED_NUM_2_5G,
		.link_status = ETH_LINK_DOWN,
		.link_autoneg = ETH_LINK_AUTONEG,
		.link_duplex = ETH_LINK_FULL_DUPLEX
	};
	char text[128];
	ret = rte_eth_link_strf(text, 128, NULL, &link_status);
	RTE_TEST_ASSERT(ret > 0, "Failed to format default string\n");
	TEST_ASSERT_BUFFERS_ARE_EQUAL("Link down\n",
		text, strlen(text), "Invalid default link status string");

	return TEST_SUCCESS;
}

static int32_t
test_link_status_string_overflow(void)
{
	int ret = 0;
	struct rte_eth_link link_status = {
		.link_speed = ETH_SPEED_NUM_2_5G,
		.link_status = ETH_LINK_UP,
		.link_autoneg = ETH_LINK_AUTONEG,
		.link_duplex = ETH_LINK_FULL_DUPLEX
	};
	char text[128];
	int i = 0;
	for (i = 0; i < 128; i++)
		text[i] = 'Y';
	text[127] = '\0';

	ret = rte_eth_link_strf(NULL, 2, "status %S, %G Gbits/s",
		&link_status);
	RTE_TEST_ASSERT(ret < 0, "Format string should fail, but it's ok\n");

	ret = rte_eth_link_strf(text, 2, "status %S, %G Gbits/s",
		&link_status);
	RTE_TEST_ASSERT(ret < 0, "Format string should fail, but it's ok\n");
	RTE_TEST_ASSERT(text[2] == 'Y', "String1 overflow\n");

	ret = rte_eth_link_strf(text, 8, NULL,
		&link_status);
	RTE_TEST_ASSERT(ret < 0, "Default format string should fail,"
			" but it's ok\n");
	RTE_TEST_ASSERT(text[8] == 'Y', "String1 overflow\n");

	ret = rte_eth_link_strf(text, 10, NULL,
		&link_status);
	RTE_TEST_ASSERT(ret < 0, "Default format string should fail,"
			" but it's ok\n");
	RTE_TEST_ASSERT(text[10] == 'Y', "String1 overflow\n");

	text[1] = 'Y';
	ret = rte_eth_link_strf(text, 1, "%S",
		&link_status);
	RTE_TEST_ASSERT(ret < 0, "Status string should fail, but it's ok\n");
	RTE_TEST_ASSERT(text[1] == 'Y', "String1 overflow\n");

	return TEST_SUCCESS;
}

static int32_t
test_link_status_format(void)
{
	int ret = 0;
	struct rte_eth_link link_status = {
		.link_speed = ETH_SPEED_NUM_40G,
		.link_status = ETH_LINK_UP,
		.link_autoneg = ETH_LINK_AUTONEG,
		.link_duplex = ETH_LINK_FULL_DUPLEX
	};
	char text[128];
	int i = 0;
	for (i = 0; i < 128; i++)
		text[i] = 'Y';
	text[127] = '\0';
	printf("status format #1: %s\n", text);
	ret = rte_eth_link_strf(text, 128, "status = %S, duplex = %D\n",
		&link_status);
	printf("status format #2: %s\n", text);
	RTE_TEST_ASSERT(ret > 0, "Failed to format string\n");
	TEST_ASSERT_BUFFERS_ARE_EQUAL("status = Up, duplex = FDX\n",
		text, strlen(text), "Invalid status string1.");

	ret = rte_eth_link_strf(text, 128, "%A", &link_status);
	printf("status format #3: %s\n", text);
	RTE_TEST_ASSERT(ret > 0, "Failed to format string\n");
	TEST_ASSERT_BUFFERS_ARE_EQUAL("Autoneg",
		text, strlen(text), "Invalid status string2.");

	ret = rte_eth_link_strf(text, 128,
		"%G",
		&link_status);
	printf("status format #4: %s\n", text);
	RTE_TEST_ASSERT(ret > 0, "Failed to format string\n");
	TEST_ASSERT_BUFFERS_ARE_EQUAL("40.0",
		text, strlen(text), "Invalid status string3.");

	ret = rte_eth_link_strf(text, 128,
		"%M",
		&link_status);
	printf("status format #5: %s\n", text);
	RTE_TEST_ASSERT(ret > 0, "Failed to format string\n");
	TEST_ASSERT_BUFFERS_ARE_EQUAL("40000",
		text, strlen(text), "Invalid status string4.");
	return TEST_SUCCESS;
}

static int32_t
test_link_status_return_value(void)
{
	int ret = 0;
	struct rte_eth_link link_status = {
		.link_speed = ETH_SPEED_NUM_40G,
		.link_status = ETH_LINK_UP,
		.link_autoneg = ETH_LINK_AUTONEG,
		.link_duplex = ETH_LINK_FULL_DUPLEX
	};
	char text[128];
	int i = 0;
	for (i = 0; i < 128; i++)
		text[i] = 'Y';
	text[127] = '\0';
	ret = rte_eth_link_strf(text, 128, "status = %S, ",
		&link_status);
	printf("return value #1:ret=%u, text=%s\n", ret, text);
	ret += rte_eth_link_strf(text + ret, 128 - ret,
		"%A",
		&link_status);
	printf("return value #2:ret=%u, text=%s\n", ret, text);
	ret += rte_eth_link_strf(text + ret, 128 - ret,
		", duplex = %D\n",
		&link_status);
	printf("return value #3:ret=%u, text=%s\n", ret, text);
	ret += rte_eth_link_strf(text + ret, 128 - ret,
		"%M Mbits/s\n",
		&link_status);
	printf("return value #4:ret=%u, text=%s\n", ret, text);
	RTE_TEST_ASSERT(ret > 0, "Failed to format string\n");
	TEST_ASSERT_BUFFERS_ARE_EQUAL("status = Up, Autoneg, duplex = FDX\n"
		"40000 Mbits/s\n",
		text, strlen(text), "Invalid status string");

	return TEST_SUCCESS;
}

static int32_t
test_link_status_invalid_fmt(void)
{
	int ret = 0;
	struct rte_eth_link link_status = {
		.link_speed = ETH_SPEED_NUM_40G,
		.link_status = ETH_LINK_UP,
		.link_autoneg = ETH_LINK_AUTONEG,
		.link_duplex = ETH_LINK_FULL_DUPLEX
	};
	char text[128];
	ret = rte_eth_link_strf(text, 128, "status = %",
		&link_status);
	RTE_TEST_ASSERT(ret < 0, "Status string1 should fail, but it's ok\n");
	ret = rte_eth_link_strf(text, 128,
		", duplex = %d\n",
		&link_status);
	RTE_TEST_ASSERT(ret < 0, "Status string2 should fail, but it's ok\n");
	ret = rte_eth_link_strf(text, 128,
		"% Mbits/s\n",
		&link_status);
	RTE_TEST_ASSERT(ret < 0, "Status string3 should fail, but it's ok\n");

	return TEST_SUCCESS;
}

static int32_t
test_link_status_format_edges(void)
{
	int ret = 0;
	struct rte_eth_link link_status = {
		.link_speed = ETH_SPEED_NUM_UNKNOWN,
		.link_status = ETH_LINK_DOWN,
		.link_autoneg = ETH_LINK_AUTONEG,
		.link_duplex = ETH_LINK_HALF_DUPLEX
	};
	char text[128];
	ret = rte_eth_link_strf(text, 4, "%S", &link_status);
	printf("format edges #1: %s\n", text);
	RTE_TEST_ASSERT(ret < 0, "It should fail. No space for "
				 "zero terminator\n");
	ret = rte_eth_link_strf(text, 6, "123%D", &link_status);
	printf("format edges #2: %s\n", text);
	RTE_TEST_ASSERT(ret < 0, "It should fail. No space for "
				 "zero terminator\n");
	ret = rte_eth_link_strf(text, 7, "%A", &link_status);
	printf("format edges #3: %s\n", text);
	RTE_TEST_ASSERT(ret < 0, "It should fail. No space for "
				 "zero terminator\n");
	ret = rte_eth_link_strf(text, 8, "%A", &link_status);
	printf("format edges #4: %s\n", text);
	RTE_TEST_ASSERT(ret > 0, "It should ok, but it fails\n");
	return TEST_SUCCESS;
}
static struct unit_test_suite link_status_testsuite = {
	.suite_name = "link status formatting",
	.setup = NULL,
	.teardown = NULL,
	.unit_test_cases = {
		TEST_CASE(test_link_status_up_default),
		TEST_CASE(test_link_status_down_default),
		TEST_CASE(test_link_status_string_overflow),
		TEST_CASE(test_link_status_format),
		TEST_CASE(test_link_status_format_edges),
		TEST_CASE(test_link_status_invalid_fmt),
		TEST_CASE(test_link_status_return_value),
		TEST_CASES_END() /**< NULL terminate unit test array */
	}
};

static int
test_link_status(void)
{
	rte_log_set_global_level(RTE_LOG_DEBUG);
	rte_log_set_level(RTE_LOGTYPE_EAL, RTE_LOG_DEBUG);

	return unit_test_suite_runner(&link_status_testsuite);
}

REGISTER_TEST_COMMAND(ethdev_link_status, test_link_status);

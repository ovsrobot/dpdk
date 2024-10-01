/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024 Robin Jarry
 */

#include <rte_ip6.h>

#include "test.h"

static const struct rte_ipv6_addr bcast_addr = {
	"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
};
static const struct rte_ipv6_addr zero_addr = { 0 };

static int
test_ipv6_addr_mask(void)
{
	const struct rte_ipv6_addr masked_3 = {
		"\xe0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	};
	const struct rte_ipv6_addr masked_42 = {
		"\xff\xff\xff\xff\xff\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	};
	const struct rte_ipv6_addr masked_85 = {
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xf8\x00\x00\x00\x00\x00"
	};
	const struct rte_ipv6_addr masked_127 = {
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe"
	};
	struct rte_ipv6_addr ip;

	ip = bcast_addr;
	rte_ipv6_addr_mask(&ip, 0);
	TEST_ASSERT(rte_ipv6_addr_eq(&ip, &zero_addr), "");
	TEST_ASSERT_EQUAL(rte_ipv6_mask_depth(&zero_addr), 0, "");

	ip = bcast_addr;
	rte_ipv6_addr_mask(&ip, 3);
	TEST_ASSERT(rte_ipv6_addr_eq(&ip, &masked_3), "");
	TEST_ASSERT_EQUAL(rte_ipv6_mask_depth(&masked_3), 3, "");

	ip = bcast_addr;
	rte_ipv6_addr_mask(&ip, 42);
	TEST_ASSERT(rte_ipv6_addr_eq(&ip, &masked_42), "");
	TEST_ASSERT_EQUAL(rte_ipv6_mask_depth(&masked_42), 42, "");

	ip = bcast_addr;
	rte_ipv6_addr_mask(&ip, 85);
	TEST_ASSERT(rte_ipv6_addr_eq(&ip, &masked_85), "");
	TEST_ASSERT_EQUAL(rte_ipv6_mask_depth(&masked_85), 85, "");

	ip = bcast_addr;
	rte_ipv6_addr_mask(&ip, 127);
	TEST_ASSERT(rte_ipv6_addr_eq(&ip, &masked_127), "");
	TEST_ASSERT_EQUAL(rte_ipv6_mask_depth(&masked_127), 127, "");

	ip = bcast_addr;
	rte_ipv6_addr_mask(&ip, 128);
	TEST_ASSERT(rte_ipv6_addr_eq(&ip, &bcast_addr), "");
	TEST_ASSERT_EQUAL(rte_ipv6_mask_depth(&bcast_addr), 128, "");

	const struct rte_ipv6_addr holed_mask = {
		"\xff\xff\xff\xff\xff\xff\xef\xff\xff\xff\xff\xff\xff\xff\xff\xff"
	};
	TEST_ASSERT_EQUAL(rte_ipv6_mask_depth(&holed_mask), 51, "");

	return TEST_SUCCESS;
}

static int
test_ipv6_addr_eq_prefix(void)
{
	struct rte_ipv6_addr ip1 = {
		"\x2a\x01\xcb\x00\x02\x54\x33\x00\x1b\x9f\x80\x71\x67\xcd\xbf\x20"
	};
	struct rte_ipv6_addr ip2 = {
		"\x2a\x01\xcb\x00\x02\x54\x33\x00\x62\x39\xe1\xf4\x7a\x0b\x23\x71"
	};
	struct rte_ipv6_addr ip3 = {
		"\xfd\x10\x00\x39\x02\x08\x00\x01\x00\x00\x00\x00\x00\x00\x10\x08"
	};

	TEST_ASSERT(rte_ipv6_addr_eq_prefix(&ip1, &ip2, 1), "");
	TEST_ASSERT(rte_ipv6_addr_eq_prefix(&ip1, &ip2, 37), "");
	TEST_ASSERT(rte_ipv6_addr_eq_prefix(&ip1, &ip2, 64), "");
	TEST_ASSERT(!rte_ipv6_addr_eq_prefix(&ip1, &ip2, 112), "");
	TEST_ASSERT(rte_ipv6_addr_eq_prefix(&ip1, &ip3, 0), "");
	TEST_ASSERT(!rte_ipv6_addr_eq_prefix(&ip1, &ip3, 13), "");

	return TEST_SUCCESS;
}

static int
test_ipv6_addr_kind(void)
{
	TEST_ASSERT(rte_ipv6_addr_is_unspec(&zero_addr), "");

	struct rte_ipv6_addr ucast = {
		"\x2a\x01\xcb\x00\x02\x54\x33\x00\x62\x39\xe1\xf4\x7a\x0b\x23\x71"
	};
	TEST_ASSERT(!rte_ipv6_addr_is_unspec(&ucast), "");

	struct rte_ipv6_addr mcast = {
		"\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
	};
	TEST_ASSERT(!rte_ipv6_addr_is_unspec(&mcast), "");

	struct rte_ipv6_addr lo = {
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
	};
	TEST_ASSERT(!rte_ipv6_addr_is_unspec(&lo), "");

	struct rte_ipv6_addr local = {
		"\xfe\x80\x00\x00\x00\x00\x00\x00\x5a\x84\xc5\x2c\x6a\xef\x46\x39"
	};
	TEST_ASSERT(!rte_ipv6_addr_is_unspec(&local), "");

	return TEST_SUCCESS;
}

static int
test_net_ipv6(void)
{
	TEST_ASSERT_SUCCESS(test_ipv6_addr_mask(), "");
	TEST_ASSERT_SUCCESS(test_ipv6_addr_eq_prefix(), "");
	TEST_ASSERT_SUCCESS(test_ipv6_addr_kind(), "");
	return TEST_SUCCESS;
}

REGISTER_FAST_TEST(net_ipv6_autotest, true, true, test_net_ipv6);

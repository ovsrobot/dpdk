/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Intel Corporation
 */

#include <stdio.h>
#include <stdint.h>

#include <rte_ip.h>
#include <rte_common.h>
#include "test.h"

static int
test_rte_ip_parse_addr(void)
{
	printf("Running IP parsing tests...\n");

	struct str_ip_t {
		const char *str;
		uint32_t exp_output;
		uint32_t expected_to_fail;
	} str_ip_tests[] = {
		{ .str = "1.2.3.4", .exp_output = RTE_IPV4(1, 2, 3, 4)},
		{ .str = "192.168.255.255", .exp_output =
				RTE_IPV4(192, 168, 255, 255)},
		{ .str = "172.16.0.9", .exp_output =
				RTE_IPV4(172, 16, 0, 9)},
		{ .str = "1.2.3", .expected_to_fail = 1},
		{ .str = "1.2.3.4.5", .expected_to_fail = 1},
		{ .str = "fail.1.2.3", .expected_to_fail = 1},
		{ .str = "", .expected_to_fail = 1},
		{ .str = "1.2.3.fail", .expected_to_fail = 1}
	};

	uint32_t i;
	for (i = 0; i < RTE_DIM(str_ip_tests); i++) {
		uint32_t test_addr;
		int32_t err = rte_ip_parse_addr(str_ip_tests[i].str,
							&test_addr);
		if (!test_addr) {
			if (str_ip_tests[i].expected_to_fail != 1)
				return -1;
		}

		if (err || test_addr != str_ip_tests[i].exp_output) {
			if (str_ip_tests[i].expected_to_fail != 1)
				return -1;
		}
	}


	return 0;
}

static int
test_net_tests(void)
{
	int ret = test_rte_ip_parse_addr();
	return ret;
}

REGISTER_TEST_COMMAND(net_autotest, test_net_tests);

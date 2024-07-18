/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdio.h>
#include <stdint.h>

#include <rte_common.h>
#include <rte_alarm.h>

#include "test.h"

#define US_PER_SEC 1000000

static volatile int flag;

static void
test_alarm_callback(void *cb_arg)
{
	flag = 1;
	printf("Callback setting flag - OK. [cb_arg = %p]\n", cb_arg);
}

static int
test_alarm(void)
{
	int ret;

	ret = rte_eal_alarm_set(0, test_alarm_callback, NULL);
	TEST_ASSERT_FAIL(ret, "should not be succeed with 0 us value");

	ret = rte_eal_alarm_set(UINT64_MAX - 1, test_alarm_callback, NULL);
	TEST_ASSERT_FAIL(ret, "should not be succeed with (UINT64_MAX-1) us value");

	ret = rte_eal_alarm_set(10, NULL, NULL);
	TEST_ASSERT_FAIL(ret, "should not succeed with null callback parameter");

	ret = rte_eal_alarm_cancel(NULL, NULL);
	TEST_ASSERT_FAIL(ret, "should not succeed to remove alarm with null callback parameter");

	ret = rte_eal_alarm_set(US_PER_SEC, test_alarm_callback, NULL);
	TEST_ASSERT_SUCCESS(ret, "could not set an alarm");

	ret = rte_eal_alarm_cancel(test_alarm_callback, NULL);
	/* return is the number of the alarm set (or 0 if none or -1 if error) */
	TEST_ASSERT(ret > 0, "could not cancel an alarm: %d", ret);

	return 0;
}

REGISTER_FAST_TEST(alarm_autotest, true, true, test_alarm);

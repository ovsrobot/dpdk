/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdio.h>
#include <stdint.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_interrupts.h>
#include <rte_atomic.h>
#include <rte_alarm.h>

#include "test.h"

#define US_PER_MS 1000

#define RTE_TEST_ALARM_TIMEOUT 10 /* ms */
#define RTE_TEST_CHECK_PERIOD   3 /* ms */
#define RTE_TEST_MAX_REPEAT    20

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
#ifdef RTE_EXEC_ENV_FREEBSD
	printf("The alarm API is not supported on FreeBSD\n");
	return 0;
#endif

	/* check if it will fail to set alarm with wrong us value */
	printf("check if it will fail to set alarm with wrong ms values\n");
	if (rte_eal_alarm_set(0, test_alarm_callback,
						NULL) >= 0) {
		printf("should not be successful with 0 us value\n");
		return -1;
	}
	if (rte_eal_alarm_set(UINT64_MAX - 1, test_alarm_callback,
						NULL) >= 0) {
		printf("should not be successful with (UINT64_MAX-1) us value\n");
		return -1;
	}

	/* check if it will fail to set alarm with null callback parameter */
	printf("check if it will fail to set alarm with null callback parameter\n");
	if (rte_eal_alarm_set(RTE_TEST_ALARM_TIMEOUT, NULL, NULL) >= 0) {
		printf("should not be successful to set alarm with null callback parameter\n");
		return -1;
	}

	/* check if it will fail to remove alarm with null callback parameter */
	printf("check if it will fail to remove alarm with null callback parameter\n");
	if (rte_eal_alarm_cancel(NULL, NULL) == 0) {
		printf("should not be successful to remove alarm with null callback parameter");
		return -1;
	}

	return 0;
}

REGISTER_TEST_COMMAND(alarm_autotest, test_alarm);

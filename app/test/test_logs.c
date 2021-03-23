/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/queue.h>

#include <rte_log.h>
#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>

#include "test.h"

/* for legacy log test */
#define RTE_LOGTYPE_TESTAPP1 RTE_LOGTYPE_USER1
#define RTE_LOGTYPE_TESTAPP2 RTE_LOGTYPE_USER2

static int logtype1;
static int logtype2;
RTE_LOG_REGISTER(logtype3, logtype3, ERR)

/*
 * Logs
 * ====
 *
 * - Enable log types.
 * - Set log level.
 * - Send logs with different types and levels, some should not be displayed.
 */
static int
test_legacy_logs(void)
{
	printf("== static log types\n");

	/* set logtype level low to so we can test global level */
	rte_log_set_level(RTE_LOGTYPE_TESTAPP1, RTE_LOG_DEBUG);
	rte_log_set_level(RTE_LOGTYPE_TESTAPP2, RTE_LOG_DEBUG);

	/* log in error level */
	rte_log_set_global_level(RTE_LOG_ERR);
	RTE_LOG(ERR, TESTAPP1, "error message\n");
	RTE_LOG(CRIT, TESTAPP1, "critical message\n");

	/* log in critical level */
	rte_log_set_global_level(RTE_LOG_CRIT);
	RTE_LOG(ERR, TESTAPP2, "error message (not displayed)\n");
	RTE_LOG(CRIT, TESTAPP2, "critical message\n");

	/* bump up single log type level above global to test it */
	rte_log_set_level(RTE_LOGTYPE_TESTAPP2, RTE_LOG_EMERG);

	/* log in error level */
	rte_log_set_global_level(RTE_LOG_ERR);
	RTE_LOG(ERR, TESTAPP1, "error message\n");
	RTE_LOG(ERR, TESTAPP2, "error message (not displayed)\n");

	return 0;
}

static int
test_logs(void)
{
	int ret;

#define CHECK_LEVELS(exp_logtype1, exp_logtype2, exp_logtype3) do \
{ \
	ret = rte_log_get_level(logtype1); \
	TEST_ASSERT_EQUAL(ret, exp_logtype1, \
		"%s:%d, invalid level for logtype1 %d, expecting %d\n", \
		__FILE__, __LINE__, ret, exp_logtype1); \
	ret = rte_log_get_level(logtype2); \
	TEST_ASSERT_EQUAL(ret, exp_logtype2, \
		"%s:%d, invalid level for logtype2 %d, expecting %d\n", \
		__FILE__, __LINE__, ret, exp_logtype2); \
	ret = rte_log_get_level(logtype3); \
	TEST_ASSERT_EQUAL(ret, exp_logtype3, \
		"%s:%d, invalid level for logtype3 %d, expecting %d\n", \
		__FILE__, __LINE__, ret, exp_logtype3); \
} while (0)

	printf("== dynamic log types\n");

	logtype1 = rte_log_register("logtype1");
	if (logtype1 < 0) {
		printf("Cannot register logtype1\n");
		return -1;
	}
	ret = rte_log_get_level(logtype1);
	TEST_ASSERT_EQUAL(ret, RTE_LOG_INFO,
		"invalid default level for logtype1 %d, expecting %d\n",
		ret, RTE_LOG_INFO);

	logtype2 = rte_log_register("logtype2");
	if (logtype2 < 0) {
		printf("Cannot register logtype2\n");
		return -1;
	}
	ret = rte_log_get_level(logtype2);
	TEST_ASSERT_EQUAL(ret, RTE_LOG_INFO,
		"invalid default level for logtype2 %d, expecting %d\n",
		ret, RTE_LOG_INFO);

	ret = rte_log_get_level(logtype3);
	TEST_ASSERT_EQUAL(ret, RTE_LOG_ERR,
		"invalid default level for logtype3 %d, expecting %d\n",
		ret, RTE_LOG_ERR);

	rte_log_set_level(logtype1, RTE_LOG_ERR);
	CHECK_LEVELS(RTE_LOG_ERR, RTE_LOG_INFO, RTE_LOG_ERR);

	rte_log_set_level_regexp("type$", RTE_LOG_EMERG);
	CHECK_LEVELS(RTE_LOG_ERR, RTE_LOG_INFO, RTE_LOG_ERR);

	rte_log_set_level_regexp("type[23]", RTE_LOG_EMERG);
	CHECK_LEVELS(RTE_LOG_ERR, RTE_LOG_EMERG, RTE_LOG_EMERG);

	rte_log_set_level_pattern("logtype", RTE_LOG_DEBUG);
	CHECK_LEVELS(RTE_LOG_ERR, RTE_LOG_EMERG, RTE_LOG_EMERG);

	/* set logtype level low to so we can test global level */
	rte_log_set_level_pattern("logtype*", RTE_LOG_DEBUG);
	CHECK_LEVELS(RTE_LOG_DEBUG, RTE_LOG_DEBUG, RTE_LOG_DEBUG);

	/* log in error level */
	rte_log_set_global_level(RTE_LOG_ERR);
	rte_log(RTE_LOG_ERR, logtype1, "error message\n");
	rte_log(RTE_LOG_CRIT, logtype1, "critical message\n");

	/* log in critical level */
	rte_log_set_global_level(RTE_LOG_CRIT);
	rte_log(RTE_LOG_ERR, logtype2, "error message (not displayed)\n");
	rte_log(RTE_LOG_CRIT, logtype2, "critical message\n");

	/* bump up single log type level above global to test it */
	rte_log_set_level(logtype2, RTE_LOG_EMERG);

	/* log in error level */
	rte_log_set_global_level(RTE_LOG_ERR);
	rte_log(RTE_LOG_ERR, logtype1, "error message\n");
	rte_log(RTE_LOG_ERR, logtype2, "error message (not displayed)\n");

	ret = test_legacy_logs();
	if (ret < 0)
		return ret;

#undef CHECK_LEVELS

	return 0;
}

REGISTER_TEST_COMMAND(logs_autotest, test_logs);

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Intel Corporation
 */

#include <rte_lcore.h>

#include "test.h"

/* Arbitrary amount of "work" to simulate busyness with */
#define WORK		32
#define TIMESTAMP_ITERS	1000000

#define LCORE_POLL_BUSYNESS_NOT_SET	-1

static int
test_lcore_poll_busyness_enable_disable(void)
{
	int initial_state, curr_state;
	bool req_state;

	/* Get the initial state */
	initial_state = rte_lcore_poll_busyness_enabled();
	if (initial_state == -ENOTSUP)
		return TEST_SKIPPED;

	/* Set state to the inverse of the initial state and check for the change */
	req_state = !initial_state;
	rte_lcore_poll_busyness_enabled_set(req_state);
	curr_state = rte_lcore_poll_busyness_enabled();
	if (curr_state != req_state)
		return TEST_FAILED;

	/* Now change the state back to the original state. By changing it back, both
	 * enable and disable will have been tested.
	 */
	req_state = !curr_state;
	rte_lcore_poll_busyness_enabled_set(req_state);
	curr_state = rte_lcore_poll_busyness_enabled();
	if (curr_state != req_state)
		return TEST_FAILED;

	return TEST_SUCCESS;
}

static int
test_lcore_poll_busyness_invalid_lcore(void)
{
	int ret;

	/* Check if lcore poll busyness is enabled */
	if (rte_lcore_poll_busyness_enabled() == -ENOTSUP)
		return TEST_SKIPPED;

	/* Only lcore_id <= RTE_MAX_LCORE are valid */
	ret = rte_lcore_poll_busyness(RTE_MAX_LCORE);
	if (ret != -EINVAL)
		return TEST_FAILED;

	return TEST_SUCCESS;
}

static int
test_lcore_poll_busyness_inactive_lcore(void)
{
	int ret;

	/* Check if lcore poll busyness is enabled */
	if (rte_lcore_poll_busyness_enabled() == -ENOTSUP)
		return TEST_SKIPPED;

	/* Use the test thread lcore_id for this test. Since it is not a polling
	 * application, the busyness is expected to return -1.
	 *
	 * Note: this will not work with affinitized cores
	 */
	ret = rte_lcore_poll_busyness(rte_lcore_id());
	if (ret != LCORE_POLL_BUSYNESS_NOT_SET)
		return TEST_FAILED;

	return TEST_SUCCESS;
}

static void
simulate_lcore_poll_busyness(int iters)
{
	int i;

	for (i = 0; i < iters; i++)
		RTE_LCORE_POLL_BUSYNESS_TIMESTAMP(WORK);
}

/* The test cannot know of an application running to test for valid lcore poll
 * busyness data. For this test, we simulate lcore poll busyness for the
 * lcore_id of the test thread for testing purposes.
 */
static int
test_lcore_poll_busyness_active_lcore(void)
{
	int ret;

	/* Check if lcore poll busyness is enabled */
	if (rte_lcore_poll_busyness_enabled() == -ENOTSUP)
		return TEST_SKIPPED;

	simulate_lcore_poll_busyness(TIMESTAMP_ITERS);

	/* After timestamping with "work" many times, lcore poll busyness should be > 0 */
	ret = rte_lcore_poll_busyness(rte_lcore_id());
	if (ret <= 0)
		return TEST_FAILED;

	return TEST_SUCCESS;
}

static struct unit_test_suite lcore_poll_busyness_tests = {
	.suite_name = "lcore poll busyness autotest",
	.setup = NULL,
	.teardown = NULL,
	.unit_test_cases = {
		TEST_CASE(test_lcore_poll_busyness_enable_disable),
		TEST_CASE(test_lcore_poll_busyness_invalid_lcore),
		TEST_CASE(test_lcore_poll_busyness_inactive_lcore),
		TEST_CASE(test_lcore_poll_busyness_active_lcore),
		TEST_CASES_END()
	}
};

static int
test_lcore_poll_busyness_api(void)
{
	return unit_test_suite_runner(&lcore_poll_busyness_tests);
}

REGISTER_TEST_COMMAND(lcore_poll_busyness_autotest, test_lcore_poll_busyness_api);

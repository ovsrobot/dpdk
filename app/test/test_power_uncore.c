/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2022 Intel Corporation
 */

#include "test.h"

#ifndef RTE_LIB_POWER

static int
test_power_uncore(void)
{
	printf("Power management library not supported, skipping test\n");
	return TEST_SKIPPED;
}

#else
#include <rte_power_uncore.h>
#include <power_common.h>

#define VALID_PKG 0
#define VALID_DIE 0
#define INVALID_PKG (RTE_MAX_NUMA_NODES + 1)
#define INVALID_DIE (RTE_MAX_NUMA_DIE + 1)
#define VALID_INDEX 1
#define INVALID_INDEX (RTE_MAX_UNCORE_FREQS + 1)

static int check_power_uncore_init(void)
{
	int ret;

	/* Test initialisation of uncore configuration*/
	ret = rte_power_uncore_init(VALID_PKG, VALID_DIE);
	if (ret < 0) {
		printf("Cannot initialise uncore power management for pkg %u die %u, this "
			"may occur if environment is not configured "
			"correctly(APCI cpufreq) or operating in another valid "
			"Power management environment\n", VALID_PKG, VALID_DIE);
		return -1;
	}

	/* Unsuccessful Test */
	ret = rte_power_uncore_init(INVALID_PKG, INVALID_DIE);
	if (ret == 0) {
		printf("Unexpectedly was able to initialise uncore power management "
			"for pkg %u die %u\n", INVALID_PKG, INVALID_DIE);
		return -1;
	}

	return 0;
}

static int
check_power_get_uncore_freq(void)
{
	int ret;

	/* Successfully get uncore freq */
	ret = rte_power_get_uncore_freq(VALID_PKG, VALID_DIE);
	if (ret < 0) {
		printf("Failed to get uncore frequency for pkg %u die %u\n",
							VALID_PKG, VALID_DIE);
		return -1;
	}

	/* Unsuccessful Test */
	ret = rte_power_get_uncore_freq(INVALID_PKG, INVALID_DIE);
	if (ret >= 0) {
		printf("Unexpectedly got invalid uncore frequency for pkg %u die %u\n",
							INVALID_PKG, INVALID_DIE);
		return -1;
	}

	return 0;
}

static int
check_power_set_uncore_freq(void)
{
	int ret;

	/* Successfully set uncore freq */
	ret = rte_power_set_uncore_freq(VALID_PKG, VALID_DIE, VALID_INDEX);
	if (ret < 0) {
		printf("Failed to set uncore frequency for pkg %u die %u index %u\n",
							VALID_PKG, VALID_DIE, VALID_INDEX);
		return -1;
	}

	/* Try to unsuccessfully set invalid uncore freq index */
	ret = rte_power_set_uncore_freq(VALID_PKG, VALID_DIE, INVALID_INDEX);
	if (ret == 0) {
		printf("Unexpectedly set invalid uncore index for pkg %u die %u index %u\n",
							VALID_PKG, VALID_DIE, INVALID_INDEX);
		return -1;
	}

	/* Unsuccessful Test */
	ret = rte_power_set_uncore_freq(INVALID_PKG, INVALID_DIE, VALID_INDEX);
	if (ret == 0) {
		printf("Unexpectedly set invalid uncore frequency for pkg %u die %u index %u\n",
							INVALID_PKG, INVALID_DIE, VALID_INDEX);
		return -1;
	}

	return 0;
}

static int
check_power_uncore_freq_max(void)
{
	int ret;

	/* Successfully get max uncore freq */
	ret = rte_power_uncore_freq_max(VALID_PKG, VALID_DIE);
	if (ret < 0) {
		printf("Failed to set max uncore frequency for pkg %u die %u\n",
							VALID_PKG, VALID_DIE);
		return -1;
	}

	/* Unsuccessful Test */
	ret = rte_power_uncore_freq_max(INVALID_PKG, INVALID_DIE);
	if (ret == 0) {
		printf("Unexpectedly set invalid max uncore frequency for pkg %u die %u\n",
							INVALID_PKG, INVALID_DIE);
		return -1;
	}

	return 0;
}

static int
check_power_uncore_freq_min(void)
{
	int ret;

	/* Successfully get min uncore freq */
	ret = rte_power_uncore_freq_min(VALID_PKG, VALID_DIE);
	if (ret < 0) {
		printf("Failed to set min uncore frequency for pkg %u die %u\n",
							VALID_PKG, VALID_DIE);
		return -1;
	}

	/* Unsuccessful Test */
	ret = rte_power_uncore_freq_min(INVALID_PKG, INVALID_DIE);
	if (ret == 0) {
		printf("Unexpectedly set invalid min uncore frequency for pkg %u die %u\n",
							INVALID_PKG, INVALID_DIE);
		return -1;
	}

	return 0;
}

static int
check_power_uncore_get_num_freqs(void)
{
	int ret;

	/* Successfully get number of uncore freq */
	ret = rte_power_uncore_get_num_freqs(VALID_PKG, VALID_DIE);
	if (ret < 0) {
		printf("Failed to get number of uncore frequencies for pkg %u die %u\n",
							VALID_PKG, VALID_DIE);
		return -1;
	}

	/* Unsuccessful Test */
	ret = rte_power_uncore_get_num_freqs(INVALID_PKG, INVALID_DIE);
	if (ret >= 0) {
		printf("Unexpectedly got number of invalid frequencies for pkg %u die %u\n",
							INVALID_PKG, INVALID_DIE);
		return -1;
	}

	return 0;
}

static int
check_power_uncore_exit(void)
{
	int ret;

	/* Successfully exit uncore power management */
	ret = rte_power_uncore_exit(VALID_PKG, VALID_DIE);
	if (ret < 0) {
		printf("Failed to exit uncore power management for pkg %u die %u\n",
							VALID_PKG, VALID_DIE);
		return -1;
	}

	/* Unsuccessful Test */
	ret = rte_power_uncore_exit(INVALID_PKG, INVALID_DIE);
	if (ret == 0) {
		printf("Unexpectedly was able to exit uncore power management for pkg %u die %u\n",
							INVALID_PKG, INVALID_DIE);
		return -1;
	}

	return 0;
}

static int
test_power_uncore(void)
{
	int ret;

	ret = check_power_uncore_init();
	if (ret < 0)
		goto fail_all;

	ret = check_power_get_uncore_freq();
	if (ret < 0)
		goto fail_all;

	ret = check_power_set_uncore_freq();
	if (ret < 0)
		goto fail_all;

	ret = check_power_uncore_freq_max();
	if (ret < 0)
		goto fail_all;

	ret = check_power_uncore_freq_min();
	if (ret < 0)
		goto fail_all;

	ret = check_power_uncore_get_num_freqs();
	if (ret < 0)
		goto fail_all;

	ret = check_power_uncore_exit();
	if (ret < 0)
		return -1;

	return 0;

fail_all:
	rte_power_uncore_exit(VALID_PKG, VALID_DIE);
	return -1;
}
#endif

REGISTER_TEST_COMMAND(power_uncore_autotest, test_power_uncore);

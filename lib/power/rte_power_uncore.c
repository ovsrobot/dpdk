/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 * Copyright(c) 2023 AMD Corporation
 */

#include <errno.h>

#include <rte_errno.h>
#include <rte_spinlock.h>

#include "rte_power_uncore.h"
#include "power_intel_uncore.h"

enum uncore_power_mgmt_env default_uncore_env = UNCORE_PM_ENV_NOT_SET;

static rte_spinlock_t global_env_cfg_lock = RTE_SPINLOCK_INITIALIZER;

/* function pointers */
rte_power_get_uncore_freq_t rte_power_get_uncore_freq;
rte_power_set_uncore_freq_t rte_power_set_uncore_freq;
rte_power_uncore_freq_change_t rte_power_uncore_freq_max;
rte_power_uncore_freq_change_t rte_power_uncore_freq_min;
rte_power_uncore_freqs_t rte_power_uncore_freqs;
rte_power_uncore_get_num_freqs_t rte_power_uncore_get_num_freqs;
rte_power_uncore_get_num_pkgs_t rte_power_uncore_get_num_pkgs;
rte_power_uncore_get_num_dies_t rte_power_uncore_get_num_dies;

static void
reset_power_uncore_function_ptrs(void)
{
	rte_power_get_uncore_freq = NULL;
	rte_power_set_uncore_freq = NULL;
	rte_power_uncore_freq_max = NULL;
	rte_power_uncore_freq_min = NULL;
	rte_power_uncore_freqs  = NULL;
	rte_power_uncore_get_num_freqs = NULL;
	rte_power_uncore_get_num_pkgs = NULL;
	rte_power_uncore_get_num_dies = NULL;
}

static int
power_set_uncore_env(enum uncore_power_mgmt_env env)
{
	rte_spinlock_lock(&global_env_cfg_lock);

	if (default_uncore_env != UNCORE_PM_ENV_NOT_SET) {
		RTE_LOG(ERR, POWER, "Uncore Power Management Env already set.\n");
		rte_spinlock_unlock(&global_env_cfg_lock);
		return -1;
	}

	int ret = 0;

	if (env == UNCORE_PM_ENV_INTEL_UNCORE) {
		rte_power_get_uncore_freq = power_get_intel_uncore_freq;
		rte_power_set_uncore_freq = power_set_intel_uncore_freq;
		rte_power_uncore_freq_min  = power_intel_uncore_freq_min;
		rte_power_uncore_freq_max  = power_intel_uncore_freq_max;
		rte_power_uncore_freqs = power_intel_uncore_freqs;
		rte_power_uncore_get_num_freqs = power_intel_uncore_get_num_freqs;
		rte_power_uncore_get_num_pkgs = power_intel_uncore_get_num_pkgs;
		rte_power_uncore_get_num_dies = power_intel_uncore_get_num_dies;
	} else {
		RTE_LOG(ERR, POWER, "Invalid Power Management Environment(%d) set\n",
				env);
		ret = -1;
	}

	if (ret == 0)
		default_uncore_env = env;
	else {
		default_uncore_env = UNCORE_PM_ENV_NOT_SET;
		reset_power_uncore_function_ptrs();
	}

	rte_spinlock_unlock(&global_env_cfg_lock);
	return ret;
}

int
rte_power_uncore_init(unsigned int pkg, unsigned int die)
{
	int ret = -1;

	switch (default_uncore_env) {
	case UNCORE_PM_ENV_INTEL_UNCORE:
		return power_intel_uncore_init(pkg, die);
	default:
		RTE_LOG(INFO, POWER, "Uncore Env isn't set yet!\n");
	}

	/* Auto detect Environment */
	RTE_LOG(INFO, POWER, "Attempting to initialise Intel Uncore power mgmt...\n");
	ret = power_intel_uncore_init(pkg, die);
	if (ret == 0) {
		power_set_uncore_env(UNCORE_PM_ENV_INTEL_UNCORE);
		goto out;
	}

	RTE_LOG(ERR, POWER, "Unable to set Power Management Environment for package "
			"%u Die %u\n", pkg, die);
out:
	return ret;
}

int
rte_power_uncore_exit(unsigned int pkg, unsigned int die)
{
	switch (default_uncore_env) {
	case UNCORE_PM_ENV_INTEL_UNCORE:
		return power_intel_uncore_exit(pkg, die);
	default:
		RTE_LOG(ERR, POWER, "Uncore Env has not been set,"
			       "unable to exit gracefully\n");
	}
	return -1;

}

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <errno.h>

#include <rte_errno.h>
#include <rte_spinlock.h>

#include "rte_power.h"
#include "power_common.h"

enum power_management_env global_default_env = PM_ENV_NOT_SET;

static rte_spinlock_t global_env_cfg_lock = RTE_SPINLOCK_INITIALIZER;
static struct rte_power_ops rte_power_ops[PM_ENV_MAX];

/* register the ops struct in rte_power_ops, return 0 on success. */
int
rte_power_register_ops(const struct rte_power_ops *op)
{
	struct rte_power_ops *ops;

	if (op->env >= PM_ENV_MAX) {
		POWER_LOG(ERR, "Unsupported power management environment\n");
		return -EINVAL;
	}

	if (op->status != 0) {
		POWER_LOG(ERR, "Power management env[%d] ops registered already\n",
			op->env);
		return -EINVAL;
	}

	if (!op->init || !op->exit || !op->check_env_support ||
		!op->get_avail_freqs || !op->get_freq || !op->set_freq ||
		!op->freq_up || !op->freq_down || !op->freq_max ||
		!op->freq_min || !op->turbo_status || !op->enable_turbo ||
		!op->disable_turbo || !op->get_caps) {
		POWER_LOG(ERR, "Missing callbacks while registering power ops\n");
		return -EINVAL;
	}

	ops = &rte_power_ops[op->env];
	ops->env = op->env;
	ops->init = op->init;
	ops->exit = op->exit;
	ops->check_env_support = op->check_env_support;
	ops->get_avail_freqs = op->get_avail_freqs;
	ops->get_freq = op->get_freq;
	ops->set_freq = op->set_freq;
	ops->freq_up = op->freq_up;
	ops->freq_down = op->freq_down;
	ops->freq_max = op->freq_max;
	ops->freq_min = op->freq_min;
	ops->turbo_status = op->turbo_status;
	ops->enable_turbo = op->enable_turbo;
	ops->disable_turbo = op->disable_turbo;
	ops->status = 1; /* registered */

	return 0;
}

struct rte_power_ops *
rte_power_get_ops(int ops_index)
{
	RTE_VERIFY((ops_index >= PM_ENV_NOT_SET) && (ops_index < PM_ENV_MAX));
	RTE_VERIFY(rte_power_ops[ops_index].status != 0);

	return &rte_power_ops[ops_index];
}

int
rte_power_check_env_supported(enum power_management_env env)
{
	struct rte_power_ops *ops;

	if ((env > PM_ENV_NOT_SET) && (env < PM_ENV_MAX)) {
		ops = rte_power_get_ops(env);
		return ops->check_env_support();
	}

	rte_errno = EINVAL;
	return -1;
}

int
rte_power_set_env(enum power_management_env env)
{
	rte_spinlock_lock(&global_env_cfg_lock);

	if (global_default_env != PM_ENV_NOT_SET) {
		POWER_LOG(ERR, "Power Management Environment already set.");
		rte_spinlock_unlock(&global_env_cfg_lock);
		return -1;
	}

	int ret = 0;
	struct rte_power_ops *ops;

	if ((env == PM_ENV_NOT_SET) || (env >= PM_ENV_MAX)) {
		POWER_LOG(ERR, "Invalid Power Management Environment(%d)"
				" set\n", env);
		ret = -1;
	}

	ops = rte_power_get_ops(env);
	if (ops->status == 0) {
		POWER_LOG(ERR, WER,
			"Power Management Environment(%d) not"
			" registered\n", env);
		ret = -1;
	}

	if (ret == 0)
		global_default_env = env;
	else
		global_default_env = PM_ENV_NOT_SET;

	rte_spinlock_unlock(&global_env_cfg_lock);
	return ret;
}

void
rte_power_unset_env(void)
{
	rte_spinlock_lock(&global_env_cfg_lock);
	global_default_env = PM_ENV_NOT_SET;
	rte_spinlock_unlock(&global_env_cfg_lock);
}

enum power_management_env
rte_power_get_env(void) {
	return global_default_env;
}

int
rte_power_init(unsigned int lcore_id)
{
	int ret = -1;
	struct rte_power_ops *ops;

	if (global_default_env != PM_ENV_NOT_SET) {
		ops = &rte_power_ops[global_default_env];
		if (!ops->status) {
			POWER_LOG(ERR, "Power management env[%d] not"
				" supported\n", global_default_env);
			goto out;
		}
		return ops->init(lcore_id);
	}
	POWER_LOG(INFO, POWER, "Env isn't set yet!\n");

	/* Auto detect Environment */
	POWER_LOG(INFO, "Attempting to initialise ACPI cpufreq"
			" power management...\n");
	ops = &rte_power_ops[PM_ENV_ACPI_CPUFREQ];
	if (ops->status) {
		ret = ops->init(lcore_id);
		if (ret == 0) {
			rte_power_set_env(PM_ENV_ACPI_CPUFREQ);
			goto out;
		}
	}

	POWER_LOG(INFO, "Attempting to initialise PSTAT"
			" power management...\n");
	ops = &rte_power_ops[PM_ENV_PSTATE_CPUFREQ];
	if (ops->status) {
		ret = ops->init(lcore_id);
		if (ret == 0) {
			rte_power_set_env(PM_ENV_PSTATE_CPUFREQ);
			goto out;
		}
	}

	POWER_LOG(INFO,	"Attempting to initialise AMD PSTATE"
			" power management...\n");
	ops = &rte_power_ops[PM_ENV_AMD_PSTATE_CPUFREQ];
	if (ops->status) {
		ret = ops->init(lcore_id);
		if (ret == 0) {
			rte_power_set_env(PM_ENV_AMD_PSTATE_CPUFREQ);
			goto out;
		}
	}

	POWER_LOG(INFO, "Attempting to initialise CPPC power"
			" management...\n");
	ops = &rte_power_ops[PM_ENV_CPPC_CPUFREQ];
	if (ops->status) {
		ret = ops->init(lcore_id);
		if (ret == 0) {
			rte_power_set_env(PM_ENV_CPPC_CPUFREQ);
			goto out;
		}
	}

	POWER_LOG(INFO, "Attempting to initialise VM power"
			" management...\n");
	ops = &rte_power_ops[PM_ENV_KVM_VM];
	if (ops->status) {
		ret = ops->init(lcore_id);
		if (ret == 0) {
			rte_power_set_env(PM_ENV_KVM_VM);
			goto out;
		}
	}
	POWER_LOG(ERR, "Unable to set Power Management Environment"
			" for lcore %u\n", lcore_id);
out:
	return ret;
}

int
rte_power_exit(unsigned int lcore_id)
{
	struct rte_power_ops *ops;

	if (global_default_env != PM_ENV_NOT_SET) {
		ops = &rte_power_ops[global_default_env];
		return ops->exit(lcore_id);
	}
	POWER_LOG(ERR, "Environment has not been set, unable "
			"to exit gracefully\n");

	return -1;
}

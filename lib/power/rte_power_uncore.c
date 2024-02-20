/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 * Copyright(c) 2023 AMD Corporation
 */

#include <errno.h>

#include <rte_errno.h>
#include <rte_spinlock.h>

#include "power_common.h"
#include "rte_power_uncore.h"
#include "power_intel_uncore.h"

enum rte_uncore_power_mgmt_env default_uncore_env = RTE_UNCORE_PM_ENV_NOT_SET;

static rte_spinlock_t global_env_cfg_lock = RTE_SPINLOCK_INITIALIZER;
static struct rte_power_uncore_ops rte_power_uncore_ops[PM_ENV_MAX];


/* register the ops struct in rte_power_uncore_ops, return 0 on success. */
int
rte_power_register_uncore_ops(const struct rte_power_uncore_ops *op)
{
	struct rte_power_uncore_ops *ops;

	if ((op->env != RTE_UNCORE_PM_ENV_INTEL_UNCORE) &&
		(op->env != RTE_UNCORE_PM_ENV_AMD_HSMP)) {
		POWER_LOG(ERR,
			"Unsupported uncore power management environment\n");
			return -EINVAL;
		return -EINVAL;
	}

	if (op->status != 0) {
		POWER_LOG(ERR,
			"uncore Power management env[%d] ops registered already\n",
			op->env);
		return -EINVAL;
	}

	if (!op->init || !op->exit || !op->get_num_pkgs || !op->get_num_dies ||
		!op->get_num_freqs || !op->get_avail_freqs || !op->get_freq ||
		!op->set_freq || !op->freq_max || !op->freq_min) {
		POWER_LOG(ERR, "Missing callbacks while registering power ops\n");
		return -EINVAL;
	}
	ops = &rte_power_uncore_ops[op->env];
	ops->env = op->env;
	ops->init = op->init;
	ops->exit = op->exit;
	ops->get_num_pkgs = op->get_num_pkgs;
	ops->get_num_dies = op->get_num_dies;
	ops->get_num_freqs = op->get_num_freqs;
	ops->get_avail_freqs = op->get_avail_freqs;
	ops->get_freq = op->get_freq;
	ops->set_freq = op->set_freq;
	ops->freq_max = op->freq_max;
	ops->freq_min = op->freq_min;
	ops->status = 1; /* registered */

	return 0;
}

struct rte_power_uncore_ops *
rte_power_get_uncore_ops(int ops_index)
{
	RTE_VERIFY((ops_index != RTE_UNCORE_PM_ENV_INTEL_UNCORE) &&
			(ops_index != RTE_UNCORE_PM_ENV_AMD_HSMP));
	RTE_VERIFY(rte_power_uncore_ops[ops_index].status != 0);

	return &rte_power_uncore_ops[ops_index];
}

int
rte_power_set_uncore_env(enum rte_uncore_power_mgmt_env env)
{
	int ret = 0;
	struct rte_power_uncore_ops *ops;

	rte_spinlock_lock(&global_env_cfg_lock);

	if (default_uncore_env != RTE_UNCORE_PM_ENV_NOT_SET) {
		POWER_LOG(ERR, "Uncore Power Management Env already set.");
		rte_spinlock_unlock(&global_env_cfg_lock);
		return -1;
	}

	if (env == RTE_UNCORE_PM_ENV_AUTO_DETECT)
		/* Currently only intel_uncore is supported.
		 * This will be extended with auto-detection support
		 * for multiple uncore implementations.
		 */
		env = RTE_UNCORE_PM_ENV_INTEL_UNCORE;

	}

	ops = rte_power_get_uncore_ops(env);
	if (ops->status == 0) {
		POWER_LOG(ERR, "Invalid Power Management Environment(%d) set", env);
		ret = -1;
	} else
		default_uncore_env = env;

	rte_spinlock_unlock(&global_env_cfg_lock);
	return ret;
}

void
rte_power_unset_uncore_env(void)
{
	rte_spinlock_lock(&global_env_cfg_lock);
	default_uncore_env = RTE_UNCORE_PM_ENV_NOT_SET;
	rte_spinlock_unlock(&global_env_cfg_lock);
}

enum rte_uncore_power_mgmt_env
rte_power_get_uncore_env(void)
{
	return default_uncore_env;
}

int
rte_power_uncore_init(unsigned int pkg, unsigned int die)
{
	int ret = -1;
	struct rte_power_uncore_ops *ops;

	if ((default_uncore_env != RTE_UNCORE_PM_ENV_NOT_SET) &&
		(default_uncore_env != RTE_UNCORE_PM_ENV_AUTO_DETECT)) {
		ops = rte_power_get_uncore_ops(default_uncore_env);
		return ops->init(pkg, die);
	}

	/* Auto detect Environment */
	POWER_LOG(INFO, "Attempting to initialise Intel Uncore power mgmt...");
	ops = rte_power_get_uncore_ops(RTE_UNCORE_PM_ENV_INTEL_UNCORE);
	ret = ops->init(pkg, die);
	if (ret == 0) {
		rte_power_set_uncore_env(RTE_UNCORE_PM_ENV_INTEL_UNCORE);
		goto out;
	}

	if (default_uncore_env == RTE_UNCORE_PM_ENV_NOT_SET) {
		POWER_LOG(ERR, "Unable to set Power Management Environment "
			"for package %u Die %u", pkg, die);
		ret = 0;
	}
out:
	return ret;
}

int
rte_power_uncore_exit(unsigned int pkg, unsigned int die)
{
	struct rte_power_uncore_ops *ops;

	if (default_uncore_env == RTE_UNCORE_PM_ENV_NOT_SET) {
		POWER_LOG(ERR,
			"Uncore Env has not been set, unable to exit gracefully");
		return -1;
	}
	ops = rte_power_get_uncore_ops(default_uncore_env);
	return ops->exit(pkg, die);
}

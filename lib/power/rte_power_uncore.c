/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 * Copyright(c) 2024 Advanced Micro Devices, Inc.
 */

#include <errno.h>

#include <rte_errno.h>
#include <rte_spinlock.h>

#include "power_common.h"
#include "rte_power_uncore.h"

static enum rte_uncore_power_mgmt_env global_uncore_env = RTE_UNCORE_PM_ENV_NOT_SET;
static struct rte_power_uncore_ops *global_uncore_ops;

static rte_spinlock_t global_env_cfg_lock = RTE_SPINLOCK_INITIALIZER;
static RTE_TAILQ_HEAD(, rte_power_uncore_ops) uncore_ops_list =
			TAILQ_HEAD_INITIALIZER(uncore_ops_list);

const char *uncore_env_str[] = {
	"not set",
	"auto-detect",
	"intel-uncore",
	"amd-hsmp"
};

/* register the ops struct in rte_power_uncore_ops, return 0 on success. */
int
rte_power_register_uncore_ops(struct rte_power_uncore_ops *driver_ops)
{
	if (!driver_ops->init || !driver_ops->exit || !driver_ops->get_num_pkgs ||
		!driver_ops->get_num_dies || !driver_ops->get_num_freqs ||
		!driver_ops->get_avail_freqs || !driver_ops->get_freq ||
		!driver_ops->set_freq || !driver_ops->freq_max ||
		!driver_ops->freq_min) {
		POWER_LOG(ERR, "Missing callbacks while registering power ops");
		return -1;
	}
	if (driver_ops->cb)
		driver_ops->cb();

	TAILQ_INSERT_TAIL(&uncore_ops_list, driver_ops, next);

	return 0;
}

int
rte_power_set_uncore_env(enum rte_uncore_power_mgmt_env env)
{
	int ret = -1;
	struct rte_power_uncore_ops *ops;

	rte_spinlock_lock(&global_env_cfg_lock);

	if (global_uncore_env != RTE_UNCORE_PM_ENV_NOT_SET) {
		POWER_LOG(ERR, "Uncore Power Management Env already set.");
		goto out;
	}

	if (env == RTE_UNCORE_PM_ENV_AUTO_DETECT)
		/* Currently only intel_uncore is supported.
		 * This will be extended with auto-detection support
		 * for multiple uncore implementations.
		 */
		env = RTE_UNCORE_PM_ENV_INTEL_UNCORE;

	if (env <= RTE_DIM(uncore_env_str)) {
		RTE_TAILQ_FOREACH(ops, &uncore_ops_list, next)
			if (strncmp(ops->name, uncore_env_str[env],
				RTE_POWER_UNCORE_DRIVER_NAMESZ) == 0) {
				global_uncore_env = env;
				global_uncore_ops = ops;
				ret = 0;
				goto out;
			}
		POWER_LOG(ERR, "Power Management (%s) not supported",
				uncore_env_str[env]);
	} else
		POWER_LOG(ERR, "Invalid Power Management Environment");

out:
	rte_spinlock_unlock(&global_env_cfg_lock);

	return ret;
}

void
rte_power_unset_uncore_env(void)
{
	rte_spinlock_lock(&global_env_cfg_lock);
	global_uncore_env = RTE_UNCORE_PM_ENV_NOT_SET;
	rte_spinlock_unlock(&global_env_cfg_lock);
}

enum rte_uncore_power_mgmt_env
rte_power_get_uncore_env(void)
{
	return global_uncore_env;
}

struct rte_power_uncore_ops *
rte_power_get_uncore_ops(void)
{
	RTE_ASSERT(global_uncore_ops != NULL);

	return global_uncore_ops;
}

int
rte_power_uncore_init(unsigned int pkg, unsigned int die)
{
	int ret = -1;
	struct rte_power_uncore_ops *ops;
	uint8_t env;

	if ((global_uncore_env != RTE_UNCORE_PM_ENV_NOT_SET) &&
		(global_uncore_env != RTE_UNCORE_PM_ENV_AUTO_DETECT))
		return global_uncore_ops->init(pkg, die);

	/* Auto Detect Environment */
	RTE_TAILQ_FOREACH(ops, &uncore_ops_list, next)
	if (ops) {
		POWER_LOG(INFO,
			"Attempting to initialise %s power management...",
			ops->name);
		ret = ops->init(pkg, die);
		if (ret == 0) {
			for (env = 0; env < RTE_DIM(uncore_env_str); env++)
				if (strncmp(ops->name, uncore_env_str[env],
					RTE_POWER_UNCORE_DRIVER_NAMESZ) == 0) {
					rte_power_set_uncore_env(env);
					goto out;
				}
		}
	}
out:
	return ret;
}

int
rte_power_uncore_exit(unsigned int pkg, unsigned int die)
{
	if ((global_uncore_env != RTE_UNCORE_PM_ENV_NOT_SET) &&
			global_uncore_ops)
		return global_uncore_ops->exit(pkg, die);

	POWER_LOG(ERR,
		"Uncore Env has not been set, unable to exit gracefully");

	return -1;
}

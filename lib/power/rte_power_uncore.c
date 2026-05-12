/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 * Copyright(c) 2023 AMD Corporation
 */
#include <errno.h>

#include <eal_export.h>
#include <rte_spinlock.h>
#include <rte_debug.h>

#include "power_common.h"
#include "power_uncore_ops.h"

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
RTE_EXPORT_INTERNAL_SYMBOL(rte_power_register_uncore_ops)
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

static uint32_t rte_power_uncore_driver_name2env(char *name)
{
	for (uint32_t i = 0; i < RTE_DIM(uncore_env_str); i++) {
		if (!strcmp(name, uncore_env_str[i]))
			return i;
	}

	return UINT32_MAX;
}

static int rte_power_probe_uncore_driver(void)
{
	struct rte_power_uncore_ops *ops;
	int ret;

	global_uncore_ops = NULL;
	/* Use package-0 and die-0 to probe uncore driver. */
	RTE_TAILQ_FOREACH(ops, &uncore_ops_list, next) {
		ret = ops->init(0, 0);
		if (!ret) {
			global_uncore_env =
				rte_power_uncore_driver_name2env(ops->name);
			global_uncore_ops = ops;
			ops->exit(0, 0);
			break;
		}
	}

	return global_uncore_ops ? 0 : -ENODEV;
}

static void rte_power_remove_uncore_driver(void)
{
	global_uncore_ops = NULL;
	global_uncore_env = RTE_UNCORE_PM_ENV_NOT_SET;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_power_set_uncore_env, 23.11)
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

	if (env == RTE_UNCORE_PM_ENV_AUTO_DETECT) {
		ret = rte_power_probe_uncore_driver();
		if (ret)
			POWER_LOG(ERR, "Probe uncore driver failed, ret = %d.", ret);
		goto out;
	}

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

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_power_unset_uncore_env, 23.11)
void
rte_power_unset_uncore_env(void)
{
	rte_spinlock_lock(&global_env_cfg_lock);
	global_uncore_env = RTE_UNCORE_PM_ENV_NOT_SET;
	rte_spinlock_unlock(&global_env_cfg_lock);
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_power_get_uncore_env, 23.11)
enum rte_uncore_power_mgmt_env
rte_power_get_uncore_env(void)
{
	return global_uncore_env;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_power_uncore_driver_init, 26.07)
int
rte_power_uncore_driver_init(void)
{
	int die, pkg, max_pkg, max_die;
	int ret;

	rte_spinlock_lock(&global_env_cfg_lock);
	ret = rte_power_probe_uncore_driver();
	if (ret) {
		POWER_LOG(ERR, "Probe uncore driver failed, ret = %d.", ret);
		goto out;
	}

	max_pkg = rte_power_uncore_get_num_pkgs();
	if (max_pkg == 0) {
		ret = -EINVAL;
		goto remove_uncore_drv;
	}

	for (pkg = 0; pkg < max_pkg; pkg++) {
		max_die = rte_power_uncore_get_num_dies(pkg);
		if (max_die == 0) {
			ret = -EINVAL;
			goto remove_uncore_drv;
		}

		for (die = 0; die < max_die; die++) {
			ret = rte_power_uncore_init(pkg, die);
			if (ret) {
				POWER_LOG(ERR, "Unable to initialize uncore for pkg-%d die-%d",
					  pkg, die);
				goto uncore_exit;
			}
		}
	}
	rte_spinlock_unlock(&global_env_cfg_lock);
	return 0;

uncore_exit:
	for (; pkg >= 0; pkg--) {
		max_die = rte_power_uncore_get_num_dies(pkg);
		for (die = 0; die < max_die; die++) {
			ret = rte_power_uncore_exit(pkg, die);
			if (ret)
				POWER_LOG(ERR, "Failed to deinitialize uncore for pkg-%d die-%d",
					  pkg, die);
		}
	}

remove_uncore_drv:
	rte_power_remove_uncore_driver();
out:
	rte_spinlock_unlock(&global_env_cfg_lock);
	return ret;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_power_uncore_driver_deinit, 26.07)
void
rte_power_uncore_driver_deinit(void)
{
	unsigned int die, pkg, max_pkg, max_die;

	rte_spinlock_lock(&global_env_cfg_lock);
	if (global_uncore_ops == NULL)
		goto out;

	max_pkg = rte_power_uncore_get_num_pkgs();
	for (pkg = 0; pkg < max_pkg; pkg++) {
		max_die = rte_power_uncore_get_num_dies(pkg);
		for (die = 0; die < max_die; die++) {
			if (rte_power_uncore_exit(pkg, die) != 0)
				POWER_LOG(ERR, "Unable to deinitialize uncore for pkg-%02u die-%02u",
					  pkg, die);
		}
	}

	rte_power_remove_uncore_driver();
out:
	rte_spinlock_unlock(&global_env_cfg_lock);
}

RTE_EXPORT_SYMBOL(rte_power_uncore_init)
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

RTE_EXPORT_SYMBOL(rte_power_uncore_exit)
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

RTE_EXPORT_SYMBOL(rte_power_get_uncore_freq)
uint32_t
rte_power_get_uncore_freq(unsigned int pkg, unsigned int die)
{
	RTE_ASSERT(global_uncore_ops != NULL);
	return global_uncore_ops->get_freq(pkg, die);
}

RTE_EXPORT_SYMBOL(rte_power_set_uncore_freq)
int
rte_power_set_uncore_freq(unsigned int pkg, unsigned int die, uint32_t index)
{
	RTE_ASSERT(global_uncore_ops != NULL);
	return global_uncore_ops->set_freq(pkg, die, index);
}

RTE_EXPORT_SYMBOL(rte_power_uncore_freq_max)
int
rte_power_uncore_freq_max(unsigned int pkg, unsigned int die)
{
	RTE_ASSERT(global_uncore_ops != NULL);
	return global_uncore_ops->freq_max(pkg, die);
}

RTE_EXPORT_SYMBOL(rte_power_uncore_freq_min)
int
rte_power_uncore_freq_min(unsigned int pkg, unsigned int die)
{
	RTE_ASSERT(global_uncore_ops != NULL);
	return global_uncore_ops->freq_min(pkg, die);
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_power_uncore_freqs, 23.11)
int
rte_power_uncore_freqs(unsigned int pkg, unsigned int die,
			uint32_t *freqs, uint32_t num)
{
	RTE_ASSERT(global_uncore_ops != NULL);
	return global_uncore_ops->get_avail_freqs(pkg, die, freqs, num);
}

RTE_EXPORT_SYMBOL(rte_power_uncore_get_num_freqs)
int
rte_power_uncore_get_num_freqs(unsigned int pkg, unsigned int die)
{
	RTE_ASSERT(global_uncore_ops != NULL);
	return global_uncore_ops->get_num_freqs(pkg, die);
}

RTE_EXPORT_SYMBOL(rte_power_uncore_get_num_pkgs)
unsigned int
rte_power_uncore_get_num_pkgs(void)
{
	RTE_ASSERT(global_uncore_ops != NULL);
	return global_uncore_ops->get_num_pkgs();
}

RTE_EXPORT_SYMBOL(rte_power_uncore_get_num_dies)
unsigned int
rte_power_uncore_get_num_dies(unsigned int pkg)
{
	RTE_ASSERT(global_uncore_ops != NULL);
	return global_uncore_ops->get_num_dies(pkg);
}

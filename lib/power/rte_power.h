/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 * Copyright(c) 2024 Advanced Micro Devices, Inc.
 */

#ifndef _RTE_POWER_H
#define _RTE_POWER_H

/**
 * @file
 * RTE Power Management
 */

#include <rte_common.h>
#include <rte_log.h>
#include <rte_power_guest_channel.h>

#include "rte_power_cpufreq_api.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Power Management Environment State */
enum power_management_env {
	PM_ENV_NOT_SET = 0,
	PM_ENV_ACPI_CPUFREQ,
	PM_ENV_KVM_VM,
	PM_ENV_PSTATE_CPUFREQ,
	PM_ENV_CPPC_CPUFREQ,
	PM_ENV_AMD_PSTATE_CPUFREQ
};

/**
 * Check if a specific power management environment type is supported on a
 * currently running system.
 *
 * @param env
 *   The environment type to check support for.
 *
 * @return
 *   - 1 if supported
 *   - 0 if unsupported
 *   - -1 if error, with rte_errno indicating reason for error.
 */
int rte_power_check_env_supported(enum power_management_env env);

/**
 * Set the default power management implementation. If this is not called prior
 * to rte_power_init(), then auto-detect of the environment will take place.
 * It is thread safe. New env can be set only in uninitialized state
 * (thus rte_power_unset_env must be called if different env was already set).
 *
 * @param env
 *  env. The environment in which to initialise Power Management for.
 *
 * @return
 *  - 0 on success.
 *  - Negative on error.
 */
int rte_power_set_env(enum power_management_env env);

/**
 * Unset the global environment configuration.
 * This can only be called after all threads have completed.
 */
void rte_power_unset_env(void);

/**
 * Get the default power management implementation.
 *
 * @return
 *  power_management_env The configured environment.
 */
enum power_management_env rte_power_get_env(void);

/**
 * @internal Get the power ops struct from its index.
 *
 * @return
 *   The pointer to the ops struct in the table if registered.
 */
struct rte_power_core_ops *
rte_power_get_core_ops(void);

/**
 * Initialize power management for a specific lcore. If rte_power_set_env() has
 * not been called then an auto-detect of the environment will start and
 * initialise the corresponding resources.
 *
 * @param lcore_id
 *  lcore id.
 *
 * @return
 *  - 0 on success.
 *  - Negative on error.
 */
int rte_power_init(unsigned int lcore_id);

/**
 * Exit power management on a specific lcore. This will call the environment
 * dependent exit function.
 *
 * @param lcore_id
 *  lcore id.
 *
 * @return
 *  - 0 on success.
 *  - Negative on error.
 */
int rte_power_exit(unsigned int lcore_id);

/**
 * Get the available frequencies of a specific lcore.
 * Function pointer definition. Review each environments
 * specific documentation for usage.
 *
 * @param lcore_id
 *  lcore id.
 * @param freqs
 *  The buffer array to save the frequencies.
 * @param num
 *  The number of frequencies to get.
 *
 * @return
 *  The number of available frequencies.
 */
static inline uint32_t
rte_power_freqs(unsigned int lcore_id, uint32_t *freqs, uint32_t n)
{
	struct rte_power_core_ops *ops = rte_power_get_core_ops();

	return ops->get_avail_freqs(lcore_id, freqs, n);
}

/**
 * Return the current index of available frequencies of a specific lcore.
 * Function pointer definition. Review each environments
 * specific documentation for usage.
 *
 * @param lcore_id
 *  lcore id.
 *
 * @return
 *  The current index of available frequencies.
 */
static inline uint32_t
rte_power_get_freq(unsigned int lcore_id)
{
	struct rte_power_core_ops *ops = rte_power_get_core_ops();

	return ops->get_freq(lcore_id);
}

/**
 * Set the new frequency for a specific lcore by indicating the index of
 * available frequencies.
 * Function pointer definition. Review each environments
 * specific documentation for usage.
 *
 * @param lcore_id
 *  lcore id.
 * @param index
 *  The index of available frequencies.
 *
 * @return
 *  - 1 on success with frequency changed.
 *  - 0 on success without frequency changed.
 *  - Negative on error.
 */
static inline uint32_t
rte_power_set_freq(unsigned int lcore_id, uint32_t index)
{
	struct rte_power_core_ops *ops = rte_power_get_core_ops();

	return ops->set_freq(lcore_id, index);
}

/**
 * Scale up the frequency of a specific lcore according to the available
 * frequencies.
 * Review each environments specific documentation for usage.
 */
static inline int
rte_power_freq_up(unsigned int lcore_id)
{
	struct rte_power_core_ops *ops = rte_power_get_core_ops();

	return ops->freq_up(lcore_id);
}

/**
 * Scale down the frequency of a specific lcore according to the available
 * frequencies.
 * Review each environments specific documentation for usage.
 */
static inline int
rte_power_freq_down(unsigned int lcore_id)
{
	struct rte_power_core_ops *ops = rte_power_get_core_ops();

	return ops->freq_down(lcore_id);
}

/**
 * Scale up the frequency of a specific lcore to the highest according to the
 * available frequencies.
 * Review each environments specific documentation for usage.
 */
static inline int
rte_power_freq_max(unsigned int lcore_id)
{
	struct rte_power_core_ops *ops = rte_power_get_core_ops();

	return ops->freq_max(lcore_id);
}

/**
 * Scale down the frequency of a specific lcore to the lowest according to the
 * available frequencies.
 * Review each environments specific documentation for usage..
 */
static inline int
rte_power_freq_min(unsigned int lcore_id)
{
	struct rte_power_core_ops *ops = rte_power_get_core_ops();

	return ops->freq_min(lcore_id);
}

/**
 * Query the Turbo Boost status of a specific lcore.
 * Review each environments specific documentation for usage..
 */
static inline int
rte_power_turbo_status(unsigned int lcore_id)
{
	struct rte_power_core_ops *ops = rte_power_get_core_ops();

	return ops->turbo_status(lcore_id);
}

/**
 * Enable Turbo Boost for this lcore.
 * Review each environments specific documentation for usage..
 */
static inline int
rte_power_freq_enable_turbo(unsigned int lcore_id)
{
	struct rte_power_core_ops *ops = rte_power_get_core_ops();

	return ops->enable_turbo(lcore_id);
}

/**
 * Disable Turbo Boost for this lcore.
 * Review each environments specific documentation for usage..
 */
static inline int
rte_power_freq_disable_turbo(unsigned int lcore_id)
{
	struct rte_power_core_ops *ops = rte_power_get_core_ops();

	return ops->disable_turbo(lcore_id);
}

/**
 * Returns power capabilities for a specific lcore.
 * Function pointer definition. Review each environments
 * specific documentation for usage.
 *
 * @param lcore_id
 *  lcore id.
 * @param caps
 *  pointer to rte_power_core_capabilities object.
 *
 * @return
 *  - 0 on success.
 *  - Negative on error.
 */
static inline int
rte_power_get_capabilities(unsigned int lcore_id,
		struct rte_power_core_capabilities *caps)
{
	struct rte_power_core_ops *ops = rte_power_get_core_ops();

	return ops->get_caps(lcore_id, caps);
}

#ifdef __cplusplus
}
#endif

#endif

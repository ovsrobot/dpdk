/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Intel Corporation
 * Copyright(c) 2023 AMD Corporation
 */

#ifndef RTE_POWER_UNCORE_H
#define RTE_POWER_UNCORE_H

/**
 * @file
 * RTE Uncore Frequency Management
 */

#include <rte_compat.h>
#include "rte_power.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Uncore Power Management Environment */
enum rte_uncore_power_mgmt_env {
	RTE_UNCORE_PM_ENV_NOT_SET,
	RTE_UNCORE_PM_ENV_AUTO_DETECT,
	RTE_UNCORE_PM_ENV_INTEL_UNCORE,
	RTE_UNCORE_PM_ENV_AMD_HSMP
};

/**
 * Set the default uncore power management implementation.
 * This has to be called prior to calling any other rte_power_uncore_*() API.
 * It is thread safe. New env can be set only in uninitialized state.
 * rte_power_unset_uncore_env must be called if different env was already set.
 *
 * @param env
 *  env. The environment in which to initialise Uncore Power Management for.
 *
 * @return
 *  - 0 on success.
 *  - Negative on error.
 */
__rte_experimental
int rte_power_set_uncore_env(enum rte_uncore_power_mgmt_env env);

/**
 * Unset the global uncore environment configuration.
 * This can only be called after all threads have completed.
 */
__rte_experimental
void rte_power_unset_uncore_env(void);

/**
 * Get the default uncore power management implementation.
 *
 * @return
 *  power_management_env The configured environment.
 */
__rte_experimental
enum rte_uncore_power_mgmt_env rte_power_get_uncore_env(void);

/**
 * Function pointers for generic frequency change functions.
 *
 * @param pkg
 *  Package number.
 *  Each physical CPU in a system is referred to as a package.
 * @param die
 *  Die number.
 *  Each package can have several dies connected together via the uncore mesh.
 *
 * @return
 *  - 1 on success with frequency changed.
 *  - 0 on success without frequency changed.
 *  - Negative on error.
 */
typedef int (*rte_power_uncore_init_t)(unsigned int pkg, unsigned int die);
typedef int (*rte_power_uncore_exit_t)(unsigned int pkg, unsigned int die);

typedef uint32_t (*rte_power_get_uncore_freq_t)(unsigned int pkg, unsigned int die);
typedef int (*rte_power_set_uncore_freq_t)(unsigned int pkg, unsigned int die, uint32_t index);
typedef int (*rte_power_uncore_get_num_freqs_t)(unsigned int pkg, unsigned int die);
typedef int (*rte_power_uncore_freqs_t)(unsigned int pkg, unsigned int die,
					uint32_t *freqs, uint32_t num);
typedef int (*rte_power_uncore_freq_change_t)(unsigned int pkg, unsigned int die);
typedef unsigned int (*rte_power_uncore_get_num_pkgs_t)(void);
typedef unsigned int (*rte_power_uncore_get_num_dies_t)(unsigned int pkg);

/** Structure defining uncore power operations structure */
struct rte_power_uncore_ops {
	uint8_t status;                         /**< ops register status. */
	enum rte_uncore_power_mgmt_env env;          /**< power mgmt env. */
	rte_power_uncore_init_t init;    /**< Initialize power management. */
	rte_power_uncore_exit_t exit;    /**< Exit power management. */
	rte_power_uncore_get_num_pkgs_t get_num_pkgs;
	rte_power_uncore_get_num_dies_t get_num_dies;
	rte_power_uncore_get_num_freqs_t get_num_freqs; /**< Number of available frequencies. */
	rte_power_uncore_freqs_t get_avail_freqs; /**< Get the available frequencies. */
	rte_power_get_uncore_freq_t get_freq; /**< Get frequency index. */
	rte_power_set_uncore_freq_t set_freq; /**< Set frequency index. */
	rte_power_uncore_freq_change_t freq_max;  /**< Scale up frequency to highest. */
	rte_power_uncore_freq_change_t freq_min;  /**< Scale up frequency to lowest. */
} __rte_cache_aligned;


/**
 * Register power uncore frequency operations.
 * @param ops
 *   Pointer to an ops structure to register.
 * @return
 *   - >=0: Success; return the index of the ops struct in the table.
 *   - -EINVAL - error while registering ops struct.
 */
__rte_internal
int rte_power_register_uncore_ops(const struct rte_power_uncore_ops *ops);

/**
 * Macro to statically register the ops of an uncore driver.
 */
#define RTE_POWER_REGISTER_UNCORE_OPS(ops)		\
	(RTE_INIT(power_hdlr_init_uncore_##ops)         \
	{                                               \
		rte_power_register_uncore_ops(&ops);    \
	})

/**
 * @internal Get the power uncore ops struct from its index.
 *
 * @param ops_index
 *   The index of the ops struct in the ops struct table.
 * @return
 *   The pointer to the ops struct in the table if registered.
 */
struct rte_power_uncore_ops *
rte_power_get_uncore_ops(int ops_index);

/**
 * Initialize uncore frequency management for specific die on a package.
 * It will get the available frequencies and prepare to set new die frequencies.
 *
 * This function should NOT be called in the fast path.
 *
 * @param pkg
 *  Package number.
 *  Each physical CPU in a system is referred to as a package.
 * @param die
 *  Die number.
 *  Each package can have several dies connected together via the uncore mesh.
 *
 * @return
 *  - 0 on success.
 *  - Negative on error.
 */
int
rte_power_uncore_init(unsigned int pkg, unsigned int die);

/**
 * Exit uncore frequency management on a specific die on a package.
 * It will restore uncore min and* max values to previous values
 * before initialization of API.
 *
 * This function should NOT be called in the fast path.
 *
 * @param pkg
 *  Package number.
 *  Each physical CPU in a system is referred to as a package.
 * @param die
 *  Die number.
 *  Each package can have several dies connected together via the uncore mesh.
 *
 * @return
 *  - 0 on success.
 *  - Negative on error.
 */
int
rte_power_uncore_exit(unsigned int pkg, unsigned int die);

/**
 * Return the current index of available frequencies of a specific die on a package.
 * It should be protected outside of this function for threadsafe.
 *
 * This function should NOT be called in the fast path.
 *
 * @param pkg
 *  Package number.
 *  Each physical CPU in a system is referred to as a package.
 * @param die
 *  Die number.
 *  Each package can have several dies connected together via the uncore mesh.
 *
 * @return
 *  The current index of available frequencies.
 *  If error, it will return 'RTE_POWER_INVALID_FREQ_INDEX = (~0)'.
 */
static inline uint32_t
rte_power_get_uncore_freq(unsigned int pkg, unsigned int die)
{
	struct rte_power_uncore_ops *ops;

	ops = rte_power_get_uncore_ops(rte_power_get_uncore_env());
	return ops->get_freq(pkg, die);
}

/**
 * Set minimum and maximum uncore frequency for specified die on a package
 * to specified index value.
 * It should be protected outside of this function for threadsafe.
 *
 * This function should NOT be called in the fast path.
 *
 * @param pkg
 *  Package number.
 *  Each physical CPU in a system is referred to as a package.
 * @param die
 *  Die number.
 *  Each package can have several dies connected together via the uncore mesh.
 * @param index
 *  The index of available frequencies.
 *
 * @return
 *  - 1 on success with frequency changed.
 *  - 0 on success without frequency changed.
 *  - Negative on error.
 */
static inline uint32_t
rte_power_set_uncore_freq(unsigned int pkg, unsigned int die, uint32_t index)
{
	struct rte_power_uncore_ops *ops;

	ops = rte_power_get_uncore_ops(rte_power_get_uncore_env());
	return ops->set_freq(pkg, die, index);
}


/**
 * Function pointer definition for generic frequency change functions.
 *
 * @param pkg
 *  Package number.
 *  Each physical CPU in a system is referred to as a package.
 * @param die
 *  Die number.
 *  Each package can have several dies connected together via the uncore mesh.
 *
 * @return
 *  - 1 on success with frequency changed.
 *  - 0 on success without frequency changed.
 *  - Negative on error.
 */
typedef int (*rte_power_uncore_freq_change_t)(unsigned int pkg, unsigned int die);

/**
 * Set minimum and maximum uncore frequency for specified die on a package
 * to maximum value according to the available frequencies.
 * It should be protected outside of this function for threadsafe.
 *
 * This function should NOT be called in the fast path.
 */
static inline uint32_t
rte_power_uncore_freq_max(unsigned int pkg, unsigned int die)
{
	struct rte_power_uncore_ops *ops;

	ops = rte_power_get_uncore_ops(rte_power_get_uncore_env());
	return ops->freq_max(pkg, die);
}

/**
 * Set minimum and maximum uncore frequency for specified die on a package
 * to minimum value according to the available frequencies.
 * It should be protected outside of this function for threadsafe.
 *
 * This function should NOT be called in the fast path.
 */
static inline uint32_t
rte_power_uncore_freq_min(unsigned int pkg, unsigned int die)
{
	struct rte_power_uncore_ops *ops;

	ops = rte_power_get_uncore_ops(rte_power_get_uncore_env());
	return ops->freq_min(pkg, die);
}

/**
 * Return the list of available frequencies in the index array.
 *
 * This function should NOT be called in the fast path.
 *
 * @param pkg
 *  Package number.
 *  Each physical CPU in a system is referred to as a package.
 * @param die
 *  Die number.
 *  Each package can have several dies connected together via the uncore mesh.
 * @param freqs
 *  The buffer array to save the frequencies.
 * @param num
 *  The number of frequencies to get.
 *
 * @return
 *  - The number of available index's in frequency array.
 *  - Negative on error.
 */
static inline uint32_t
rte_power_uncore_freqs(unsigned int pkg, unsigned int die,
		uint32_t *freqs, uint32_t num)
{
	struct rte_power_uncore_ops *ops;

	ops = rte_power_get_uncore_ops(rte_power_get_uncore_env());
	return ops->get_avail_freqs(pkg, die, freqs, num);
}

/**
 * Return the list length of available frequencies in the index array.
 *
 * This function should NOT be called in the fast path.
 *
 * @param pkg
 *  Package number.
 *  Each physical CPU in a system is referred to as a package.
 * @param die
 *  Die number.
 *  Each package can have several dies connected together via the uncore mesh.
 *
 * @return
 *  - The number of available index's in frequency array.
 *  - Negative on error.
 */
static inline int
rte_power_uncore_get_num_freqs(unsigned int pkg, unsigned int die)
{
	struct rte_power_uncore_ops *ops;

	ops = rte_power_get_uncore_ops(rte_power_get_uncore_env());
	return ops->get_num_freqs(pkg, die);
}

/**
 * Return the number of packages (CPUs) on a system
 * by parsing the uncore sysfs directory.
 *
 * This function should NOT be called in the fast path.
 *
 * @return
 *  - Zero on error.
 *  - Number of package on system on success.
 */
static inline unsigned int
rte_power_uncore_get_num_pkgs(void)
{
	struct rte_power_uncore_ops *ops;

	ops = rte_power_get_uncore_ops(rte_power_get_uncore_env());
	return ops->get_num_pkgs(void);
}

/**
 * Return the number of dies for pakckages (CPUs) specified
 * from parsing the uncore sysfs directory.
 *
 * This function should NOT be called in the fast path.
 *
 * @param pkg
 *  Package number.
 *  Each physical CPU in a system is referred to as a package.
 *
 * @return
 *  - Zero on error.
 *  - Number of dies for package on sucecss.
 */
static inline unsigned int
rte_power_uncore_get_num_dies(unsigned int pkg)
{
	struct rte_power_uncore_ops *ops;

	ops = rte_power_get_uncore_ops(rte_power_get_uncore_env());
	return ops->get_num_dies(pkg);
}

#ifdef __cplusplus
}
#endif

#endif /* RTE_POWER_UNCORE_H */

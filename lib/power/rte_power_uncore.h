/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Intel Corporation
 */

#ifndef _RTE_POWER_UNCORE_H
#define _RTE_POWER_UNCORE_H

/**
 * @file
 * RTE Uncore Frequency Management
 */

#include "rte_power.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize uncore frequency management for specific die on a package. It will check and set the
 * governor to performance for the die, get the available frequencies, and
 * prepare to set new die frequency.
 *
 * This function should NOT be called in the fast path.
 *
 * @param pkg
 *  Package number.
 * @param die
 *  Die number.
 *
 * @return
 *  - 0 on success.
 *  - Negative on error.
 */
__rte_experimental
int
rte_power_uncore_init(unsigned int pkg, unsigned int die);

/**
 * Exit uncore frequency management on a specific die on a package. It will set the governor to
 * which is before initialized.
 *
 * This function should NOT be called in the fast path.
 *
 * @param pkg
 *  Package number.
 * @param die
 *  Die number.
 *
 * @return
 *  - 0 on success.
 *  - Negative on error.
 */
__rte_experimental
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
 * @param die
 *  Die number.
 *
 * @return
 *  - The current index of available frequencies.
 *  - Negative on error.
 */
__rte_experimental
int
rte_power_get_uncore_freq(unsigned int pkg, unsigned int die);

/**
 * Set the new frequency for a specific die on a package by indicating the index of
 * available frequencies.
 * It should be protected outside of this function for threadsafe.
 *
 * This function should NOT be called in the fast path.
 *
 * @param pkg
 *  Package number.
 * @param die
 *  Die number.
 * @param index
 *  The index of available frequencies.
 *
 * @return
 *  - 0 on success.
 *  - Negative on error.
 */
__rte_experimental
int
rte_power_set_uncore_freq(unsigned int pkg, unsigned int die, uint32_t index);

/**
 * Scale up the frequency of a specific die on a package to the highest according to the
 * available frequencies.
 * It should be protected outside of this function for threadsafe.
 *
 * This function should NOT be called in the fast path.
 *
 * @param pkg
 *  Package number.
 * @param die
 *  Die number.
 *
 * @return
 *  - 0 on success.
 *  - Negative on error.
 */
__rte_experimental
int
rte_power_uncore_freq_max(unsigned int pkg, unsigned int die);

/**
 * Scale down the frequency of a specific die on a package to the lowest according to the
 * available frequencies.
 * It should be protected outside of this function for threadsafe.
 *
 * This function should NOT be called in the fast path.
 *
 * @param pkg
 *  Package number.
 * @param die
 *  Die number.
 *
 * @return
 *  - 0 on success.
 *  - Negative on error.
 */
__rte_experimental
int
rte_power_uncore_freq_min(unsigned int pkg, unsigned int die);

/**
 * Return the list length of available frequencies in the index array
 *
 * @param pkg
 *  Package number.
 * @param die
 *  Die number.
 *
 * @return
 *  - The number of available index's in frequency array
 *  - Negative on error
 */
__rte_experimental
int
rte_power_uncore_get_num_freqs(unsigned int pkg, unsigned int die);

#ifdef __cplusplus
}
#endif

#endif

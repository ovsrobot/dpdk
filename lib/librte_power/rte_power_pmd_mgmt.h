/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2020 Intel Corporation
 */

#ifndef _RTE_POWER_PMD_MGMT_H
#define _RTE_POWER_PMD_MGMT_H

/**
 * @file
 * RTE PMD Power Management
 */
#include <stdint.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_power.h>
#include <rte_atomic.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * PMD Power Management Type
 */
enum rte_power_pmd_mgmt_type {
	/** WAIT callback mode. */
	RTE_POWER_MGMT_TYPE_WAIT = 1,
	/** PAUSE callback mode. */
	RTE_POWER_MGMT_TYPE_PAUSE,
	/** Freq Scaling callback mode. */
	RTE_POWER_MGMT_TYPE_SCALE,
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Setup per-queue power management callback.
 *
 * @note This function is not thread-safe.
 *
 * @param lcore_id
 *   lcore_id.
 * @param port_id
 *   The port identifier of the Ethernet device.
 * @param queue_id
 *   The queue identifier of the Ethernet device.
 * @param mode
 *   The power management callback function type.

 * @return
 *   0 on success
 *   <0 on error
 */
__rte_experimental
int
rte_power_pmd_mgmt_queue_enable(unsigned int lcore_id,
				uint16_t port_id,
				uint16_t queue_id,
				enum rte_power_pmd_mgmt_type mode);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Remove per-queue power management callback.
 *
 * @note This function is not thread-safe.
 *
 * @param lcore_id
 *   lcore_id.
 * @param port_id
 *   The port identifier of the Ethernet device.
 * @param queue_id
 *   The queue identifier of the Ethernet device.
 * @return
 *   0 on success
 *   <0 on error
 */
__rte_experimental
int
rte_power_pmd_mgmt_queue_disable(unsigned int lcore_id,
				uint16_t port_id,
				uint16_t queue_id);
#ifdef __cplusplus
}
#endif

#endif

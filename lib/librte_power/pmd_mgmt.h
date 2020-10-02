/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2020 Intel Corporation
 */

#ifndef _PMD_MGMT_H
#define _PMD_MGMT_H

/**
 * @file
 * Power Management
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Possible power management states of an ethdev port.
 */
enum pmd_mgmt_state {
	/** Device power management is disabled. */
	PMD_MGMT_DISABLED = 0,
	/** Device power management is enabled. */
	PMD_MGMT_ENABLED,
};

struct pmd_queue_cfg {
	enum pmd_mgmt_state pwr_mgmt_state;
	/**< Power mgmt Callback mode */
	enum rte_power_pmd_mgmt_type cb_mode;
	/**< Empty poll number */
	uint16_t empty_poll_stats;
	/**< Callback instance  */
	const struct rte_eth_rxtx_callback *cur_cb;
} __rte_cache_aligned;

struct pmd_port_cfg {
	int  ref_cnt;
	struct pmd_queue_cfg *queue_cfg;
} __rte_cache_aligned;




#ifdef __cplusplus
}
#endif

#endif

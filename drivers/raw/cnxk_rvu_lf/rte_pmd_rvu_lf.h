/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2024 Marvell.
 */

#ifndef _CNXK_RVU_LF_H_
#define _CNXK_RVU_LF_H_

#include <stdint.h>

#include <rte_common.h>
#include <rte_dev.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_rawdev.h>

/**
 * @file rte_pmd_rvu_lf.h
 *
 * Marvell RVU LF raw PMD specific structures and interface
 *
 * This API allows applications to manage RVU LF device in user space along with
 * installing interrupt handlers for low latency signal processing.
 */

#ifdef __cplusplus
extern "C" {
#endif

extern int cnxk_logtype_rvu_lf;

#define CNXK_RVU_LF_LOG(level, fmt, args...)	\
	rte_log(RTE_LOG_ ## level, cnxk_logtype_rvu_lf, \
		"%s(): " fmt "\n", __func__, ## args)

/**
 * Signature of callback function called when an interrupt is received on RVU LF device.
 *
 * @param cb_arg
 *   pointer to the information received on an interrupt
 */
typedef void (*rte_pmd_rvu_lf_intr_callback_fn)(void *cb_arg);

/**
 * Register interrupt callback
 *
 * Registers an interrupt callback to be executed when interrupt is raised.
 *
 * @param dev_id
 *   device id of RVU LF device
 * @param irq
 *   interrupt number for which interrupt will be raised
 * @param cb
 *   callback function to be executed
 * @param cb_arg
 *   argument to be passed to callback function
 *
 * @return 0 on success, negative value otherwise
 */
__rte_experimental
int rte_pmd_rvu_lf_irq_register(uint8_t dev_id, unsigned int irq,
				rte_pmd_rvu_lf_intr_callback_fn cb, void *cb_arg);

/**
 * Unregister interrupt callback
 *
 * @param dev_id
 *   device id of RVU LF device
 * @param irq
 *   interrupt number
 * @param cb
 *   callback function registered
 * @param cb_arg
 *   argument to be passed to callback function
 *
 * @return 0 on success, negative value otherwise
 */
__rte_experimental
int rte_pmd_rvu_lf_irq_unregister(uint8_t dev_id, unsigned int irq,
				  rte_pmd_rvu_lf_intr_callback_fn cb, void *cb_arg);

/**
 * Obtain NPA PF func
 *
 * @return
 *   Returns NPA pf_func on success, 0 in case of invalid pf_func.
 */
__rte_experimental
uint16_t rte_pmd_rvu_lf_npa_pf_func_get(void);

/**
 * Obtain SSO PF func
 *
 * @return
 *   Returns SSO pf_func on success, 0 in case of invalid pf_func.
 */
__rte_experimental
uint16_t rte_pmd_rvu_lf_sso_pf_func_get(void);

/**
 * Get BAR addresses for the RVU LF device.
 *
 * @param dev_id
 *   device id of RVU LF device
 * @param bar_num
 *   BAR number for which address is required
 * @param[out] va
 *    Virtual address of the BAR. 0 if not mapped
 * @param[out] mask
 *    BAR address mask, 0 if not mapped
 *
 * @return
 *   Returns 0 on success, negative error code otherwise
 */
__rte_experimental
int rte_pmd_rvu_lf_bar_get(uint8_t dev_id, uint8_t bar_num, size_t *va, size_t *mask);

#ifdef __cplusplus
}
#endif

#endif /* _CNXK_RVU_LF_H_ */

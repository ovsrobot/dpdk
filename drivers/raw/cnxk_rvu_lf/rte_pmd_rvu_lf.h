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

#ifdef __cplusplus
}
#endif

#endif /* _CNXK_RVU_LF_H_ */

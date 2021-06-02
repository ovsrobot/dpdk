/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#ifndef _CNXK_CPT_OPS_HELPER_H_
#define _CNXK_CPT_OPS_HELPER_H_

#define CPT_MAX_IV_LEN		 16
#define CPT_OFFSET_CONTROL_BYTES 8
#define SG_ENTRY_SIZE		 sizeof(struct roc_se_sglist_comp)

/*
 * Get size of contiguous meta buffer to be allocated
 *
 * @return
 *   - length
 */
int cnxk_cpt_ops_helper_get_mlen(void);

#endif /* _CNXK_CPT_OPS_HELPER_H_ */

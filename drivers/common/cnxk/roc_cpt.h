/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#ifndef _ROC_CPT_H_
#define _ROC_CPT_H_

#include "roc_api.h"

#define ROC_CPT_MAX_LFS 64

struct roc_cpt {
	struct plt_pci_device *pci_dev;
	struct roc_cpt_lf *lf[ROC_CPT_MAX_LFS];
	uint16_t nb_lf;
	uint16_t nb_lf_avail;
	uintptr_t lmt_base;
	/**< CPT device capabilities */
	union cpt_eng_caps hw_caps[CPT_MAX_ENG_TYPES];
	uint8_t eng_grp[CPT_MAX_ENG_TYPES];

#define ROC_CPT_MEM_SZ (6 * 1024)
	uint8_t reserved[ROC_CPT_MEM_SZ] __plt_cache_aligned;
} __plt_cache_aligned;

int __roc_api roc_cpt_dev_init(struct roc_cpt *roc_cpt);
int __roc_api roc_cpt_dev_fini(struct roc_cpt *roc_cpt);
int __roc_api roc_cpt_eng_grp_add(struct roc_cpt *roc_cpt,
				  enum cpt_eng_type eng_type);
int __roc_api roc_cpt_dev_configure(struct roc_cpt *roc_cpt, int nb_lf);
void __roc_api roc_cpt_dev_clear(struct roc_cpt *roc_cpt);
#endif /* _ROC_CPT_H_ */

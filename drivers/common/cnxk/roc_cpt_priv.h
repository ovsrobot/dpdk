/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#ifndef _ROC_CPT_PRIV_H_
#define _ROC_CPT_PRIV_H_

/* Set number of number of hystbits to 6.
 * This will trigger the FC writes whenever
 * number of outstanding commands in the queue
 * becomes multiple of 32.
 */
#define CPT_FC_NUM_HYST_BITS 6

struct cpt {
	struct plt_pci_device *pci_dev;
	struct dev dev;
	uint16_t lf_msix_off[ROC_CPT_MAX_LFS];
	uint8_t lf_blkaddr[ROC_CPT_MAX_LFS];
} __plt_cache_aligned;

static inline struct cpt *
roc_cpt_to_cpt_priv(struct roc_cpt *roc_cpt)
{
	return (struct cpt *)&roc_cpt->reserved[0];
}

#endif /* _ROC_CPT_PRIV_H_ */

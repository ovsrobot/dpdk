/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#ifndef _ROC_IDEV_PRIV_H_
#define _ROC_IDEV_PRIV_H_

/* Intra device related functions */
struct npa_lf;
struct idev_cfg {
	uint16_t npa_pf_func;
	struct npa_lf *npa;
	uint16_t npa_refcnt;
	uint32_t max_pools;
	uint16_t lmt_pf_func;
	uint16_t num_lmtlines;
	uint64_t lmt_base_addr;
};

/* Generic */
struct idev_cfg *idev_get_cfg(void);
void idev_set_defaults(struct idev_cfg *idev);

/* idev npa */
uint16_t idev_npa_pffunc_get(void);
struct npa_lf *idev_npa_obj_get(void);
uint32_t idev_npa_maxpools_get(void);
void idev_npa_maxpools_set(uint32_t max_pools);
uint16_t idev_npa_lf_active(struct dev *dev);

/* idev lmt */
uint16_t idev_lmt_pffunc_get(void);

#endif /* _ROC_IDEV_PRIV_H_ */

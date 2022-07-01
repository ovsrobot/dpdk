/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Corigine, Inc.
 * All rights reserved.
 */

#ifndef _NFP_FLOWER_H_
#define _NFP_FLOWER_H_

enum nfp_flower_service {
	NFP_FLOWER_SERVICE_MAX
};

/* The flower application's private structure */
struct nfp_app_flower {
	/* List of rte_service ID's for the flower app */
	uint32_t flower_services_ids[NFP_FLOWER_SERVICE_MAX];
};

int nfp_init_app_flower(struct nfp_pf_dev *pf_dev);
int nfp_secondary_init_app_flower(struct nfp_cpp *cpp);

#endif /* _NFP_FLOWER_H_ */

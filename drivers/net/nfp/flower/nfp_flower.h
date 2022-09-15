/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Corigine, Inc.
 * All rights reserved.
 */

#ifndef _NFP_FLOWER_H_
#define _NFP_FLOWER_H_

/* The flower application's private structure */
struct nfp_app_fw_flower {
	/* Pointer to a mempool for the PF vNIC */
	struct rte_mempool *pf_pktmbuf_pool;

	/* Pointer to the PF vNIC */
	struct nfp_net_hw *pf_hw;

	/* the eth table as reported by firmware */
	struct nfp_eth_table *nfp_eth_table;
};

int nfp_init_app_fw_flower(struct nfp_pf_dev *pf_dev);
int nfp_secondary_init_app_fw_flower(struct nfp_cpp *cpp);

#endif /* _NFP_FLOWER_H_ */

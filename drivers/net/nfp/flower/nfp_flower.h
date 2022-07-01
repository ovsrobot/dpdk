/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Corigine, Inc.
 * All rights reserved.
 */

#ifndef _NFP_FLOWER_H_
#define _NFP_FLOWER_H_

enum nfp_flower_service {
	NFP_FLOWER_SERVICE_CTRL,
	NFP_FLOWER_SERVICE_MAX
};

/*
 * Flower fallback and ctrl path always adds and removes
 * 8 bytes of prepended data. Tx descriptors must point
 * to the correct packet data offset after metadata has
 * been added
 */
#define FLOWER_PKT_DATA_OFFSET 8

/* The flower application's private structure */
struct nfp_app_flower {
	/* List of rte_service ID's for the flower app */
	uint32_t flower_services_ids[NFP_FLOWER_SERVICE_MAX];

	/* Pointer to a mempool for the PF vNIC */
	struct rte_mempool *pf_pktmbuf_pool;

	/* Pointer to the PF vNIC */
	struct nfp_net_hw *pf_hw;

	/* Pointer to a mempool for the ctrlvNIC */
	struct rte_mempool *ctrl_pktmbuf_pool;

	/* Pointer to the ctrl vNIC */
	struct nfp_net_hw *ctrl_hw;

	/* the eth table as reported by firmware */
	struct nfp_eth_table *nfp_eth_table;

	/* Ctrl vNIC Rx counter */
	uint64_t ctrl_vnic_rx_count;

	/* Ctrl vNIC Tx counter */
	uint64_t ctrl_vnic_tx_count;
};

int nfp_init_app_flower(struct nfp_pf_dev *pf_dev);
int nfp_secondary_init_app_flower(struct nfp_cpp *cpp);

#endif /* _NFP_FLOWER_H_ */

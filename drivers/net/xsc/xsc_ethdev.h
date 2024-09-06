/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 Yunsilicon Technology Co., Ltd.
 */

#ifndef _XSC_ETHDEV_H_
#define _XSC_ETHDEV_H_

#define XSC_RSS_HASH_KEY_LEN 52
#define XSC_MAX_DESC_NUMBER 1024
#define XSC_RX_FREE_THRESH 32

#define XSC_CMD_OP_MODIFY_NIC_HCA 0x812

struct xsc_dev_config {
	uint8_t pph_flag;
	unsigned int hw_csum:1;
	unsigned int tso:1;
	unsigned int tso_max_payload_sz;
};

struct xsc_ethdev_priv {
	struct rte_eth_dev *eth_dev;
	struct rte_pci_device *pci_dev;
	struct xsc_dev *xdev;
	struct xsc_repr_port *repr_port;
	struct xsc_dev_config config;
	struct rte_eth_dev_data *dev_data;
	struct rte_ether_addr mac[XSC_MAX_MAC_ADDRESSES];
	struct rte_eth_rss_conf rss_conf;

	int32_t representor_id;

	uint32_t ifindex;
	uint16_t mtu;
	uint8_t isolated;
	uint8_t representor;

	uint32_t mode:7;
	uint32_t member_bitmap:8;
	uint32_t funcid_type:3;
	uint32_t funcid:14;

	uint16_t eth_type;
	uint16_t qp_set_id;

	uint16_t num_sq;
	uint16_t num_rq;

	struct xsc_txq_data *(*txqs)[];
	struct xsc_rxq_data *(*rxqs)[];
};

#define TO_XSC_ETHDEV_PRIV(dev) \
	((struct xsc_ethdev_priv *)(dev)->data->dev_private)

enum {
	XSC_TBM_CAP_HASH_PPH = 0,
	XSC_TBM_CAP_RSS,
	XSC_TBM_CAP_PP_BYPASS,
	XSC_TBM_CAP_PCT_DROP_CONFIG,
};

enum {
	XSC_RSS_HASH_KEY_UPDATE = 0,
	XSC_RSS_HASH_TEMP_UPDATE,
	XSC_RSS_HASH_FUNC_UPDATE,
	XSC_RSS_RXQ_UPDATE,
	XSC_RSS_RXQ_DROP,
};

#endif /* _XSC_ETHDEV_H_ */
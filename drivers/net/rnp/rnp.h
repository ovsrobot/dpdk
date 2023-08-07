/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Mucse IC Design Ltd.
 */
#ifndef __RNP_H__
#define __RNP_H__

#include "base/rnp_hw.h"

#define PCI_VENDOR_ID_MUCSE	(0x8848)
#define RNP_DEV_ID_N10G		(0x1000)
#define RNP_MAX_PORT_OF_PF	(4)
#define RNP_CFG_BAR		(4)
#define RNP_PF_INFO_BAR		(0)

struct rnp_eth_port {
	struct rnp_eth_adapter *adapt;
	struct rte_eth_dev *eth_dev;
} __rte_cache_aligned;

struct rnp_share_ops {
} __rte_cache_aligned;

struct rnp_eth_adapter {
	struct rnp_hw hw;
	struct rte_pci_device *pdev;
	struct rte_eth_dev *eth_dev; /* master eth_dev */
	struct rnp_eth_port *ports[RNP_MAX_PORT_OF_PF];
	struct rnp_share_ops *share_priv;

	uint8_t num_ports; /* Cur Pf Has physical Port Num */
} __rte_cache_aligned;

#define RNP_DEV_TO_PORT(eth_dev) \
	(((struct rnp_eth_port *)((eth_dev)->data->dev_private)))
#define RNP_DEV_TO_ADAPTER(eth_dev) \
	((struct rnp_eth_adapter *)(RNP_DEV_TO_PORT(eth_dev)->adapt))

#endif /* __RNP_H__ */

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Mucse IC Design Ltd.
 */
#ifndef __RNP_H__
#define __RNP_H__
#include <rte_log.h>

#include "base/rnp_hw.h"

#define PCI_VENDOR_ID_MUCSE	(0x8848)
#define RNP_DEV_ID_N10G		(0x1000)
#define RNP_MAX_PORT_OF_PF	(4)
#define RNP_CFG_BAR		(4)
#define RNP_PF_INFO_BAR		(0)

enum rnp_resource_share_m {
	RNP_SHARE_CORPORATE = 0,
	RNP_SHARE_INDEPEND,
};
/*
 * Structure to store private data for each driver instance (for each port).
 */
enum rnp_work_mode {
	RNP_SINGLE_40G = 0,
	RNP_SINGLE_10G = 1,
	RNP_DUAL_10G = 2,
	RNP_QUAD_10G = 3,
};

struct rnp_eth_port {
	void *adapt;
	struct rnp_hw *hw;
	struct rte_eth_dev *eth_dev;
} __rte_cache_aligned;

struct rnp_share_ops {
	const struct rnp_mbx_api *mbx_api;
	const struct rnp_mac_api *mac_api;
} __rte_cache_aligned;

struct rnp_eth_adapter {
	enum rnp_work_mode mode;
	enum rnp_resource_share_m s_mode; /* Port Resource Share Policy */
	struct rnp_hw hw;
	uint16_t max_vfs;
	struct rte_pci_device *pdev;
	struct rte_eth_dev *eth_dev; /* master eth_dev */
	struct rnp_eth_port *ports[RNP_MAX_PORT_OF_PF];
	struct rnp_share_ops *share_priv;

	int max_link_speed;
	uint8_t num_ports; /* Cur Pf Has physical Port Num */
	uint8_t lane_mask;
} __rte_cache_aligned;

#define RNP_DEV_TO_PORT(eth_dev) \
	(((struct rnp_eth_port *)((eth_dev)->data->dev_private)))
#define RNP_DEV_TO_ADAPTER(eth_dev) \
	((struct rnp_eth_adapter *)(RNP_DEV_TO_PORT(eth_dev)->adapt))
#define RNP_DEV_TO_HW(eth_dev) \
	(&((struct rnp_eth_adapter *)(RNP_DEV_TO_PORT((eth_dev))->adapt))->hw)
#define RNP_HW_TO_ADAPTER(hw) \
	((struct rnp_eth_adapter *)((hw)->back))
#define RNP_DEV_PP_PRIV_TO_MBX_OPS(dev) \
	(((struct rnp_share_ops *)(dev)->process_private)->mbx_api)
#define RNP_DEV_TO_MBX_OPS(dev)	RNP_DEV_PP_PRIV_TO_MBX_OPS(dev)
#define RNP_DEV_PP_PRIV_TO_MAC_OPS(dev) \
	(((struct rnp_share_ops *)(dev)->process_private)->mac_api)
#define RNP_DEV_TO_MAC_OPS(dev) RNP_DEV_PP_PRIV_TO_MAC_OPS(dev)

static inline void rnp_reg_offset_init(struct rnp_hw *hw)
{
	uint16_t i;

	if (hw->device_id == RNP_DEV_ID_N10G && hw->mbx.pf_num) {
		hw->iobar4 += 0x100000;
		hw->msix_base = hw->iobar4 + 0xa0000;
		hw->msix_base += 0x200;
	} else {
		hw->msix_base = hw->iobar4 + 0xa0000;
	}
	/* === dma status/config====== */
	hw->dev_version  = hw->iobar4 + 0x0000;
	hw->link_sync    = hw->iobar4 + 0x000c;
	hw->dma_axi_en   = hw->iobar4 + 0x0010;
	hw->dma_axi_st   = hw->iobar4 + 0x0014;
	if (hw->mbx.pf_num)
		hw->msix_base += 0x200;
	/* === queue registers === */
	hw->dma_base     = hw->iobar4 + 0x08000;
	hw->veb_base     = hw->iobar4 + 0x0;
	hw->eth_base     = hw->iobar4 + 0x10000;
	/* mac */
	for (i = 0; i < RNP_MAX_HW_PORT_PERR_PF; i++)
		hw->mac_base[i] = hw->iobar4 + 0x60000 + 0x10000 * i;
	/* ===  top reg === */
	hw->comm_reg_base = hw->iobar4 + 0x30000;
}
#endif /* __RNP_H__ */

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

struct rnp_eth_port {
	void *adapt;
	struct rnp_hw *hw;
	struct rte_eth_dev *eth_dev;
} __rte_cache_aligned;

struct rnp_share_ops {
	const struct rnp_mbx_api *mbx_api;
} __rte_cache_aligned;

struct rnp_eth_adapter {
	struct rnp_hw hw;
	uint16_t max_vfs;
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
#define RNP_DEV_TO_HW(eth_dev) \
	(&((struct rnp_eth_adapter *)(RNP_DEV_TO_PORT((eth_dev))->adapt))->hw)
#define RNP_DEV_PP_PRIV_TO_MBX_OPS(dev) \
	(((struct rnp_share_ops *)(dev)->process_private)->mbx_api)
#define RNP_DEV_TO_MBX_OPS(dev)	RNP_DEV_PP_PRIV_TO_MBX_OPS(dev)

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
}
#endif /* __RNP_H__ */

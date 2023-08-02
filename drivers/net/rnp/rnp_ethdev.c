/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Mucse IC Design Ltd.
 */

#include <ethdev_pci.h>
#include <rte_io.h>
#include <rte_malloc.h>
#include <ethdev_driver.h>

#include "rnp.h"
#include "rnp_api.h"
#include "rnp_mbx.h"
#include "rnp_mbx_fw.h"
#include "rnp_logs.h"

static int
rnp_mac_rx_disable(struct rte_eth_dev *dev)
{
	RTE_SET_USED(dev);

	return 0;
}

static int
rnp_mac_tx_disable(struct rte_eth_dev *dev)
{
	RTE_SET_USED(dev);

	return 0;
}

static int rnp_dev_close(struct rte_eth_dev *dev)
{
	RTE_SET_USED(dev);

	return 0;
}

/* Features supported by this driver */
static const struct eth_dev_ops rnp_eth_dev_ops = {
};

static int
rnp_init_port_resource(struct rnp_eth_adapter *adapter,
		       struct rte_eth_dev *dev,
		       char *name,
		       uint8_t p_id)
{
	struct rnp_eth_port *port = RNP_DEV_TO_PORT(dev);

	port->eth_dev = dev;
	adapter->ports[p_id] = port;
	dev->dev_ops = &rnp_eth_dev_ops;
	RTE_SET_USED(name);

	return 0;
}

static struct rte_eth_dev *
rnp_alloc_eth_port(struct rte_pci_device *master_pci, char *name)
{
	struct rnp_eth_port *port;
	struct rte_eth_dev *eth_dev;

	eth_dev = rte_eth_dev_allocate(name);
	if (!eth_dev) {
		RNP_PMD_DRV_LOG(ERR, "Could not allocate "
				"eth_dev for %s\n", name);
		return NULL;
	}
	port = rte_zmalloc_socket(name,
			sizeof(*port),
			RTE_CACHE_LINE_SIZE,
			master_pci->device.numa_node);
	if (!port) {
		RNP_PMD_DRV_LOG(ERR, "Could not allocate "
				"rnp_eth_port for %s\n", name);
		return NULL;
	}
	eth_dev->data->dev_private = port;
	eth_dev->process_private = calloc(1, sizeof(struct rnp_share_ops));
	if (!eth_dev->process_private) {
		RNP_PMD_DRV_LOG(ERR, "Could not calloc "
				"for Process_priv\n");
		goto fail_calloc;
	}
	return eth_dev;
fail_calloc:
	rte_free(port);
	rte_eth_dev_release_port(eth_dev);

	return NULL;
}

static void rnp_get_nic_attr(struct rnp_eth_adapter *adapter)
{
	struct rnp_hw *hw = &adapter->hw;
	int lane_mask = 0, err, mode = 0;

	rnp_mbx_link_event_enable(adapter->eth_dev, false);

	err = rnp_mbx_get_capability(adapter->eth_dev, &lane_mask, &mode);
	if (err < 0 || !lane_mask) {
		PMD_DRV_LOG(ERR, "%s: mbx_get_capability error! errcode=%d\n",
				__func__, hw->speed);
		return;
	}

	adapter->num_ports = __builtin_popcount(lane_mask);
	adapter->max_link_speed = hw->speed;
	adapter->lane_mask = lane_mask;
	adapter->mode = hw->nic_mode;

	PMD_DRV_LOG(INFO, "max link speed:%d lane_mask:0x%x nic-mode:0x%x\n",
			(int)adapter->max_link_speed,
			(int)adapter->num_ports, adapter->mode);
	if (adapter->num_ports && adapter->num_ports == 1)
		adapter->s_mode = RNP_SHARE_CORPORATE;
	else
		adapter->s_mode = RNP_SHARE_INDEPEND;
}

static int
rnp_process_resource_init(struct rte_eth_dev *eth_dev)
{
	struct rnp_share_ops *share_priv;

	/* allocate process_private memory this must can't
	 * belone to the dpdk mem resource manager
	 * such as from rte_malloc or rte_dma_zone..
	 */
	/* use the process_prive point to resolve secondary process
	 * use point-func. This point is per process will be safe to cover.
	 * This will cause secondary process core-dump because of IPC
	 * Secondary will call primary process point func virt-address
	 * secondary process don't alloc user/pmd to alloc or free
	 * the memory of dpdk-mem resource it will cause hugepage
	 * mem exception
	 * be careful for secondary Process to use the share-mem of
	 * point correlation
	 */
	share_priv = calloc(1, sizeof(*share_priv));
	if (!share_priv) {
		PMD_DRV_LOG(ERR, "calloc share_priv failed");
		return -ENOMEM;
	}
	memset(share_priv, 0, sizeof(*share_priv));
	eth_dev->process_private = share_priv;

	return 0;
}

static int32_t rnp_init_hw_pf(struct rnp_hw *hw)
{
	struct rnp_eth_adapter *adapter = RNP_HW_TO_ADAPTER(hw);
	uint32_t version;
	uint32_t reg;

	PMD_INIT_FUNC_TRACE();
	version = rnp_rd_reg(hw->dev_version);
	PMD_DRV_LOG(INFO, "NIC HW Version:0x%.2x\n", version);

	/* Disable Rx/Tx Dma */
	rnp_wr_reg(hw->dma_axi_en, false);
	/* Check Dma Chanle Status */
	while (rnp_rd_reg(hw->dma_axi_st) == 0)
		;

	/* Reset Nic All Hardware */
	if (rnp_reset_hw(adapter->eth_dev, hw))
		return -EPERM;

	/* Rx Proto Offload No-BYPASS */
	rnp_eth_wr(hw, RNP_ETH_ENGINE_BYPASS, false);
	/* Enable Flow Filter Engine */
	rnp_eth_wr(hw, RNP_HOST_FILTER_EN, true);
	/* Enable VXLAN Parse */
	rnp_eth_wr(hw, RNP_EN_TUNNEL_VXLAN_PARSE, true);
	/* Enabled REDIR ACTION */
	rnp_eth_wr(hw, RNP_REDIR_CTRL, true);

	/* Setup Scatter DMA Mem Size */
	reg = ((RTE_ETHER_MAX_LEN / 16) << RNP_DMA_SCATTER_MEM_SHIFT);
	rnp_wr_reg(hw->iobar4 + RNP_DMA_CTRL, reg);
#ifdef PHYTIUM_SUPPORT
#define RNP_DMA_PADDING      (1 << 8)
	reg = rnp_rd_reg(hw->iobar4 + RNP_DMA_CTRL);
	reg |= RNP_DMA_PADDING;
	rnp_wr_reg(hw->iobar4 + RNP_DMA_CTRL, reg);
#endif
	/* Enable Rx/Tx Dma */
	rnp_wr_reg(hw->dma_axi_en, 0b1111);

	rnp_wr_reg(hw->comm_reg_base + RNP_TX_QINQ_WORKAROUND, 1);

	return 0;
}

static int32_t rnp_reset_hw_pf(struct rnp_hw *hw)
{
	struct rnp_eth_adapter *adapter = hw->back;

	rnp_wr_reg(hw->comm_reg_base + RNP_NIC_RESET, 0);
	rte_wmb();
	rnp_wr_reg(hw->comm_reg_base + RNP_NIC_RESET, 1);

	rnp_mbx_fw_reset_phy(adapter->eth_dev);

	PMD_DRV_LOG(INFO, "PF[%d] reset nic finish\n",
			hw->function);
	return 0;
}

const struct rnp_mac_api rnp_mac_ops = {
	.reset_hw	= rnp_reset_hw_pf,
	.init_hw	= rnp_init_hw_pf
};

static void
rnp_common_ops_init(struct rnp_eth_adapter *adapter)
{
	struct rnp_share_ops *share_priv;

	share_priv = adapter->share_priv;
	share_priv->mbx_api = &rnp_mbx_pf_ops;
}

static int
rnp_special_ops_init(struct rte_eth_dev *eth_dev)
{
	RTE_SET_USED(eth_dev);

	return 0;
}

static int
rnp_eth_dev_init(struct rte_eth_dev *dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(dev);
	struct rnp_eth_adapter *adapter = NULL;
	char name[RTE_ETH_NAME_MAX_LEN] = " ";
	struct rnp_eth_port *port = NULL;
	struct rte_eth_dev *eth_dev;
	struct rnp_hw *hw = NULL;
	int32_t p_id;
	int ret;

	PMD_INIT_FUNC_TRACE();

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;
	memset(name, 0, sizeof(name));
	snprintf(name, sizeof(name), "rnp_adapter_%d", dev->data->port_id);
	adapter = rte_zmalloc(name, sizeof(struct rnp_eth_adapter), 0);
	if (!adapter) {
		RNP_PMD_DRV_LOG(ERR, "zmalloc for adapter failed\n");
		return -ENOMEM;
	}
	hw = &adapter->hw;
	adapter->pdev = pci_dev;
	adapter->eth_dev = dev;
	adapter->num_ports = 1;
	hw->back = (void *)adapter;
	hw->iobar4 = (char *)pci_dev->mem_resource[RNP_CFG_BAR].addr;
	hw->iobar0 = (char *)pci_dev->mem_resource[RNP_PF_INFO_BAR].addr;
	hw->iobar4_len = pci_dev->mem_resource[RNP_CFG_BAR].len;
	hw->iobar0_len = pci_dev->mem_resource[RNP_PF_INFO_BAR].len;
	hw->device_id = pci_dev->id.device_id;
	hw->vendor_id = pci_dev->id.vendor_id;
	hw->device_id = pci_dev->id.device_id;
	adapter->max_vfs = pci_dev->max_vfs;
	ret = rnp_process_resource_init(dev);
	if (ret) {
		PMD_DRV_LOG(ERR, "share prive resource init failed");
		return ret;
	}
	adapter->share_priv = dev->process_private;
	rnp_common_ops_init(adapter);
	rnp_get_nic_attr(adapter);
	/* We need Use Device Id To Change The Resource Mode */
	rnp_special_ops_init(dev);
	port->adapt = adapter;
	port->hw = hw;
	rnp_init_mbx_ops_pf(hw);
	for (p_id = 0; p_id < adapter->num_ports; p_id++) {
		/* port 0 resource has been alloced When Probe */
		if (!p_id) {
			eth_dev = dev;
		} else {
			snprintf(name, sizeof(name), "%s_%d",
					adapter->pdev->device.name,
					p_id);
			eth_dev = rnp_alloc_eth_port(pci_dev, name);
			if (eth_dev)
				rte_memcpy(eth_dev->process_private,
						adapter->share_priv,
						sizeof(*adapter->share_priv));
			if (!eth_dev) {
				ret = -ENOMEM;
				goto eth_alloc_error;
			}
		}
		ret = rnp_init_port_resource(adapter, eth_dev, name, p_id);
		if (ret)
			goto eth_alloc_error;

		rnp_mac_rx_disable(eth_dev);
		rnp_mac_tx_disable(eth_dev);
	}

	return 0;
eth_alloc_error:
	for (p_id = 0; p_id < adapter->num_ports; p_id++) {
		port = adapter->ports[p_id];
		if (!port)
			continue;
		if (port->eth_dev) {
			rnp_dev_close(port->eth_dev);
			if (port->eth_dev->process_private)
				free(port->eth_dev->process_private);
			rte_eth_dev_release_port(port->eth_dev);
		}
	}
	rte_free(adapter);

	return 0;
}

static int
rnp_eth_dev_uninit(struct rte_eth_dev *eth_dev)
{
	struct rnp_eth_adapter *adapter = RNP_DEV_TO_ADAPTER(eth_dev);
	struct rnp_eth_port *port = NULL;
	uint8_t p_id;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	if (adapter->eth_dev != eth_dev) {
		RNP_PMD_DRV_LOG(ERR, "Input Argument ethdev "
			       "Isn't Master Ethdev\n");
		return -EINVAL;
	}
	for (p_id = 0; p_id < adapter->num_ports; p_id++) {
		port = adapter->ports[p_id];
		if (!port)
			continue;
		if (port->eth_dev) {
			rnp_dev_close(port->eth_dev);
			/* Just Release Not Master Port Alloced By PMD */
			if (p_id)
				rte_eth_dev_release_port(port->eth_dev);
		}
	}

	return 0;
}

static int
rnp_pci_remove(struct rte_pci_device *pci_dev)
{
	struct rte_eth_dev *eth_dev;
	int rc;

	eth_dev = rte_eth_dev_allocated(pci_dev->device.name);

	if (eth_dev) {
		/* Cleanup eth dev */
		rc = rte_eth_dev_pci_generic_remove(pci_dev,
				rnp_eth_dev_uninit);
		if (rc)
			return rc;
	}
	/* Nothing to be done for secondary processes */
	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	return 0;
}

static int
rnp_pci_probe(struct rte_pci_driver *pci_drv, struct rte_pci_device *pci_dev)
{
	int rc;

	RTE_SET_USED(pci_drv);

	rc = rte_eth_dev_pci_generic_probe(pci_dev, sizeof(struct rnp_eth_port),
					   rnp_eth_dev_init);

	/* On error on secondary, recheck if port exists in primary or
	 * in mid of detach state.
	 */
	if (rte_eal_process_type() != RTE_PROC_PRIMARY && rc)
		if (!rte_eth_dev_allocated(pci_dev->device.name))
			return 0;
	return rc;
}

static const struct rte_pci_id pci_id_rnp_map[] = {
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MUCSE, RNP_DEV_ID_N10G)
	},
	{
		.vendor_id = 0,
	},
};

static struct rte_pci_driver rte_rnp_pmd = {
	.id_table = pci_id_rnp_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING | RTE_PCI_DRV_INTR_LSC,
	.probe = rnp_pci_probe,
	.remove = rnp_pci_remove,
};

RTE_PMD_REGISTER_PCI(net_rnp, rte_rnp_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_rnp, pci_id_rnp_map);
RTE_PMD_REGISTER_KMOD_DEP(net_txgbe, "igb_uio | uio_pci_generic");

RTE_LOG_REGISTER_SUFFIX(rnp_init_logtype, init, NOTICE);
RTE_LOG_REGISTER_SUFFIX(rnp_drv_logtype, driver, NOTICE);

#ifdef RTE_LIBRTE_RNP_DEBUG_RX
	RTE_LOG_REGISTER_SUFFIX(rnp_rx_logtype, rx, DEBUG);
#endif

#ifdef RTE_LIBRTE_RNP_DEBUG_TX
	RTE_LOG_REGISTER_SUFFIX(rnp_tx_logtype, tx, DEBUG);
#endif

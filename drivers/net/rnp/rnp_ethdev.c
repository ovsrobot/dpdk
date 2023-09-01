/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Mucse IC Design Ltd.
 */

#include <ethdev_pci.h>
#include <rte_io.h>
#include <rte_malloc.h>
#include <ethdev_driver.h>
#include <rte_kvargs.h>

#include "rnp.h"
#include "rnp_api.h"
#include "rnp_mbx.h"
#include "rnp_mbx_fw.h"
#include "rnp_rxtx.h"
#include "rnp_logs.h"

#define RNP_HW_MAC_LOOPBACK_ARG      "hw_loopback"
#define RNP_FW_UPDATE                "fw_update"
#define RNP_RX_FUNC_SELECT           "rx_func_sec"
#define RNP_TX_FUNC_SELECT           "tx_func_sec"
#define RNP_FW_4X10G_10G_1G_DET      "fw_4x10g_10g_1g_auto_det"
#define RNP_FW_FORCE_SPEED_1G        "fw_force_1g_speed"

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

static void
rnp_setup_port_attr(struct rnp_eth_port *port,
		    struct rte_eth_dev *dev,
		    uint8_t num_ports,
		    uint8_t p_id)
{
	struct rnp_port_attr *attr = &port->attr;
	struct rnp_hw *hw = RNP_DEV_TO_HW(dev);
	uint32_t lane_bit;

	if (port->s_mode == RNP_SHARE_INDEPENDENT) {
		attr->max_mac_addrs = RNP_PORT_MAX_MACADDR;
		attr->max_uc_mac_hash = RNP_PORT_MAX_UC_MAC_SIZE;
		attr->uc_hash_tb_size = RNP_PORT_MAX_UC_HASH_TB;
		attr->max_mc_mac_hash = RNP_PORT_MAX_MACADDR;
		attr->max_vlan_hash = RNP_PORT_MAX_VLAN_HASH;
		attr->hash_table_shift = 26 - (attr->max_uc_mac_hash >> 7);
	} else {
		attr->max_mac_addrs = RNP_MAX_MAC_ADDRS / num_ports;
		attr->max_uc_mac_hash = RNP_MAX_UC_MAC_SIZE / num_ports;
		attr->uc_hash_tb_size = RNP_MAX_UC_HASH_TB;
		attr->max_mc_mac_hash = RNP_MAX_MC_MAC_SIZE / num_ports;
		attr->mc_hash_tb_size = RNP_MAC_MC_HASH_TB;
		attr->max_vlan_hash = RNP_MAX_VLAN_HASH_TB_SIZE / num_ports;
		attr->hash_table_shift = RNP_UTA_BIT_SHIFT;
	}
	if (hw->ncsi_en)
		attr->uc_hash_tb_size -= hw->ncsi_rar_entries;
	if (hw->device_id == RNP_DEV_ID_N400L_X4) {
		attr->max_rx_queues = RNP_N400_MAX_RX_QUEUE_NUM;
		attr->max_tx_queues = RNP_N400_MAX_TX_QUEUE_NUM;
	} else {
		attr->max_rx_queues = RNP_MAX_RX_QUEUE_NUM / num_ports;
		attr->max_tx_queues = RNP_MAX_TX_QUEUE_NUM / num_ports;
	}

	attr->rte_pid = dev->data->port_id;
	lane_bit = hw->phy_port_ids[p_id] & (hw->max_port_num - 1);

	attr->nr_port = lane_bit;
	attr->port_offset = rnp_eth_rd(hw, RNP_TC_PORT_MAP_TB(attr->nr_port));

	rnp_mbx_get_lane_stat(dev);

	PMD_DRV_LOG(INFO, "PF[%d] SW-ETH-PORT[%d]<->PHY_LANE[%d]\n",
			hw->function, p_id, lane_bit);
}

static void
rnp_init_filter_setup(struct rnp_eth_port *port,
		      uint8_t num_ports)
{
	RTE_SET_USED(port);
	RTE_SET_USED(num_ports);
}

static int
rnp_init_port_resource(struct rnp_eth_adapter *adapter,
		       struct rte_eth_dev *dev,
		       char *name,
		       uint8_t p_id)
{
	struct rnp_eth_port *port = RNP_DEV_TO_PORT(dev);
	struct rte_pci_device *pci_dev = adapter->pdev;
	struct rnp_hw *hw = &adapter->hw;

	port->adapt = adapter;
	port->rx_func_sec = adapter->rx_func_sec;
	port->tx_func_sec = adapter->tx_func_sec;
	port->s_mode = adapter->s_mode;
	port->port_stopped = 1;
	port->hw = hw;
	port->eth_dev = dev;

	dev->device = &pci_dev->device;
	rte_eth_copy_pci_info(dev, pci_dev);
	dev->dev_ops = &rnp_eth_dev_ops;
	dev->rx_queue_count       = rnp_dev_rx_queue_count;
	dev->rx_descriptor_status = rnp_dev_rx_descriptor_status;
	dev->tx_descriptor_status = rnp_dev_tx_descriptor_status;
	dev->rx_pkt_burst = rnp_recv_pkts;
	dev->tx_pkt_burst = rnp_xmit_pkts;
	dev->tx_pkt_prepare = rnp_prep_pkts;

	rnp_setup_port_attr(port, dev, adapter->num_ports, p_id);
	rnp_init_filter_setup(port, adapter->num_ports);
	rnp_get_mac_addr(dev, port->mac_addr);
	dev->data->mac_addrs = rte_zmalloc(name, sizeof(struct rte_ether_addr) *
			port->attr.max_mac_addrs, 0);
	if (!dev->data->mac_addrs) {
		RNP_PMD_DRV_LOG(ERR, "Memory allocation "
				"for MAC failed! Exiting.\n");
		return -ENOMEM;
	}
	/* Allocate memory for storing hash filter MAC addresses */
	dev->data->hash_mac_addrs = rte_zmalloc(name,
			RTE_ETHER_ADDR_LEN * port->attr.max_uc_mac_hash, 0);
	if (dev->data->hash_mac_addrs == NULL) {
		RNP_PMD_INIT_LOG(ERR, "Failed to allocate %d bytes "
				"needed to store MAC addresses",
				RTE_ETHER_ADDR_LEN * port->attr.max_uc_mac_hash);
		return -ENOMEM;
	}

	rnp_set_default_mac(dev, port->mac_addr);
	rte_ether_addr_copy((const struct rte_ether_addr *)port->mac_addr,
			dev->data->mac_addrs);
	/* MTU */
	dev->data->mtu = RTE_ETHER_MAX_LEN -
		RTE_ETHER_HDR_LEN - RTE_ETHER_CRC_LEN;
	adapter->ports[p_id] = port;
	rte_eth_dev_probing_finish(dev);

	return 0;
}

static struct rte_eth_dev *
rnp_alloc_eth_port(struct rte_pci_device *primary_pci, char *name)
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
			primary_pci->device.numa_node);
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
		adapter->s_mode = RNP_SHARE_INDEPENDENT;
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
	rnp_dma_wr(hw,  RNP_DMA_CTRL, reg);
#ifdef PHYTIUM_SUPPORT
#define RNP_DMA_PADDING      (1 << 8)
	reg = rnp_dma_rd(hw, RNP_DMA_CTRL);
	reg |= RNP_DMA_PADDING;
	rnp_dma_wr(hw, RNP_DMA_CTRL, reg);
#endif
	/* Enable Rx/Tx Dma */
	rnp_wr_reg(hw->dma_axi_en, 0b1111);

	rnp_top_wr(hw, RNP_TX_QINQ_WORKAROUND, 1);

	return 0;
}

static int32_t rnp_reset_hw_pf(struct rnp_hw *hw)
{
	struct rnp_eth_adapter *adapter = hw->back;

	rnp_top_wr(hw, RNP_NIC_RESET, 0);
	rte_wmb();
	rnp_top_wr(hw, RNP_NIC_RESET, 1);

	rnp_mbx_fw_reset_phy(adapter->eth_dev);

	PMD_DRV_LOG(INFO, "PF[%d] reset nic finish\n",
			hw->function);
	return 0;
}

static void
rnp_mac_res_take_in(struct rnp_eth_port *port,
		    uint8_t index)
{
	if (!port->mac_use_tb[index]) {
		port->mac_use_tb[index] = true;
		port->use_num_mac++;
	}
}

static void
rnp_mac_res_remove(struct rnp_eth_port *port,
		   uint8_t index)
{
	if (port->mac_use_tb[index]) {
		port->mac_use_tb[index] = false;
		port->use_num_mac--;
	}
}

static int32_t rnp_set_mac_addr_pf(struct rnp_eth_port *port,
				   uint8_t *mac, uint8_t vm_pool,
				   uint8_t index)
{
	struct rnp_hw *hw = RNP_PORT_TO_HW(port);
	struct rnp_port_attr *attr = &port->attr;
	uint8_t hw_idx;
	uint32_t value;

	if (port->use_num_mac > port->attr.max_mac_addrs ||
			index > port->attr.max_mac_addrs)
		return -ENOMEM;

	if (vm_pool != UINT8_MAX)
		hw_idx = (attr->nr_port * attr->max_mac_addrs) + vm_pool + index;
	else
		hw_idx = (attr->nr_port * attr->max_mac_addrs) + index;

	rnp_mac_res_take_in(port, hw_idx);

	value = (mac[0] << 8) | mac[1];
	value |= RNP_MAC_FILTER_EN;
	RNP_MACADDR_UPDATE_HI(hw, hw_idx, value);

	value = (mac[2] << 24) | (mac[3] << 16) | (mac[4] << 8) | mac[5];
	RNP_MACADDR_UPDATE_LO(hw, hw_idx, value);

	return 0;
}

static void
rnp_remove_mac_from_hw(struct rnp_eth_port *port,
		       uint8_t vm_pool, uint8_t index)
{
	struct rnp_hw *hw = RNP_PORT_TO_HW(port);
	struct rnp_port_attr *attr = &port->attr;
	uint16_t hw_idx;

	if (vm_pool != UINT8_MAX)
		hw_idx = (attr->nr_port * attr->max_mac_addrs) + vm_pool + index;
	else
		hw_idx = (attr->nr_port * attr->max_mac_addrs) + index;

	rnp_mac_res_remove(port, hw_idx);

	rnp_eth_wr(hw, RNP_RAL_BASE_ADDR(hw_idx), 0);
	rnp_eth_wr(hw, RNP_RAH_BASE_ADDR(hw_idx), 0);
}

static int32_t
rnp_clear_mac_addr_pf(struct rnp_eth_port *port,
		      uint8_t vm_pool, uint8_t index)
{
	rnp_remove_mac_from_hw(port, vm_pool, index);

	return 0;
}

static int32_t rnp_get_mac_addr_pf(struct rnp_eth_port *port,
				   uint8_t lane,
				   uint8_t *macaddr)
{
	struct rnp_hw *hw = RNP_DEV_TO_HW(port->eth_dev);

	return rnp_fw_get_macaddr(port->eth_dev, hw->pf_vf_num, macaddr, lane);
}

static int32_t
rnp_set_default_mac_pf(struct rnp_eth_port *port,
		       uint8_t *mac)
{
	struct rnp_eth_adapter *adap = RNP_PORT_TO_ADAPTER(port);
	uint16_t max_vfs;

	if (port->s_mode == RNP_SHARE_INDEPENDENT)
		return rnp_set_rafb(port->eth_dev, (uint8_t *)mac,
				UINT8_MAX, 0);

	max_vfs = adap->max_vfs;

	return rnp_set_rafb(port->eth_dev, mac, max_vfs, 0);
}

const struct rnp_mac_api rnp_mac_ops = {
	.reset_hw	= rnp_reset_hw_pf,
	.init_hw	= rnp_init_hw_pf,
	.get_mac_addr	= rnp_get_mac_addr_pf,
	.set_default_mac = rnp_set_default_mac_pf,
	.set_rafb	= rnp_set_mac_addr_pf,
	.clear_rafb	= rnp_clear_mac_addr_pf
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
	struct rnp_eth_adapter *adapter = RNP_DEV_TO_ADAPTER(eth_dev);
	struct rnp_share_ops *share_priv;

	share_priv = adapter->share_priv;
	share_priv->mac_api = &rnp_mac_ops;

	return 0;
}

static const char *const rnp_valid_arguments[] = {
	RNP_HW_MAC_LOOPBACK_ARG,
	RNP_FW_UPDATE,
	RNP_RX_FUNC_SELECT,
	RNP_TX_FUNC_SELECT,
	RNP_FW_4X10G_10G_1G_DET,
	RNP_FW_FORCE_SPEED_1G,
	NULL
};

static int
rnp_parse_handle_devarg(const char *key, const char *value,
			void *extra_args)
{
	struct rnp_eth_adapter *adapter = NULL;

	if (value == NULL || extra_args == NULL)
		return -EINVAL;

	if (strcmp(key, RNP_HW_MAC_LOOPBACK_ARG) == 0) {
		uint64_t *n = extra_args;
		*n = (uint16_t)strtoul(value, NULL, 10);
		if (*n > UINT16_MAX && errno == ERANGE) {
			RNP_PMD_DRV_LOG(ERR, "invalid extra param value\n");
			return -1;
		}
	} else if (strcmp(key, RNP_FW_UPDATE) == 0) {
		adapter = (struct rnp_eth_adapter *)extra_args;
		adapter->do_fw_update = true;
		adapter->fw_path = strdup(value);
	} else if (strcmp(key, RNP_FW_4X10G_10G_1G_DET) == 0) {
		adapter = (struct rnp_eth_adapter *)extra_args;
		if (adapter->num_ports == 2 && adapter->hw.speed == 10 * 1000) {
			adapter->fw_sfp_10g_1g_auto_det =
				(strcmp(value, "on") == 0) ? true : false;
		} else {
			adapter->fw_sfp_10g_1g_auto_det = false;
		}
	} else if (strcmp(key, RNP_FW_FORCE_SPEED_1G) == 0) {
		adapter = (struct rnp_eth_adapter *)extra_args;
		if (adapter->num_ports == 2) {
			if (strcmp(value, "on") == 0)
				adapter->fw_force_speed_1g = FOCE_SPEED_1G_ENABLED;
			else if (strcmp(value, "off") == 0)
				adapter->fw_force_speed_1g = FOCE_SPEED_1G_DISABLED;
		}
	} else {
		return -1;
	}

	return 0;
}

static int
rnp_parse_io_select_func(const char *key, const char *value, void *extra_args)
{
	uint8_t select = RNP_IO_FUNC_USE_NONE;

	RTE_SET_USED(key);

	if (strcmp(value, "vec") == 0)
		select = RNP_IO_FUNC_USE_VEC;
	else if (strcmp(value, "simple") == 0)
		select = RNP_IO_FUNC_USE_SIMPLE;
	else if (strcmp(value, "common") == 0)
		select = RNP_IO_FUNC_USE_COMMON;

	*(uint8_t *)extra_args = select;

	return 0;
}

static int
rnp_parse_devargs(struct rnp_eth_adapter *adapter,
		  struct rte_devargs *devargs)
{
	uint8_t rx_io_func = RNP_IO_FUNC_USE_NONE;
	uint8_t tx_io_func = RNP_IO_FUNC_USE_NONE;
	struct rte_kvargs *kvlist;
	bool loopback_en = false;
	int ret = 0;

	adapter->do_fw_update = false;
	adapter->fw_sfp_10g_1g_auto_det = false;
	adapter->fw_force_speed_1g = FOCE_SPEED_1G_NOT_SET;

	if (!devargs)
		goto def;

	kvlist = rte_kvargs_parse(devargs->args, rnp_valid_arguments);
	if (kvlist == NULL)
		goto def;

	if (rte_kvargs_count(kvlist, RNP_HW_MAC_LOOPBACK_ARG) == 1)
		ret = rte_kvargs_process(kvlist, RNP_HW_MAC_LOOPBACK_ARG,
				&rnp_parse_handle_devarg, &loopback_en);

	if (rte_kvargs_count(kvlist, RNP_FW_4X10G_10G_1G_DET) == 1)
		ret = rte_kvargs_process(kvlist,
				RNP_FW_4X10G_10G_1G_DET,
				&rnp_parse_handle_devarg,
				adapter);

	if (rte_kvargs_count(kvlist, RNP_FW_FORCE_SPEED_1G) == 1)
		ret = rte_kvargs_process(kvlist,
				RNP_FW_FORCE_SPEED_1G,
				&rnp_parse_handle_devarg,
				adapter);

	if (rte_kvargs_count(kvlist, RNP_FW_UPDATE) == 1)
		ret = rte_kvargs_process(kvlist, RNP_FW_UPDATE,
				&rnp_parse_handle_devarg, adapter);
	if (rte_kvargs_count(kvlist, RNP_RX_FUNC_SELECT) == 1)
		ret = rte_kvargs_process(kvlist, RNP_RX_FUNC_SELECT,
				&rnp_parse_io_select_func, &rx_io_func);
	if (rte_kvargs_count(kvlist, RNP_TX_FUNC_SELECT) == 1)
		ret = rte_kvargs_process(kvlist, RNP_TX_FUNC_SELECT,
				&rnp_parse_io_select_func, &tx_io_func);
	rte_kvargs_free(kvlist);
def:
	adapter->loopback_en = loopback_en;
	adapter->rx_func_sec = rx_io_func;
	adapter->tx_func_sec = tx_io_func;

	return ret;
}

static int rnp_post_handle(struct rnp_eth_adapter *adapter)
{
	bool on = false;

	if (!adapter->eth_dev)
		return -ENOMEM;
	if (adapter->do_fw_update && adapter->fw_path) {
		rnp_fw_update(adapter);
		adapter->do_fw_update = 0;
	}

	if (adapter->fw_sfp_10g_1g_auto_det)
		return rnp_hw_set_fw_10g_1g_auto_detch(adapter->eth_dev, 1);

	on = (adapter->fw_force_speed_1g == FOCE_SPEED_1G_ENABLED) ? 1 : 0;
	if (adapter->fw_force_speed_1g != FOCE_SPEED_1G_NOT_SET)
		return rnp_hw_set_fw_force_speed_1g(adapter->eth_dev, on);

	return 0;
}

static int
rnp_eth_dev_init(struct rte_eth_dev *dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(dev);
	struct rnp_eth_port *port = RNP_DEV_TO_PORT(dev);
	struct rnp_eth_adapter *adapter = NULL;
	char name[RTE_ETH_NAME_MAX_LEN] = " ";
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
	hw->back = adapter;
	hw->iobar4 = pci_dev->mem_resource[RNP_CFG_BAR].addr;
	hw->iobar0 = pci_dev->mem_resource[RNP_PF_INFO_BAR].addr;
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
	port->adapt = adapter;
	rnp_common_ops_init(adapter);
	rnp_init_mbx_ops_pf(hw);
	rnp_get_nic_attr(adapter);
	/* We need Use Device Id To Change The Resource Mode */
	rnp_special_ops_init(dev);
	port->hw = hw;
	ret = rnp_parse_devargs(adapter, pci_dev->device.devargs);
	if (ret) {
		PMD_DRV_LOG(ERR, "parse_devargs failed");
		return ret;
	}
	for (p_id = 0; p_id < adapter->num_ports; p_id++) {
		/* port 0 resource has been allocated When Probe */
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
	ret = rnp_post_handle(adapter);
	if (ret)
		goto eth_alloc_error;

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
			       "Isn't Primary Ethdev\n");
		return -EINVAL;
	}
	for (p_id = 0; p_id < adapter->num_ports; p_id++) {
		port = adapter->ports[p_id];
		if (!port)
			continue;
		if (port->eth_dev) {
			rnp_dev_close(port->eth_dev);
			/* Just Release Not Primary Port Allocated By PMD */
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
RTE_PMD_REGISTER_KMOD_DEP(net_rnp, "igb_uio | uio_pci_generic | vfio-pci");

RTE_LOG_REGISTER_SUFFIX(rnp_init_logtype, init, NOTICE);
RTE_LOG_REGISTER_SUFFIX(rnp_drv_logtype, driver, NOTICE);

#ifdef RTE_LIBRTE_RNP_DEBUG_RX
	RTE_LOG_REGISTER_SUFFIX(rnp_rx_logtype, rx, DEBUG);
#endif

#ifdef RTE_LIBRTE_RNP_DEBUG_TX
	RTE_LOG_REGISTER_SUFFIX(rnp_tx_logtype, tx, DEBUG);
#endif

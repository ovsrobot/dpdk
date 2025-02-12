/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Mucse IC Design Ltd.
 */

#include <ethdev_pci.h>
#include <ethdev_driver.h>
#include <rte_io.h>
#include <rte_malloc.h>

#include "rnp.h"
#include "rnp_logs.h"
#include "base/rnp_mbx.h"
#include "base/rnp_mbx_fw.h"
#include "base/rnp_mac.h"
#include "base/rnp_eth_regs.h"
#include "base/rnp_common.h"

static struct rte_eth_dev *
rnp_alloc_eth_port(struct rte_pci_device *pci, char *name)
{
	struct rte_eth_dev *eth_dev = NULL;
	struct rnp_eth_port *port = NULL;

	eth_dev = rte_eth_dev_allocate(name);
	if (!eth_dev) {
		RNP_PMD_ERR("Could not allocate eth_dev for %s", name);
		return NULL;
	}
	port = rte_zmalloc_socket(name,
			sizeof(*port),
			RTE_CACHE_LINE_SIZE,
			pci->device.numa_node);
	if (!port) {
		RNP_PMD_ERR("Could not allocate rnp_eth_port for %s", name);
		goto fail_calloc;
	}
	rte_eth_copy_pci_info(eth_dev, pci);
	eth_dev->data->dev_private = port;
	eth_dev->device = &pci->device;

	return eth_dev;
fail_calloc:
	rte_free(port);
	rte_eth_dev_release_port(eth_dev);

	return NULL;
}

static void rnp_dev_interrupt_handler(void *param)
{
	RTE_SET_USED(param);
}

static int rnp_dev_stop(struct rte_eth_dev *eth_dev)
{
	RTE_SET_USED(eth_dev);

	return 0;
}

static int rnp_dev_close(struct rte_eth_dev *eth_dev)
{
	struct rnp_eth_adapter *adapter = RNP_DEV_TO_ADAPTER(eth_dev);
	struct rte_pci_device *pci_dev;
	int ret = 0;

	PMD_INIT_FUNC_TRACE();

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;
	ret = rnp_dev_stop(eth_dev);
	if (ret < 0)
		return ret;
	if (adapter->closed_ports == adapter->inited_ports) {
		pci_dev = RTE_DEV_TO_PCI(eth_dev->device);
		if (adapter->intr_registered) {
			/* disable uio intr before callback unregister */
			rte_intr_disable(pci_dev->intr_handle);
			rte_intr_callback_unregister(pci_dev->intr_handle,
					rnp_dev_interrupt_handler,
					(void *)eth_dev);
			adapter->intr_registered = false;
		}
		rnp_dma_mem_free(&adapter->hw, &adapter->hw.fw_info.mem);
		rte_free(adapter);
	}
	adapter->closed_ports++;

	return 0;
}

/* Features supported by this driver */
static const struct eth_dev_ops rnp_eth_dev_ops = {
	.dev_close                    = rnp_dev_close,
	.dev_stop                     = rnp_dev_stop,
};

static void
rnp_setup_port_attr(struct rnp_eth_port *port,
		    struct rte_eth_dev *eth_dev,
		    uint8_t sw_id)
{
	struct rnp_port_attr *attr = &port->attr;
	struct rnp_hw *hw = port->hw;
	uint32_t lane;

	PMD_INIT_FUNC_TRACE();

	lane = hw->phy_port_ids[sw_id] & (hw->max_port_num - 1);
	attr->port_id = eth_dev->data->port_id;
	attr->port_offset = RNP_E_REG_RD(hw, RNP_TC_PORT_OFFSET(lane));
	attr->nr_lane = lane;
	attr->sw_id = sw_id;
	attr->max_mac_addrs = 1;

	RNP_PMD_INFO("PF[%d] SW-ETH-PORT[%d]<->PHY_LANE[%d]",
			hw->mbx.pf_num, sw_id, lane);
}

static int
rnp_init_port_resource(struct rnp_eth_adapter *adapter,
		       struct rte_eth_dev *eth_dev,
		       char *name,
		       uint8_t p_id)
{
	struct rnp_eth_port *port = RNP_DEV_TO_PORT(eth_dev);
	struct rte_pci_device *pci_dev = adapter->pdev;
	char mac_str[RTE_ETHER_ADDR_FMT_SIZE] = " ";

	PMD_INIT_FUNC_TRACE();

	port->eth_dev = eth_dev;
	port->hw = &adapter->hw;

	eth_dev->dev_ops = &rnp_eth_dev_ops;
	eth_dev->device = &pci_dev->device;
	eth_dev->data->mtu = RTE_ETHER_MTU;

	rnp_setup_port_attr(port, eth_dev, p_id);
	eth_dev->data->mac_addrs = rte_zmalloc(name,
			sizeof(struct rte_ether_addr) *
			port->attr.max_mac_addrs, 0);
	if (!eth_dev->data->mac_addrs) {
		RNP_PMD_ERR("zmalloc for mac failed! Exiting.");
		return -ENOMEM;
	}
	rnp_get_mac_addr(port, port->mac_addr.addr_bytes);
	rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE,
					&port->mac_addr);
	RNP_PMD_INFO("get mac addr from firmware %s", mac_str);
	if (!rte_is_valid_assigned_ether_addr(&port->mac_addr)) {
		RNP_PMD_WARN("get mac_addr is invalid, just use random");
		rte_eth_random_addr(port->mac_addr.addr_bytes);
	}
	rte_ether_addr_copy(&port->mac_addr, &eth_dev->data->mac_addrs[0]);

	adapter->ports[p_id] = port;
	adapter->inited_ports++;

	return 0;
}

static int
rnp_proc_priv_init(struct rte_eth_dev *dev)
{
	struct rnp_proc_priv *priv;

	priv = rte_zmalloc_socket("rnp_proc_priv",
			sizeof(struct rnp_proc_priv),
			RTE_CACHE_LINE_SIZE,
			dev->device->numa_node);
	if (!priv)
		return -ENOMEM;
	dev->process_private = priv;

	return 0;
}

static int
rnp_eth_dev_init(struct rte_eth_dev *eth_dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	struct rte_intr_handle *intr_handle = pci_dev->intr_handle;
	struct rnp_eth_port *port = RNP_DEV_TO_PORT(eth_dev);
	char name[RTE_ETH_NAME_MAX_LEN] = " ";
	struct rnp_eth_adapter *adapter;
	struct rte_eth_dev *sub_eth_dev;
	struct rnp_hw *hw;
	uint16_t p_id;
	int ret = -1;

	PMD_INIT_FUNC_TRACE();

	snprintf(name, sizeof(name), "rnp_adapter_%d", eth_dev->data->port_id);
	adapter = rte_zmalloc(name, sizeof(struct rnp_eth_adapter), 0);
	if (!adapter) {
		RNP_PMD_ERR("rnp_adapter zmalloc mem failed");
		return -ENOMEM;
	}
	hw = &adapter->hw;
	adapter->pdev = pci_dev;
	adapter->eth_dev = eth_dev;
	adapter->ports[0] = port;
	hw->back = (void *)adapter;
	port->eth_dev = eth_dev;
	port->hw = hw;

	hw->e_ctrl = (u8 *)pci_dev->mem_resource[4].addr;
	hw->c_ctrl = (u8 *)pci_dev->mem_resource[0].addr;
	hw->c_blen = pci_dev->mem_resource[0].len;
	hw->device_id = pci_dev->id.device_id;
	hw->vendor_id = pci_dev->id.vendor_id;
	hw->mbx.en_vfs = pci_dev->max_vfs;
	if (hw->mbx.en_vfs > hw->max_vfs) {
		ret = -EINVAL;
		RNP_PMD_ERR("sriov vfs max support 64");
		goto free_ad;
	}

	strlcpy(hw->device_name, pci_dev->device.name,
			strlen(pci_dev->device.name) + 1);
	ret = rnp_proc_priv_init(eth_dev);
	if (ret < 0) {
		RNP_PMD_ERR("proc_priv_alloc failed");
		goto free_ad;
	}
	ret = rnp_init_mbx_pf(hw);
	if (ret < 0) {
		RNP_PMD_ERR("mailbox hardware init failed");
		goto free_ad;
	}
	ret = rnp_init_hw(hw);
	if (ret < 0) {
		RNP_PMD_ERR("Hardware initialization failed");
		goto free_ad;
	}
	ret = rnp_setup_common_ops(hw);
	if (ret < 0) {
		RNP_PMD_ERR("hardware common ops setup failed");
		goto free_ad;
	}
	for (p_id = 0; p_id < hw->max_port_num; p_id++) {
		/* port 0 resource has been allocated when probe */
		if (!p_id) {
			sub_eth_dev = eth_dev;
		} else {
			memset(name, 0, sizeof(name));
			snprintf(name, sizeof(name),
					"%s_%d", hw->device_name, p_id);
			sub_eth_dev = rnp_alloc_eth_port(pci_dev, name);
			if (!sub_eth_dev) {
				RNP_PMD_ERR("%s sub_eth alloc failed",
						hw->device_name);
				ret = -ENOMEM;
				goto eth_alloc_error;
			}
			ret = rnp_proc_priv_init(sub_eth_dev);
			if (ret < 0) {
				RNP_PMD_ERR("proc_priv_alloc failed");
				goto eth_alloc_error;
			}
			rte_memcpy(sub_eth_dev->process_private,
					eth_dev->process_private,
					sizeof(struct rnp_proc_priv));
		}
		ret = rnp_init_port_resource(adapter, sub_eth_dev, name, p_id);
		if (ret)
			goto eth_alloc_error;
		if (p_id) {
			/* port 0 will be probe by platform */
			rte_eth_dev_probing_finish(sub_eth_dev);
		}
	}
	/* enable link update event interrupt */
	rte_intr_callback_register(intr_handle,
			rnp_dev_interrupt_handler, adapter);
	rte_intr_enable(intr_handle);
	adapter->intr_registered = true;
	hw->fw_info.fw_irq_en = true;

	return 0;

eth_alloc_error:
	for (p_id = 0; p_id < adapter->inited_ports; p_id++) {
		port = adapter->ports[p_id];
		if (!port)
			continue;
		if (port->eth_dev) {
			rnp_dev_close(port->eth_dev);
			/* just release eth_dev allocated by myself */
			if (port->eth_dev != adapter->eth_dev)
				rte_eth_dev_release_port(port->eth_dev);
		}
	}
free_ad:
	if (hw->fw_info.cookie_pool)
		rnp_dma_mem_free(hw, &hw->fw_info.mem);
	rte_free(adapter);

	return ret;
}

static int
rnp_eth_dev_uninit(struct rte_eth_dev *eth_dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	uint16_t port_id;
	int err = 0;

	/* Free up other ports and all resources */
	RTE_ETH_FOREACH_DEV_OF(port_id, &pci_dev->device)
		err |= rte_eth_dev_close(port_id);

	return err == 0 ? 0 : -EIO;
}

static int
rnp_pci_remove(struct rte_pci_device *pci_dev)
{
	char device_name[RTE_ETH_NAME_MAX_LEN] = "";
	struct rte_eth_dev *eth_dev;
	uint16_t idx = 0;
	int rc;

	/* Find a port belong to pf that not be called dev_close */
	for (idx = 0; idx < RNP_MAX_PORT_OF_PF; idx++) {
		if (idx)
			snprintf(device_name, sizeof(device_name), "%s_%d",
					pci_dev->device.name,
					idx);
		else
			snprintf(device_name, sizeof(device_name), "%s",
					pci_dev->device.name);
		eth_dev = rte_eth_dev_allocated(device_name);
		if (eth_dev)
			break;
	}
	if (eth_dev) {
		/* Cleanup eth dev */
		rc = rnp_eth_dev_uninit(eth_dev);
		if (rc)
			return rc;
	}

	return 0;
}

static int
rnp_pci_probe(struct rte_pci_driver *pci_drv, struct rte_pci_device *pci_dev)
{
	int rc;

	RTE_SET_USED(pci_drv);

	rc = rte_eth_dev_pci_generic_probe(pci_dev, sizeof(struct rnp_eth_port),
			rnp_eth_dev_init);

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

RTE_LOG_REGISTER_SUFFIX(rnp_init_logtype, init, NOTICE);

RTE_PMD_REGISTER_PCI(net_rnp, rte_rnp_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_rnp, pci_id_rnp_map);
RTE_PMD_REGISTER_KMOD_DEP(net_rnp, "igb_uio | uio_pci_generic | vfio-pci");

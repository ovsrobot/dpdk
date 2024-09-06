/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 Yunsilicon Technology Co., Ltd.
 */

#include <ethdev_pci.h>

#include "xsc_log.h"
#include "xsc_defs.h"
#include "xsc_dev.h"
#include "xsc_ethdev.h"
#include "xsc_utils.h"

#include "xsc_ctrl.h"

const struct eth_dev_ops xsc_dev_ops = {
};

static int
xsc_ethdev_init_one_representor(struct rte_eth_dev *eth_dev, void *init_params)
{
	struct xsc_repr_port *repr_port = (struct xsc_repr_port *)init_params;
	struct xsc_ethdev_priv *priv = TO_XSC_ETHDEV_PRIV(eth_dev);
	struct xsc_dev_config *config = &priv->config;
	struct rte_ether_addr mac;

	priv->repr_port = repr_port;
	repr_port->drv_data = eth_dev;
	priv->xdev = repr_port->xdev;
	priv->mtu = RTE_ETHER_MTU;
	priv->funcid_type = (repr_port->info.funcid & FUNCID_TYPE_MASK) >> 14;
	priv->funcid = repr_port->info.funcid & FUNCID_MASK;
	if (repr_port->info.port_type == XSC_PORT_TYPE_UPLINK ||
		repr_port->info.port_type == XSC_PORT_TYPE_UPLINK_BOND)
		priv->eth_type = RTE_ETH_REPRESENTOR_PF;
	else
		priv->eth_type = RTE_ETH_REPRESENTOR_VF;
	priv->representor_id = repr_port->info.repr_id;
	priv->dev_data = eth_dev->data;
	priv->ifindex = repr_port->info.ifindex;

	eth_dev->data->dev_flags |= RTE_ETH_DEV_AUTOFILL_QUEUE_XSTATS;
	eth_dev->data->mac_addrs = priv->mac;
	if (rte_is_zero_ether_addr(eth_dev->data->mac_addrs)) {
		if (priv->ifindex > 0) {
			int ret  = xsc_get_mac(mac.addr_bytes, priv->ifindex);
			if (ret != 0) {
				PMD_DRV_LOG(ERR, "port %u cannot get MAC address",
						eth_dev->data->port_id);
				return -ENODEV;
			}
		} else {
			rte_eth_random_addr(mac.addr_bytes);
		}
	}

	xsc_mac_addr_add(eth_dev, &mac, 0);

	if (priv->ifindex > 0)
		xsc_get_mtu(&priv->mtu, priv->ifindex);

	config->hw_csum = 1;

	config->pph_flag =  priv->xdev->devargs.pph_mode;
	if ((config->pph_flag & XSC_TX_PPH) != 0) {
		config->tso = 0;
	} else {
		config->tso = 1;
		if (config->tso)
			config->tso_max_payload_sz = 1500;
	}

	priv->representor = !!priv->eth_type;
	if (priv->representor) {
		eth_dev->data->dev_flags |= RTE_ETH_DEV_REPRESENTOR;
		eth_dev->data->representor_id = priv->representor_id;
		eth_dev->data->backer_port_id = eth_dev->data->port_id;
	}
	eth_dev->dev_ops = &xsc_dev_ops;

	eth_dev->rx_pkt_burst = rte_eth_pkt_burst_dummy;
	eth_dev->tx_pkt_burst = rte_eth_pkt_burst_dummy;

	rte_eth_dev_probing_finish(eth_dev);

	return 0;
}

static int
xsc_ethdev_init_representors(struct rte_eth_dev *eth_dev)
{
	struct xsc_ethdev_priv *priv = TO_XSC_ETHDEV_PRIV(eth_dev);
	struct rte_eth_devargs eth_da = { .nb_representor_ports = 0 };
	struct rte_device *dev;
	struct xsc_dev *xdev;
	struct xsc_repr_port *repr_port;
	char name[RTE_ETH_NAME_MAX_LEN];
	int i;
	int ret;

	PMD_INIT_FUNC_TRACE();

	dev = &priv->pci_dev->device;
	if (dev->devargs != NULL) {
		ret = rte_eth_devargs_parse(dev->devargs->args, &eth_da, 1);
		if (ret < 0) {
			PMD_DRV_LOG(ERR, "Failed to parse device arguments: %s",
				    dev->devargs->args);
			return -EINVAL;
		}
	}

	xdev = priv->xdev;
	ret = xsc_repr_ports_probe(xdev, eth_da.nb_representor_ports, RTE_MAX_ETHPORTS);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to probe %d xsc device representors",
			    eth_da.nb_representor_ports);
		return ret;
	}

	repr_port = &xdev->repr_ports[XSC_DEV_REPR_PORT];
	ret = xsc_ethdev_init_one_representor(eth_dev, repr_port);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to init backing representor");
		return ret;
	}

	for (i = 1; i < xdev->num_repr_ports; i++) {
		repr_port = &xdev->repr_ports[i];
		snprintf(name, sizeof(name), "%s_rep_%d",
			 xdev->ibv_name, repr_port->info.repr_id);
		ret = rte_eth_dev_create(&xdev->pci_dev->device,
					 name,
					 sizeof(struct xsc_ethdev_priv),
					 NULL, NULL,
					 xsc_ethdev_init_one_representor,
					 repr_port);
		if (ret != 0) {
			PMD_DRV_LOG(ERR, "Failed to create representor: %d", i);
			goto destroy_reprs;
		}
	}

	return 0;

destroy_reprs:
	while ((i--) > 1) {
		repr_port = &xdev->repr_ports[i];
		rte_eth_dev_destroy((struct rte_eth_dev *)repr_port->drv_data, NULL);
	}
	return ret;
}

static int
xsc_ethdev_init(struct rte_eth_dev *eth_dev)
{
	struct xsc_ethdev_priv *priv = TO_XSC_ETHDEV_PRIV(eth_dev);
	int ret;

	PMD_INIT_FUNC_TRACE();

	priv->eth_dev = eth_dev;
	priv->pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);

	ret = xsc_dev_init(priv->pci_dev, &priv->xdev);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failed to initialize xsc device");
		return ret;
	}

	ret = xsc_ethdev_init_representors(eth_dev);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to initialize representors");
		goto uninit_xsc_dev;
	}

	return 0;

uninit_xsc_dev:
	xsc_dev_uninit(priv->xdev);
	return ret;
}

static int
xsc_ethdev_uninit(struct rte_eth_dev *eth_dev)
{
	struct xsc_ethdev_priv *priv = TO_XSC_ETHDEV_PRIV(eth_dev);

	PMD_INIT_FUNC_TRACE();

	xsc_dev_uninit(priv->xdev);

	return 0;
}

static int
xsc_ethdev_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
		     struct rte_pci_device *pci_dev)
{
	int ret;

	PMD_INIT_FUNC_TRACE();

	ret = rte_eth_dev_pci_generic_probe(pci_dev,
					    sizeof(struct xsc_ethdev_priv),
					    xsc_ethdev_init);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failed to probe ethdev: %s", pci_dev->name);
		return ret;
	}

	return 0;
}

static int
xsc_ethdev_pci_remove(struct rte_pci_device *pci_dev)
{
	int ret;

	PMD_INIT_FUNC_TRACE();

	ret = rte_eth_dev_pci_generic_remove(pci_dev, xsc_ethdev_uninit);
	if (ret) {
		PMD_DRV_LOG(ERR, "Could not remove ethdev: %s", pci_dev->name);
		return ret;
	}

	return 0;
}

static const struct rte_pci_id xsc_ethdev_pci_id_map[] = {
	{ RTE_PCI_DEVICE(XSC_PCI_VENDOR_ID, XSC_PCI_DEV_ID_MS) },
};

static struct rte_pci_driver xsc_ethdev_pci_driver = {
	.id_table  = xsc_ethdev_pci_id_map,
	.probe = xsc_ethdev_pci_probe,
	.remove = xsc_ethdev_pci_remove,
};

RTE_INIT(xsc_pmd_init)
{
	ibv_fork_init();
}

RTE_PMD_REGISTER_PCI(net_xsc, xsc_ethdev_pci_driver);
RTE_PMD_REGISTER_PCI_TABLE(net_xsc, xsc_ethdev_pci_id_map);
RTE_PMD_REGISTER_PARAM_STRING(net_xsc,
			      XSC_PPH_MODE_ARG "=<x>"
			      XSC_NIC_MODE_ARG "=<x>"
			      XSC_FLOW_MODE_ARG "=<x>");

RTE_LOG_REGISTER_SUFFIX(xsc_logtype_init, init, NOTICE);
RTE_LOG_REGISTER_SUFFIX(xsc_logtype_driver, driver, NOTICE);
#ifdef RTE_ETHDEV_DEBUG_RX
RTE_LOG_REGISTER_SUFFIX(xsc_logtype_rx, rx, DEBUG);
#endif
#ifdef RTE_ETHDEV_DEBUG_TX
RTE_LOG_REGISTER_SUFFIX(xsc_logtype_tx, tx, DEBUG);
#endif

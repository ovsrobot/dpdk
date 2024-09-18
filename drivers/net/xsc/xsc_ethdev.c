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
#include "xsc_rxtx.h"

static int
xsc_rss_modify_cmd(struct xsc_ethdev_priv *priv, uint8_t *rss_key,
		   uint8_t rss_key_len)
{
	return 0;
}

static int
xsc_ethdev_rss_hash_update(struct rte_eth_dev *dev,
			   struct rte_eth_rss_conf *rss_conf)
{
	struct xsc_ethdev_priv *priv = TO_XSC_ETHDEV_PRIV(dev);
	int ret = 0;

	if (rss_conf->rss_key_len > XSC_RSS_HASH_KEY_LEN ||
		rss_conf->rss_key == NULL) {
		PMD_DRV_LOG(ERR, "Xsc pmd key len is %d bigger than %d",
				rss_conf->rss_key_len, XSC_RSS_HASH_KEY_LEN);
		return -EINVAL;
	}

	ret = xsc_rss_modify_cmd(priv, rss_conf->rss_key, rss_conf->rss_key_len);
	if (ret == 0) {
		rte_memcpy(priv->rss_conf.rss_key, rss_conf->rss_key,
				priv->rss_conf.rss_key_len);
		priv->rss_conf.rss_key_len = rss_conf->rss_key_len;
		priv->rss_conf.rss_hf = rss_conf->rss_hf;
	}

	return ret;
}

static int
xsc_ethdev_configure(struct rte_eth_dev *dev)
{
	struct xsc_ethdev_priv *priv = TO_XSC_ETHDEV_PRIV(dev);
	struct rte_eth_rxmode *rxmode = &dev->data->dev_conf.rxmode;
	int ret;
	struct rte_eth_rss_conf *rss_conf;

	priv->num_sq = dev->data->nb_tx_queues;
	priv->num_rq = dev->data->nb_rx_queues;

	if (dev->data->dev_conf.rxmode.mq_mode & RTE_ETH_MQ_RX_RSS_FLAG)
		dev->data->dev_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_RSS_HASH;

	if (priv->rss_conf.rss_key == NULL) {
		priv->rss_conf.rss_key = rte_zmalloc(NULL, XSC_RSS_HASH_KEY_LEN,
						RTE_CACHE_LINE_SIZE);
		if (priv->rss_conf.rss_key == NULL) {
			PMD_DRV_LOG(ERR, "Failed to alloc rss_key");
			rte_errno = ENOMEM;
			ret = -rte_errno;
			goto error;
		}
		priv->rss_conf.rss_key_len = XSC_RSS_HASH_KEY_LEN;
	}

	if (dev->data->dev_conf.rx_adv_conf.rss_conf.rss_key != NULL) {
		rss_conf = &dev->data->dev_conf.rx_adv_conf.rss_conf;
		ret = xsc_ethdev_rss_hash_update(dev, rss_conf);
		if (ret != 0) {
			PMD_DRV_LOG(ERR, "Xsc pmd set rss key error!");
			rte_errno = -ENOEXEC;
			goto error;
		}
	}

	if (rxmode->offloads & RTE_ETH_RX_OFFLOAD_VLAN_FILTER) {
		PMD_DRV_LOG(ERR, "xsc pmd do not support vlan filter now!");
		rte_errno = EINVAL;
		goto error;
	}

	if (rxmode->offloads & RTE_ETH_RX_OFFLOAD_VLAN_STRIP) {
		PMD_DRV_LOG(ERR, "xsc pmd do not support vlan strip now!");
		rte_errno = EINVAL;
		goto error;
	}

	priv->txqs = (void *)dev->data->tx_queues;
	priv->rxqs = (void *)dev->data->rx_queues;
	return 0;

error:
	return -rte_errno;
}

static int
xsc_ethdev_rx_queue_setup(struct rte_eth_dev *dev, uint16_t idx, uint16_t desc,
			  uint32_t socket, const struct rte_eth_rxconf *conf,
			  struct rte_mempool *mp)
{
	struct xsc_ethdev_priv *priv = TO_XSC_ETHDEV_PRIV(dev);
	struct xsc_rxq_data *rxq_data = NULL;
	uint16_t desc_n;
	uint16_t rx_free_thresh;
	uint64_t offloads = conf->offloads |
			    dev->data->dev_conf.rxmode.offloads;

	desc = (desc > XSC_MAX_DESC_NUMBER) ? XSC_MAX_DESC_NUMBER : desc;
	desc_n = desc;

	if (!rte_is_power_of_2(desc))
		desc_n = 1 << rte_log2_u32(desc);

	rxq_data = rte_malloc_socket(NULL, sizeof(*rxq_data) + desc_n * sizeof(struct rte_mbuf *),
					RTE_CACHE_LINE_SIZE, socket);
	if (rxq_data == NULL) {
		PMD_DRV_LOG(ERR, "Port %u create rxq idx %d failure",
				dev->data->port_id, idx);
		rte_errno = ENOMEM;
		return -rte_errno;
	}
	rxq_data->idx = idx;
	rxq_data->priv = priv;
	(*priv->rxqs)[idx] = rxq_data;

	rx_free_thresh = (conf->rx_free_thresh) ? conf->rx_free_thresh : XSC_RX_FREE_THRESH;
	rxq_data->rx_free_thresh = rx_free_thresh;

	rxq_data->elts = (struct rte_mbuf *(*)[desc_n])(rxq_data + 1);
	rxq_data->mp = mp;
	rxq_data->socket = socket;

	rxq_data->csum = !!(offloads & RTE_ETH_RX_OFFLOAD_CHECKSUM);
	rxq_data->hw_timestamp = !!(offloads & RTE_ETH_RX_OFFLOAD_TIMESTAMP);
	rxq_data->crc_present = 0;

	rxq_data->wqe_n = rte_log2_u32(desc_n);
	rxq_data->wqe_s = desc_n;
	rxq_data->wqe_m = desc_n - 1;

	dev->data->rx_queues[idx] = rxq_data;
	return 0;
}

static int
xsc_ethdev_tx_queue_setup(struct rte_eth_dev *dev, uint16_t idx, uint16_t desc,
			  uint32_t socket, const struct rte_eth_txconf *conf)
{
	struct xsc_ethdev_priv *priv = TO_XSC_ETHDEV_PRIV(dev);
	struct xsc_txq_data *txq;
	uint16_t desc_n;

	desc = (desc > XSC_MAX_DESC_NUMBER) ? XSC_MAX_DESC_NUMBER : desc;
	desc_n = desc;

	if (!rte_is_power_of_2(desc))
		desc_n = 1 << rte_log2_u32(desc);

	txq = rte_malloc_socket(NULL, sizeof(*txq) + desc_n * sizeof(struct rte_mbuf *),
					RTE_CACHE_LINE_SIZE, socket);
	txq->offloads = conf->offloads | dev->data->dev_conf.txmode.offloads;
	txq->priv = priv;
	txq->socket = socket;

	txq->elts_n = rte_log2_u32(desc_n);
	txq->elts_s = desc_n;
	txq->elts_m = desc_n - 1;
	txq->port_id = dev->data->port_id;
	txq->idx = idx;

	(*priv->txqs)[idx] = txq;
	return 0;
}

const struct eth_dev_ops xsc_dev_ops = {
	.dev_configure = xsc_ethdev_configure,
	.rx_queue_setup = xsc_ethdev_rx_queue_setup,
	.tx_queue_setup = xsc_ethdev_tx_queue_setup,
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
				PMD_DRV_LOG(ERR, "Port %u cannot get MAC address",
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

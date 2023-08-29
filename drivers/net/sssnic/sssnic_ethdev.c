/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#include <error.h>
#include <rte_common.h>
#include <ethdev_pci.h>

#include "sssnic_log.h"
#include "base/sssnic_hw.h"
#include "sssnic_ethdev.h"

static int
sssnic_ethdev_infos_get(struct rte_eth_dev *ethdev,
	struct rte_eth_dev_info *devinfo)
{
	struct sssnic_netdev *netdev;

	netdev = SSSNIC_ETHDEV_PRIVATE(ethdev);

	devinfo->max_rx_queues = netdev->max_num_rxq;
	devinfo->max_tx_queues = netdev->max_num_txq;

	devinfo->max_mtu = SSSNIC_ETHDEV_MAX_MTU;
	devinfo->min_mtu = SSSNIC_ETHDEV_MIN_MTU;
	devinfo->min_rx_bufsize = SSSNIC_ETHDEV_MIN_RXBUF_SZ;
	devinfo->max_rx_pktlen = SSSNIC_ETHDEV_MAX_RXPKT_LEN;
	devinfo->max_lro_pkt_size = SSSNIC_ETHDEV_MAX_LRO_PKT_SZ;

	devinfo->max_mac_addrs = SSSNIC_ETHDEV_MAX_NUM_UC_MAC;

	devinfo->rx_queue_offload_capa = 0;
	devinfo->tx_queue_offload_capa = 0;
	devinfo->rx_offload_capa = SSSNIC_ETHDEV_RX_OFFLOAD_CAPA;
	devinfo->tx_offload_capa = SSSNIC_ETHDEV_TX_OFFLOAD_CAPA;

	devinfo->hash_key_size = SSSNIC_ETHDEV_RSS_KEY_SZ;
	devinfo->reta_size = SSSNIC_ETHDEV_RSS_RETA_SZ;
	devinfo->flow_type_rss_offloads = SSSNIC_ETHDEV_RSS_OFFLOAD_FLOW_TYPES;

	devinfo->rx_desc_lim = (struct rte_eth_desc_lim){
		.nb_max = SSSNIC_ETHDEV_MAX_NUM_Q_DESC,
		.nb_min = SSSNIC_ETHDEV_MIN_NUM_Q_DESC,
		.nb_align = SSSNIC_ETHDEV_NUM_Q_DESC_ALGIN,
	};
	devinfo->tx_desc_lim = (struct rte_eth_desc_lim){
		.nb_max = SSSNIC_ETHDEV_MAX_NUM_Q_DESC,
		.nb_min = SSSNIC_ETHDEV_MIN_NUM_Q_DESC,
		.nb_align = SSSNIC_ETHDEV_NUM_Q_DESC_ALGIN,
	};

	devinfo->default_rxportconf = (struct rte_eth_dev_portconf){
		.burst_size = SSSNIC_ETHDEV_DEF_BURST_SZ,
		.ring_size = SSSNIC_ETHDEV_DEF_RING_SZ,
		.nb_queues = SSSNIC_ETHDEV_DEF_NUM_QUEUES,
	};

	devinfo->default_txportconf = (struct rte_eth_dev_portconf){
		.burst_size = SSSNIC_ETHDEV_DEF_BURST_SZ,
		.ring_size = SSSNIC_ETHDEV_DEF_RING_SZ,
		.nb_queues = SSSNIC_ETHDEV_DEF_NUM_QUEUES,
	};

	return 0;
}

static int
sssnic_ethdev_configure(struct rte_eth_dev *ethdev)
{
	if (ethdev->data->dev_conf.rxmode.mq_mode & RTE_ETH_MQ_RX_RSS_FLAG)
		ethdev->data->dev_conf.rxmode.offloads |=
			RTE_ETH_RX_OFFLOAD_RSS_HASH;

	PMD_DRV_LOG(INFO, "Port %u is configured", ethdev->data->port_id);

	return 0;
}

static void
sssnic_ethdev_release(struct rte_eth_dev *ethdev)
{
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);

	sssnic_hw_shutdown(hw);
	rte_free(hw);
}

static const struct eth_dev_ops sssnic_ethdev_ops = {
	.dev_configure = sssnic_ethdev_configure,
	.dev_infos_get = sssnic_ethdev_infos_get,
};

static int
sssnic_ethdev_init(struct rte_eth_dev *ethdev)
{
	int ret;
	struct sssnic_hw *hw;
	struct sssnic_netdev *netdev;
	struct rte_pci_device *pci_dev;

	PMD_INIT_FUNC_TRACE();

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	netdev = SSSNIC_ETHDEV_PRIVATE(ethdev);
	pci_dev = RTE_ETH_DEV_TO_PCI(ethdev);
	hw = rte_zmalloc("sssnic_hw", sizeof(struct sssnic_hw), 0);
	if (hw == NULL) {
		PMD_DRV_LOG(ERR, "Failed to alloc memory for hw");
		return -ENOMEM;
	}
	netdev->hw = hw;
	hw->pci_dev = pci_dev;
	hw->eth_port_id = ethdev->data->port_id;
	ret = sssnic_hw_init(hw);
	if (ret != 0) {
		rte_free(hw);
		return ret;
	}

	netdev->max_num_rxq = SSSNIC_MAX_NUM_RXQ(hw);
	netdev->max_num_txq = SSSNIC_MAX_NUM_TXQ(hw);

	ethdev->dev_ops = &sssnic_ethdev_ops;

	return 0;
}

static int
sssnic_ethdev_uninit(struct rte_eth_dev *ethdev)
{
	PMD_INIT_FUNC_TRACE();

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	/* ethdev port has been released */
	if (ethdev->state == RTE_ETH_DEV_UNUSED)
		return 0;

	sssnic_ethdev_release(ethdev);

	return -EINVAL;
}

static int
sssnic_pci_probe(struct rte_pci_driver *pci_drv, struct rte_pci_device *pci_dev)
{
	RTE_SET_USED(pci_drv);
	PMD_INIT_FUNC_TRACE();

	return rte_eth_dev_pci_generic_probe(pci_dev,
		sizeof(struct sssnic_netdev), sssnic_ethdev_init);
}

static int
sssnic_pci_remove(struct rte_pci_device *pci_dev)
{
	PMD_INIT_FUNC_TRACE();

	return rte_eth_dev_pci_generic_remove(pci_dev, sssnic_ethdev_uninit);
}

static const struct rte_pci_id sssnic_pci_id_map[] = {
	{ RTE_PCI_DEVICE(SSSNIC_PCI_VENDOR_ID, SSSNIC_DEVICE_ID_STD) },
	{ .vendor_id = 0 },
};

static struct rte_pci_driver sssnic_pmd = {
	.id_table = sssnic_pci_id_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING,
	.probe = sssnic_pci_probe,
	.remove = sssnic_pci_remove,
};

RTE_PMD_REGISTER_PCI(net_sssnic, sssnic_pmd);

RTE_LOG_REGISTER_SUFFIX(sssnic_logtype_driver, driver, INFO);
RTE_LOG_REGISTER_SUFFIX(sssnic_logtype_init, init, NOTICE);
#ifdef RTE_ETHDEV_DEBUG_RX
RTE_LOG_REGISTER_SUFFIX(sssnic_logtype_rx, rx, DEBUG);
#endif /*RTE_ETHDEV_DEBUG_RX*/
#ifdef RTE_ETHDEV_DEBUG_TX
RTE_LOG_REGISTER_SUFFIX(sssnic_logtype_tx, tx, DEBUG);
#endif /*RTE_ETHDEV_DEBUG_TX*/

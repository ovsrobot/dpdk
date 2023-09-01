/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#include <rte_common.h>
#include <ethdev_pci.h>

#include "sssnic_log.h"
#include "base/sssnic_hw.h"
#include "base/sssnic_api.h"
#include "sssnic_ethdev.h"
#include "sssnic_ethdev_link.h"
#include "sssnic_ethdev_rx.h"
#include "sssnic_ethdev_tx.h"

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
sssnic_ethdev_mac_addr_set(struct rte_eth_dev *ethdev,
	struct rte_ether_addr *mac_addr)
{
	int ret;
	struct sssnic_netdev *netdev;
	struct sssnic_hw *hw;
	char mac_str[RTE_ETHER_ADDR_FMT_SIZE];

	netdev = SSSNIC_ETHDEV_PRIVATE(ethdev);
	hw = SSSNIC_NETDEV_TO_HW(netdev);

	rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE, mac_addr);

	ret = sssnic_mac_addr_update(hw, mac_addr->addr_bytes,
		netdev->default_addr.addr_bytes);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to update default MAC address: %s",
			mac_str);
		return ret;
	}
	rte_ether_addr_copy(mac_addr, &netdev->default_addr);

	PMD_DRV_LOG(INFO, "Updated default MAC address %s of port %u", mac_str,
		ethdev->data->port_id);

	return 0;
}

static void
sssnic_ethdev_mac_addr_remove(struct rte_eth_dev *ethdev, uint32_t index)
{
	int ret;
	struct sssnic_netdev *netdev;
	struct sssnic_hw *hw;
	struct rte_ether_addr *mac;
	char mac_str[RTE_ETHER_ADDR_FMT_SIZE];

	netdev = SSSNIC_ETHDEV_PRIVATE(ethdev);
	hw = SSSNIC_NETDEV_TO_HW(netdev);

	mac = &ethdev->data->mac_addrs[index];
	ret = sssnic_mac_addr_del(hw, mac->addr_bytes);
	if (ret != 0) {
		rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE, mac);
		PMD_DRV_LOG(ERR, "Failed to delete MAC address %s", mac_str);
	}
}

static int
sssnic_ethdev_mac_addr_add(struct rte_eth_dev *ethdev,
	struct rte_ether_addr *mac_addr, __rte_unused uint32_t index,
	__rte_unused uint32_t vmdq)
{
	int ret;
	struct sssnic_netdev *netdev;
	struct sssnic_hw *hw;
	char mac_str[RTE_ETHER_ADDR_FMT_SIZE];

	netdev = SSSNIC_ETHDEV_PRIVATE(ethdev);
	hw = SSSNIC_NETDEV_TO_HW(netdev);

	if (rte_is_multicast_ether_addr(mac_addr)) {
		rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE,
			mac_addr);
		PMD_DRV_LOG(ERR,
			"Invalid MAC address:%s, cannot be multicast address",
			mac_str);
	}

	ret = sssnic_mac_addr_add(hw, mac_addr->addr_bytes);
	if (ret != 0) {
		rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE,
			mac_addr);
		PMD_DRV_LOG(ERR, "Failed to add MAC address %s", mac_str);
		return ret;
	}

	return 0;
}

static void
sssnic_ethdev_mcast_addrs_clean(struct rte_eth_dev *ethdev)
{
	int ret;
	struct sssnic_netdev *netdev;
	struct sssnic_hw *hw;
	int i;

	netdev = SSSNIC_ETHDEV_PRIVATE(ethdev);
	hw = SSSNIC_NETDEV_TO_HW(netdev);

	for (i = 0; i < SSSNIC_ETHDEV_MAX_NUM_MC_MAC; i++) {
		if (rte_is_zero_ether_addr(&netdev->mcast_addrs[i]))
			break;

		ret = sssnic_mac_addr_del(hw,
			netdev->mcast_addrs[i].addr_bytes);
		if (ret != 0)
			PMD_DRV_LOG(WARNING, "Failed to delete MAC address");

		memset(&netdev->mcast_addrs[i], 0,
			sizeof(struct rte_ether_addr));
	}
}

static int
sssnic_ethdev_set_mc_addr_list(struct rte_eth_dev *ethdev,
	struct rte_ether_addr *mc_addr_set, uint32_t nb_mc_addr)
{
	int ret;
	struct sssnic_netdev *netdev;
	struct sssnic_hw *hw;
	char mac_str[RTE_ETHER_ADDR_FMT_SIZE];
	uint32_t i;

	netdev = SSSNIC_ETHDEV_PRIVATE(ethdev);
	hw = SSSNIC_NETDEV_TO_HW(netdev);

	if (nb_mc_addr > SSSNIC_ETHDEV_MAX_NUM_MC_MAC) {
		PMD_DRV_LOG(ERR,
			"Failed to set mcast address list to port %u, excceds max number:%u",
			ethdev->data->port_id, SSSNIC_ETHDEV_MAX_NUM_MC_MAC);
		return -EINVAL;
	}

	for (i = 0; i < nb_mc_addr; i++) {
		if (!rte_is_multicast_ether_addr(&mc_addr_set[i])) {
			rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE,
				&mc_addr_set[i]);
			PMD_DRV_LOG(ERR, "Invalid Multicast MAC address: %s",
				mac_str);
			return -EINVAL;
		}
	}

	sssnic_ethdev_mcast_addrs_clean(ethdev);

	for (i = 0; i < nb_mc_addr; i++) {
		ret = sssnic_mac_addr_add(hw, mc_addr_set[i].addr_bytes);
		if (ret != 0) {
			sssnic_ethdev_mcast_addrs_clean(ethdev);
			rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE,
				&mc_addr_set[i]);
			PMD_DRV_LOG(ERR,
				"Failed to add Multicast MAC address: %s",
				mac_str);
			return ret;
		}
		rte_ether_addr_copy(&mc_addr_set[i], &netdev->mcast_addrs[i]);
	}

	return 0;
}

static int
sssnic_ethdev_mac_addrs_init(struct rte_eth_dev *ethdev)
{
	int ret;
	struct sssnic_netdev *netdev;
	struct sssnic_hw *hw;
	struct rte_ether_addr default_addr;
	char mac_str[RTE_ETHER_ADDR_FMT_SIZE];

	PMD_INIT_FUNC_TRACE();

	netdev = SSSNIC_ETHDEV_PRIVATE(ethdev);
	hw = SSSNIC_NETDEV_TO_HW(netdev);

	ethdev->data->mac_addrs = rte_zmalloc(NULL,
		SSSNIC_ETHDEV_MAX_NUM_UC_MAC * sizeof(struct rte_ether_addr),
		0);
	if (ethdev->data->mac_addrs == NULL) {
		PMD_DRV_LOG(ERR,
			"Failed to allocate memory to store %u mac addresses",
			SSSNIC_ETHDEV_MAX_NUM_UC_MAC);
		return -ENOMEM;
	}

	netdev->mcast_addrs = rte_zmalloc(NULL,
		SSSNIC_ETHDEV_MAX_NUM_MC_MAC * sizeof(struct rte_ether_addr),
		0);
	if (netdev->mcast_addrs == NULL) {
		PMD_DRV_LOG(ERR,
			"Failed to allocate memory to store %u mcast addresses",
			SSSNIC_ETHDEV_MAX_NUM_MC_MAC);
		ret = -ENOMEM;
		goto alloc_mcast_addr_fail;
	}

	/* initialize default MAC address */
	memset(&default_addr, 0, sizeof(default_addr));
	ret = sssnic_mac_addr_get(hw, default_addr.addr_bytes);
	if (ret != 0)
		PMD_DRV_LOG(NOTICE,
			"Could not get default MAC address, will use random address");

	if (rte_is_zero_ether_addr(&default_addr))
		rte_eth_random_addr(default_addr.addr_bytes);

	rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE, &default_addr);

	ret = sssnic_mac_addr_add(hw, default_addr.addr_bytes);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to add default MAC address: %s",
			mac_str);
		goto add_ether_addr_fail;
	}

	rte_ether_addr_copy(&default_addr, &ethdev->data->mac_addrs[0]);
	rte_ether_addr_copy(&default_addr, &netdev->default_addr);

	PMD_DRV_LOG(INFO, "Port %u default MAC address: %s",
		ethdev->data->port_id, mac_str);

	return 0;

add_ether_addr_fail:
	rte_free(netdev->mcast_addrs);
	netdev->mcast_addrs = NULL;
alloc_mcast_addr_fail:
	rte_free(ethdev->data->mac_addrs);
	ethdev->data->mac_addrs = NULL;
	return ret;
}

static void
sssnic_ethdev_mac_addrs_clean(struct rte_eth_dev *ethdev)
{
	int ret;
	struct sssnic_netdev *netdev;
	struct sssnic_hw *hw;
	int i;

	netdev = SSSNIC_ETHDEV_PRIVATE(ethdev);
	hw = SSSNIC_NETDEV_TO_HW(netdev);

	for (i = 0; i < SSSNIC_ETHDEV_MAX_NUM_UC_MAC; i++) {
		if (rte_is_zero_ether_addr(&ethdev->data->mac_addrs[i]))
			continue;

		ret = sssnic_mac_addr_del(hw,
			ethdev->data->mac_addrs[i].addr_bytes);
		if (ret != 0)
			PMD_DRV_LOG(ERR,
				"Failed to delete MAC address from port %u",
				ethdev->data->port_id);
	}

	sssnic_ethdev_mcast_addrs_clean(ethdev);
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

	sssnic_ethdev_link_intr_disable(ethdev);
	sssnic_ethdev_tx_queue_all_release(ethdev);
	sssnic_ethdev_rx_queue_all_release(ethdev);
	sssnic_ethdev_mac_addrs_clean(ethdev);
	sssnic_hw_shutdown(hw);
	rte_free(hw);
}

static const struct eth_dev_ops sssnic_ethdev_ops = {
	.dev_set_link_up = sssnic_ethdev_set_link_up,
	.dev_set_link_down = sssnic_ethdev_set_link_down,
	.link_update = sssnic_ethdev_link_update,
	.dev_configure = sssnic_ethdev_configure,
	.dev_infos_get = sssnic_ethdev_infos_get,
	.mac_addr_set = sssnic_ethdev_mac_addr_set,
	.mac_addr_remove = sssnic_ethdev_mac_addr_remove,
	.mac_addr_add = sssnic_ethdev_mac_addr_add,
	.set_mc_addr_list = sssnic_ethdev_set_mc_addr_list,
	.rx_queue_setup = sssnic_ethdev_rx_queue_setup,
	.rx_queue_release = sssnic_ethdev_rx_queue_release,
	.tx_queue_setup = sssnic_ethdev_tx_queue_setup,
	.tx_queue_release = sssnic_ethdev_tx_queue_release,
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

	ret = sssnic_ethdev_mac_addrs_init(ethdev);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to initialize MAC addresses");
		goto mac_addrs_init_fail;
	}

	netdev->max_num_rxq = SSSNIC_MAX_NUM_RXQ(hw);
	netdev->max_num_txq = SSSNIC_MAX_NUM_TXQ(hw);

	ethdev->dev_ops = &sssnic_ethdev_ops;

	sssnic_ethdev_link_update(ethdev, 0);
	sssnic_ethdev_link_intr_enable(ethdev);

	return 0;

mac_addrs_init_fail:
	sssnic_hw_shutdown(0);
	return ret;
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

	return 0;
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
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING | RTE_PCI_DRV_INTR_LSC,
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

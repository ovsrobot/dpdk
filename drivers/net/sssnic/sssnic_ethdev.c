/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#include <error.h>
#include <rte_common.h>
#include <ethdev_pci.h>

#include "sssnic_log.h"
#include "base/sssnic_hw.h"
#include "base/sssnic_api.h"
#include "sssnic_ethdev.h"
#include "sssnic_ethdev_link.h"
#include "sssnic_ethdev_rx.h"
#include "sssnic_ethdev_tx.h"
#include "sssnic_ethdev_stats.h"
#include "sssnic_ethdev_rss.h"
#include "sssnic_ethdev_fdir.h"
#include "sssnic_ethdev_flow.h"

static int sssnic_ethdev_init(struct rte_eth_dev *ethdev);
static void sssnic_ethdev_vlan_filter_clean(struct rte_eth_dev *ethdev);

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

	sssnic_ethdev_vlan_filter_clean(ethdev);
	sssnic_ethdev_link_intr_disable(ethdev);
	sssnic_ethdev_tx_queue_all_release(ethdev);
	sssnic_ethdev_rx_queue_all_release(ethdev);
	sssnic_ethdev_fdir_shutdown(ethdev);
	sssnic_ethdev_mac_addrs_clean(ethdev);
	sssnic_hw_shutdown(hw);
	rte_free(hw);
}

static int
sssnic_ethdev_rxtx_max_size_init(struct rte_eth_dev *ethdev)
{
	int ret;
	struct sssnic_netdev *netdev = SSSNIC_ETHDEV_PRIVATE(ethdev);
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);

	netdev->max_rx_size = sssnic_ethdev_rx_max_size_determine(ethdev);

	ret = sssnic_rxtx_max_size_init(hw, netdev->max_rx_size, 0x3fff);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to initialize max rx and tx size");
		return ret;
	}

	return 0;
}

static int
sssnic_ethdev_features_setup(struct rte_eth_dev *ethdev)
{
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);
	uint64_t features;
	int ret;

	ret = sssnic_port_features_get(hw, &features);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to get features");
		return ret;
	}

	features &= SSSNIC_ETHDEV_DEFAULT_FEATURES;

	ret = sssnic_port_features_set(hw, features);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to set features to %" PRIx64,
			features);
		return ret;
	}

	PMD_DRV_LOG(DEBUG, "Set features to %" PRIx64, features);

	return 0;
}

static int
sssnic_ethdev_queues_ctx_setup(struct rte_eth_dev *ethdev)
{
	int ret;

	ret = sssnic_ethdev_tx_queues_ctx_init(ethdev);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to initialize tx queues context");
		return ret;
	}

	ret = sssnic_ethdev_rx_queues_ctx_init(ethdev);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to initialize rx queues context");
		return ret;
	}

	ret = sssnic_ethdev_rx_offload_ctx_reset(ethdev);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to initialize rx offload context");
		return ret;
	}

	ret = sssnic_ethdev_tx_offload_ctx_reset(ethdev);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to initialize tx offload context");
		return ret;
	}

	return 0;
}

static int
sssnic_ethdev_rxtx_ctx_setup(struct rte_eth_dev *ethdev)
{
	struct sssnic_netdev *netdev = SSSNIC_ETHDEV_PRIVATE(ethdev);
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);
	uint16_t rxq_depth;
	uint16_t txq_depth;
	uint16_t rx_buf_idx;
	int ret;

	/* queue 0 as default depth */
	rxq_depth = sssnic_ethdev_rx_queue_depth_get(ethdev, 0);
	rxq_depth = rxq_depth << 1;
	txq_depth = sssnic_ethdev_tx_queue_depth_get(ethdev, 0);

	rx_buf_idx = sssnic_ethdev_rx_buf_size_index_get(netdev->max_rx_size);

	ret = sssnic_rxtx_ctx_set(hw, true, rxq_depth, rx_buf_idx, txq_depth);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to set rxtx context");
		return ret;
	}

	PMD_DRV_LOG(INFO,
		"Setup rxq_depth: %u, max_rx_size: %u, rx_buf_idx: %u, txq_depth: %u",
		rxq_depth >> 1, netdev->max_rx_size, rx_buf_idx, txq_depth);

	return 0;
}

static void
sssnic_ethdev_rxtx_ctx_clean(struct rte_eth_dev *ethdev)
{
	sssnic_rxtx_ctx_set(SSSNIC_ETHDEV_TO_HW(ethdev), 0, 0, 0, 0);
}

static int
sssnic_ethdev_resource_clean(struct rte_eth_dev *ethdev)
{
	return sssnic_port_resource_clean(SSSNIC_ETHDEV_TO_HW(ethdev));
}

static int
sssnic_ethdev_start(struct rte_eth_dev *ethdev)
{
	int ret;

	/* disable link event */
	sssnic_ethdev_link_intr_disable(ethdev);

	/* Allocate rx intr vec */
	ret = sssnic_ethdev_rx_intr_init(ethdev);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to initialize rx initr of port %u",
			ethdev->data->port_id);
		goto link_intr_enable;
	}

	/* Initialize rx and tx max size */
	ret = sssnic_ethdev_rxtx_max_size_init(ethdev);
	if (ret != 0) {
		PMD_DRV_LOG(ERR,
			"Failed to initialize rxtx max size of port %u",
			ethdev->data->port_id);
		goto rx_intr_shutdown;
	}

	/* Setup default features for port */
	ret = sssnic_ethdev_features_setup(ethdev);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to setup features");
		goto rx_intr_shutdown;
	}

	/* Setup txqs and rxqs context */
	ret = sssnic_ethdev_queues_ctx_setup(ethdev);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to setup queues context");
		goto rx_intr_shutdown;
	}

	/* Setup tx and rx root context */
	ret = sssnic_ethdev_rxtx_ctx_setup(ethdev);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to setup rxtx context");
		goto rx_intr_shutdown;
	}

	/* Initialize tx ci attributes */
	ret = sssnic_ethdev_tx_ci_attr_init(ethdev);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to initialize tx ci attributes");
		goto rxtx_ctx_clean;
	}

	/* Set MTU */
	ret = sssnic_ethdev_tx_max_size_set(ethdev, ethdev->data->mtu);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to set tx max size to %u",
			ethdev->data->mtu);
		goto rxtx_ctx_clean;
	}

	/* init rx mode */
	ret = sssnic_ethdev_rx_mode_set(ethdev, SSSNIC_ETHDEV_DEF_RX_MODE);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to set rx mode to %x",
			SSSNIC_ETHDEV_DEF_RX_MODE);
		goto rxtx_ctx_clean;
	}

	/* setup rx offload */
	ret = sssnic_ethdev_rx_offload_setup(ethdev);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to setup rx offload");
		goto rx_mode_reset;
	}

	/* setup RSS */
	ret = sssnic_ethdev_rss_setup(ethdev);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to setup RSS");
		goto rx_mode_reset;
	}

	/* start all rx queues */
	ret = sssnic_ethdev_rx_queue_all_start(ethdev);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to start all rx queues");
		goto clean_port_res;
	}

	/* start all tx queues */
	sssnic_ethdev_tx_queue_all_start(ethdev);

	/* enable link event */
	sssnic_ethdev_link_intr_enable(ethdev);

	/* set port link up */
	ret = sssnic_ethdev_set_link_up(ethdev);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to set port link up");
		goto stop_queues;
	}

	PMD_DRV_LOG(INFO, "Port %u is started", ethdev->data->port_id);

	return 0;

stop_queues:
	sssnic_ethdev_tx_queue_all_stop(ethdev);
	sssnic_ethdev_rx_queue_all_stop(ethdev);
clean_port_res:
	sssnic_ethdev_resource_clean(ethdev);
rx_mode_reset:
	sssnic_ethdev_rss_shutdown(ethdev);
	sssnic_ethdev_rx_mode_set(ethdev, SSSNIC_ETHDEV_RX_MODE_NONE);
rxtx_ctx_clean:
	sssnic_ethdev_rxtx_ctx_clean(ethdev);
rx_intr_shutdown:
	sssnic_ethdev_rx_intr_shutdown(ethdev);
link_intr_enable:
	sssnic_ethdev_link_intr_enable(ethdev);
	return ret;
}

static int
sssnic_ethdev_stop(struct rte_eth_dev *ethdev)
{
	struct rte_eth_link linkstatus = { 0 };
	int ret;

	/* disable link event */
	sssnic_ethdev_link_intr_disable(ethdev);

	/* set link down */
	ret = sssnic_ethdev_set_link_down(ethdev);
	if (ret != 0)
		PMD_DRV_LOG(WARNING, "Failed to set port %u link down",
			ethdev->data->port_id);

	rte_eth_linkstatus_set(ethdev, &linkstatus);

	/* wait for hw to stop rx and tx packet */
	rte_delay_ms(100);

	/* stop all tx queues */
	sssnic_ethdev_tx_queue_all_stop(ethdev);

	/* stop all rx queues */
	sssnic_ethdev_rx_queue_all_stop(ethdev);

	/* clean hardware resource */
	sssnic_ethdev_resource_clean(ethdev);

	/* shut down rx queue interrupt */
	sssnic_ethdev_rx_intr_shutdown(ethdev);

	/* Disable RSS */
	sssnic_ethdev_rss_shutdown(ethdev);

	/* clean rxtx context */
	sssnic_ethdev_rxtx_ctx_clean(ethdev);

	/* enable link event */
	sssnic_ethdev_link_intr_enable(ethdev);

	PMD_DRV_LOG(INFO, "Port %u is stopped", ethdev->data->port_id);

	return 0;
}

static int
sssnic_ethdev_close(struct rte_eth_dev *ethdev)
{
	sssnic_ethdev_release(ethdev);

	PMD_DRV_LOG(INFO, "Port %u is closed", ethdev->data->port_id);

	return 0;
}

static int
sssnic_ethdev_reset(struct rte_eth_dev *ethdev)
{
	int ret;

	sssnic_ethdev_release(ethdev);

	ret = sssnic_ethdev_init(ethdev);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to initialize sssnic ethdev");
		return ret;
	}

	PMD_DRV_LOG(INFO, "Port %u is reset", ethdev->data->port_id);

	return 0;
}

static int
sssnic_ethdev_allmulticast_enable(struct rte_eth_dev *ethdev)
{
	struct sssnic_netdev *netdev = SSSNIC_ETHDEV_PRIVATE(ethdev);
	uint32_t rx_mode;
	int ret;

	rx_mode = netdev->rx_mode | SSSNIC_ETHDEV_RX_ALL_MCAST;
	ret = sssnic_ethdev_rx_mode_set(ethdev, rx_mode);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to set rx_mode: %x", rx_mode);
		return ret;
	}

	return 0;
}

static int
sssnic_ethdev_allmulticast_disable(struct rte_eth_dev *ethdev)
{
	struct sssnic_netdev *netdev = SSSNIC_ETHDEV_PRIVATE(ethdev);
	uint32_t rx_mode;
	int ret;

	rx_mode = netdev->rx_mode & (~SSSNIC_ETHDEV_RX_ALL_MCAST);
	ret = sssnic_ethdev_rx_mode_set(ethdev, rx_mode);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to set rx_mode: %x", rx_mode);
		return ret;
	}

	return 0;
}

static int
sssnic_ethdev_promiscuous_enable(struct rte_eth_dev *ethdev)
{
	struct sssnic_netdev *netdev = SSSNIC_ETHDEV_PRIVATE(ethdev);
	uint32_t rx_mode;
	int ret;

	rx_mode = netdev->rx_mode | SSSNIC_ETHDEV_RX_PROMISC;
	ret = sssnic_ethdev_rx_mode_set(ethdev, rx_mode);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to set rx_mode: %x", rx_mode);
		return ret;
	}

	return 0;
}

static int
sssnic_ethdev_promiscuous_disable(struct rte_eth_dev *ethdev)
{
	struct sssnic_netdev *netdev = SSSNIC_ETHDEV_PRIVATE(ethdev);
	uint32_t rx_mode;
	int ret;

	rx_mode = netdev->rx_mode & (~SSSNIC_ETHDEV_RX_PROMISC);
	ret = sssnic_ethdev_rx_mode_set(ethdev, rx_mode);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to set rx_mode: %x", rx_mode);
		return ret;
	}

	return 0;
}

static int
sssnic_ethdev_mtu_set(struct rte_eth_dev *ethdev, uint16_t mtu)
{
	return sssnic_ethdev_tx_max_size_set(ethdev, mtu);
}

static int
sssnic_ethdev_fw_version_get(struct rte_eth_dev *ethdev, char *fw_version,
	size_t fw_size)
{
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);
	struct sssnic_fw_version version;
	int ret;

	ret = sssnic_fw_version_get(hw, &version);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failed to get firmware version");
		return ret;
	}

	snprintf(fw_version, fw_size, "%s", version.version);

	return 0;
}

static int
sssnic_ethdev_flow_ctrl_set(struct rte_eth_dev *ethdev,
	struct rte_eth_fc_conf *fc_conf)
{
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);
	bool autoneg, rx_en, tx_en;
	int ret;

	if (fc_conf->autoneg != 0)
		autoneg = true;
	else
		autoneg = false;

	if (fc_conf->mode == RTE_ETH_FC_FULL ||
		fc_conf->mode == RTE_ETH_FC_RX_PAUSE)
		rx_en = true;
	else
		rx_en = false;

	if (fc_conf->mode == RTE_ETH_FC_FULL ||
		fc_conf->mode == RTE_ETH_FC_TX_PAUSE)
		tx_en = true;
	else
		tx_en = false;

	ret = sssnic_flow_ctrl_set(hw, autoneg, rx_en, tx_en);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failed to set flow conctrol");
		return ret;
	}

	return 0;
}

static int
sssnic_ethdev_flow_ctrl_get(struct rte_eth_dev *ethdev,
	struct rte_eth_fc_conf *fc_conf)
{
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);
	bool autoneg, rx_en, tx_en;
	int ret;

	ret = sssnic_flow_ctrl_get(hw, &autoneg, &rx_en, &tx_en);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failed to get flow conctrol");
		return ret;
	}

	if (autoneg)
		fc_conf->autoneg = true;

	if (rx_en && tx_en)
		fc_conf->mode = RTE_ETH_FC_FULL;
	else if (rx_en)
		fc_conf->mode = RTE_ETH_FC_RX_PAUSE;
	else if (tx_en)
		fc_conf->mode = RTE_ETH_FC_TX_PAUSE;
	else
		fc_conf->mode = RTE_ETH_FC_NONE;

	return 0;
}

static int
sssnic_ethdev_vlan_offload_set(struct rte_eth_dev *ethdev, int mask)
{
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);
	struct rte_eth_conf *dev_conf = &ethdev->data->dev_conf;
	uint8_t vlan_strip_en;
	uint32_t vlan_filter_en;
	int ret;

	if (mask & RTE_ETH_VLAN_STRIP_MASK) {
		if (dev_conf->rxmode.offloads & RTE_ETH_RX_OFFLOAD_VLAN_STRIP)
			vlan_strip_en = 1;
		else
			vlan_strip_en = 0;

		ret = sssnic_vlan_strip_enable_set(hw, vlan_strip_en);
		if (ret != 0) {
			PMD_DRV_LOG(ERR, "Failed to %s vlan strip offload",
				vlan_strip_en ? "enable" : "disable");
			return ret;
		}
	}

	if (mask & RTE_ETH_VLAN_FILTER_MASK) {
		if (dev_conf->rxmode.offloads & RTE_ETH_RX_OFFLOAD_VLAN_FILTER)
			vlan_filter_en = 1;
		else
			vlan_filter_en = 0;

		ret = sssnic_vlan_filter_enable_set(hw, vlan_filter_en);
		if (ret != 0) {
			PMD_DRV_LOG(ERR, "Failed to %s vlan filter offload",
				vlan_filter_en ? "enable" : "disable");
			return ret;
		}
	}

	return 0;
}

static int
sssnic_ethdev_vlan_filter_get(struct rte_eth_dev *ethdev, uint16_t vlan_id)
{
	struct rte_vlan_filter_conf *vfc = &ethdev->data->vlan_filter_conf;
	int vidx = vlan_id / 64;
	int vbit = vlan_id % 64;

	return !!(vfc->ids[vidx] & RTE_BIT64(vbit));
}

static int
sssnic_ethdev_vlan_filter_set(struct rte_eth_dev *ethdev, uint16_t vlan_id,
	int on)
{
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);
	int ret;

	if (sssnic_ethdev_vlan_filter_get(ethdev, vlan_id) == !!on)
		return 0;

	ret = sssnic_vlan_filter_set(hw, vlan_id, !!on);
	if (ret) {
		PMD_DRV_LOG(ERR,
			"Failed to %s VLAN filter, vlan_id: %u, port: %u",
			on ? "add" : "remove", vlan_id, ethdev->data->port_id);
		return ret;
	}

	PMD_DRV_LOG(DEBUG, "%s VLAN %u filter to port %u",
		on ? "Added" : "Removed", vlan_id, ethdev->data->port_id);

	return 0;
}

static void
sssnic_ethdev_vlan_filter_clean(struct rte_eth_dev *ethdev)
{
	uint16_t vlan_id;

	for (vlan_id = 0; vlan_id <= RTE_ETHER_MAX_VLAN_ID; vlan_id++)
		sssnic_ethdev_vlan_filter_set(ethdev, vlan_id, 0);
}

static const struct eth_dev_ops sssnic_ethdev_ops = {
	.dev_start = sssnic_ethdev_start,
	.dev_stop = sssnic_ethdev_stop,
	.dev_close = sssnic_ethdev_close,
	.dev_reset = sssnic_ethdev_reset,
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
	.rx_queue_start = sssnic_ethdev_rx_queue_start,
	.rx_queue_stop = sssnic_ethdev_rx_queue_stop,
	.tx_queue_start = sssnic_ethdev_tx_queue_start,
	.tx_queue_stop = sssnic_ethdev_tx_queue_stop,
	.rx_queue_intr_enable = sssnic_ethdev_rx_queue_intr_enable,
	.rx_queue_intr_disable = sssnic_ethdev_rx_queue_intr_disable,
	.allmulticast_enable = sssnic_ethdev_allmulticast_enable,
	.allmulticast_disable = sssnic_ethdev_allmulticast_disable,
	.promiscuous_enable = sssnic_ethdev_promiscuous_enable,
	.promiscuous_disable = sssnic_ethdev_promiscuous_disable,
	.stats_get = sssnic_ethdev_stats_get,
	.stats_reset = sssnic_ethdev_stats_reset,
	.xstats_get_names = sssnic_ethdev_xstats_get_names,
	.xstats_get = sssnic_ethdev_xstats_get,
	.xstats_reset = sssnic_ethdev_xstats_reset,
	.rss_hash_conf_get = sssnic_ethdev_rss_hash_config_get,
	.rss_hash_update = sssnic_ethdev_rss_hash_update,
	.reta_update = sssnic_ethdev_rss_reta_update,
	.reta_query = sssnic_ethdev_rss_reta_query,
	.mtu_set = sssnic_ethdev_mtu_set,
	.rxq_info_get = sssnic_ethdev_rx_queue_info_get,
	.txq_info_get = sssnic_ethdev_tx_queue_info_get,
	.fw_version_get = sssnic_ethdev_fw_version_get,
	.flow_ctrl_set = sssnic_ethdev_flow_ctrl_set,
	.flow_ctrl_get = sssnic_ethdev_flow_ctrl_get,
	.vlan_offload_set = sssnic_ethdev_vlan_offload_set,
	.vlan_filter_set = sssnic_ethdev_vlan_filter_set,
	.flow_ops_get = sssnic_ethdev_flow_ops_get,
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

	ethdev->rx_pkt_burst = sssnic_ethdev_rx_pkt_burst;
	ethdev->tx_pkt_burst = sssnic_ethdev_tx_pkt_burst;

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

	ret = sssnic_ethdev_fdir_init(ethdev);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failed to initialize fdir info");
		goto fdir_init_fail;
	}

	netdev->max_num_rxq = SSSNIC_MAX_NUM_RXQ(hw);
	netdev->max_num_txq = SSSNIC_MAX_NUM_TXQ(hw);

	ethdev->dev_ops = &sssnic_ethdev_ops;

	sssnic_ethdev_link_update(ethdev, 0);
	sssnic_ethdev_link_intr_enable(ethdev);

	return 0;

fdir_init_fail:
	sssnic_ethdev_mac_addrs_clean(ethdev);
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

	/* stop ethdev first */
	if (ethdev->data->dev_started)
		sssnic_ethdev_stop(ethdev);

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

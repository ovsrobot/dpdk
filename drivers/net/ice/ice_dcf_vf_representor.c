/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#include <errno.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <rte_interrupts.h>
#include <rte_debug.h>
#include <rte_pci.h>
#include <rte_atomic.h>
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_ethdev_pci.h>
#include <rte_kvargs.h>
#include <rte_malloc.h>
#include <rte_memzone.h>
#include <rte_dev.h>

#include <iavf_devids.h>

#include "ice_generic_flow.h"
#include "ice_dcf_ethdev.h"
#include "ice_rxtx.h"

static uint16_t
ice_dcf_representor_rx_burst(__rte_unused void *rxq,
			     __rte_unused struct rte_mbuf **rx_pkts,
			     __rte_unused uint16_t nb_pkts)
{
	return 0;
}

static uint16_t
ice_dcf_representor_tx_burst(__rte_unused void *txq,
			     __rte_unused struct rte_mbuf **tx_pkts,
			     __rte_unused uint16_t nb_pkts)
{
	return 0;
}

static int
ice_dcf_representor_dev_configure(__rte_unused struct rte_eth_dev *dev)
{
	return 0;
}

static int
ice_dcf_representor_dev_start(struct rte_eth_dev *dev)
{
	dev->data->dev_link.link_status = ETH_LINK_UP;

	return 0;
}

static void
ice_dcf_representor_dev_stop(struct rte_eth_dev *dev)
{
	dev->data->dev_link.link_status = ETH_LINK_DOWN;
}

static int
ice_dcf_representor_rx_queue_setup(__rte_unused struct rte_eth_dev *dev,
			__rte_unused uint16_t rx_queue_id,
			__rte_unused uint16_t nb_rx_desc,
			__rte_unused unsigned int socket_id,
			__rte_unused const struct rte_eth_rxconf *rx_conf,
			__rte_unused struct rte_mempool *mb_pool)
{
	return 0;
}

static int
ice_dcf_representor_tx_queue_setup(__rte_unused struct rte_eth_dev *dev,
			__rte_unused uint16_t rx_queue_id,
			__rte_unused uint16_t nb_rx_desc,
			__rte_unused unsigned int socket_id,
			__rte_unused const struct rte_eth_txconf *tx_conf)
{
	return 0;
}

static int
ice_dcf_representor_promiscuous_enable(__rte_unused struct rte_eth_dev *ethdev)
{
	return 0;
}

static int
ice_dcf_representor_promiscuous_disable(__rte_unused struct rte_eth_dev *ethdev)
{
	return 0;
}

static int
ice_dcf_representor_link_update(__rte_unused struct rte_eth_dev *ethdev,
				__rte_unused int wait_to_complete)
{
	return 0;
}

static int
ice_dcf_representor_dev_info_get(struct rte_eth_dev *dev,
				 struct rte_eth_dev_info *dev_info)
{
	struct ice_dcf_vf_representor *representor = dev->data->dev_private;
	struct ice_dcf_hw *hw = &representor->adapter->real_hw;

	dev_info->device = dev->device;
	dev_info->max_mac_addrs = 1;
	dev_info->max_rx_queues = hw->vsi_res->num_queue_pairs;
	dev_info->max_tx_queues = hw->vsi_res->num_queue_pairs;
	dev_info->min_rx_bufsize = ICE_BUF_SIZE_MIN;
	dev_info->max_rx_pktlen = ICE_FRAME_SIZE_MAX;
	dev_info->hash_key_size = hw->vf_res->rss_key_size;
	dev_info->reta_size = hw->vf_res->rss_lut_size;
	dev_info->flow_type_rss_offloads = ICE_RSS_OFFLOAD_ALL;

	dev_info->rx_offload_capa =
		DEV_RX_OFFLOAD_VLAN_STRIP |
		DEV_RX_OFFLOAD_IPV4_CKSUM |
		DEV_RX_OFFLOAD_UDP_CKSUM |
		DEV_RX_OFFLOAD_TCP_CKSUM |
		DEV_RX_OFFLOAD_OUTER_IPV4_CKSUM |
		DEV_RX_OFFLOAD_SCATTER |
		DEV_RX_OFFLOAD_JUMBO_FRAME |
		DEV_RX_OFFLOAD_VLAN_FILTER |
		DEV_RX_OFFLOAD_RSS_HASH;
	dev_info->tx_offload_capa =
		DEV_TX_OFFLOAD_VLAN_INSERT |
		DEV_TX_OFFLOAD_IPV4_CKSUM |
		DEV_TX_OFFLOAD_UDP_CKSUM |
		DEV_TX_OFFLOAD_TCP_CKSUM |
		DEV_TX_OFFLOAD_SCTP_CKSUM |
		DEV_TX_OFFLOAD_OUTER_IPV4_CKSUM |
		DEV_TX_OFFLOAD_TCP_TSO |
		DEV_TX_OFFLOAD_VXLAN_TNL_TSO |
		DEV_TX_OFFLOAD_GRE_TNL_TSO |
		DEV_TX_OFFLOAD_IPIP_TNL_TSO |
		DEV_TX_OFFLOAD_GENEVE_TNL_TSO |
		DEV_TX_OFFLOAD_MULTI_SEGS;

	dev_info->default_rxconf = (struct rte_eth_rxconf) {
		.rx_thresh = {
			.pthresh = ICE_DEFAULT_RX_PTHRESH,
			.hthresh = ICE_DEFAULT_RX_HTHRESH,
			.wthresh = ICE_DEFAULT_RX_WTHRESH,
		},
		.rx_free_thresh = ICE_DEFAULT_RX_FREE_THRESH,
		.rx_drop_en = 0,
		.offloads = 0,
	};

	dev_info->default_txconf = (struct rte_eth_txconf) {
		.tx_thresh = {
			.pthresh = ICE_DEFAULT_TX_PTHRESH,
			.hthresh = ICE_DEFAULT_TX_HTHRESH,
			.wthresh = ICE_DEFAULT_TX_WTHRESH,
		},
		.tx_free_thresh = ICE_DEFAULT_TX_FREE_THRESH,
		.tx_rs_thresh = ICE_DEFAULT_TX_RSBIT_THRESH,
		.offloads = 0,
	};

	dev_info->rx_desc_lim = (struct rte_eth_desc_lim) {
		.nb_max = ICE_MAX_RING_DESC,
		.nb_min = ICE_MIN_RING_DESC,
		.nb_align = ICE_ALIGN_RING_DESC,
	};

	dev_info->tx_desc_lim = (struct rte_eth_desc_lim) {
		.nb_max = ICE_MAX_RING_DESC,
		.nb_min = ICE_MIN_RING_DESC,
		.nb_align = ICE_ALIGN_RING_DESC,
	};

	dev_info->switch_info.name =
		representor->adapter->real_hw.eth_dev->device->name;
	dev_info->switch_info.domain_id = representor->switch_domain_id;
	dev_info->switch_info.port_id = representor->vf_id;

	return 0;
}

static const struct eth_dev_ops ice_dcf_representor_dev_ops = {
	.dev_configure        = ice_dcf_representor_dev_configure,
	.dev_start            = ice_dcf_representor_dev_start,
	.dev_stop             = ice_dcf_representor_dev_stop,
	.dev_infos_get        = ice_dcf_representor_dev_info_get,
	.rx_queue_setup       = ice_dcf_representor_rx_queue_setup,
	.tx_queue_setup       = ice_dcf_representor_tx_queue_setup,
	.promiscuous_enable   = ice_dcf_representor_promiscuous_enable,
	.promiscuous_disable  = ice_dcf_representor_promiscuous_disable,
	.link_update          = ice_dcf_representor_link_update,
};

int
ice_dcf_vf_representor_init(struct rte_eth_dev *ethdev, void *init_params)
{
	struct ice_dcf_vf_representor *representor = ethdev->data->dev_private;
	struct ice_dcf_hw *real_hw;

	representor->adapter =
		((struct ice_dcf_vf_representor *)init_params)->adapter;
	representor->switch_domain_id =
		((struct ice_dcf_vf_representor *)
		 init_params)->switch_domain_id;
	representor->vf_id =
		((struct ice_dcf_vf_representor *)init_params)->vf_id;

	real_hw = &representor->adapter->real_hw;

	if (representor->vf_id >= real_hw->num_vfs)
		return -ENODEV;

	ethdev->dev_ops = &ice_dcf_representor_dev_ops;

	/* No data-path, but need stub Rx/Tx functions to avoid crash
	 * when testing with the likes of testpmd.
	 */
	ethdev->rx_pkt_burst = ice_dcf_representor_rx_burst;
	ethdev->tx_pkt_burst = ice_dcf_representor_tx_burst;

	ethdev->data->dev_flags |= RTE_ETH_DEV_REPRESENTOR;
	ethdev->data->representor_id = representor->vf_id;

	struct rte_ether_addr mac_addr;

	memset(&mac_addr, 0, sizeof(mac_addr));
	ethdev->data->mac_addrs = &mac_addr;

	return 0;
}

int
ice_dcf_vf_representor_uninit(struct rte_eth_dev *ethdev)
{
	ethdev->data->mac_addrs = NULL;

	return 0;
}


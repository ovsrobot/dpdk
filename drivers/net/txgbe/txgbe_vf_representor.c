/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2015-2020
 */

#include <rte_ethdev.h>
#include <rte_pci.h>
#include <rte_malloc.h>

#include "base/txgbe_type.h"
#include "base/txgbe_vf.h"
#include "txgbe_ethdev.h"
#include "txgbe_rxtx.h"
#include "rte_pmd_txgbe.h"

static int
txgbe_vf_representor_link_update(struct rte_eth_dev *ethdev,
	int wait_to_complete)
{
	struct txgbe_vf_representor *representor =
			TXGBE_DEV_REPRESENTOR(ethdev);

	return txgbe_dev_link_update_share(representor->pf_ethdev,
		wait_to_complete);
}

static int
txgbe_vf_representor_mac_addr_set(struct rte_eth_dev *ethdev,
	struct rte_ether_addr *mac_addr)
{
	struct txgbe_vf_representor *representor =
			TXGBE_DEV_REPRESENTOR(ethdev);

	return rte_pmd_txgbe_set_vf_mac_addr(
		representor->pf_ethdev->data->port_id,
		representor->vf_id, mac_addr);
}

static int
txgbe_vf_representor_dev_infos_get(struct rte_eth_dev *ethdev,
	struct rte_eth_dev_info *dev_info)
{
	struct txgbe_vf_representor *representor =
			TXGBE_DEV_REPRESENTOR(ethdev);

	struct txgbe_hw *hw = TXGBE_DEV_HW(representor->pf_ethdev);

	dev_info->device = representor->pf_ethdev->device;

	dev_info->min_rx_bufsize = 1024;
	/**< Minimum size of RX buffer. */
	dev_info->max_rx_pktlen = 9728;
	/**< Maximum configurable length of RX pkt. */
	dev_info->max_rx_queues = TXGBE_VF_MAX_RX_QUEUES;
	/**< Maximum number of RX queues. */
	dev_info->max_tx_queues = TXGBE_VF_MAX_TX_QUEUES;
	/**< Maximum number of TX queues. */

	dev_info->max_mac_addrs = hw->mac.num_rar_entries;
	/**< Maximum number of MAC addresses. */

	dev_info->rx_offload_capa = DEV_RX_OFFLOAD_VLAN_STRIP |
		DEV_RX_OFFLOAD_IPV4_CKSUM |	DEV_RX_OFFLOAD_UDP_CKSUM  |
		DEV_RX_OFFLOAD_TCP_CKSUM;
	/**< Device RX offload capabilities. */

	dev_info->tx_offload_capa = DEV_TX_OFFLOAD_VLAN_INSERT |
		DEV_TX_OFFLOAD_IPV4_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM |
		DEV_TX_OFFLOAD_TCP_CKSUM | DEV_TX_OFFLOAD_SCTP_CKSUM |
		DEV_TX_OFFLOAD_TCP_TSO | DEV_TX_OFFLOAD_MULTI_SEGS;
	/**< Device TX offload capabilities. */

	dev_info->speed_capa =
		representor->pf_ethdev->data->dev_link.link_speed;
	/**< Supported speeds bitmap (ETH_LINK_SPEED_). */

	dev_info->switch_info.name =
		representor->pf_ethdev->device->name;
	dev_info->switch_info.domain_id = representor->switch_domain_id;
	dev_info->switch_info.port_id = representor->vf_id;

	return 0;
}

static int
txgbe_vf_representor_vlan_filter_set(struct rte_eth_dev *ethdev,
	uint16_t vlan_id, int on)
{
	struct txgbe_vf_representor *representor =
			TXGBE_DEV_REPRESENTOR(ethdev);
	uint64_t vf_mask = 1ULL << representor->vf_id;

	return rte_pmd_txgbe_set_vf_vlan_filter(
		representor->pf_ethdev->data->port_id, vlan_id, vf_mask, on);
}

static void
txgbe_vf_representor_vlan_strip_queue_set(struct rte_eth_dev *ethdev,
	__rte_unused uint16_t rx_queue_id, int on)
{
	struct txgbe_vf_representor *representor =
			TXGBE_DEV_REPRESENTOR(ethdev);

	rte_pmd_txgbe_set_vf_vlan_stripq(representor->pf_ethdev->data->port_id,
		representor->vf_id, on);
}

static const struct eth_dev_ops txgbe_vf_representor_dev_ops = {
	.dev_infos_get		= txgbe_vf_representor_dev_infos_get,
	.link_update		= txgbe_vf_representor_link_update,
	.vlan_filter_set	= txgbe_vf_representor_vlan_filter_set,
	.vlan_strip_queue_set	= txgbe_vf_representor_vlan_strip_queue_set,
	.mac_addr_set		= txgbe_vf_representor_mac_addr_set,
};

static uint16_t
txgbe_vf_representor_rx_burst(__rte_unused void *rx_queue,
	__rte_unused struct rte_mbuf **rx_pkts, __rte_unused uint16_t nb_pkts)
{
	return 0;
}

static uint16_t
txgbe_vf_representor_tx_burst(__rte_unused void *tx_queue,
	__rte_unused struct rte_mbuf **tx_pkts, __rte_unused uint16_t nb_pkts)
{
	return 0;
}

int
txgbe_vf_representor_init(struct rte_eth_dev *ethdev, void *init_params)
{
	struct txgbe_vf_representor *representor =
			TXGBE_DEV_REPRESENTOR(ethdev);

	struct txgbe_vf_info *vf_data;
	struct rte_pci_device *pci_dev;
	struct rte_eth_link *link;

	if (!representor)
		return -ENOMEM;

	representor->vf_id =
		((struct txgbe_vf_representor *)init_params)->vf_id;
	representor->switch_domain_id =
		((struct txgbe_vf_representor *)init_params)->switch_domain_id;
	representor->pf_ethdev =
		((struct txgbe_vf_representor *)init_params)->pf_ethdev;

	pci_dev = RTE_ETH_DEV_TO_PCI(representor->pf_ethdev);

	if (representor->vf_id >= pci_dev->max_vfs)
		return -ENODEV;

	ethdev->data->dev_flags |= RTE_ETH_DEV_REPRESENTOR;
	ethdev->data->representor_id = representor->vf_id;

	/* Set representor device ops */
	ethdev->dev_ops = &txgbe_vf_representor_dev_ops;

	/* No data-path, but need stub Rx/Tx functions to avoid crash
	 * when testing with the likes of testpmd.
	 */
	ethdev->rx_pkt_burst = txgbe_vf_representor_rx_burst;
	ethdev->tx_pkt_burst = txgbe_vf_representor_tx_burst;

	/* Setting the number queues allocated to the VF */
	ethdev->data->nb_rx_queues = TXGBE_VF_MAX_RX_QUEUES;
	ethdev->data->nb_tx_queues = TXGBE_VF_MAX_RX_QUEUES;

	/* Reference VF mac address from PF data structure */
	vf_data = *TXGBE_DEV_VFDATA(representor->pf_ethdev);

	ethdev->data->mac_addrs = (struct rte_ether_addr *)
		vf_data[representor->vf_id].vf_mac_addresses;

	/* Link state. Inherited from PF */
	link = &representor->pf_ethdev->data->dev_link;

	ethdev->data->dev_link.link_speed = link->link_speed;
	ethdev->data->dev_link.link_duplex = link->link_duplex;
	ethdev->data->dev_link.link_status = link->link_status;
	ethdev->data->dev_link.link_autoneg = link->link_autoneg;

	return 0;
}

int
txgbe_vf_representor_uninit(struct rte_eth_dev *ethdev)
{
	/* mac_addrs must not be freed because part of txgbe_vf_info */
	ethdev->data->mac_addrs = NULL;

	return 0;
}


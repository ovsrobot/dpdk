/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2015-2020
 */

#include <rte_ethdev_driver.h>

#include "base/txgbe.h"
#include "txgbe_ethdev.h"
#include "rte_pmd_txgbe.h"

int
rte_pmd_txgbe_set_vf_mac_addr(uint16_t port, uint16_t vf,
			      struct rte_ether_addr *mac_addr)
{
	struct txgbe_hw *hw;
	struct txgbe_vf_info *vfinfo;
	int rar_entry;
	struct rte_ether_addr *new_mac = mac_addr;
	struct rte_eth_dev *dev;
	struct rte_pci_device *pci_dev;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port, -ENODEV);

	dev = &rte_eth_devices[port];
	pci_dev = RTE_ETH_DEV_TO_PCI(dev);

	if (!is_txgbe_supported(dev))
		return -ENOTSUP;

	if (vf >= pci_dev->max_vfs)
		return -EINVAL;

	hw = TXGBE_DEV_HW(dev);
	vfinfo = *(TXGBE_DEV_VFDATA(dev));
	rar_entry = hw->mac.num_rar_entries - (vf + 1);

	if (rte_is_valid_assigned_ether_addr(new_mac)) {
		rte_memcpy(vfinfo[vf].vf_mac_addresses, (uint8_t *)new_mac,
			   RTE_ETHER_ADDR_LEN);
		return hw->mac.set_rar(hw, rar_entry, (uint8_t *)new_mac, vf,
					   true);
	}
	return -EINVAL;
}

int
rte_pmd_txgbe_set_vf_vlan_stripq(uint16_t port, uint16_t vf, uint8_t on)
{
	struct rte_eth_dev *dev;
	struct rte_pci_device *pci_dev;
	struct txgbe_hw *hw;
	uint16_t queues_per_pool;
	uint32_t q;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port, -ENODEV);

	dev = &rte_eth_devices[port];
	pci_dev = RTE_ETH_DEV_TO_PCI(dev);
	hw = TXGBE_DEV_HW(dev);

	if (!is_txgbe_supported(dev))
		return -ENOTSUP;

	if (vf >= pci_dev->max_vfs)
		return -EINVAL;

	if (on > 1)
		return -EINVAL;

	RTE_FUNC_PTR_OR_ERR_RET(*dev->dev_ops->vlan_strip_queue_set, -ENOTSUP);

	/* The PF has 128 queue pairs and in SRIOV configuration
	 * those queues will be assigned to VF's, so RXDCTL
	 * registers will be dealing with queues which will be
	 * assigned to VF's.
	 * Let's say we have SRIOV configured with 31 VF's then the
	 * first 124 queues 0-123 will be allocated to VF's and only
	 * the last 4 queues 123-127 will be assigned to the PF.
	 */
	queues_per_pool = (uint16_t)hw->mac.max_rx_queues /
			  ETH_64_POOLS;

	for (q = 0; q < queues_per_pool; q++)
		(*dev->dev_ops->vlan_strip_queue_set)(dev,
				q + vf * queues_per_pool, on);
	return 0;
}

int
rte_pmd_txgbe_set_vf_vlan_filter(uint16_t port, uint16_t vlan,
				 uint64_t vf_mask, uint8_t vlan_on)
{
	struct rte_eth_dev *dev;
	int ret = 0;
	uint16_t vf_idx;
	struct txgbe_hw *hw;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port, -ENODEV);

	dev = &rte_eth_devices[port];

	if (!is_txgbe_supported(dev))
		return -ENOTSUP;

	if (vlan > RTE_ETHER_MAX_VLAN_ID || vf_mask == 0)
		return -EINVAL;

	hw = TXGBE_DEV_HW(dev);
	if (txgbe_vt_check(hw) < 0)
		return -ENOTSUP;

	for (vf_idx = 0; vf_idx < 64; vf_idx++) {
		if (vf_mask & ((uint64_t)(1ULL << vf_idx))) {
			ret = hw->mac.set_vfta(hw, vlan, vf_idx,
						   vlan_on, false);
			if (ret < 0)
				return ret;
		}
	}

	return ret;
}


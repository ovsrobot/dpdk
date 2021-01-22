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


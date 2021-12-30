/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#include <rte_pci.h>
#include <rte_bus_pci.h>
#include <ethdev_pci.h>
#include <rte_malloc.h>
#include <rte_errno.h>
#include <rte_ether.h>

#include "base/spnic_compat.h"
#include "base/spnic_cmd.h"
#include "base/spnic_csr.h"
#include "base/spnic_wq.h"
#include "base/spnic_eqs.h"
#include "base/spnic_mgmt.h"
#include "base/spnic_cmdq.h"
#include "base/spnic_hwdev.h"
#include "base/spnic_hwif.h"
#include "base/spnic_hw_cfg.h"
#include "base/spnic_hw_comm.h"
#include "base/spnic_nic_cfg.h"
#include "base/spnic_nic_event.h"
#include "spnic_ethdev.h"

/* Driver-specific log messages type */
int spnic_logtype;

#define SPNIC_MAX_UC_MAC_ADDRS		128
#define SPNIC_MAX_MC_MAC_ADDRS		128

static void spnic_delete_mc_addr_list(struct spnic_nic_dev *nic_dev)
{
	u16 func_id;
	u32 i;

	func_id = spnic_global_func_id(nic_dev->hwdev);

	for (i = 0; i < SPNIC_MAX_MC_MAC_ADDRS; i++) {
		if (rte_is_zero_ether_addr(&nic_dev->mc_list[i]))
			break;

		spnic_del_mac(nic_dev->hwdev, nic_dev->mc_list[i].addr_bytes,
			      0, func_id);
		memset(&nic_dev->mc_list[i], 0, sizeof(struct rte_ether_addr));
	}
}

/**
 * Deinit mac_vlan table in hardware.
 *
 * @param[in] eth_dev
 *   Pointer to ethernet device structure.
 */
static void spnic_deinit_mac_addr(struct rte_eth_dev *eth_dev)
{
	struct spnic_nic_dev *nic_dev =
				SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(eth_dev);
	u16 func_id = 0;
	int err;
	int i;

	func_id = spnic_global_func_id(nic_dev->hwdev);

	for (i = 0; i < SPNIC_MAX_UC_MAC_ADDRS; i++) {
		if (rte_is_zero_ether_addr(&eth_dev->data->mac_addrs[i]))
			continue;

		err = spnic_del_mac(nic_dev->hwdev,
				    eth_dev->data->mac_addrs[i].addr_bytes,
				    0, func_id);
		if (err && err != SPNIC_PF_SET_VF_ALREADY)
			PMD_DRV_LOG(ERR, "Delete mac table failed, dev_name: %s",
				    eth_dev->data->name);

		memset(&eth_dev->data->mac_addrs[i], 0,
		       sizeof(struct rte_ether_addr));
	}

	/* Delete multicast mac addrs */
	spnic_delete_mc_addr_list(nic_dev);
}

/**
 * Close the device.
 *
 * @param[in] dev
 *   Pointer to ethernet device structure.
 */
static int spnic_dev_close(struct rte_eth_dev *eth_dev)
{
	struct spnic_nic_dev *nic_dev =
		SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(eth_dev);

	if (rte_bit_relaxed_test_and_set32(SPNIC_DEV_CLOSE, &nic_dev->dev_status)) {
		PMD_DRV_LOG(WARNING, "Device %s already closed",
			    nic_dev->dev_name);
		return 0;
	}

	spnic_deinit_mac_addr(eth_dev);
	rte_free(nic_dev->mc_list);

	rte_bit_relaxed_clear32(SPNIC_DEV_INTR_EN, &nic_dev->dev_status);

	spnic_free_hwdev(nic_dev->hwdev);

	eth_dev->dev_ops = NULL;

	rte_free(nic_dev->hwdev);
	nic_dev->hwdev = NULL;

	return 0;
}
/**
 * Update MAC address
 *
 * @param[in] dev
 *   Pointer to ethernet device structure.
 * @param[in] addr
 *   Pointer to MAC address
 *
 * @retval zero: Success
 * @retval non-zero: Failure
 */
static int spnic_set_mac_addr(struct rte_eth_dev *dev,
			      struct rte_ether_addr *addr)
{
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	char mac_addr[RTE_ETHER_ADDR_FMT_SIZE];
	u16 func_id;
	int err;

	if (!rte_is_valid_assigned_ether_addr(addr)) {
		rte_ether_format_addr(mac_addr, RTE_ETHER_ADDR_FMT_SIZE, addr);
		PMD_DRV_LOG(ERR, "Set invalid MAC address %s", mac_addr);
		return -EINVAL;
	}

	func_id = spnic_global_func_id(nic_dev->hwdev);
	err = spnic_update_mac(nic_dev->hwdev,
				nic_dev->default_addr.addr_bytes,
				addr->addr_bytes, 0, func_id);
	if (err)
		return err;

	rte_ether_addr_copy(addr, &nic_dev->default_addr);
	rte_ether_format_addr(mac_addr, RTE_ETHER_ADDR_FMT_SIZE,
			      &nic_dev->default_addr);

	PMD_DRV_LOG(INFO, "Set new MAC address %s", mac_addr);

	return 0;
}

/**
 * Remove a MAC address.
 *
 * @param[in] dev
 *   Pointer to ethernet device structure.
 * @param[in] index
 *   MAC address index.
 */
static void spnic_mac_addr_remove(struct rte_eth_dev *dev, uint32_t index)
{
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	u16 func_id;
	int err;

	if (index >= SPNIC_MAX_UC_MAC_ADDRS) {
		PMD_DRV_LOG(INFO, "Remove MAC index(%u) is out of range",
			    index);
		return;
	}

	func_id = spnic_global_func_id(nic_dev->hwdev);
	err = spnic_del_mac(nic_dev->hwdev,
			     dev->data->mac_addrs[index].addr_bytes,
			     0, func_id);
	if (err)
		PMD_DRV_LOG(ERR, "Remove MAC index(%u) failed", index);
}

/**
 * Add a MAC address.
 *
 * @param[in] dev
 *   Pointer to ethernet device structure.
 * @param[in] mac_addr
 *   MAC address to register.
 * @param[in] index
 *   MAC address index.
 * @param[in] vmdq
 *   VMDq pool index to associate address with (unused_).
 *
 * @retval zero: Success
 * @retval non-zero: Failure
 */
static int spnic_mac_addr_add(struct rte_eth_dev *dev,
			      struct rte_ether_addr *mac_addr, uint32_t index,
			      __rte_unused uint32_t vmdq)
{
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	unsigned int i;
	u16 func_id;
	int err;

	if (!rte_is_valid_assigned_ether_addr(mac_addr)) {
		PMD_DRV_LOG(ERR, "Add invalid MAC address");
		return -EINVAL;
	}

	if (index >= SPNIC_MAX_UC_MAC_ADDRS) {
		PMD_DRV_LOG(ERR, "Add MAC index(%u) is out of range", index);
		return -EINVAL;
	}

	/* Make sure this address doesn't already be configured */
	for (i = 0; i < SPNIC_MAX_UC_MAC_ADDRS; i++) {
		if (rte_is_same_ether_addr(mac_addr,
			&dev->data->mac_addrs[i])) {
			PMD_DRV_LOG(ERR, "MAC address is already configured");
			return -EADDRINUSE;
		}
	}

	func_id = spnic_global_func_id(nic_dev->hwdev);
	err = spnic_set_mac(nic_dev->hwdev, mac_addr->addr_bytes, 0, func_id);
	if (err)
		return err;

	return 0;
}

/**
 * Set multicast MAC address
 *
 * @param[in] dev
 *   Pointer to ethernet device structure.
 * @param[in] mc_addr_set
 *   Pointer to multicast MAC address
 * @param[in] nb_mc_addr
 *   The number of multicast MAC address to set
 *
 * @retval zero: Success
 * @retval non-zero: Failure
 */
static int spnic_set_mc_addr_list(struct rte_eth_dev *dev,
				  struct rte_ether_addr *mc_addr_set,
				  uint32_t nb_mc_addr)
{
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	char mac_addr[RTE_ETHER_ADDR_FMT_SIZE];
	u16 func_id;
	int err;
	u32 i;

	func_id = spnic_global_func_id(nic_dev->hwdev);

	/* Delete old multi_cast addrs firstly */
	spnic_delete_mc_addr_list(nic_dev);

	if (nb_mc_addr > SPNIC_MAX_MC_MAC_ADDRS)
		return -EINVAL;

	for (i = 0; i < nb_mc_addr; i++) {
		if (!rte_is_multicast_ether_addr(&mc_addr_set[i])) {
			rte_ether_format_addr(mac_addr, RTE_ETHER_ADDR_FMT_SIZE,
					      &mc_addr_set[i]);
			PMD_DRV_LOG(ERR, "Set mc MAC addr failed, addr(%s) invalid",
				    mac_addr);
			return -EINVAL;
		}
	}

	for (i = 0; i < nb_mc_addr; i++) {
		err = spnic_set_mac(nic_dev->hwdev, mc_addr_set[i].addr_bytes,
				    0, func_id);
		if (err) {
			spnic_delete_mc_addr_list(nic_dev);
			return err;
		}

		rte_ether_addr_copy(&mc_addr_set[i], &nic_dev->mc_list[i]);
	}

	return 0;
}
static const struct eth_dev_ops spnic_pmd_ops = {
	.mac_addr_set                  = spnic_set_mac_addr,
	.mac_addr_remove               = spnic_mac_addr_remove,
	.mac_addr_add                  = spnic_mac_addr_add,
	.set_mc_addr_list              = spnic_set_mc_addr_list,
};

static const struct eth_dev_ops spnic_pmd_vf_ops = {
	.mac_addr_set                  = spnic_set_mac_addr,
	.mac_addr_remove               = spnic_mac_addr_remove,
	.mac_addr_add                  = spnic_mac_addr_add,
	.set_mc_addr_list              = spnic_set_mc_addr_list,
};

/**
 * Init mac_vlan table in hardwares.
 *
 * @param[in] eth_dev
 *   Pointer to ethernet device structure.
 *
 * @retval zero: Success
 * @retval non-zero: Failure
 */
static int spnic_init_mac_table(struct rte_eth_dev *eth_dev)
{
	struct spnic_nic_dev *nic_dev =
		SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(eth_dev);
	u8 addr_bytes[RTE_ETHER_ADDR_LEN];
	u16 func_id = 0;
	int err = 0;

	err = spnic_get_default_mac(nic_dev->hwdev, addr_bytes,
				     RTE_ETHER_ADDR_LEN);
	if (err)
		return err;

	rte_ether_addr_copy((struct rte_ether_addr *)addr_bytes,
			    &eth_dev->data->mac_addrs[0]);
	if (rte_is_zero_ether_addr(&eth_dev->data->mac_addrs[0]))
		rte_eth_random_addr(eth_dev->data->mac_addrs[0].addr_bytes);

	func_id = spnic_global_func_id(nic_dev->hwdev);
	err = spnic_set_mac(nic_dev->hwdev,
			    eth_dev->data->mac_addrs[0].addr_bytes,
			    0, func_id);
	if (err && err != SPNIC_PF_SET_VF_ALREADY)
		return err;

	rte_ether_addr_copy(&eth_dev->data->mac_addrs[0],
			    &nic_dev->default_addr);

	return 0;
}

static int spnic_func_init(struct rte_eth_dev *eth_dev)
{
	struct spnic_nic_dev *nic_dev = NULL;
	struct rte_pci_device *pci_dev = NULL;
	int err;

	pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);

	/* EAL is secondary and eth_dev is already created */
	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		PMD_DRV_LOG(INFO, "Initialize %s in secondary process",
			    eth_dev->data->name);

		return 0;
	}

	nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(eth_dev);
	memset(nic_dev, 0, sizeof(*nic_dev));
	snprintf(nic_dev->dev_name, sizeof(nic_dev->dev_name),
		 "spnic-%.4x:%.2x:%.2x.%x",
		 pci_dev->addr.domain, pci_dev->addr.bus,
		 pci_dev->addr.devid, pci_dev->addr.function);

	/* Alloc mac_addrs */
	eth_dev->data->mac_addrs = rte_zmalloc("spnic_mac",
		SPNIC_MAX_UC_MAC_ADDRS * sizeof(struct rte_ether_addr), 0);
	if (!eth_dev->data->mac_addrs) {
		PMD_DRV_LOG(ERR, "Allocate %zx bytes to store MAC addresses "
			    "failed, dev_name: %s",
			    SPNIC_MAX_UC_MAC_ADDRS *
			    sizeof(struct rte_ether_addr),
			    eth_dev->data->name);
		err = -ENOMEM;
		goto alloc_eth_addr_fail;
	}

	nic_dev->mc_list = rte_zmalloc("spnic_mc",
		SPNIC_MAX_MC_MAC_ADDRS * sizeof(struct rte_ether_addr), 0);
	if (!nic_dev->mc_list) {
		PMD_DRV_LOG(ERR, "Allocate %zx bytes to store multicast "
			    "addresses failed, dev_name: %s",
			    SPNIC_MAX_MC_MAC_ADDRS *
			    sizeof(struct rte_ether_addr),
			    eth_dev->data->name);
		err = -ENOMEM;
		goto alloc_mc_list_fail;
	}

	/* Create hardware device */
	nic_dev->hwdev = rte_zmalloc("spnic_hwdev", sizeof(*nic_dev->hwdev),
				     RTE_CACHE_LINE_SIZE);
	if (!nic_dev->hwdev) {
		PMD_DRV_LOG(ERR, "Allocate hwdev memory failed, dev_name: %s",
			    eth_dev->data->name);
		err = -ENOMEM;
		goto alloc_hwdev_mem_fail;
	}
	nic_dev->hwdev->pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	nic_dev->hwdev->dev_handle = nic_dev;
	nic_dev->hwdev->eth_dev = eth_dev;
	nic_dev->hwdev->port_id = eth_dev->data->port_id;

	err = spnic_init_hwdev(nic_dev->hwdev);
	if (err) {
		PMD_DRV_LOG(ERR, "Init chip hwdev failed, dev_name: %s",
			    eth_dev->data->name);
		goto init_hwdev_fail;
	}

	if (SPNIC_FUNC_TYPE(nic_dev->hwdev) == TYPE_VF)
		eth_dev->dev_ops = &spnic_pmd_vf_ops;
	else
		eth_dev->dev_ops = &spnic_pmd_ops;
	err = spnic_init_mac_table(eth_dev);
	if (err) {
		PMD_DRV_LOG(ERR, "Init mac table failed, dev_name: %s",
			    eth_dev->data->name);
		goto init_mac_table_fail;
	}

	rte_bit_relaxed_set32(SPNIC_DEV_INTR_EN, &nic_dev->dev_status);

	rte_bit_relaxed_set32(SPNIC_DEV_INIT, &nic_dev->dev_status);
	PMD_DRV_LOG(INFO, "Initialize %s in primary succeed",
		    eth_dev->data->name);

	return 0;

init_mac_table_fail:
	spnic_free_hwdev(nic_dev->hwdev);
	eth_dev->dev_ops = NULL;

init_hwdev_fail:
	rte_free(nic_dev->hwdev);
	nic_dev->hwdev = NULL;

alloc_hwdev_mem_fail:
	rte_free(nic_dev->mc_list);
	nic_dev->mc_list = NULL;

alloc_mc_list_fail:
	rte_free(eth_dev->data->mac_addrs);
	eth_dev->data->mac_addrs = NULL;

alloc_eth_addr_fail:
	PMD_DRV_LOG(ERR, "Initialize %s in primary failed",
		    eth_dev->data->name);
	return err;
}

static int spnic_dev_init(struct rte_eth_dev *eth_dev)
{
	struct rte_pci_device *pci_dev;

	pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);

	PMD_DRV_LOG(INFO, "Initializing spnic-%.4x:%.2x:%.2x.%x in %s process",
		    pci_dev->addr.domain, pci_dev->addr.bus,
		    pci_dev->addr.devid, pci_dev->addr.function,
		    (rte_eal_process_type() == RTE_PROC_PRIMARY) ?
		    "primary" : "secondary");

	return spnic_func_init(eth_dev);
}

static int spnic_dev_uninit(struct rte_eth_dev *dev)
{
	struct spnic_nic_dev *nic_dev;

	nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	rte_bit_relaxed_clear32(SPNIC_DEV_INIT, &nic_dev->dev_status);

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	spnic_dev_close(dev);

	return 0;
}

static struct rte_pci_id pci_id_spnic_map[] = {
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_RAMAXEL, SPNIC_DEV_ID_PF) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_RAMAXEL, SPNIC_DEV_ID_VF) },
	{.vendor_id = 0},
};

static int spnic_pci_probe(__rte_unused struct rte_pci_driver *pci_drv,
			   struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_probe(pci_dev,
					     sizeof(struct spnic_nic_dev),
					     spnic_dev_init);
}

static int spnic_pci_remove(struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_remove(pci_dev, spnic_dev_uninit);
}

static struct rte_pci_driver rte_spnic_pmd = {
	.id_table = pci_id_spnic_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING | RTE_PCI_DRV_INTR_LSC,
	.probe = spnic_pci_probe,
	.remove = spnic_pci_remove,
};

RTE_PMD_REGISTER_PCI(net_spnic, rte_spnic_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_spnic, pci_id_spnic_map);

RTE_INIT(spnic_init_log)
{
	spnic_logtype = rte_log_register("pmd.net.spnic");
	if (spnic_logtype >= 0)
		rte_log_set_level(spnic_logtype, RTE_LOG_INFO);
}

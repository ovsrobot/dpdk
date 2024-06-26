/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */


#include <rte_kvargs.h>
#include <rte_eal.h>
#include <rte_dev.h>
#include <rte_vfio.h>
#include <rte_ethdev.h>
#include <rte_bus_pci.h>
#include <ethdev_pci.h>

#include "ntlog.h"

#include "nt_util.h"

/* Global static variables: */

static int
nthw_pci_dev_init(struct rte_pci_device *pci_dev)
{
	uint32_t n_port_mask = -1;	/* All ports enabled by default */
	int n_phy_ports;
	NT_LOG_DBGX(DEBUG, NTNIC, "Dev %s PF #%i Init : %02x:%02x:%i\n", pci_dev->name,
		pci_dev->addr.function, pci_dev->addr.bus, pci_dev->addr.devid,
		pci_dev->addr.function);

	n_phy_ports = 0;

	for (int n_intf_no = 0; n_intf_no < n_phy_ports; n_intf_no++) {
		struct rte_eth_dev *eth_dev = NULL;
		char name[32];

		if ((1 << n_intf_no) & ~n_port_mask)
			continue;

		snprintf(name, sizeof(name), "ntnic%d", n_intf_no);

		eth_dev = rte_eth_dev_allocate(name);	/* TODO: name */

		if (!eth_dev) {
			NT_LOG_DBGX(ERR, NTNIC, "%s: %s: error=%d\n",
				(pci_dev->name[0] ? pci_dev->name : "NA"), name, -1);
			return -1;
		}

		NT_LOG_DBGX(DEBUG, NTNIC, "eth_dev %p, port_id %u, if_index %u\n",
					eth_dev, eth_dev->data->port_id, n_intf_no);


		struct rte_eth_link pmd_link;
		pmd_link.link_speed = RTE_ETH_SPEED_NUM_NONE;
		pmd_link.link_duplex = RTE_ETH_LINK_FULL_DUPLEX;
		pmd_link.link_status = RTE_ETH_LINK_DOWN;
		pmd_link.link_autoneg = RTE_ETH_LINK_AUTONEG;

		eth_dev->device = &pci_dev->device;
		eth_dev->data->dev_link = pmd_link;
		eth_dev->data->numa_node = pci_dev->device.numa_node;
		eth_dev->dev_ops = NULL;
		eth_dev->state = RTE_ETH_DEV_ATTACHED;

		rte_eth_copy_pci_info(eth_dev, pci_dev);
		/* performs rte_eth_copy_pci_info() */
		eth_dev_pci_specific_init(eth_dev, pci_dev);

		/* increase initialized ethernet devices - PF */
	}

	return 0;
}

static int
nthw_pci_dev_deinit(struct rte_eth_dev *eth_dev __rte_unused)
{
	NT_LOG_DBGX(DEBUG, NTNIC, "PCI device deinitialization\n");
	return 0;
}

static int
nthw_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
	struct rte_pci_device *pci_dev)
{
	int res;

	NT_LOG_DBGX(DEBUG, NTNIC, "pcidev: name: '%s'\n", pci_dev->name);
	NT_LOG_DBGX(DEBUG, NTNIC, "devargs: name: '%s'\n", pci_dev->device.name);

	if (pci_dev->device.devargs) {
		NT_LOG_DBGX(DEBUG, NTNIC, "devargs: args: '%s'\n",
			(pci_dev->device.devargs->args ? pci_dev->device.devargs->args : "NULL"));
		NT_LOG_DBGX(DEBUG, NTNIC, "devargs: data: '%s'\n",
			(pci_dev->device.devargs->data ? pci_dev->device.devargs->data : "NULL"));
	}

	const int n_rte_has_pci = rte_eal_has_pci();
	NT_LOG(DBG, NTNIC, "has_pci=%d\n", n_rte_has_pci);

	if (n_rte_has_pci == 0) {
		NT_LOG(ERR, NTNIC, "has_pci=%d: this PMD needs hugepages\n", n_rte_has_pci);
		return -1;
	}

	const int n_rte_vfio_no_io_mmu_enabled = rte_vfio_noiommu_is_enabled();
	NT_LOG(DBG, NTNIC, "vfio_no_iommu_enabled=%d\n", n_rte_vfio_no_io_mmu_enabled);

	if (n_rte_vfio_no_io_mmu_enabled) {
		NT_LOG(ERR, NTNIC, "vfio_no_iommu_enabled=%d: this PMD needs VFIO IOMMU\n",
			n_rte_vfio_no_io_mmu_enabled);
		return -1;
	}

	const enum rte_iova_mode n_rte_io_va_mode = rte_eal_iova_mode();
	NT_LOG(DBG, NTNIC, "iova mode=%d\n", n_rte_io_va_mode);

	if (n_rte_io_va_mode != RTE_IOVA_PA) {
		NT_LOG(WRN, NTNIC, "iova mode (%d) should be PA for performance reasons\n",
			n_rte_io_va_mode);
	}

	NT_LOG(DBG, NTNIC,
		"busid=" PCI_PRI_FMT
		" pciid=%04x:%04x_%04x:%04x locstr=%s @ numanode=%d: drv=%s drvalias=%s\n",
		pci_dev->addr.domain, pci_dev->addr.bus, pci_dev->addr.devid,
		pci_dev->addr.function, pci_dev->id.vendor_id, pci_dev->id.device_id,
		pci_dev->id.subsystem_vendor_id, pci_dev->id.subsystem_device_id,
		pci_dev->name[0] ? pci_dev->name : "NA",	/* locstr */
		pci_dev->device.numa_node,
		pci_dev->driver->driver.name ? pci_dev->driver->driver.name : "NA",
		pci_dev->driver->driver.alias ? pci_dev->driver->driver.alias : "NA");


	res = nthw_pci_dev_init(pci_dev);

	NT_LOG_DBGX(DEBUG, NTNIC, "leave: res=%d\n", res);
	return res;
}

static int
nthw_pci_remove(struct rte_pci_device *pci_dev)
{
	NT_LOG_DBGX(DEBUG, NTNIC);

	return rte_eth_dev_pci_generic_remove(pci_dev, nthw_pci_dev_deinit);
}

static struct rte_pci_driver rte_nthw_pmd = {
	.driver = {
		.name = "net_ntnic",
	},

	.drv_flags = RTE_PCI_DRV_NEED_MAPPING,
	.probe = nthw_pci_probe,
	.remove = nthw_pci_remove,
};

RTE_PMD_REGISTER_PCI(net_ntnic, rte_nthw_pmd);

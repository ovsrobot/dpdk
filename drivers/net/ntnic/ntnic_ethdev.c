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

/* Global static variables: */

static int
nthw_pci_dev_init(struct rte_pci_device *pci_dev __rte_unused)
{
	return 0;
}

static int
nthw_pci_dev_deinit(struct rte_eth_dev *eth_dev __rte_unused)
{
	return 0;
}

static int
nthw_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
	struct rte_pci_device *pci_dev)
{
	int res;
	res = nthw_pci_dev_init(pci_dev);
	return res;
}

static int
nthw_pci_remove(struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_remove(pci_dev, nthw_pci_dev_deinit);
}

static struct rte_pci_driver rte_nthw_pmd = {
	.driver = {
		.name = "net_ntnic",
	},

	.probe = nthw_pci_probe,
	.remove = nthw_pci_remove,
};

RTE_PMD_REGISTER_PCI(net_ntnic, rte_nthw_pmd);

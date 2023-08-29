/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#include <error.h>
#include <rte_common.h>
#include <ethdev_pci.h>

static int
sssnic_pci_probe(struct rte_pci_driver *pci_drv, struct rte_pci_device *pci_dev)
{
	RTE_SET_USED(pci_drv);
	RTE_SET_USED(pci_dev);
	return -EINVAL;
}

static int
sssnic_pci_remove(struct rte_pci_device *pci_dev)
{
	RTE_SET_USED(pci_dev);
	return -EINVAL;
}

static struct rte_pci_driver sssnic_pmd = {
	.probe = sssnic_pci_probe,
	.remove = sssnic_pci_remove,
};

RTE_PMD_REGISTER_PCI(net_sssnic, sssnic_pmd);

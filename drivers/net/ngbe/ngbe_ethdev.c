/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2020
 */

#include <rte_common.h>
#include <ethdev_pci.h>

#include <base/ngbe_devids.h>
#include "ngbe_ethdev.h"

/*
 * The set of PCI devices this driver supports
 */
static const struct rte_pci_id pci_id_ngbe_map[] = {
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_WANGXUN, NGBE_DEV_ID_EM_WX1860A2) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_WANGXUN, NGBE_DEV_ID_EM_WX1860A2S) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_WANGXUN, NGBE_DEV_ID_EM_WX1860A4) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_WANGXUN, NGBE_DEV_ID_EM_WX1860A4S) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_WANGXUN, NGBE_DEV_ID_EM_WX1860AL2) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_WANGXUN, NGBE_DEV_ID_EM_WX1860AL2S) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_WANGXUN, NGBE_DEV_ID_EM_WX1860AL4) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_WANGXUN, NGBE_DEV_ID_EM_WX1860AL4S) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_WANGXUN, NGBE_DEV_ID_EM_WX1860NCSI) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_WANGXUN, NGBE_DEV_ID_EM_WX1860A1) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_WANGXUN, NGBE_DEV_ID_EM_WX1860A1L) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_WANGXUN, NGBE_DEV_ID_EM_WX1860AL_W) },
	{ .vendor_id = 0, /* sentinel */ },
};

static int
eth_ngbe_dev_init(struct rte_eth_dev *eth_dev, void *init_params __rte_unused)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	rte_eth_copy_pci_info(eth_dev, pci_dev);

	return 0;
}

static int
eth_ngbe_dev_uninit(struct rte_eth_dev *eth_dev)
{
	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	RTE_SET_USED(eth_dev);

	return 0;
}

static int
eth_ngbe_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
		struct rte_pci_device *pci_dev)
{
	struct rte_eth_dev *pf_ethdev;
	struct rte_eth_devargs eth_da;
	int retval;

	if (pci_dev->device.devargs) {
		retval = rte_eth_devargs_parse(pci_dev->device.devargs->args,
				&eth_da);
		if (retval)
			return retval;
	} else {
		memset(&eth_da, 0, sizeof(eth_da));
	}

	retval = rte_eth_dev_create(&pci_dev->device, pci_dev->device.name,
			sizeof(struct ngbe_adapter),
			eth_dev_pci_specific_init, pci_dev,
			eth_ngbe_dev_init, NULL);

	if (retval || eth_da.nb_representor_ports < 1)
		return retval;

	pf_ethdev = rte_eth_dev_allocated(pci_dev->device.name);
	if (pf_ethdev == NULL)
		return -ENODEV;

	return 0;
}

static int eth_ngbe_pci_remove(struct rte_pci_device *pci_dev)
{
	struct rte_eth_dev *ethdev;

	ethdev = rte_eth_dev_allocated(pci_dev->device.name);
	if (!ethdev)
		return -ENODEV;

	return rte_eth_dev_destroy(ethdev, eth_ngbe_dev_uninit);
}

static struct rte_pci_driver rte_ngbe_pmd = {
	.id_table = pci_id_ngbe_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING |
		     RTE_PCI_DRV_INTR_LSC,
	.probe = eth_ngbe_pci_probe,
	.remove = eth_ngbe_pci_remove,
};

RTE_PMD_REGISTER_PCI(net_ngbe, rte_ngbe_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_ngbe, pci_id_ngbe_map);
RTE_PMD_REGISTER_KMOD_DEP(net_ngbe, "* igb_uio | uio_pci_generic | vfio-pci");


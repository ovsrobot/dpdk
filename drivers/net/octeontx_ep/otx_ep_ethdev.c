/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include <rte_ethdev_pci.h>
#include <rte_malloc.h>
#include <rte_io.h>

#include "otx2_common.h"
#include "otx_ep_common.h"
#include "otx_ep_vf.h"

#define OTX_EP_DEV(_eth_dev)            ((_eth_dev)->data->dev_private)
static int
otx_ep_chip_specific_setup(struct otx_ep_device *otx_epvf)
{
	struct rte_pci_device *pdev = otx_epvf->pdev;
	uint32_t dev_id = pdev->id.device_id;
	int ret;

	switch (dev_id) {
	case PCI_DEVID_OCTEONTX_EP_VF:
		otx_epvf->chip_id = dev_id;
		break;
	case PCI_DEVID_OCTEONTX2_EP_NET_VF:
	case PCI_DEVID_CN98XX_EP_NET_VF:
		otx_epvf->chip_id = dev_id;
		break;
	default:
		otx_ep_err("Unsupported device\n");
		ret = -EINVAL;
	}

	if (!ret)
		otx_ep_info("OTX_EP dev_id[%d]\n", dev_id);

	return ret;
}

/* OTX_EP VF device initialization */
static int
otx_epdev_init(struct otx_ep_device *otx_epvf)
{
	if (otx_ep_chip_specific_setup(otx_epvf)) {
		otx_ep_err("Chip specific setup failed\n");
		goto setup_fail;
	}

	return 0;

setup_fail:
	return -ENOMEM;
}

static int
otx_ep_eth_dev_uninit(struct rte_eth_dev *eth_dev)
{
	struct otx_ep_device *otx_epvf = OTX_EP_DEV(eth_dev);

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;
	otx_epvf->port_configured = 0;

	if (eth_dev->data->mac_addrs != NULL)
		rte_free(eth_dev->data->mac_addrs);

	return 0;
}

static int
otx_ep_eth_dev_init(struct rte_eth_dev *eth_dev)
{
	struct rte_pci_device *pdev = RTE_ETH_DEV_TO_PCI(eth_dev);
	struct otx_ep_device *otx_epvf = OTX_EP_DEV(eth_dev);
	unsigned char vf_mac_addr[RTE_ETHER_ADDR_LEN];

	/* Single process support */
	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	rte_eth_copy_pci_info(eth_dev, pdev);

	if (pdev->mem_resource[0].addr) {
		otx_ep_info("OTX_EP BAR0 is mapped:\n");
	} else {
		otx_ep_err("OTX_EP: Failed to map device BARs\n");
		otx_ep_err("BAR0 %p\n", pdev->mem_resource[0].addr);
		return -ENODEV;
	}
	otx_epvf->eth_dev = eth_dev;
	otx_epvf->port_id = eth_dev->data->port_id;
	eth_dev->data->mac_addrs = rte_zmalloc("otx_ep", RTE_ETHER_ADDR_LEN, 0);
	if (eth_dev->data->mac_addrs == NULL) {
		otx_ep_err("MAC addresses memory allocation failed\n");
		return -ENOMEM;
	}
	rte_eth_random_addr(vf_mac_addr);
	memcpy(eth_dev->data->mac_addrs, vf_mac_addr, RTE_ETHER_ADDR_LEN);
	otx_epvf->hw_addr = pdev->mem_resource[0].addr;
	otx_epvf->pdev = pdev;

	otx_epdev_init(otx_epvf);
	otx_epvf->port_configured = 0;

	return 0;
}

static int
otx_ep_eth_dev_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
		      struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_probe(pci_dev,
					     sizeof(struct otx_ep_device),
					     otx_ep_eth_dev_init);
}

static int
otx_ep_eth_dev_pci_remove(struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_remove(pci_dev,
					      otx_ep_eth_dev_uninit);
}

/* Set of PCI devices this driver supports */
static const struct rte_pci_id pci_id_otx_ep_map[] = {
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVID_OCTEONTX_EP_VF) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVID_OCTEONTX2_EP_NET_VF) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVID_CN98XX_EP_NET_VF) },
	{ .vendor_id = 0, /* sentinel */ }
};



static struct rte_pci_driver rte_otx_ep_pmd = {
	.id_table	= pci_id_otx_ep_map,
	.drv_flags      = RTE_PCI_DRV_NEED_MAPPING,
	.probe		= otx_ep_eth_dev_pci_probe,
	.remove		= otx_ep_eth_dev_pci_remove,
};

RTE_PMD_REGISTER_PCI(net_otx_ep, rte_otx_ep_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_otx_ep, pci_id_otx_ep_map);
RTE_PMD_REGISTER_KMOD_DEP(net_otx_ep, "* igb_uio | vfio-pci");
